use std::cell::OnceCell;
use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsStr;
use std::fs::File;
use std::future::Future;
use std::io::{Cursor, Read, Write};
use std::mem::size_of;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::from_utf8;
use std::{env, fs};

use object::Object;
use pdb_addr2line::pdb::PDB;
use pdb_addr2line::{Context, ContextPdbData, Frame};
use symsrv::SymbolCache;
use tokio::runtime;
use tokio::runtime::Runtime;

use crate::log::log_verbose;
use crate::trace::{EtwTraceShared, StackMap, StackTrace, ThreadNameMap};

pub struct LoadedImage {
    pub image_path: PathBuf,
    pub image_base: usize,
    pub image_size: usize,
}

pub struct PdbContext<'context, 'symbols: 'context> {
    _context_data: Pin<Box<ContextPdbData<'symbols, 'symbols, Cursor<Vec<u8>>>>>,
    pub inner_context: Context<'context, 'context>,
}

impl<'context: 'symbols, 'symbols> PdbContext<'context, 'symbols> {
    pub fn new(context_data: ContextPdbData<'symbols, 'symbols, Cursor<Vec<u8>>>) -> Self {
        unsafe {
            let box_ptr = Box::into_raw(Box::new(context_data));

            let inner_context = (*box_ptr).make_context().expect("Error parsing PDB data");

            let recreated_box_pin = Pin::new(Box::from_raw(box_ptr));

            Self {
                _context_data: recreated_box_pin,
                inner_context,
            }
        }
    }
}

type ContextFuture<'symbols> =
    dyn Future<Output = Option<ContextPdbData<'symbols, 'symbols, Cursor<Vec<u8>>>>> + 'symbols;

pub struct ImageSymbols<'symbols> {
    pub image_name: Box<str>,
    pub image_base: usize,
    pub image_size: usize,
    future_cell: OnceCell<Pin<Box<ContextFuture<'symbols>>>>,
    pdb_context: Option<Option<PdbContext<'symbols, 'symbols>>>,
}

impl<'symbols> ImageSymbols<'symbols> {
    pub fn new(
        image_name: Box<str>,
        image_base: usize,
        image_size: usize,
        future: Pin<Box<ContextFuture<'symbols>>>,
    ) -> Self {
        Self {
            image_name,
            image_base,
            image_size,
            future_cell: OnceCell::from(future),
            pdb_context: None,
        }
    }
}

impl<'symbols> ImageSymbols<'symbols> {
    pub fn find_frames(&mut self, runtime: &Runtime, addr_in_module: usize) -> Option<Vec<Frame>> {
        self.pdb_context
            .get_or_insert_with(|| unsafe {
                // Safety: This is safe because we should never hit this control flow more than
                // once. The mutable reference to self being a requirement for this function
                // guarantees that.
                runtime
                    .block_on(self.future_cell.take().unwrap_unchecked())
                    .map(PdbContext::new)
            })
            .as_ref()
            .and_then(|context| {
                context
                    .inner_context
                    .find_frames(addr_in_module as u32)
                    .unwrap_or(None)
            })
    }
}

pub struct TraceResults {
    pub stack_counts_map: StackMap,
    pub thread_name_map: ThreadNameMap,
    pub loaded_images: Vec<LoadedImage>,
    pub show_kernel_stacks: bool,
    pub is_system_trace: bool,
}

impl From<EtwTraceShared> for TraceResults {
    fn from(value: EtwTraceShared) -> Self {
        Self {
            stack_counts_map: value.stack_counts_map,
            thread_name_map: value.thread_name_map,
            loaded_images: value.loaded_images,
            show_kernel_stacks: value.show_kernel_stacks,
            is_system_trace: value.process_id.is_none(),
        }
    }
}

pub struct StackFrame<'frame> {
    /// Sample Address
    pub address: usize,
    /// Displacement into the symbol, or 0 if none
    pub displacement: usize,
    pub symbol_name: Option<&'frame str>,
    pub file_string: Option<&'frame str>,
}

impl<'frame> StackFrame<'frame> {
    pub fn has_displacement(&self) -> bool {
        self.displacement != 0
    }

    pub fn is_kernel_address(&self) -> bool {
        // kernel addresses have the highest bit set on windows
        self.address >> (size_of::<usize>() - 1) != 0
    }
}

//// Code below based off crate "blondie" by nico-abram

/// A stack trace and the count of samples it was found in
///
/// You can get them using [`CollectionResults::iter_callstacks`]
pub struct StackTraceEntry<'inner> {
    pub stack: &'inner StackTrace,
    pub sample_count: usize,
}

/// Base Address to LoadedSymbolContext Map
type PdbDb<'db> = BTreeMap<usize, ImageSymbols<'db>>;

fn create_pdb_db(images: &[LoadedImage]) -> PdbDb {
    // Only download symbols from symbol servers if the env var is set
    let use_symsrv = env::var("_NT_SYMBOL_PATH").is_ok();

    images
        .iter()
        .map(|image| {
            // if it's somehow a path, just use the whole path as the name
            let image_name = image
                .image_path
                .file_name()
                .unwrap_or(image.image_path.as_ref())
                .to_string_lossy()
                .to_string()
                .into_boxed_str();

            let pdb_future = Box::pin(async move {
                if let Some(path_str) = image.image_path.to_str() {
                    // Convert the \Device\HardDiskVolume path to a verbatim path \\?\HardDiskVolume
                    let verbatim_path = PathBuf::from(path_str.trim_end_matches('\0').replacen(
                        "\\Device\\",
                        "\\\\?\\",
                        1,
                    ));

                    if let Ok(image_contents) = fs::read(&verbatim_path) {
                        if let Ok(pe_file) = object::File::parse(&image_contents[..]) {
                            if let Ok(Some(pdb_info)) = pe_file.pdb_info() {
                                if let Ok(pdb_path_str) = from_utf8(pdb_info.path()) {
                                    let pdb_path = PathBuf::from(pdb_path_str);

                                    let mut pdb_file_bytes: Option<Vec<u8>> = None;

                                    if pdb_path.exists() {
                                        if let Ok(mut file) = File::open(pdb_path) {
                                            let mut file_bytes = Vec::with_capacity(0);
                                            if file.read_to_end(&mut file_bytes).is_ok() {
                                                pdb_file_bytes = Some(file_bytes);
                                            }
                                        }
                                    } else if use_symsrv {
                                        if let Some(pdb_filename) = pdb_path.file_name() {
                                            let symbol_cache = SymbolCache::new(
                                                symsrv::get_symbol_path_from_environment(""),
                                                false,
                                            );

                                            let mut guid_string = String::new();
                                            use std::fmt::Write;

                                            let pdb_guid = pdb_info.guid();

                                            for byte in pdb_guid[..4].iter().rev() {
                                                write!(&mut guid_string, "{byte:02X}").unwrap();
                                            }

                                            write!(&mut guid_string, "{:02X}", pdb_guid[5])
                                                .unwrap();
                                            write!(&mut guid_string, "{:02X}", pdb_guid[4])
                                                .unwrap();
                                            write!(&mut guid_string, "{:02X}", pdb_guid[7])
                                                .unwrap();
                                            write!(&mut guid_string, "{:02X}", pdb_guid[6])
                                                .unwrap();

                                            for byte in &pdb_guid[8..] {
                                                write!(&mut guid_string, "{byte:02X}").unwrap();
                                            }

                                            write!(&mut guid_string, "{:X}", pdb_info.age())
                                                .unwrap();

                                            let guid_str = OsStr::new(&guid_string);

                                            let relative_path: PathBuf =
                                                [pdb_filename, guid_str, pdb_filename]
                                                    .iter()
                                                    .collect();

                                            if let Ok(file_contents) =
                                                symbol_cache.get_file(&relative_path).await
                                            {
                                                pdb_file_bytes = Some(file_contents.to_vec());
                                            }
                                        }
                                    }

                                    return pdb_file_bytes
                                        .and_then(|bytes| PDB::open(Cursor::new(bytes)).ok())
                                        .and_then(|pdb| ContextPdbData::try_from_pdb(pdb).ok());
                                }
                            }
                        }
                    }
                }
                None
            });

            (
                image.image_base,
                ImageSymbols::new(image_name, image.image_base, image.image_size, pdb_future),
            )
        })
        .collect()
}
impl<'inner> StackTraceEntry<'inner> {
    /// Iterate stack frames in the callstack
    ///
    /// This also performs symbol resolution if possible, and tries to find the
    /// image (DLL/EXE) it comes from
    fn iter_stack_frames<
        'iter,
        F: for<'frame> FnMut(StackFrame<'frame>) -> Result<(), Box<dyn Error>>,
    >(
        &self,
        runtime: &'iter Runtime,
        pdb_db: &'iter mut PdbDb,
        use_source_paths: bool,
        mut callback: F,
    ) -> Result<(), Box<dyn Error>> {
        for frame_address in self.stack.address_stack {
            if frame_address == 0 {
                return Ok(());
            }

            // also checks if the address is within the image bounds
            if let Some((_, module)) = PdbDb::range_mut(pdb_db, ..frame_address).next_back()
                && (frame_address - module.image_base) <= module.image_size {

                let addr_in_image = frame_address - module.image_base;
                let image_name_cloned = module.image_name.clone();
                let image_name = Some(&*image_name_cloned);

                if let Some(symbol_frames) = module.find_frames(runtime, addr_in_image) {
                    for frame in symbol_frames {
                        let file_string = if use_source_paths {
                            frame.file.as_deref().or(image_name)
                        } else {
                            image_name
                        };

                        callback(StackFrame {
                            address: frame_address,
                            displacement: addr_in_image - frame.start_rva as usize,
                            symbol_name: frame.function.as_deref(),
                            file_string,
                        })?;
                    }
                } else {
                    callback(StackFrame {
                        address: frame_address,
                        displacement: addr_in_image,
                        symbol_name: None,
                        file_string: image_name,
                    })?;

                    continue;
                };
            } else {
                callback(StackFrame {
                    address: frame_address,
                    displacement: 0,
                    symbol_name: None,
                    file_string: None,
                })?;

                continue;
            }
        }
        Ok(())
    }
}

impl TraceResults {
    /// Iterate the distinct callstacks sampled in this execution
    pub fn iter_stack_traces(&self) -> impl Iterator<Item = StackTraceEntry<'_>> {
        self.stack_counts_map.iter().map(|x| StackTraceEntry {
            stack: x.0,
            sample_count: *x.1,
        })
    }

    /// Resolve call stack symbols and write a dtrace-like sampling report to `w`
    pub fn write_dtrace<W: Write>(
        &self,
        mut w: W,
        use_source_paths: bool,
    ) -> Result<(), Box<dyn Error>> {
        log_verbose!("Locating symbols...");
        let mut pdb_db = create_pdb_db(&self.loaded_images);

        let runtime = if let Ok(multi_thread_rt) = runtime::Builder::new_multi_thread()
            .enable_io()
            .enable_time()
            .build()
        {
            println!("Using multi-threaded symbol resolution");
            multi_thread_rt
        } else {
            println!("Using single-threaded symbol resolution");
            runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("Unable to build tokio runtime")
        };

        log_verbose!("Converting stacks to dtrace format...");
        for callstack in self.iter_stack_traces() {
            callstack.iter_stack_frames(&runtime, &mut pdb_db, use_source_paths, |frame| {
                if !self.show_kernel_stacks && frame.is_kernel_address() {
                    return Ok(());
                }

                if frame.file_string.is_some() || frame.symbol_name.is_some() {
                    let file_part = frame
                        .file_string
                        .map_or(String::new(), |name| name.to_string());
                    let symbol_part = frame
                        .symbol_name
                        .map_or(String::new(), |name| format!("`{name}"));
                    let displacement_part = if frame.has_displacement() {
                        format!("+0x{:X}", frame.displacement)
                    } else {
                        String::new()
                    };

                    writeln!(w, "\t\t{file_part}{symbol_part}{displacement_part}")?;
                } else {
                    writeln!(w, "\t\t{:X}", frame.address)?;
                }

                Ok(())
            })?;

            // add fake stack frame to include process and thread info
            // TODO: update to use image names from Process/Start and Process/DCStart
            let pid = callstack.stack.process_id;
            let pid_string = if self.is_system_trace {
                format!("PID: {pid} ")
            } else {
                "".to_string()
            };

            let tid = callstack.stack.thread_id;
            let thread_string = self
                .thread_name_map
                .get(&tid)
                .filter(|name| !name.is_empty())
                .map_or_else(
                    || format!("Thread ID {tid}"),
                    |name| format!("{name} (ID: {tid})"),
                );

            writeln!(w, "\t\t{pid_string}{thread_string}")?;

            let count = callstack.sample_count;
            write!(w, "\t\t{count}\n\n")?;
        }
        Ok(())
    }
}
