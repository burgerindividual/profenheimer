use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::io::*;
use std::path::PathBuf;

use object::Object;
use pdb_addr2line::pdb::PDB;
use pdb_addr2line::ContextPdbData;
use symsrv::SymbolCache;

use crate::log::log_verbose;
use crate::trace::{EtwTraceShared, StackMap, StackTrace, ThreadNameMap};

pub struct LoadedImage {
    pub image_path: PathBuf,
    pub image_base: usize,
    pub image_size: usize,
}

pub struct LoadedImageSymbols {
    pub image_name: Box<str>,
    pub image_base: usize,
    pub image_size: usize,
    pub pdb_context: OwnedPdb,
}

pub struct LoadedSymbolContext<'a, 'b> {
    pub image_name: Box<str>,
    pub image_base: usize,
    pub image_size: usize,
    pub pdb_context: pdb_addr2line::Context<'a, 'b>,
}

pub struct TraceResults {
    pub stack_counts_map: StackMap,
    pub thread_name_map: ThreadNameMap,
    pub loaded_images: Vec<LoadedImage>,
    pub show_kernel_stacks: bool,
}

impl From<EtwTraceShared> for TraceResults {
    fn from(value: EtwTraceShared) -> Self {
        Self {
            stack_counts_map: value.stack_counts_map,
            thread_name_map: value.thread_name_map,
            loaded_images: value.loaded_images,
            show_kernel_stacks: value.show_kernel_stacks,
        }
    }
}

//// Code below based off crate "blondie" by nico-abram

/// A stack trace and the count of samples it was found in
///
/// You can get them using [`CollectionResults::iter_callstacks`]
pub struct StackTraceEntry<'a> {
    pub stack: &'a StackTrace,
    pub sample_count: usize,
}

/// An address from a callstack
///
/// You can get them using [`StackTraceEntry::iter_resolved_addresses`]
pub struct CallstackSample<'a> {
    /// Sample Address
    pub address: usize,
    /// Displacement into the symbol
    pub displacement: usize,
    pub symbol_names: &'a [&'a str],
    pub image_name: Option<Box<str>>,
}

type OwnedPdb = ContextPdbData<'static, 'static, Cursor<Vec<u8>>>;
/// Base Address to LoadedSymbolContext Map
type PdbDb<'a, 'b> = BTreeMap<usize, LoadedSymbolContext<'a, 'b>>;

fn find_pdbs(images: &[LoadedImage]) -> Vec<LoadedImageSymbols> {
    let mut pdb_db = Vec::with_capacity(images.len());

    fn owned_pdb(pdb_file_bytes: Vec<u8>) -> Option<OwnedPdb> {
        let pdb = PDB::open(Cursor::new(pdb_file_bytes)).ok()?;
        ContextPdbData::try_from_pdb(pdb).ok()
    }

    // Only download symbols from symbol servers if the env var is set
    let use_symsrv = env::var("_NT_SYMBOL_PATH").is_ok();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    for image in images {
        let path_str = match image.image_path.to_str() {
            Some(x) => x,
            _ => continue,
        };
        // Convert the \Device\HardDiskVolume path to a verbatim path \\?\HardDiskVolume
        let verbatim_path_os: OsString = path_str
            .trim_end_matches('\0')
            .replacen("\\Device\\", "\\\\?\\", 1)
            .into();

        let path = PathBuf::from(verbatim_path_os);

        let image_contents = match std::fs::read(&path) {
            Ok(x) => x,
            _ => continue,
        };
        let image_name = path.file_name().unwrap();
        let pe_file = match object::File::parse(&image_contents[..]) {
            Ok(x) => x,
            _ => continue,
        };

        let (pdb_path, pdb_guid, pdb_age) = match pe_file.pdb_info() {
            Ok(Some(x)) => (x.path(), x.guid(), x.age()),
            _ => continue,
        };
        let pdb_path = match std::str::from_utf8(pdb_path) {
            Ok(x) => x,
            _ => continue,
        };
        let pdb_path = PathBuf::from(pdb_path);
        if pdb_path.exists() {
            let mut file = match std::fs::File::open(pdb_path) {
                Err(_) => continue,
                Ok(x) => x,
            };
            let mut file_bytes = Vec::with_capacity(0);
            if file.read_to_end(&mut file_bytes).is_err() {
                continue;
            }
            let pdb_context = match owned_pdb(file_bytes) {
                Some(x) => x,
                _ => continue,
            };

            pdb_db.push(LoadedImageSymbols {
                image_name: image_name.to_string_lossy().to_string().into_boxed_str(),
                image_base: image.image_base,
                image_size: image.image_size,
                pdb_context,
            });
        } else if use_symsrv {
            let pdb_filename = match pdb_path.file_name() {
                Some(x) => x,
                _ => continue,
            };

            let symbol_cache =
                SymbolCache::new(symsrv::get_symbol_path_from_environment(""), false);

            let mut guid_string = String::new();
            use std::fmt::Write;
            for byte in pdb_guid[..4].iter().rev() {
                write!(&mut guid_string, "{byte:02X}").unwrap();
            }
            write!(&mut guid_string, "{:02X}", pdb_guid[5]).unwrap();
            write!(&mut guid_string, "{:02X}", pdb_guid[4]).unwrap();
            write!(&mut guid_string, "{:02X}", pdb_guid[7]).unwrap();
            write!(&mut guid_string, "{:02X}", pdb_guid[6]).unwrap();
            for byte in &pdb_guid[8..] {
                write!(&mut guid_string, "{byte:02X}").unwrap();
            }
            write!(&mut guid_string, "{pdb_age:X}").unwrap();
            let guid_str = std::ffi::OsStr::new(&guid_string);

            let relative_path: PathBuf = [pdb_filename, guid_str, pdb_filename].iter().collect();

            if let Ok(rt) = &rt {
                if let Ok(file_contents) = rt.block_on(symbol_cache.get_file(&relative_path)) {
                    let pdb_context = match owned_pdb(file_contents.to_vec()) {
                        Some(x) => x,
                        _ => continue,
                    };
                    pdb_db.push(LoadedImageSymbols {
                        image_name: image_name.to_string_lossy().to_string().into_boxed_str(),
                        image_base: image.image_base,
                        image_size: image.image_size,
                        pdb_context,
                    });
                }
            }
        }
    }
    pdb_db
}
impl<'a> StackTraceEntry<'a> {
    /// Iterate addresses in this callstack
    ///
    /// This also performs symbol resolution if possible, and tries to find the
    /// image (DLL/EXE) it comes from
    fn iter_resolved_addresses<F: for<'b> FnMut(CallstackSample) -> Result<()>>(
        &'a self,
        pdb_db: &'a PdbDb,
        vec: &mut Vec<&'_ str>,
        mut callback: F,
    ) -> Result<()> {
        fn reuse_vec<T, U>(mut vec: Vec<T>) -> Vec<U> {
            // See https://users.rust-lang.org/t/pattern-how-to-reuse-a-vec-str-across-loop-iterations/61657/3
            assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<U>());
            assert_eq!(std::mem::align_of::<T>(), std::mem::align_of::<U>());
            vec.clear();
            vec.into_iter().map(|_| unreachable!()).collect()
        }

        let mut symbol_names_storage = reuse_vec(std::mem::take(vec));
        for sample_address in self.stack.address_stack {
            if sample_address == 0 {
                *vec = symbol_names_storage;
                return Ok(());
            }
            let mut symbol_names = symbol_names_storage;

            let module = pdb_db.range(..sample_address).rev().next();
            let module = match module {
                None => {
                    callback(CallstackSample {
                        address: sample_address,
                        displacement: 0,
                        symbol_names: &[],
                        image_name: None,
                    })?;
                    symbol_names_storage = reuse_vec(symbol_names);
                    continue;
                }
                Some(x) => x.1,
            };
            let image_name = module.image_name.clone();
            let addr_in_module = sample_address - module.image_base;

            let procedure_frames = match module.pdb_context.find_frames(addr_in_module as u32) {
                Ok(Some(x)) => x,
                _ => {
                    callback(CallstackSample {
                        address: sample_address,
                        displacement: 0,
                        symbol_names: &[],
                        image_name: Some(image_name),
                    })?;
                    symbol_names_storage = reuse_vec(symbol_names);
                    continue;
                }
            };

            for frame in &procedure_frames.frames {
                symbol_names.push(frame.function.as_deref().unwrap_or("Unknown"));
            }

            callback(CallstackSample {
                address: sample_address,
                displacement: sample_address - procedure_frames.start_rva as usize, // TODO: validate this
                symbol_names: &symbol_names,
                image_name: Some(image_name),
            })?;

            symbol_names_storage = reuse_vec(symbol_names);
        }
        *vec = symbol_names_storage;
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
    pub fn write_dtrace<W: Write>(&self, mut w: W) -> Result<()> {
        log_verbose!("Loading symbols...");
        let pdbs = find_pdbs(&self.loaded_images);
        let pdb_db: PdbDb = pdbs
            .iter()
            .filter_map(|symbols| {
                symbols.pdb_context.make_context().ok().map(|pdb_context| {
                    (
                        symbols.image_base,
                        LoadedSymbolContext {
                            image_base: symbols.image_base,
                            image_size: symbols.image_size,
                            image_name: symbols.image_name.clone(),
                            pdb_context,
                        },
                    )
                })
            })
            .collect::<BTreeMap<_, _>>();
        let mut v = vec![];

        log_verbose!("Converting stacks to dtrace format...");
        for callstack in self.iter_stack_traces() {
            callstack.iter_resolved_addresses(&pdb_db, &mut v, |sample| {
                if !self.show_kernel_stacks {
                    // kernel addresses have the highest bit set on windows
                    if sample.address & (1 << 63) != 0 {
                        return Ok(());
                    }
                }
                for symbol_name in sample.symbol_names {
                    let displacement = sample.displacement;
                    if let Some(image_name) = sample.image_name.clone() {
                        if displacement != 0 {
                            writeln!(w, "\t\t{image_name}`{symbol_name}+0x{displacement:X}")?;
                        } else {
                            writeln!(w, "\t\t{image_name}`{symbol_name}")?;
                        }
                    } else {
                        // Image name not found
                        if displacement != 0 {
                            writeln!(w, "\t\t{symbol_name}+0x{displacement:X}")?;
                        } else {
                            writeln!(w, "\t\t{symbol_name}")?;
                        }
                    }
                }
                if sample.symbol_names.is_empty() {
                    // Symbol not found
                    writeln!(w, "\t\t{:X}", sample.address)?;
                }
                Ok(())
            })?;

            let count = callstack.sample_count;
            write!(w, "\t\t{count}\n\n")?;
        }
        Ok(())
    }
}
