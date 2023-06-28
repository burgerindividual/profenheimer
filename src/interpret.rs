// use std::collections::BTreeMap;
// use std::ffi::OsString;
// use std::io;
// use std::io::{Read, Write};
// use std::path::PathBuf;
//
// use object::Object;
// use pdb_addr2line::pdb::PDB;
// use pdb_addr2line::ContextPdbData;
//
// use crate::trace::MAX_STACK_DEPTH;
//
// pub struct TraceResults {}
//
// // CODE BELOW BASED OFF CRATE "blondie"
// //
// // MIT License
// //
// // Copyright (c) 2021 Nicolas Abram Lujan
// //
// // Permission is hereby granted, free of charge, to any person obtaining a
// copy // of this software and associated documentation files (the "Software"),
// to deal // in the Software without restriction, including without limitation
// the rights // to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell // copies of the Software, and to permit persons to whom the
// Software is // furnished to do so, subject to the following conditions:
// //
// // The above copyright notice and this permission notice shall be included in
// // all copies or substantial portions of the Software.
// //
// // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// // IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// // FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE // AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// // LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, // OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE // SOFTWARE.
//
// /// A callstack and the count of samples it was found in
// ///
// /// You can get them using [`CollectionResults::iter_callstacks`]
// pub struct CallStack<'a> {
//     stack: &'a [u64; MAX_STACK_DEPTH],
//     sample_count: u64,
// }
//
// /// An address from a callstack
// ///
// /// You can get them using [`CallStack::iter_resolved_addresses`]
// pub struct Address {
//     /// Sample Address
//     pub addr: u64,
//     /// Displacement into the symbol
//     pub displacement: u64,
//     /// Symbol names
//     pub symbol_names: Vec<String>,
//     /// Imager (Exe or Dll) name
//     pub image_name: Option<String>,
// }
// type OwnedPdb = ContextPdbData<'static, 'static, std::io::Cursor<Vec<u8>>>;
// type PdbDb<'a, 'b> =
//     std::collections::BTreeMap<u64, (u64, u64, OsString,
// pdb_addr2line::Context<'a, 'b>)>;
//
// /// Returns Vec<(image_base, image_size, image_name, addr2line pdb context)>
// fn find_pdbs(images: &[(OsString, u64, u64)]) -> Vec<(u64, u64, OsString,
// OwnedPdb)> {     let mut pdb_db = Vec::with_capacity(images.len());
//
//     fn owned_pdb(pdb_file_bytes: Vec<u8>) -> Option<OwnedPdb> {
//         let pdb = PDB::open(std::io::Cursor::new(pdb_file_bytes)).ok()?;
//         ContextPdbData::try_from_pdb(pdb).ok()
//     }
//
//     // Only download symbols from symbol servers if the env var is set
//     let use_symsrv = std::env::var("_NT_SYMBOL_PATH").is_ok();
//
//     let rt = tokio::runtime::Builder::new_current_thread()
//         .enable_all()
//         .build();
//     for (path, image_base, image_size) in images {
//         let path_str = match path.to_str() {
//             Some(x) => x,
//             _ => continue,
//         };
//         // Convert the \Device\HardDiskVolume path to a verbatim path
// \\?\HardDiskVolume         let verbatim_path_os: OsString = path_str
//             .trim_end_matches('\0')
//             .replacen("\\Device\\", "\\\\?\\", 1)
//             .into();
//
//         let path = PathBuf::from(verbatim_path_os);
//
//         let image_contents = match std::fs::read(&path) {
//             Ok(x) => x,
//             _ => continue,
//         };
//         let image_name = path.file_name().unwrap();
//         let pe_file = match object::File::parse(&image_contents[..]) {
//             Ok(x) => x,
//             _ => continue,
//         };
//
//         let (pdb_path, pdb_guid, pdb_age) = match pe_file.pdb_info() {
//             Ok(Some(x)) => (x.path(), x.guid(), x.age()),
//             _ => continue,
//         };
//         let pdb_path = match std::str::from_utf8(pdb_path) {
//             Ok(x) => x,
//             _ => continue,
//         };
//         let pdb_path = PathBuf::from(pdb_path);
//         if pdb_path.exists() {
//             let mut file = match std::fs::File::open(pdb_path) {
//                 Err(_) => continue,
//                 Ok(x) => x,
//             };
//             let mut file_bytes = Vec::with_capacity(0);
//             if file.read_to_end(&mut file_bytes).is_err() {
//                 continue;
//             }
//             let pdb_ctx = match owned_pdb(file_bytes) {
//                 Some(x) => x,
//                 _ => continue,
//             };
//
//             pdb_db.push((*image_base, *image_size, image_name.to_owned(),
// pdb_ctx));         } else if use_symsrv {
//             let pdb_filename = match pdb_path.file_name() {
//                 Some(x) => x,
//                 _ => continue,
//             };
//
//             let symbol_cache =
//
// symsrv::SymbolCache::new(symsrv::get_symbol_path_from_environment(""),
// false);
//
//             let mut guid_string = String::new();
//             use std::fmt::Write;
//             for byte in pdb_guid[..4].iter().rev() {
//                 write!(&mut guid_string, "{byte:02X}").unwrap();
//             }
//             write!(&mut guid_string, "{:02X}", pdb_guid[5]).unwrap();
//             write!(&mut guid_string, "{:02X}", pdb_guid[4]).unwrap();
//             write!(&mut guid_string, "{:02X}", pdb_guid[7]).unwrap();
//             write!(&mut guid_string, "{:02X}", pdb_guid[6]).unwrap();
//             for byte in &pdb_guid[8..] {
//                 write!(&mut guid_string, "{byte:02X}").unwrap();
//             }
//             write!(&mut guid_string, "{pdb_age:X}").unwrap();
//             let guid_str = std::ffi::OsStr::new(&guid_string);
//
//             let relative_path: PathBuf = [pdb_filename, guid_str,
// pdb_filename].iter().collect();
//
//             if let Ok(rt) = &rt {
//                 if let Ok(file_contents) =
// rt.block_on(symbol_cache.get_file(&relative_path)) {                     let
// pdb_ctx = match owned_pdb(file_contents.to_vec()) {
// Some(x) => x,                         _ => continue,
//                     };
//                     pdb_db.push((*image_base, *image_size,
// image_name.to_owned(), pdb_ctx));                 }
//             }
//         }
//     }
//     pdb_db
// }
// impl<'a> CallStack<'a> {
//     /// Iterate addresses in this callstack
//     ///
//     /// This also performs symbol resolution if possible, and tries to find
// the     /// image (DLL/EXE) it comes from
//     fn iter_resolved_addresses2<
//         F: for<'b> FnMut(u64, u64, &'b [&'b str], Option<&'b str>) ->
// io::Result<()>,     >(
//         &'a self,
//         pdb_db: &'a PdbDb,
//         v: &mut Vec<&'_ str>,
//         mut f: F,
//     ) -> io::Result<()> {
//         fn reuse_vec<T, U>(mut v: Vec<T>) -> Vec<U> {
//             // See https://users.rust-lang.org/t/pattern-how-to-reuse-a-vec-str-across-loop-iterations/61657/3
//             assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<U>());
//             assert_eq!(std::mem::align_of::<T>(), std::mem::align_of::<U>());
//             v.clear();
//             v.into_iter().map(|_| unreachable!()).collect()
//         }
//         let displacement = 0u64;
//         let mut symbol_names_storage = reuse_vec(std::mem::take(v));
//         for &addr in self.stack {
//             if addr == 0 {
//                 *v = symbol_names_storage;
//                 return Ok(());
//             }
//             let mut symbol_names = symbol_names_storage;
//
//             let module = pdb_db.range(..addr).rev().next();
//             let module = match module {
//                 None => {
//                     f(addr, 0, &[], None)?;
//                     symbol_names_storage = reuse_vec(symbol_names);
//                     continue;
//                 }
//                 Some(x) => x.1,
//             };
//             let image_name = module.2.to_str();
//             let addr_in_module = addr - module.0;
//
//             let procedure_frames = match module.3.find_frames(addr_in_module
// as u32) {                 Ok(Some(x)) => x,
//                 _ => {
//                     f(addr, 0, &[], image_name)?;
//                     symbol_names_storage = reuse_vec(symbol_names);
//                     continue;
//                 }
//             };
//             for frame in &procedure_frames.frames {
//
// symbol_names.push(frame.function.as_deref().unwrap_or("Unknown"));
//             }
//             f(addr, displacement, &symbol_names, image_name)?;
//             symbol_names_storage = reuse_vec(symbol_names);
//         }
//         *v = symbol_names_storage;
//         Ok(())
//     }
// }
//
// impl TraceResults {
//     /// Resolve call stack symbols and write a dtrace-like sampling report to
//     /// `w`
//     pub fn write_dtrace<W: Write>(&self, mut w: W) -> io::Result<()> {
//         let pdbs = find_pdbs(&self.0.image_paths);
//         let pdb_db: PdbDb = pdbs
//             .iter()
//             .filter_map(|(a, b, c, d)| d.make_context().ok().map(|d| (*a,
// (*a, *b, c.clone(), d))))             .collect::<BTreeMap<_, _>>();
//         let mut v = vec![];
//
//         for callstack in self.iter_callstacks() {
//             callstack.iter_resolved_addresses2(
//                 &pdb_db,
//                 &mut v,
//                 |address, displacement, symbol_names, image_name| {
//                     if !self.0.show_kernel_samples {
//                         // kernel addresses have the highest bit set on
// windows                         if address & (1 << 63) != 0 {
//                             return Ok(());
//                         }
//                     }
//                     for symbol_name in symbol_names {
//                         if let Some(image_name) = image_name {
//                             if displacement != 0 {
//                                 writeln!(w,
// "\t\t{image_name}`{symbol_name}+0x{displacement:X}")?;
// } else {                                 writeln!(w,
// "\t\t{image_name}`{symbol_name}")?;                             }
//                         } else {
//                             // Image name not found
//                             if displacement != 0 {
//                                 writeln!(w,
// "\t\t{symbol_name}+0x{displacement:X}")?;                             } else
// {                                 writeln!(w, "\t\t{symbol_name}")?;
//                             }
//                         }
//                     }
//                     if symbol_names.is_empty() {
//                         // Symbol not found
//                         writeln!(w, "\t\t{address:X}")?;
//                     }
//                     Ok(())
//                 },
//             )?;
//
//             let count = callstack.sample_count;
//             write!(w, "\t\t{count}\n\n")?;
//         }
//         Ok(())
//     }
// }
