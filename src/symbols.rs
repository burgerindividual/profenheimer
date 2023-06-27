use std::ffi::OsString;
// use std::path::Path;
//
// #[derive(Debug, Clone)]
// pub struct LoadedImage {
//     pub image_path: Box<Path>,
//     pub image_base: usize,
//     pub image_size: u32,
// }

/// (image_path, image_base, image_size)
pub type LoadedImage = (OsString, u64, u64);
