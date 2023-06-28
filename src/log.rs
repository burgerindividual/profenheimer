use std::sync::OnceLock;

pub static VERBOSE_LOGGING: OnceLock<bool> = OnceLock::new();

macro_rules! log_verbose {
    ($($arg:tt)*) => {{
        if *crate::log::VERBOSE_LOGGING.get().unwrap_or(&false) {
            println!($($arg)*);
        }
    }}
}

macro_rules! err_verbose {
    ($($arg:tt)*) => {{
        if *crate::log::VERBOSE_LOGGING.get().unwrap_or(&false) {
            eprintln!($($arg)*);
        }
    }}
}

pub(crate) use {err_verbose, log_verbose};
