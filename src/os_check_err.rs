use std::io;

pub trait CheckOsError: Sized {
    fn check_os_error(self) -> io::Result<Self>;
}

// avoids conflicting trait bounds with CheckOsError
pub trait CheckOsErrorPtr: Sized {
    fn check_os_error(self) -> io::Result<Self>;
}

pub trait CheckOsErrorReturned: Sized {
    fn check_os_error(self) -> Result<(), windows::core::Error>;
}

impl<T> CheckOsError for T
where
    T: PartialEq + From<bool>,
{
    fn check_os_error(self) -> io::Result<Self> {
        if self == T::from(false) {
            Err(io::Error::last_os_error())
        } else {
            Ok(self)
        }
    }
}

impl<T> CheckOsErrorPtr for *const T {
    fn check_os_error(self) -> io::Result<Self> {
        if self.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(self)
        }
    }
}

impl<T> CheckOsErrorPtr for *mut T {
    fn check_os_error(self) -> io::Result<Self> {
        if self.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(self)
        }
    }
}
