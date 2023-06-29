use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::process::ExitCode;
use std::ptr::{addr_of, from_exposed_addr};

use windows::Win32::Foundation::*;
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    SE_SYSTEM_PROFILE_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, RegisterWaitForSingleObject, INFINITE,
    PROCESS_ALL_ACCESS, WT_EXECUTEONLYONCE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, EnumWindows, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId,
};

use crate::log::{err_verbose, log_verbose};

static mut CURRENT_WINDOW_HANDLE: HWND = HWND(0);

pub unsafe fn get_window_process(partial_window_title: &str) -> Process {
    EnumWindows(
        Some(check_window_title_parents),
        LPARAM((&partial_window_title as *const &str).expose_addr() as isize),
    );

    if CURRENT_WINDOW_HANDLE.0 == 0 {
        err_verbose!("Unable to find process, exiting...");
        ExitCode::FAILURE.exit_process();
    }

    let mut process_id: u32 = 0;
    GetWindowThreadProcessId(CURRENT_WINDOW_HANDLE, Some(&mut process_id));

    log_verbose!("Attaching to PID {process_id}...");
    let process_handle = get_process_handle_from_pid(process_id);

    Process {
        handle: process_handle,
        id: process_id,
    }
}

pub unsafe fn get_process_handle_from_pid(process_id: u32) -> OwnedHandle {
    OwnedHandle::from_raw_handle(RawHandle::from(
        OpenProcess(PROCESS_ALL_ACCESS, true, process_id)
            .expect("Unable to attach to process")
            .0 as RawHandle,
    ))
}

unsafe extern "system" fn check_window_title_parents(
    window_handle: HWND,
    partial_window_title_ptr: LPARAM,
) -> BOOL {
    check_window_title(window_handle, partial_window_title_ptr, true)
}

unsafe extern "system" fn check_window_title_children(
    window_handle: HWND,
    partial_window_title_ptr: LPARAM,
) -> BOOL {
    check_window_title(window_handle, partial_window_title_ptr, false)
}

#[inline(always)]
unsafe fn check_window_title(
    window_handle: HWND,
    partial_window_title_ptr: LPARAM,
    enumerate_children: bool,
) -> BOOL {
    let partial_window_title: &str =
        *from_exposed_addr::<&str>(partial_window_title_ptr.0 as usize);

    let length = GetWindowTextLengthW(window_handle) + 1; // account for nul char
    let length_usize = length as usize;
    // we should be calling assume_init after this, but because GetWindowTextW takes
    // a reference, we have to do this
    let mut lpstring: Box<[u16]> = Box::new_uninit_slice(length_usize).assume_init();

    GetWindowTextW(window_handle, &mut lpstring);

    // remove null char
    let window_title = String::from_utf16_lossy(&lpstring[0..(length_usize - 1)]);

    if window_title.contains(partial_window_title) {
        log_verbose!("Found window with title \"{window_title}\"");
        CURRENT_WINDOW_HANDLE = window_handle;
        // return false to break out of the loop
        BOOL::from(false)
    } else {
        if enumerate_children {
            EnumChildWindows(
                window_handle,
                Some(check_window_title_children),
                LPARAM((&partial_window_title as *const &str).expose_addr() as isize),
            );
        }
        BOOL::from(true)
    }
}

pub unsafe fn register_wait_on_process_close(
    process_handle: &OwnedHandle,
    callback: unsafe extern "system" fn(*mut c_void, BOOLEAN) -> (),
) -> OwnedHandle {
    let raw_process_handle = HANDLE(process_handle.as_raw_handle() as isize);
    let mut raw_wait_handle = HANDLE::default();

    RegisterWaitForSingleObject(
        &mut raw_wait_handle,
        raw_process_handle,
        Some(callback),
        None,
        INFINITE,
        WT_EXECUTEONLYONCE,
    )
    .ok()
    .expect("Error registering for process close");

    OwnedHandle::from_raw_handle(raw_wait_handle.0 as RawHandle)
}

#[derive(Debug)]
pub struct Process {
    pub handle: OwnedHandle,
    pub id: u32,
}

//// Code below based off crate "blondie" by nico-abram

pub unsafe fn acquire_privileges() {
    let mut privs = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: Default::default(),
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    LookupPrivilegeValueW(None, SE_SYSTEM_PROFILE_NAME, &mut privs.Privileges[0].Luid)
        .ok()
        .expect("Error looking up privilege value");

    let mut token_handle_raw = HANDLE::default();
    OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES,
        &mut token_handle_raw,
    )
    .ok()
    .expect("Error opening process token");

    AdjustTokenPrivileges(
        token_handle_raw,
        false,
        Some(addr_of!(privs)),
        0,
        None,
        None,
    )
    .ok()
    .unwrap_or_else(|_| {
        CloseHandle(token_handle_raw);
        panic!("Error adjusting privileges (Was the process run as Admin?)");
    });

    CloseHandle(token_handle_raw)
        .ok()
        .expect("Error closing process token handle");
}
