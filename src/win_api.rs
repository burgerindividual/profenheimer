use crate::symbols::LoadedImage;
use ferrisetw::native::ControlHandle;
use ferrisetw::provider::kernel_providers::PROFILE_PROVIDER;
use std::ffi::OsString;
use std::mem::{size_of, transmute, MaybeUninit};
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::process::ExitCode;
use std::ptr::{addr_of, from_exposed_addr};
use windows::Win32::Foundation::*;
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    SE_SYSTEM_PROFILE_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
};
use windows::Win32::System::Diagnostics::Etw::{
    TraceSampledProfileIntervalInfo, TraceSetInformation, TraceStackTracingInfo, CLASSIC_EVENT_ID,
    CONTROLTRACE_HANDLE, TRACE_PROFILE_INTERVAL,
};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModules, GetModuleFileNameExW, GetModuleInformation, MODULEINFO,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, WaitForSingleObject, PROCESS_ALL_ACCESS,
};
use windows::Win32::System::WindowsProgramming::{
    NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, EnumWindows, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId,
};

static mut CURRENT_WINDOW_HANDLE: HWND = HWND(0);

pub unsafe fn get_window_process_handle_pid(partial_window_title: &str) -> (OwnedHandle, u32) {
    EnumWindows(
        Some(check_window_title_parents),
        LPARAM((&partial_window_title as *const &str).expose_addr() as isize),
    );

    if CURRENT_WINDOW_HANDLE.0 == 0 {
        eprintln!("Unable to find process, exiting...");
        ExitCode::FAILURE.exit_process();
    }

    let mut process_pid: u32 = 0;
    GetWindowThreadProcessId(CURRENT_WINDOW_HANDLE, Some(&mut process_pid));

    println!("Attaching to PID {process_pid}...");
    let owned_handle = OwnedHandle::from_raw_handle(RawHandle::from(
        OpenProcess(PROCESS_ALL_ACCESS, true, process_pid)
            .expect("Unable to attach to process")
            .0 as RawHandle,
    ));

    (owned_handle, process_pid)
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
    // we should be calling assume_init after this, but because GetWindowTextW takes a reference, we
    // have to do this
    let mut lpstring: Box<[u16]> = Box::new_uninit_slice(length_usize).assume_init();

    GetWindowTextW(window_handle, &mut lpstring);

    // remove null char
    let window_title = String::from_utf16_lossy(&lpstring[0..(length_usize - 1)]);

    if window_title.contains(partial_window_title) {
        println!("Found window with title \"{window_title}\"");
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

pub unsafe fn get_loaded_process_images(process_handle: OwnedHandle) -> Box<[LoadedImage]> {
    let raw_process_handle = HANDLE(process_handle.as_raw_handle() as isize);

    // maximum should be 500 by default but just in case
    const TEMP_BUF_SIZE: usize = 4096;
    const ELEMENT_SIZE_BYTES: usize = size_of::<HMODULE>();

    let mut temp_handles_buf: Box<[MaybeUninit<HMODULE>]> = Box::new_uninit_slice(TEMP_BUF_SIZE);

    let buf_size_bytes = (TEMP_BUF_SIZE * ELEMENT_SIZE_BYTES) as u32;
    let mut new_size_bytes = 0_u32;

    EnumProcessModules(
        raw_process_handle,
        temp_handles_buf.as_mut_ptr() as *mut HMODULE,
        buf_size_bytes,
        &mut new_size_bytes as *mut u32,
    )
    .ok()
    .expect("Unable to enumerate over process modules");

    let module_count = new_size_bytes as usize / ELEMENT_SIZE_BYTES;
    // the assume_init should really be after the slice, because only the slice is guaranteed to be
    // initialized, but whatever
    let module_handles = &temp_handles_buf.assume_init()[..module_count];

    let mut loaded_images: Box<[MaybeUninit<LoadedImage>]> = Box::new_uninit_slice(module_count);

    // the api is trash and doesn't give an explicit size.
    // it says that 32768 may not be enough to store a path due to expansion, so we make it bigger.
    const MODULE_MAX_PATH_LEN: usize = 65536;
    let mut module_path_buf: Box<[u16]> = Box::new_uninit_slice(MODULE_MAX_PATH_LEN).assume_init();

    for (idx, &module_handle) in module_handles.iter().enumerate() {
        let mut module_info = MODULEINFO::default();

        GetModuleInformation(
            raw_process_handle,
            module_handle,
            &mut module_info as *mut MODULEINFO,
            size_of::<MODULEINFO>() as u32, // ...why is this needed?
        )
        .ok()
        .unwrap_or_else(|_| {
            panic!(
                "Unable to get module information for handle {}",
                module_handle.0
            )
        });

        let len =
            GetModuleFileNameExW(raw_process_handle, module_handle, &mut module_path_buf) as usize;

        let image_path = OsString::from_wide(&module_path_buf[0..len]);

        loaded_images[idx].write((
            image_path,
            module_info.lpBaseOfDll.expose_addr() as u64,
            module_info.SizeOfImage as u64,
        ));
    }

    loaded_images.assume_init()
}

pub unsafe fn wait_on_process_close(process_handle: &OwnedHandle, milliseconds: u32) -> bool {
    let raw_process_handle = HANDLE(process_handle.as_raw_handle() as isize);

    WaitForSingleObject(raw_process_handle, milliseconds).is_ok()
}

// CODE BELOW FROM CRATE "blondie", ty for making it MIT nico-abram
//
// MIT License
//
// Copyright (c) 2021 Nicolas Abram Lujan
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

pub unsafe fn configure_trace(samples_per_second: u32, trace_control_handle: ControlHandle) {
    let interval = TRACE_PROFILE_INTERVAL {
        Source: 0, // idk
        Interval: 10000000 / samples_per_second,
    };
    TraceSetInformation(
        None,
        TraceSampledProfileIntervalInfo,
        addr_of!(interval).cast(),
        size_of::<TRACE_PROFILE_INTERVAL>() as u32,
    )
    .ok()
    .expect("Error setting trace interval");

    let stack_event_id = CLASSIC_EVENT_ID {
        EventGuid: transmute(PROFILE_PROVIDER.guid),
        Type: 0, //46, // Sampled profile event
        Reserved: [0; 7],
    };
    TraceSetInformation(
        CONTROLTRACE_HANDLE(trace_control_handle.0), // this conversion shouldn't be necessary, but whatever
        TraceStackTracingInfo,
        addr_of!(stack_event_id).cast(),
        size_of::<CLASSIC_EVENT_ID>() as u32,
    )
    .ok()
    .expect("Error setting stack trace info");
}

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
        .expect("Error looking up privelage value");

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
        panic!("Error adjusting privelages");
    });

    CloseHandle(token_handle_raw)
        .ok()
        .expect("Error closing process token handle");
}

pub unsafe fn get_kernel_images() -> Vec<LoadedImage> {
    // kernel module enumeration code based on http://www.rohitab.com/discuss/topic/40696-list-loaded-drivers-with-ntquerysysteminformation/
    const BUF_LEN: usize = 1024 * 1024;
    let mut out_buf = vec![0u8; BUF_LEN];
    let mut out_size = 0u32;

    NtQuerySystemInformation(
        SYSTEM_INFORMATION_CLASS(11), // SystemModuleInformation
        out_buf.as_mut_ptr().cast(),
        BUF_LEN as u32,
        &mut out_size,
    )
    .ok()
    .expect("Failed to find loaded kernel modules");

    let number_of_modules = unsafe { out_buf.as_ptr().cast::<u32>().read_unaligned() as usize };

    #[repr(C)]
    #[derive(Debug)]
    #[allow(non_snake_case)]
    #[allow(non_camel_case_types)]
    struct _RTL_PROCESS_MODULE_INFORMATION {
        Section: *mut std::ffi::c_void,
        MappedBase: *mut std::ffi::c_void,
        ImageBase: *mut std::ffi::c_void,
        ImageSize: u32,
        Flags: u32,
        LoadOrderIndex: u16,
        InitOrderIndex: u16,
        LoadCount: u16,
        OffsetToFileName: u16,
        FullPathName: [u8; 256],
    }
    let modules = unsafe {
        let modules_ptr = out_buf
            .as_ptr()
            .cast::<u32>()
            .offset(2)
            .cast::<_RTL_PROCESS_MODULE_INFORMATION>();
        std::slice::from_raw_parts(modules_ptr, number_of_modules)
    };

    let kernel_module_paths = modules
        .iter()
        .filter_map(|module| {
            unsafe { std::ffi::CStr::from_ptr(module.FullPathName.as_ptr().cast()) }
                .to_str()
                .ok()
                .map(|mod_str_filepath| {
                    let verbatim_path_osstring: OsString = mod_str_filepath
                        .replacen("\\SystemRoot\\", "\\\\?\\C:\\Windows\\", 1)
                        .into();
                    (
                        verbatim_path_osstring,
                        module.ImageBase as u64,
                        module.ImageSize as u64,
                    )
                })
        })
        .collect();
    kernel_module_paths
}
