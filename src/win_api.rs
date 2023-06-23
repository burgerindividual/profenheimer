use std::io;
use std::os::windows::io::{FromRawHandle, OwnedHandle, RawHandle};
use std::process::ExitCode;
use std::ptr::from_exposed_addr;
use windows::Win32::Foundation::*;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, EnumWindows, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId,
};

static mut CURRENT_WINDOW_HANDLE: HWND = HWND(0);

unsafe fn get_window_process_handle_pid(partial_window_title: &str) -> (OwnedHandle, u32) {
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
