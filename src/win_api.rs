use crate::blondie_interop::{ImageLoadEvent, LoadedImage, TraceContext, MAX_STACK_DEPTH};
use blondie::CollectionResults;
use std::ffi::{c_void, CStr, OsString};
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::pin::Pin;
use std::process::ExitCode;
use std::ptr::{addr_of, addr_of_mut, from_exposed_addr};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::{slice, thread};
use windows::core::{GUID, PCSTR, PSTR};
use windows::Win32::Foundation::*;
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    SE_SYSTEM_PROFILE_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
};
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceA, OpenTraceA, ProcessTrace, StartTraceA, SystemTraceControlGuid,
    TraceSampledProfileIntervalInfo, TraceSetInformation, TraceStackTracingInfo, CLASSIC_EVENT_ID,
    CONTROLTRACE_HANDLE, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG_IMAGE_LOAD,
    EVENT_TRACE_FLAG_PROFILE, EVENT_TRACE_LOGFILEA, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_TYPE_DC_START, EVENT_TRACE_TYPE_LOAD,
    KERNEL_LOGGER_NAMEA, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_RAW_TIMESTAMP,
    PROCESS_TRACE_MODE_REAL_TIME, TRACE_PROFILE_INTERVAL, WNODE_FLAG_TRACED_GUID,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken,
    RegisterWaitForSingleObject, SetThreadPriority, INFINITE, PROCESS_ALL_ACCESS,
    THREAD_PRIORITY_TIME_CRITICAL, WT_EXECUTEONLYONCE,
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

pub struct ExtendedTraceContext {
    inner_context: Arc<Mutex<TraceContext>>,
    /// this isn't a normal handle and shouldn't be closed
    pub control_trace_handle: CONTROLTRACE_HANDLE,
    pub trace_properties: EVENT_TRACE_PROPERTIES_WITH_STRING,
    pub trace_join_handle: JoinHandle<()>,
}

impl ExtendedTraceContext {
    pub fn get_inner_context(&self) -> MutexGuard<TraceContext> {
        self.inner_context
            .lock()
            .expect("Unable to lock TraceContext")
    }
}

// CODE BELOW BASED OFF CRATE "blondie"
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

const KERNEL_LOGGER_NAMEA_LEN: usize = unsafe {
    let mut ptr = KERNEL_LOGGER_NAMEA.0;
    let mut len = 0;
    while *ptr != 0 {
        len += 1;
        ptr = ptr.add(1);
    }
    len
};

// From https://docs.microsoft.com/en-us/windows/win32/etw/stackwalk
const EVENT_TRACE_TYPE_STACK_WALK: u8 = 32;
const STACK_WALK_GUID: GUID = GUID::from_values(
    0xdef2fe46,
    0x7bd6,
    0x4b80,
    [0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3],
);

// From https://learn.microsoft.com/en-us/windows/win32/etw/perfinfo
const EVENT_TRACE_TYPE_SAMPLED_PROFILE: u8 = 46;
const PERF_INFO_GUID: GUID = GUID::from_values(
    0xce1dbfb4,
    0x137e,
    0x4da6,
    [0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc],
);

const IMAGE_LOAD_GUID: GUID = GUID::from_values(
    0x2cb15d1d,
    0x5fc1,
    0x11d2,
    [0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18],
);

const PROPS_SIZE: usize = size_of::<EVENT_TRACE_PROPERTIES>() + KERNEL_LOGGER_NAMEA_LEN + 1;

#[allow(non_camel_case_types)]
#[derive(Clone)]
#[repr(C)]
pub struct EVENT_TRACE_PROPERTIES_WITH_STRING {
    data: EVENT_TRACE_PROPERTIES,
    s: [u8; KERNEL_LOGGER_NAMEA_LEN + 1],
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
    .expect("Failed to find loaded kernel modules");

    let number_of_modules = out_buf.as_ptr().cast::<u32>().read_unaligned() as usize;

    #[repr(C)]
    #[derive(Debug)]
    #[allow(non_snake_case)]
    #[allow(non_camel_case_types)]
    struct _RTL_PROCESS_MODULE_INFORMATION {
        Section: *mut c_void,
        MappedBase: *mut c_void,
        ImageBase: *mut c_void,
        ImageSize: u32,
        Flags: u32,
        LoadOrderIndex: u16,
        InitOrderIndex: u16,
        LoadCount: u16,
        OffsetToFileName: u16,
        FullPathName: [u8; 256],
    }
    let modules_ptr = out_buf
        .as_ptr()
        .cast::<u32>()
        .offset(2)
        .cast::<_RTL_PROCESS_MODULE_INFORMATION>();

    let modules = slice::from_raw_parts(modules_ptr, number_of_modules);

    let kernel_module_paths = modules
        .iter()
        .filter_map(|module| {
            CStr::from_ptr(module.FullPathName.as_ptr().cast())
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

pub unsafe fn start_trace(
    process_handle: &OwnedHandle,
    process_id: u32,
    samples_per_second: u32,
    collect_kernel_stacks: bool,
) -> ExtendedTraceContext {
    // set sample interval
    let interval = TRACE_PROFILE_INTERVAL {
        Source: 0,
        Interval: 10000000 / samples_per_second, // should work?
    };
    TraceSetInformation(
        None,
        TraceSampledProfileIntervalInfo,
        addr_of!(interval).cast(),
        size_of::<TRACE_PROFILE_INTERVAL>() as u32,
    )
    .ok()
    .expect("Error setting trace interval");

    // TODO: replace this with our own title if possible
    let mut kernel_logger_name_with_nul = KERNEL_LOGGER_NAMEA
        .as_bytes()
        .iter()
        .cloned()
        .chain(Some(0))
        .collect::<Vec<u8>>();
    // Build the trace properties, we want EVENT_TRACE_FLAG_PROFILE for the "SampledProfile" event
    // https://docs.microsoft.com/en-us/windows/win32/etw/sampledprofile
    // In https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-mof-classes that event is listed as a "kernel event"
    // And https://docs.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants says
    // "The NT Kernel Logger session is the only session that can accept events from kernel event providers."
    // Therefore we must use GUID SystemTraceControlGuid/KERNEL_LOGGER_NAME as the session
    // EVENT_TRACE_REAL_TIME_MODE:
    //  Events are delivered when the buffers are flushed (https://docs.microsoft.com/en-us/windows/win32/etw/logging-mode-constants)
    // We also use Image_Load events to know which dlls to load debug information from for symbol resolution
    // Which is enabled by the EVENT_TRACE_FLAG_IMAGE_LOAD flag
    let mut event_trace_props = EVENT_TRACE_PROPERTIES_WITH_STRING {
        data: EVENT_TRACE_PROPERTIES::default(),
        s: [0u8; KERNEL_LOGGER_NAMEA_LEN + 1],
    };
    event_trace_props.data.EnableFlags = EVENT_TRACE_FLAG_PROFILE | EVENT_TRACE_FLAG_IMAGE_LOAD;
    event_trace_props.data.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    event_trace_props.data.Wnode.BufferSize = PROPS_SIZE as u32;
    event_trace_props.data.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    event_trace_props.data.Wnode.ClientContext = 3;
    event_trace_props.data.Wnode.Guid = SystemTraceControlGuid;
    event_trace_props.data.BufferSize = 1024;
    let core_count =
        thread::available_parallelism().unwrap_or(std::num::NonZeroUsize::new(1usize).unwrap());
    event_trace_props.data.MinimumBuffers = core_count.get() as u32 * 4;
    event_trace_props.data.MaximumBuffers = core_count.get() as u32 * 6;
    event_trace_props.data.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    event_trace_props
        .s
        .copy_from_slice(&kernel_logger_name_with_nul[..]);

    let kernel_logger_name_with_nul_pcstr = PCSTR(kernel_logger_name_with_nul.as_ptr());

    // Start kernel trace session
    let mut control_trace_handle: CONTROLTRACE_HANDLE = Default::default();
    StartTraceA(
        addr_of_mut!(control_trace_handle),
        kernel_logger_name_with_nul_pcstr,
        addr_of_mut!(event_trace_props) as *mut _,
    )
    .ok()
    .expect("Error starting trace");

    // Set sample stack traces
    let stack_event_id = CLASSIC_EVENT_ID {
        EventGuid: PERF_INFO_GUID,
        Type: EVENT_TRACE_TYPE_SAMPLED_PROFILE, // Sampled profile event
        Reserved: [0; 7],
    };
    TraceSetInformation(
        control_trace_handle,
        TraceStackTracingInfo,
        addr_of!(stack_event_id).cast(),
        size_of::<CLASSIC_EVENT_ID>() as u32,
    )
    .ok()
    .expect("Error setting stack trace info");

    let context: Arc<Mutex<TraceContext>> = Arc::new(Mutex::new(TraceContext {
        target_process_handle: process_handle
            .try_clone()
            .expect("Error cloning process handle"),
        stack_counts_hashmap: Default::default(),
        target_proc_pid: process_id,
        trace_running: AtomicBool::new(false),
        show_kernel_samples: collect_kernel_stacks,
        image_paths: Vec::with_capacity(1024),
    }));

    // This Arc clone will be put on the heap and moved to the processing thread. This will be used
    // to clone itself to all threads that need to reference the TraceContext. This specific pinned,
    // boxed arc will be dropped after the processing thread is finished.
    let mut process_thread_context = Box::pin(context.clone());

    let mut log = EVENT_TRACE_LOGFILEA::default();
    log.LoggerName = PSTR(kernel_logger_name_with_nul.as_mut_ptr());
    log.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME
        | PROCESS_TRACE_MODE_EVENT_RECORD
        | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    log.Context = process_thread_context.as_mut().get_mut() as *mut _ as *mut c_void;

    unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
        // clones the Arc from the one dedicated to the ProcessTrace thread
        let context_arc =
            (*((*record).UserContext as *const Pin<Arc<Mutex<TraceContext>>>)).clone();
        let mut context = context_arc
            .lock()
            .expect("Unable to lock TraceContext for callback");

        let provider_guid = (*record).EventHeader.ProviderId;
        let event_opcode = (*record).EventHeader.EventDescriptor.Opcode;

        if (event_opcode == EVENT_TRACE_TYPE_LOAD as u8
            || event_opcode == EVENT_TRACE_TYPE_DC_START as u8)
            && provider_guid == IMAGE_LOAD_GUID
        {
            let event = (*record).UserData.cast::<ImageLoadEvent>().read_unaligned();
            if event.ProcessId != context.target_proc_pid {
                // Ignore dlls for other processes
                return;
            }
            let filename_p = (*record)
                .UserData
                .cast::<ImageLoadEvent>()
                .offset(1)
                .cast::<u16>();
            let filename_os_string = OsString::from_wide(slice::from_raw_parts(
                filename_p,
                ((*record).UserDataLength as usize - size_of::<ImageLoadEvent>()) / 2,
            ));
            context.image_paths.push((
                filename_os_string,
                event.ImageBase as u64,
                event.ImageSize as u64,
            ));
        } else if event_opcode == EVENT_TRACE_TYPE_STACK_WALK || provider_guid == STACK_WALK_GUID {
            let ud_p = (*record).UserData;
            let _timestamp = ud_p.cast::<u64>().read_unaligned();
            let proc = ud_p.cast::<u32>().offset(2).read_unaligned();
            let _thread = ud_p.cast::<u32>().offset(3).read_unaligned();
            if proc != context.target_proc_pid {
                // Ignore stackwalks for other processes
                return;
            }

            let stack_depth_32 = ((*record).UserDataLength - 16) / 4;
            let stack_depth_64 = stack_depth_32 / 2;
            let stack_depth = if size_of::<usize>() == 8 {
                stack_depth_64
            } else {
                stack_depth_32
            };

            let mut tmp = vec![];
            let mut stack_addrs = if size_of::<usize>() == 8 {
                slice::from_raw_parts(ud_p.cast::<u64>().offset(2), stack_depth as usize)
            } else {
                tmp.extend(
                    slice::from_raw_parts(
                        ud_p.cast::<u64>().offset(2).cast::<u32>(),
                        stack_depth as usize,
                    )
                    .iter()
                    .map(|x| *x as u64),
                );
                &tmp
            };
            if stack_addrs.len() > MAX_STACK_DEPTH {
                stack_addrs = &stack_addrs[(stack_addrs.len() - MAX_STACK_DEPTH)..];
            }

            let mut stack = [0u64; MAX_STACK_DEPTH];
            stack[..(stack_depth as usize).min(MAX_STACK_DEPTH)].copy_from_slice(stack_addrs);

            let entry = context.stack_counts_hashmap.entry(stack);
            *entry.or_insert(0) += 1;
        }
    }
    log.Anonymous2.EventRecordCallback = Some(event_record_callback);

    let process_trace_handle = OpenTraceA(&mut log);
    if process_trace_handle.0 == INVALID_HANDLE_VALUE.0 as u64 {
        GetLastError().ok().expect("Error opening trace");
    }

    let trace_join_handle = thread::spawn(move || {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

        // This blocks
        ProcessTrace(&[process_trace_handle], None, None)
            .ok()
            .expect("Error processing trace");

        CloseTrace(process_trace_handle)
            .ok()
            .expect("Error closing trace");

        // This should move the reference of the context to the thread, so it can be disposed of
        // after ProcessTrace has completely finished.
        drop(process_thread_context);

        // TODO: handle forced shutdown from powershell, etc by signaling atomic
    });

    ExtendedTraceContext {
        inner_context: context,
        control_trace_handle,
        trace_properties: event_trace_props,
        trace_join_handle,
    }
}

pub unsafe fn stop_trace(mut extended_context: ExtendedTraceContext) -> CollectionResults {
    // This unblocks ProcessTrace
    ControlTraceA(
        extended_context.control_trace_handle,
        PCSTR::null(), // this forces the function to use the handle
        addr_of_mut!(extended_context.trace_properties) as *mut _,
        EVENT_TRACE_CONTROL_STOP,
    )
    .ok()
    .expect("Error stopping trace");

    extended_context
        .trace_join_handle
        .join()
        .expect("Error joining trace processing thread");

    Arc::into_inner(extended_context.inner_context)
        .expect("Arc has more than 1 reference left when it shouldn't")
        .into_inner()
        .expect("Error getting TraceContext from Mutex")
        .into_collection_results()
}
