use std::ffi::{c_void, OsString};
use std::mem::size_of;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::ExitCode;
use std::ptr::{addr_of, addr_of_mut, null_mut};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use std::{slice, thread};

use rustc_hash::FxHashMap;
use windows::core::{GUID, PCSTR, PSTR};
use windows::Win32::Foundation::*;
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
    GetCurrentThread, GetThreadDescription, OpenThread, SetThreadPriority,
    THREAD_PRIORITY_TIME_CRITICAL, THREAD_QUERY_LIMITED_INFORMATION,
};

use crate::atomic_wait::AtomicWait;
use crate::interpret::{LoadedImage, TraceResults};
use crate::log::log_verbose;
use crate::process::{register_wait_on_process_close, Process};

pub unsafe fn trace(
    process: Option<Process>,
    wait_time: Duration,
    length_time: Duration,
    samples_per_second: u32,
    show_kernel_stacks: bool,
) -> TraceResults {
    if !wait_time.is_zero() {
        log_verbose!("Waiting for {:.2} seconds...", wait_time.as_secs_f64());
        thread::sleep(wait_time);
    }

    let trace = EtwTrace::start(
        process.as_ref().map(|p| p.id),
        samples_per_second,
        show_kernel_stacks,
    );

    let mut ctrl_c_tracing = trace.is_running.clone();
    GLOBAL_TRACING_REF.store(&mut ctrl_c_tracing, Ordering::SeqCst);

    if let Some(p) = process.as_ref() {
        register_wait_on_process_close(&p.handle, process_ended_callback);
    }

    if !length_time.is_zero() {
        log_verbose!(
            "Profiling for {:.2} seconds... Press Ctrl+C to stop",
            length_time.as_secs_f64()
        );

        trace.is_running.wait_timeout(true, length_time);
    } else {
        log_verbose!("Profiling... Press Ctrl+C to stop");

        trace.is_running.wait(true);
    }

    // is this okay here?
    GLOBAL_TRACING_REF.store(null_mut(), Ordering::SeqCst);

    try_signal_stopped(&trace.is_running, "Profiling time elapsed, stopping...");

    let results = trace.stop();

    log_verbose!("Finished profile");

    results
}

static GLOBAL_TRACING_REF: AtomicPtr<Pin<Arc<AtomicBool>>> = AtomicPtr::new(null_mut());

pub fn init_ctrl_c_handler() {
    ctrlc::set_handler(|| unsafe {
        let tracing_ptr = GLOBAL_TRACING_REF.swap(null_mut(), Ordering::SeqCst);
        if let Some(tracing) = tracing_ptr.as_ref() {
            try_signal_stopped(tracing, "Ctrl+C intercepted, stopping...");
        } else {
            ExitCode::FAILURE.exit_process();
        }
    })
    .expect("Unable to set Ctrl+C handler");
}

unsafe extern "system" fn process_ended_callback(_: *mut c_void, _: BOOLEAN) {
    let tracing_ptr = GLOBAL_TRACING_REF.swap(null_mut(), Ordering::SeqCst);
    if let Some(tracing) = tracing_ptr.as_ref() {
        try_signal_stopped(tracing, "Traced process has ended, stopping...");
    }
}

pub fn try_signal_stopped(tracing: &Pin<Arc<AtomicBool>>, message: &str) {
    // if this doesn't pass, we're likely already stopping
    if tracing
        .compare_exchange(true, false, Ordering::SeqCst, Ordering::Relaxed)
        .is_ok()
    {
        log_verbose!("{}", message);
        tracing.wake_all();
    }
}

#[derive(Eq, Hash, PartialEq)]
pub struct StackTrace {
    pub process_id: u32,
    pub thread_id: u32,
    pub address_stack: [usize; MAX_STACK_DEPTH],
}

pub struct EtwTraceShared {
    pub stack_counts_map: StackMap,
    pub thread_name_map: ThreadNameMap,
    pub loaded_images: Vec<LoadedImage>,
    pub process_id: Option<u32>,
    pub show_kernel_stacks: bool,
}

impl EtwTraceShared {
    pub fn new(process_id: Option<u32>, show_kernel_stacks: bool) -> Self {
        EtwTraceShared {
            stack_counts_map: Default::default(),
            thread_name_map: Default::default(),
            loaded_images: Vec::with_capacity(500),
            process_id,
            show_kernel_stacks,
        }
    }
}

pub struct EtwTrace {
    pub shared: Arc<Mutex<EtwTraceShared>>,
    /// used for signaling
    pub is_running: Pin<Arc<AtomicBool>>,
    /// this isn't a normal handle and shouldn't be closed
    pub control_trace_handle: CONTROLTRACE_HANDLE,
    pub trace_properties: EVENT_TRACE_PROPERTIES_WITH_STRING,
    pub trace_join_handle: JoinHandle<()>,
}

pub type ThreadNameMap = FxHashMap<u32, Box<str>>;

//// Code below based off crate "blondie" by nico-abram

/// map[array_of_stacktrace_addrs] = sample_count
pub type StackMap = FxHashMap<StackTrace, usize>;

// higher than what msdn says, but just want to be safe
pub const MAX_STACK_DEPTH: usize = 200;

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

// https://docs.microsoft.com/en-us/windows/win32/etw/image-load
#[allow(non_snake_case)]
#[derive(Debug)]
#[repr(C)]
pub struct ImageLoadEvent {
    pub ImageBase: usize,
    pub ImageSize: usize,
    pub ProcessId: u32,
    pub ImageCheckSum: u32,
    pub TimeDateStamp: u32,
    pub Reserved0: u32,
    pub DefaultBase: usize,
    pub Reserved1: u32,
    pub Reserved2: u32,
    pub Reserved3: u32,
    pub Reserved4: u32,
}

impl EtwTrace {
    pub unsafe fn start(
        process_id: Option<u32>,
        samples_per_second: u32,
        show_kernel_stacks: bool,
    ) -> Self {
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
        // Build the trace properties, we want EVENT_TRACE_FLAG_PROFILE for the
        // "SampledProfile" event https://docs.microsoft.com/en-us/windows/win32/etw/sampledprofile
        // In https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-mof-classes that event is listed as a "kernel event"
        // And https://docs.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants says
        // "The NT Kernel Logger session is the only session that can accept events from
        // kernel event providers." Therefore we must use GUID
        // SystemTraceControlGuid/KERNEL_LOGGER_NAME as the session
        // EVENT_TRACE_REAL_TIME_MODE:
        //  Events are delivered when the buffers are flushed (https://docs.microsoft.com/en-us/windows/win32/etw/logging-mode-constants)
        // We also use Image_Load events to know which dlls to load debug information
        // from for symbol resolution Which is enabled by the
        // EVENT_TRACE_FLAG_IMAGE_LOAD flag
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
            Reserved: Default::default(),
        };
        TraceSetInformation(
            control_trace_handle,
            TraceStackTracingInfo,
            addr_of!(stack_event_id).cast(),
            size_of::<CLASSIC_EVENT_ID>() as u32,
        )
        .ok()
        .expect("Error setting stack trace info");

        let shared_context = Arc::new(Mutex::new(EtwTraceShared::new(
            process_id,
            show_kernel_stacks,
        )));

        // This Arc clone will be put on the heap and moved to the processing thread.
        // This will be used to clone itself to all threads that need to
        // reference the EtwTraceShared. This specific pinned, boxed arc will be
        // dropped after the processing thread is finished.
        let mut process_thread_context = Box::pin(shared_context.clone());

        let mut log = EVENT_TRACE_LOGFILEA::default();
        log.LoggerName = PSTR(kernel_logger_name_with_nul.as_mut_ptr());
        log.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME
            | PROCESS_TRACE_MODE_EVENT_RECORD
            | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
        log.Context = process_thread_context.as_mut().get_mut() as *mut _ as *mut c_void;

        unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
            // clones the Arc from the one dedicated to the ProcessTrace thread
            let context_arc =
                (*((*record).UserContext as *const Pin<Arc<Mutex<EtwTraceShared>>>)).clone();
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

                let is_traced_process = context.process_id.map_or(true, |id| {
                    // Ignore dlls for other processes, but if the PID is 0 it should be a driver
                    // image, so we should log it if need be.
                    let is_kernel = event.ProcessId == 0;
                    id == event.ProcessId || (is_kernel && context.show_kernel_stacks)
                });

                if is_traced_process {
                    // file path is right after the event data
                    let image_path_ptr = (*record)
                        .UserData
                        .cast::<ImageLoadEvent>()
                        .offset(1)
                        .cast::<u16>();

                    let image_path = PathBuf::from(OsString::from_wide(slice::from_raw_parts(
                        image_path_ptr,
                        ((*record).UserDataLength as usize - size_of::<ImageLoadEvent>()) / 2,
                    )));

                    context.loaded_images.push(LoadedImage {
                        image_path,
                        image_base: event.ImageBase,
                        image_size: event.ImageSize,
                    });
                }
            } else if event_opcode == EVENT_TRACE_TYPE_STACK_WALK
                || provider_guid == STACK_WALK_GUID
            {
                let user_data_ptr = (*record).UserData;
                let _timestamp = user_data_ptr.cast::<u64>().read_unaligned();
                let process_id = user_data_ptr.cast::<u32>().offset(2).read_unaligned();
                let thread_id = user_data_ptr.cast::<u32>().offset(3).read_unaligned();

                let is_traced_process = context.process_id.map_or(true, |id| id == process_id);
                if !is_traced_process {
                    // Ignore stackwalks for other processes
                    return;
                }

                let thread_entry = context.thread_name_map.entry(thread_id);
                // TODO: use image names from Thread/Start and Thread/DCStart if widely supported
                thread_entry.or_insert_with(|| {
                    OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, thread_id)
                        .ok()
                        .and_then(|thread_handle| {
                            let raw_str = GetThreadDescription(thread_handle).ok();

                            CloseHandle(thread_handle)
                                .ok()
                                .expect("Error closing thread handle");
                            raw_str
                        })
                        .map_or(String::new(), |raw_str| {
                            String::from_utf16_lossy(raw_str.as_wide())
                        })
                        .into_boxed_str()
                });

                let stack_depth = (((*record).UserDataLength - 16) as usize / size_of::<usize>())
                    .min(MAX_STACK_DEPTH);

                let stack_addresses_slice =
                    slice::from_raw_parts(user_data_ptr.cast::<usize>().offset(2), stack_depth);

                let mut stack_addresses = [0_usize; MAX_STACK_DEPTH];
                stack_addresses[..stack_depth].copy_from_slice(stack_addresses_slice);

                let stack_trace = StackTrace {
                    process_id,
                    thread_id,
                    address_stack: stack_addresses,
                };

                let stack_trace_entry = context.stack_counts_map.entry(stack_trace);
                *stack_trace_entry.or_insert(0) += 1;
            }
        }
        log.Anonymous2.EventRecordCallback = Some(event_record_callback);

        let process_trace_handle = OpenTraceA(&mut log);
        if process_trace_handle.0 == INVALID_HANDLE_VALUE.0 as u64 {
            GetLastError().ok().expect("Error opening trace");
        }

        let is_running = Arc::pin(AtomicBool::new(true));

        let trace_join_handle = thread::spawn({
            let is_running = is_running.clone();

            move || {
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

                // This blocks
                ProcessTrace(&[process_trace_handle], None, None)
                    .ok()
                    .expect("Error processing trace");

                CloseTrace(process_trace_handle)
                    .ok()
                    .expect("Error closing trace");

                // This should move the reference of the context to the thread, so it can be
                // disposed of after ProcessTrace has completely finished.
                drop(process_thread_context);

                try_signal_stopped(&is_running, "Trace ended early, ");
            }
        });

        EtwTrace {
            shared: shared_context,
            control_trace_handle,
            trace_properties: event_trace_props,
            trace_join_handle,
            is_running,
        }
    }

    pub unsafe fn stop(mut self) -> TraceResults {
        // This unblocks ProcessTrace
        ControlTraceA(
            self.control_trace_handle,
            PCSTR::null(), // this forces the function to use the handle
            addr_of_mut!(self.trace_properties) as *mut _,
            EVENT_TRACE_CONTROL_STOP,
        )
        .ok()
        .expect("Error stopping trace");

        self.trace_join_handle
            .join()
            .expect("Error joining trace processing thread");

        TraceResults::from(
            Arc::into_inner(self.shared)
                .expect("Arc has more than 1 reference left when it shouldn't")
                .into_inner()
                .expect("Error getting shared trace from Mutex"),
        )
    }
}
