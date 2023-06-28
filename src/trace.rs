// use std::ffi::{c_void, OsString};
// use std::mem::size_of;
// use std::os::windows::ffi::OsStringExt;
// use std::os::windows::io::OwnedHandle;
// use std::pin::Pin;
// use std::process::ExitCode;
// use std::ptr::{addr_of, addr_of_mut, null_mut};
// use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
// use std::sync::{Arc, Mutex, MutexGuard};
// use std::thread::JoinHandle;
// use std::time::Duration;
// use std::{slice, thread};
//
// use windows::core::{GUID, PCSTR, PSTR};
// use windows::Win32::Foundation::*;
// use windows::Win32::System::Diagnostics::Etw::{
//     CloseTrace, ControlTraceA, OpenTraceA, ProcessTrace, StartTraceA,
// SystemTraceControlGuid,     TraceSampledProfileIntervalInfo,
// TraceSetInformation, TraceStackTracingInfo, CLASSIC_EVENT_ID,
//     CONTROLTRACE_HANDLE, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP,
// EVENT_TRACE_FLAG_IMAGE_LOAD,     EVENT_TRACE_FLAG_PROFILE,
// EVENT_TRACE_LOGFILEA, EVENT_TRACE_PROPERTIES,     EVENT_TRACE_REAL_TIME_MODE,
// EVENT_TRACE_TYPE_DC_START, EVENT_TRACE_TYPE_LOAD,     KERNEL_LOGGER_NAMEA,
// PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_RAW_TIMESTAMP,
//     PROCESS_TRACE_MODE_REAL_TIME, TRACE_PROFILE_INTERVAL,
// WNODE_FLAG_TRACED_GUID, };
// use windows::Win32::System::Threading::{
//     GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_TIME_CRITICAL,
// };
//
// use crate::atomic_wait::AtomicWait;
// use crate::interpret::TraceResults;
// use crate::log::log_verbose;
// use crate::process::{register_wait_on_process_close, Process};
//
// pub unsafe fn trace_process(
//     process: Option<Process>,
//     wait_time: Duration,
//     length_time: Duration,
//     samples_per_second: u32,
//     show_kernel_stacks: bool,
// ) -> TraceResults {
//     if !wait_time.is_zero() {
//         log_verbose!("Waiting for {:.2} seconds...",
// wait_time.as_secs_f64());         thread::sleep(wait_time);
//     }
//
//     let trace = EtwTrace::start(process_id, samples_per_second,
// show_kernel_stacks);
//
//     let tracing = Arc::pin(AtomicBool::new(true));
//
//     let mut ctrl_c_tracing = tracing.clone();
//     GLOBAL_TRACING_REF.store(&mut ctrl_c_tracing, Ordering::SeqCst);
//
//     register_wait_on_process_close(&process_handle, process_ended_callback);
//
//     if !length_time.is_zero() {
//         log_verbose!(
//             "Profiling for {:.2} seconds... Press Ctrl+C to stop",
//             wait_time.as_secs_f64()
//         );
//
//         tracing.wait_timeout(true, length_time);
//     } else {
//         log_verbose!("Profiling... Press Ctrl+C to stop");
//
//         tracing.wait(true);
//     }
//
//     // is this okay here?
//     GLOBAL_TRACING_REF.store(null_mut(), Ordering::SeqCst);
//
//     try_signal_stopped(&tracing, "Profiling time elapsed, stopping...");
//
//     let results = trace.stop();
//
//     log_verbose!("Finished profile");
//
//     results
// }
//
// static GLOBAL_TRACING_REF: AtomicPtr<Pin<Arc<AtomicBool>>> =
// AtomicPtr::new(null_mut());
//
// pub fn init_ctrl_c_handler() {
//     ctrlc::set_handler(|| unsafe {
//         let tracing_ptr = GLOBAL_TRACING_REF.swap(null_mut(),
// Ordering::SeqCst);         if let Some(tracing) = tracing_ptr.as_ref() {
//             try_signal_stopped(tracing, "Ctrl+C intercepted, stopping...");
//         } else {
//             ExitCode::FAILURE.exit_process();
//         }
//     })
//     .expect("Unable to set Ctrl+C handler");
// }
//
// unsafe extern "system" fn process_ended_callback(_: *mut c_void, _: BOOLEAN)
// {     let tracing_ptr = GLOBAL_TRACING_REF.swap(null_mut(),
// Ordering::SeqCst);     if let Some(tracing) = tracing_ptr.as_ref() {
//         try_signal_stopped(tracing, "Traced process has ended, stopping...");
//     }
// }
//
// pub fn try_signal_stopped(tracing: &Pin<Arc<AtomicBool>>, message: &str) {
//     // if this doesn't pass, we're likely already stopping
//     if tracing
//         .compare_exchange(true, false, Ordering::SeqCst, Ordering::Relaxed)
//         .is_ok()
//     {
//         log_verbose!("{}", message);
//         tracing.wake_all();
//     }
// }
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
// pub const MAX_STACK_DEPTH: usize = 200;
//
// /// map[array_of_stacktrace_addrs] = sample_count
// pub type StackMap = rustc_hash::FxHashMap<[u64; MAX_STACK_DEPTH], u64>;
//
// /// (image_path, image_base, image_size)
// pub type LoadedImage = (OsString, u64, u64);
//
// // TODO: make this repr(C) and copy the rust layout of the original
// // TraceContext?
// #[derive(Debug)]
// pub struct TraceContext {
//     pub target_process_handle: OwnedHandle,
//     pub stack_counts_hashmap: StackMap,
//     pub target_proc_pid: u32,
//     pub trace_running: AtomicBool,
//     pub show_kernel_samples: bool,
//
//     /// (image_path, image_base, image_size)
//     pub image_paths: Vec<(OsString, u64, u64)>,
// }
//
// const KERNEL_LOGGER_NAMEA_LEN: usize = unsafe {
//     let mut ptr = KERNEL_LOGGER_NAMEA.0;
//     let mut len = 0;
//     while *ptr != 0 {
//         len += 1;
//         ptr = ptr.add(1);
//     }
//     len
// };
//
// // From https://docs.microsoft.com/en-us/windows/win32/etw/stackwalk
// const EVENT_TRACE_TYPE_STACK_WALK: u8 = 32;
// const STACK_WALK_GUID: GUID = GUID::from_values(
//     0xdef2fe46,
//     0x7bd6,
//     0x4b80,
//     [0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3],
// );
//
// // From https://learn.microsoft.com/en-us/windows/win32/etw/perfinfo
// const EVENT_TRACE_TYPE_SAMPLED_PROFILE: u8 = 46;
// const PERF_INFO_GUID: GUID = GUID::from_values(
//     0xce1dbfb4,
//     0x137e,
//     0x4da6,
//     [0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc],
// );
//
// const IMAGE_LOAD_GUID: GUID = GUID::from_values(
//     0x2cb15d1d,
//     0x5fc1,
//     0x11d2,
//     [0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18],
// );
//
// const PROPS_SIZE: usize = size_of::<EVENT_TRACE_PROPERTIES>() +
// KERNEL_LOGGER_NAMEA_LEN + 1;
//
// #[allow(non_camel_case_types)]
// #[derive(Clone)]
// #[repr(C)]
// pub struct EVENT_TRACE_PROPERTIES_WITH_STRING {
//     data: EVENT_TRACE_PROPERTIES,
//     s: [u8; KERNEL_LOGGER_NAMEA_LEN + 1],
// }
//
// // https://docs.microsoft.com/en-us/windows/win32/etw/image-load
// #[allow(non_snake_case)]
// #[derive(Debug)]
// #[repr(C)]
// pub struct ImageLoadEvent {
//     pub ImageBase: usize,
//     pub ImageSize: usize,
//     pub ProcessId: u32,
//     pub ImageCheckSum: u32,
//     pub TimeDateStamp: u32,
//     pub Reserved0: u32,
//     pub DefaultBase: usize,
//     pub Reserved1: u32,
//     pub Reserved2: u32,
//     pub Reserved3: u32,
//     pub Reserved4: u32,
// }
//
// pub struct EtwTraceShared {
//     pub stack_counts_hashmap: StackMap,
//     pub process_id: Option<u32>,
// }
//
// pub struct EtwTrace {
//     pub stack_counts_hashmap: StackMap,
//     pub process_id: u32,
//     pub show_kernel_stacks: bool,
//
//     /// (image_path, image_base, image_size)
//     pub image_paths: Vec<(OsString, u64, u64)>,
//     pub is_running: Pin<Arc<AtomicBool>>,
//     /// this isn't a normal handle and shouldn't be closed
//     pub control_trace_handle: CONTROLTRACE_HANDLE,
//     pub trace_properties: EVENT_TRACE_PROPERTIES_WITH_STRING,
//     pub trace_join_handle: JoinHandle<()>,
// }
//
// impl EtwTrace {
//     pub unsafe fn start(
//         process_id: Option<u32>,
//         samples_per_second: u32,
//         show_kernel_stacks: bool,
//     ) -> Self {
//         // set sample interval
//         let interval = TRACE_PROFILE_INTERVAL {
//             Source: 0,
//             Interval: 10000000 / samples_per_second, // should work?
//         };
//         TraceSetInformation(
//             None,
//             TraceSampledProfileIntervalInfo,
//             addr_of!(interval).cast(),
//             size_of::<TRACE_PROFILE_INTERVAL>() as u32,
//         )
//         .ok()
//         .expect("Error setting trace interval");
//
//         // TODO: replace this with our own title if possible
//         let mut kernel_logger_name_with_nul = KERNEL_LOGGER_NAMEA
//             .as_bytes()
//             .iter()
//             .cloned()
//             .chain(Some(0))
//             .collect::<Vec<u8>>();
//         // Build the trace properties, we want EVENT_TRACE_FLAG_PROFILE for
// the         // "SampledProfile" event https://docs.microsoft.com/en-us/windows/win32/etw/sampledprofile
//         // In https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-mof-classes that event is listed as a "kernel event"
//         // And https://docs.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants says
//         // "The NT Kernel Logger session is the only session that can accept
// events from         // kernel event providers." Therefore we must use GUID
//         // SystemTraceControlGuid/KERNEL_LOGGER_NAME as the session
//         // EVENT_TRACE_REAL_TIME_MODE:
//         //  Events are delivered when the buffers are flushed (https://docs.microsoft.com/en-us/windows/win32/etw/logging-mode-constants)
//         // We also use Image_Load events to know which dlls to load debug
// information         // from for symbol resolution Which is enabled by the
//         // EVENT_TRACE_FLAG_IMAGE_LOAD flag
//         let mut event_trace_props = EVENT_TRACE_PROPERTIES_WITH_STRING {
//             data: EVENT_TRACE_PROPERTIES::default(),
//             s: [0u8; KERNEL_LOGGER_NAMEA_LEN + 1],
//         };
//         event_trace_props.data.EnableFlags = EVENT_TRACE_FLAG_PROFILE |
// EVENT_TRACE_FLAG_IMAGE_LOAD;         event_trace_props.data.LogFileMode =
// EVENT_TRACE_REAL_TIME_MODE;         event_trace_props.data.Wnode.BufferSize =
// PROPS_SIZE as u32;         event_trace_props.data.Wnode.Flags =
// WNODE_FLAG_TRACED_GUID;         event_trace_props.data.Wnode.ClientContext =
// 3;         event_trace_props.data.Wnode.Guid = SystemTraceControlGuid;
//         event_trace_props.data.BufferSize = 1024;
//         let core_count =
//
// thread::available_parallelism().
// unwrap_or(std::num::NonZeroUsize::new(1usize).unwrap());
//         event_trace_props.data.MinimumBuffers = core_count.get() as u32 * 4;
//         event_trace_props.data.MaximumBuffers = core_count.get() as u32 * 6;
//         event_trace_props.data.LoggerNameOffset =
// size_of::<EVENT_TRACE_PROPERTIES>() as u32;         event_trace_props
//             .s
//             .copy_from_slice(&kernel_logger_name_with_nul[..]);
//
//         let kernel_logger_name_with_nul_pcstr =
// PCSTR(kernel_logger_name_with_nul.as_ptr());
//
//         // Start kernel trace session
//         let mut control_trace_handle: CONTROLTRACE_HANDLE =
// Default::default();         StartTraceA(
//             addr_of_mut!(control_trace_handle),
//             kernel_logger_name_with_nul_pcstr,
//             addr_of_mut!(event_trace_props) as *mut _,
//         )
//         .ok()
//         .expect("Error starting trace");
//
//         // Set sample stack traces
//         let stack_event_id = CLASSIC_EVENT_ID {
//             EventGuid: PERF_INFO_GUID,
//             Type: EVENT_TRACE_TYPE_SAMPLED_PROFILE, // Sampled profile event
//             Reserved: Default::default(),
//         };
//         TraceSetInformation(
//             control_trace_handle,
//             TraceStackTracingInfo,
//             addr_of!(stack_event_id).cast(),
//             size_of::<CLASSIC_EVENT_ID>() as u32,
//         )
//         .ok()
//         .expect("Error setting stack trace info");
//
//         let context: Arc<Mutex<TraceContext>> =
// Arc::new(Mutex::new(TraceContext {             target_process_handle:
// process_handle                 .try_clone()
//                 .expect("Error cloning process handle"),
//             stack_counts_hashmap: Default::default(),
//             target_proc_pid: process_id,
//             trace_running: AtomicBool::new(true),
//             show_kernel_samples: show_kernel_stacks,
//             image_paths: Vec::with_capacity(1024),
//         }));
//
//         // This Arc clone will be put on the heap and moved to the processing
// thread.         // This will be used to clone itself to all threads that need
// to         // reference the TraceContext. This specific pinned, boxed arc
// will be         // dropped after the processing thread is finished.
//         let mut process_thread_context = Box::pin(context.clone());
//
//         let mut log = EVENT_TRACE_LOGFILEA::default();
//         log.LoggerName = PSTR(kernel_logger_name_with_nul.as_mut_ptr());
//         log.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME
//             | PROCESS_TRACE_MODE_EVENT_RECORD
//             | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
//         log.Context = process_thread_context.as_mut().get_mut() as *mut _ as
// *mut c_void;
//
//         unsafe extern "system" fn event_record_callback(record: *mut
// EVENT_RECORD) {             // clones the Arc from the one dedicated to the
// ProcessTrace thread             let context_arc =
//                 (*((*record).UserContext as *const
// Pin<Arc<Mutex<TraceContext>>>)).clone();             let mut context =
// context_arc                 .lock()
//                 .expect("Unable to lock TraceContext for callback");
//
//             let provider_guid = (*record).EventHeader.ProviderId;
//             let event_opcode = (*record).EventHeader.EventDescriptor.Opcode;
//
//             if (event_opcode == EVENT_TRACE_TYPE_LOAD as u8
//                 || event_opcode == EVENT_TRACE_TYPE_DC_START as u8)
//                 && provider_guid == IMAGE_LOAD_GUID
//             {
//                 let event =
// (*record).UserData.cast::<ImageLoadEvent>().read_unaligned();
//
//                 // Ignore dlls for other processes, but if the PID is 0, it
// should be a driver                 // image, so we should log it if kernel
// samples are enabled.                 let is_current_process = event.ProcessId
// == context.target_proc_pid;                 let is_kernel = event.ProcessId
// == 0;                 if is_current_process || (is_kernel &&
// context.show_kernel_samples) {                     let filename_p = (*record)
//                         .UserData
//                         .cast::<ImageLoadEvent>()
//                         .offset(1)
//                         .cast::<u16>();
//                     let filename_os_string =
// OsString::from_wide(slice::from_raw_parts(
// filename_p,                         ((*record).UserDataLength as usize -
// size_of::<ImageLoadEvent>()) / 2,                     ));
//
//                     if is_kernel {
//                         log_verbose!("{}",
// filename_os_string.to_string_lossy());                     }
//
//                     context.image_paths.push((
//                         filename_os_string,
//                         event.ImageBase as u64,
//                         event.ImageSize as u64,
//                     ));
//                 }
//             } else if event_opcode == EVENT_TRACE_TYPE_STACK_WALK
//                 || provider_guid == STACK_WALK_GUID
//             {
//                 let ud_p = (*record).UserData;
//                 let _timestamp = ud_p.cast::<u64>().read_unaligned();
//                 let proc = ud_p.cast::<u32>().offset(2).read_unaligned();
//                 let _thread = ud_p.cast::<u32>().offset(3).read_unaligned();
//                 // TODO: use thread
//
//                 if proc != context.target_proc_pid {
//                     // Ignore stackwalks for other processes
//                     return;
//                 }
//
//                 let stack_depth = ((*record).UserDataLength - 16) /
// size_of::<usize>() as u16;
//
//                 let mut tmp = vec![];
//                 let mut stack_addrs = if size_of::<usize>() == 8 {
//                     slice::from_raw_parts(ud_p.cast::<u64>().offset(2),
// stack_depth as usize)                 } else {
//                     tmp.extend(
//                         slice::from_raw_parts(
//                             ud_p.cast::<u64>().offset(2).cast::<u32>(),
//                             stack_depth as usize,
//                         )
//                         .iter()
//                         .map(|x| *x as u64),
//                     );
//                     &tmp
//                 };
//                 if stack_addrs.len() > MAX_STACK_DEPTH {
//                     stack_addrs = &stack_addrs[(stack_addrs.len() -
// MAX_STACK_DEPTH)..];                 }
//
//                 let mut stack = [0u64; MAX_STACK_DEPTH];
//                 stack[..(stack_depth as
// usize).min(MAX_STACK_DEPTH)].copy_from_slice(stack_addrs);
//
//                 let entry = context.stack_counts_hashmap.entry(stack);
//                 *entry.or_insert(0) += 1;
//             }
//         }
//         log.Anonymous2.EventRecordCallback = Some(event_record_callback);
//
//         let process_trace_handle = OpenTraceA(&mut log);
//         if process_trace_handle.0 == INVALID_HANDLE_VALUE.0 as u64 {
//             GetLastError().ok().expect("Error opening trace");
//         }
//
//         let trace_join_handle = thread::spawn(move || {
//             SetThreadPriority(GetCurrentThread(),
// THREAD_PRIORITY_TIME_CRITICAL);
//
//             // This blocks
//             ProcessTrace(&[process_trace_handle], None, None)
//                 .ok()
//                 .expect("Error processing trace");
//
//             CloseTrace(process_trace_handle)
//                 .ok()
//                 .expect("Error closing trace");
//
//             // This should move the reference of the context to the thread,
// so it can be             // disposed of after ProcessTrace has completely
// finished.             drop(process_thread_context);
//
//             // TODO: handle forced shutdown from powershell, etc by signaling
//             // atomic
//         });
//
//         EtwTrace {
//             inner_context: context,
//             control_trace_handle,
//             trace_properties: event_trace_props,
//             trace_join_handle,
//         }
//     }
//
//     pub fn get_shared(&self) -> MutexGuard<TraceContext> {
//         self.shared.lock().expect("Unable to lock TraceContext")
//     }
//
//     pub unsafe fn stop(self) -> TraceResults {
//         // if collect_kernel_stacks {
//         //     trace
//         //         .get_inner_context()
//         //         .image_paths
//         //         .append(get_kernel_images().as_mut());
//         // }
//         // TODO: remove above
//
//         // This unblocks ProcessTrace
//         ControlTraceA(
//             self.control_trace_handle,
//             PCSTR::null(), // this forces the function to use the handle
//             addr_of_mut!(self.trace_properties) as *mut _,
//             EVENT_TRACE_CONTROL_STOP,
//         )
//         .ok()
//         .expect("Error stopping trace");
//
//         self.trace_join_handle
//             .join()
//             .expect("Error joining trace processing thread");
//
//         Arc::into_inner(self.inner_context)
//             .expect("Arc has more than 1 reference left when it shouldn't")
//             .into_inner()
//             .expect("Error getting TraceContext from Mutex")
//             .into_results()
//     }
// }
