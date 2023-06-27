use crate::win_api::wait_on_process_close;
use ferrisetw::provider::kernel_providers::PROFILE_PROVIDER;
use ferrisetw::provider::{Provider, TraceFlags};
use ferrisetw::trace::{LoggingMode, TraceProperties};
use ferrisetw::*;
use std::os::windows::io::OwnedHandle;
use std::process::ExitCode;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use windows::Win32::System::Diagnostics::Etw::{
    KERNEL_LOGGER_NAMEA, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_RAW_TIMESTAMP,
    PROCESS_TRACE_MODE_REAL_TIME,
};

fn process_callback(record: &EventRecord, process_id: u32) {
    const STACK_WALK_GUID: GUID = GUID::from_values(
        0xdef2fe46,
        0x7bd6,
        0x4b80,
        [0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3],
    );
    // if record.provider_id() == STACK_WALK_GUID {}
    println!(
        "provider: {:?}, event: {}, opcode: {}",
        record.provider_id(),
        record.event_id(),
        record.opcode(),
    );
}

pub unsafe fn trace_process(
    process_id: u32,
    process_handle: OwnedHandle,
    samples_per_second: u32,
    wait_time: Duration,
    duration: Duration,
) {
    if !wait_time.is_zero() {
        println!("Waiting for {:.2} seconds...", wait_time.as_secs_f64());
        thread::sleep(wait_time);
    }

    let provider = Provider::kernel(&PROFILE_PROVIDER)
        // .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_STACK_TRACE)
        .add_callback(move |record, _| process_callback(record, process_id))
        .build();

    let core_count =
        thread::available_parallelism().unwrap_or(std::num::NonZeroUsize::new(1usize).unwrap());

    let trace = KernelTrace::new()
        // .named(format!(
        //     "Profenheimer Trace {:?}",
        //     SystemTime::now()
        //         .duration_since(UNIX_EPOCH)
        //         .unwrap()
        //         .as_millis()
        // ))
        .named(KERNEL_LOGGER_NAMEA.to_string().unwrap())
        .enable(provider)
        .set_trace_properties(TraceProperties {
            buffer_size: 1024,
            min_buffer: (core_count.get() * 4) as u32,
            max_buffer: (core_count.get() * 6) as u32,
            flush_timer: Default::default(),
            log_file_mode: LoggingMode::EVENT_TRACE_REAL_TIME_MODE,
        })
        .start_and_process(samples_per_second)
        .expect("Error creating kernel trace");

    let tracing_pair = Arc::new((Mutex::new(true), Condvar::new()));

    CTRL_C_TRACING_PAIR = Some(tracing_pair.clone());

    let close_thread_handle = thread::Builder::new()
        .name("Process Close Detection Thread".to_string())
        .spawn({
            let tracing_pair = tracing_pair.clone();

            move || {
                let tracing_mutex = &tracing_pair.0;
                let tracing_cvar = &tracing_pair.1;

                while *tracing_mutex.lock().unwrap() {
                    if wait_on_process_close(&process_handle, 500) {
                        {
                            let mut guard = tracing_mutex.lock().unwrap();
                            if *guard {
                                println!("Process closed, stopping...")
                            }

                            *guard = false;
                        }
                        tracing_cvar.notify_all();
                        break;
                    }
                }
            }
        })
        .expect("Unable to create process close detection thread");

    // explicit scope for guard, avoids deadlock on join
    {
        let tracing_mutex = &tracing_pair.0;
        let tracing_cvar = &tracing_pair.1;
        let mut guard;

        if !duration.is_zero() {
            println!(
                "Profiling for {:.2} seconds... Press Ctrl+C to stop",
                wait_time.as_secs_f64()
            );

            guard = tracing_cvar
                .wait_timeout_while(tracing_mutex.lock().unwrap(), duration, |&mut tracing| {
                    tracing
                })
                .expect("Mutex poisoned")
                .0;

            if *guard {
                println!("Profiling time elapsed, stopping...")
            }
        } else {
            println!("Profiling... Press Ctrl+C to stop");

            guard = tracing_cvar
                .wait_while(tracing_mutex.lock().unwrap(), |&mut tracing| tracing)
                .expect("Mutex poisoned");
        }

        CTRL_C_TRACING_PAIR = None;

        *guard = false;
        tracing_cvar.notify_all();
    }

    trace.stop().expect("Unable to stop trace");

    close_thread_handle
        .join()
        .expect("Unable to join process close detection thread");

    println!("Finished profile");
}

static mut CTRL_C_TRACING_PAIR: Option<Arc<(Mutex<bool>, Condvar)>> = None;

pub fn init_ctrl_c_handler() {
    ctrlc::set_handler(|| unsafe {
        if let Some(tracing_pair) = &CTRL_C_TRACING_PAIR {
            let tracing_mutex = &tracing_pair.0;
            let tracing_cvar = &tracing_pair.1;

            {
                let mut guard = tracing_mutex.lock().unwrap();
                if *guard {
                    println!("Ctrl+C intercepted, stopping...")
                }

                *guard = false;
            }
            tracing_cvar.notify_all();

            CTRL_C_TRACING_PAIR = None;
        } else {
            ExitCode::FAILURE.exit_process();
        }
    })
    .expect("Unable to set Ctrl+C handler");
}
