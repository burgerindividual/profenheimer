use crate::atomic_wait::AtomicWait;
use crate::win_api::{get_kernel_images, register_wait_on_process_close, start_trace, stop_trace};
use blondie::CollectionResults;
use std::ffi::c_void;
use std::os::windows::io::OwnedHandle;
use std::pin::Pin;
use std::process::ExitCode;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use windows::Win32::Foundation::BOOLEAN;

pub unsafe fn trace_process(
    process_handle: OwnedHandle,
    process_id: u32,
    wait_time: Duration,
    duration: Duration,
    samples_per_second: u32,
    collect_kernel_stacks: bool,
) -> CollectionResults {
    if !wait_time.is_zero() {
        println!("Waiting for {:.2} seconds...", wait_time.as_secs_f64());
        thread::sleep(wait_time);
    }

    let extended_trace_context = start_trace(
        &process_handle,
        process_id,
        samples_per_second,
        collect_kernel_stacks,
    );

    let tracing = Arc::pin(AtomicBool::new(true));

    let mut ctrl_c_tracing = tracing.clone();
    GLOBAL_TRACING_REF.store(&mut ctrl_c_tracing, Ordering::SeqCst);

    register_wait_on_process_close(&process_handle, process_ended_callback);

    if !duration.is_zero() {
        println!(
            "Profiling for {:.2} seconds... Press Ctrl+C to stop",
            wait_time.as_secs_f64()
        );

        tracing.wait_timeout(true, duration);
    } else {
        println!("Profiling... Press Ctrl+C to stop");

        tracing.wait(true);
    }

    // is this okay here?
    GLOBAL_TRACING_REF.store(null_mut(), Ordering::SeqCst);

    try_set_stopped(&tracing, "Profiling time elapsed, stopping...");

    if collect_kernel_stacks {
        extended_trace_context
            .get_inner_context()
            .image_paths
            .append(get_kernel_images().as_mut());
    }

    let results = stop_trace(extended_trace_context);

    println!("Finished profile");

    results
}

static GLOBAL_TRACING_REF: AtomicPtr<Pin<Arc<AtomicBool>>> = AtomicPtr::new(null_mut());

pub fn init_ctrl_c_handler() {
    ctrlc::set_handler(|| unsafe {
        let tracing_ptr = GLOBAL_TRACING_REF.swap(null_mut(), Ordering::SeqCst);
        if let Some(tracing) = tracing_ptr.as_ref() {
            try_set_stopped(tracing, "Ctrl+C intercepted, stopping...");
        } else {
            ExitCode::FAILURE.exit_process();
        }
    })
    .expect("Unable to set Ctrl+C handler");
}

unsafe extern "system" fn process_ended_callback(_: *mut c_void, _: BOOLEAN) {
    let tracing_ptr = GLOBAL_TRACING_REF.swap(null_mut(), Ordering::SeqCst);
    if let Some(tracing) = tracing_ptr.as_ref() {
        try_set_stopped(tracing, "Traced process has ended, stopping...");
    }
}

fn try_set_stopped(tracing: &Pin<Arc<AtomicBool>>, message: &str) {
    // if this doesn't pass, we're likely already stopping
    if tracing
        .compare_exchange(true, false, Ordering::SeqCst, Ordering::Relaxed)
        .is_ok()
    {
        println!("{}", message);
        tracing.wake_all();
    }
}
