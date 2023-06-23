use ferrisetw::provider::kernel_providers::PROFILE_PROVIDER;
use ferrisetw::provider::{Provider, ProviderBuilder, TraceFlags};
use ferrisetw::query::ProfileSource::ProfileTime;
use ferrisetw::trace::{TraceProperties, TraceTrait};
use ferrisetw::*;
use std::mem::size_of;
use std::os::windows::prelude::OwnedHandle;
use std::ptr::addr_of;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Diagnostics::Etw::{
    TraceSampledProfileIntervalInfo, TraceSetInformation, CONTROLTRACE_HANDLE,
    TRACE_PROFILE_INTERVAL,
};

pub unsafe fn trace_process(
    process_handle: OwnedHandle,
    process_id: u32,
    trace_name: String,
    samples_per_second: u32,
) {
    let provider = Provider::by_guid(PROFILE_PROVIDER.guid)
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_STACK_TRACE)
        .add_callback(EventRecord::process_id(process_id))
        .build();

    let (mut trace, trace_handle) = KernelTrace::new()
        .named(trace_name)
        .start()
        .expect("Unable to start trace");

    // set configured interval manually
    let mut interval = TRACE_PROFILE_INTERVAL::default();
    interval.Interval = 1000000000 / samples_per_second;
    TraceSetInformation(
        CONTROLTRACE_HANDLE(trace_handle.0), // this looks dumb, but i think it's correct
        TraceSampledProfileIntervalInfo,
        addr_of!(interval).cast(),
        size_of::<TRACE_PROFILE_INTERVAL>() as u32,
    )
    .ok()
    .expect("Error setting trace interval");

    std::thread::spawn(move || KernelTrace::process_from_handle(trace_handle));

    trace.stop().expect("Unable to stop trace");
}
