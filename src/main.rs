#![feature(new_uninit, strict_provenance, windows_handle, exitcode_exit_method)]

mod atomic_wait;
mod interpret;
mod log;
mod process;
mod trace;

use std::fs::File;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::*;
use inferno::collapse::dtrace::{Folder, Options};
use inferno::collapse::Collapse;
use tinyfiledialogs::save_file_dialog_with_filter;

use crate::log::{err_verbose, log_verbose, VERBOSE_LOGGING};
use crate::process::{
    acquire_privileges, get_process_handle_from_pid, get_window_process, Process,
};
use crate::trace::{init_ctrl_c_handler, trace};

const BUFFER_DEFAULT_SIZE: usize = 50000000; // 50MB

fn main() {
    let matches = command!()
        .arg(
            arg!(
                -o --output <FILE> "Sets the output file for the collapsed stacks (leave blank to open file chooser)"
            )
            .required(false)
            .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(
                -t --title <STRING> "Partial window title to match processes to"
            )
                .required_unless_present_any(["pid", "system"]),
        )
        .arg(
            arg!(
                -p --pid <PID> "PID of the process to match to"
            )
                .required_unless_present_any(["system", "title"])
                .value_parser(value_parser!(u32)),
        )
        .arg(
            arg!(
                --system "Do a full system profile (not recommended)"
            )
                .required_unless_present_any(["pid", "title"])
                .action(ArgAction::SetTrue),
        )
        .arg(
            arg!(
                --wait <SECONDS> "How long the trace should wait before starting (default: 0)"
            )
                .required(false)
                .value_parser(value_parser!(f64)),
        )
        .arg(
            arg!(
                -l --length <SECONDS> "How long the trace should last (default: until manually stopped)"
            )
                .required(false)
                .value_parser(value_parser!(f64)),
        )
        .arg(
            arg!(
                -s --sample_rate <SAMPLE_RATE> "The amount of samples that should be taken per second (default: 997)"
            )
                .required(false)
                .value_parser(value_parser!(u32)),
        )
        .arg(
            arg!(
                -k --kernel "Enable logging kernel and driver stacks"
            )
                .required(false)
                .action(ArgAction::SetTrue),
        )
        .arg(
            arg!(
                -n --no_offsets "Disable function offsets in output"
            )
                .required(false)
                .action(ArgAction::SetTrue),
        )
        .arg(
            arg!(
                -q --quiet "Disable verbose logging"
            )
                .required(false)
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    VERBOSE_LOGGING.set(!matches.get_flag("quiet")).unwrap();

    unsafe {
        // fails if we aren't admin
        acquire_privileges();
    }

    let show_kernel_stacks = matches.get_flag("kernel");
    let include_offsets = !matches.get_flag("no_offsets");

    let input_partial_window_title = matches.get_one::<String>("title");
    let input_process_id = matches.get_one::<u32>("pid");

    let wait_time: Duration = matches
        .get_one::<f64>("wait")
        .map_or(Duration::ZERO, |&secs| Duration::from_secs_f64(secs));

    let length_time: Duration = matches
        .get_one::<f64>("length")
        .map_or(Duration::ZERO, |&secs| Duration::from_secs_f64(secs));

    let samples_per_second = *matches.get_one::<u32>("sample_rate").unwrap_or(&997_u32);

    let process: Option<Process> = unsafe {
        if let Some(&process_id) = input_process_id {
            let process_handle = get_process_handle_from_pid(process_id);
            Some(Process {
                handle: process_handle,
                id: process_id,
            })
        } else {
            input_partial_window_title
                .map(|partial_window_title| get_window_process(partial_window_title.as_str()))
        }
    };

    let out_path: PathBuf = if let Some(path_buf) = matches.get_one::<PathBuf>("output") {
        path_buf.clone()
    } else {
        log_verbose!("Opening file dialog...");

        PathBuf::from(
            save_file_dialog_with_filter(
                "Choose output location...",
                "out",
                &["*.collapsed"],
                "FlameGraph (*.collapsed)",
            )
            .unwrap_or_else(|| {
                err_verbose!("Did not input path, exiting...");
                // the user did it intentionally, so i'm calling it a success
                ExitCode::SUCCESS.exit_process();
            }),
        )
    };

    init_ctrl_c_handler();

    unsafe {
        let results = trace(
            process,
            wait_time,
            length_time,
            samples_per_second,
            show_kernel_stacks,
        );

        let mut dtrace_stacks = Vec::<u8>::with_capacity(BUFFER_DEFAULT_SIZE);
        results
            .write_dtrace(&mut dtrace_stacks)
            .expect("Error writing dtrace stacks");

        let file = File::create(&out_path)
            .unwrap_or_else(|_| panic!("Error creating output file {}", out_path.display()));

        log_verbose!(
            "Folding dtrace stacks and saving to {}...",
            out_path.display()
        );
        let mut inferno_options = Options::default();
        inferno_options.includeoffset = include_offsets;
        let mut folder = Folder::from(inferno_options);

        folder
            .collapse(&dtrace_stacks[..], file)
            .expect("Error folding dtrace stacks");

        log_verbose!("Finished folding");
    }
}
