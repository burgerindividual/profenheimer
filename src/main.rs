#![feature(
    new_uninit,
    strict_provenance,
    pointer_like_trait,
    windows_handle,
    exitcode_exit_method
)]

mod os_check_err;
mod trace;
mod win_api;

use blondie::*;
use colored::Colorize;
use inferno::collapse::dtrace::{Folder, Options};
use inferno::collapse::Collapse;
use std::fs::File;
use std::io::{stdin, stdout, Write};
use std::mem::{transmute, MaybeUninit};
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::os::windows::prelude::OwnedHandle;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, ExitCode};
use std::ptr::from_exposed_addr;
use tinyfiledialogs::*;

const KERNEL_STACKS: bool = true;
const INCLUDE_OFFSETS: bool = true;
const BUFFER_DEFAULT_SIZE: usize = 20000000; // 20MB

fn main() {
    println!(
        "{} by burgerindividual\n\"I am become depth, destroyer of stacks.\"\n",
        "profenheimer".bold()
    );

    println!("Opening file dialog...");
    // unwrapping should be fine here bc we got the path from the file system anyway,
    // so it should be valid
    let out_path = save_file_dialog_with_filter(
        "Choose output location...",
        "out",
        &["*.collapsed"],
        "FlameGraph (*.collapsed)",
    )
    .unwrap_or_else(|| {
        eprintln!("Did not input path, exiting...");
        // the user did it intentionally, so i'm calling it a success
        ExitCode::SUCCESS.exit_process();
    });

    print!("Window Title: ");
    stdout().flush().expect("Error flushing stdout");
    let mut in_buffer = String::new();
    stdin()
        .read_line(&mut in_buffer)
        .expect("Expected window title");
    let partial_window_title = in_buffer.trim_end_matches('\n').trim_end_matches('\r');

    unsafe {
        acquire_priviledges().unwrap();
        let handle = get_window_process_handle(partial_window_title);
        let child = FakeChildProcess::new(handle).into_child_process();

        println!("Beginning profile, will finish when process is exited...");
        // returns when the process is exited
        let results = trace_child(child, KERNEL_STACKS).expect("Error tracing the process");
        println!("Finished profile");

        let mut dtrace_stacks = Vec::<u8>::with_capacity(BUFFER_DEFAULT_SIZE);
        println!("Converting stacks to dtrace format...");
        results
            .write_dtrace(&mut dtrace_stacks)
            .expect("Error writing dtrace stacks");

        let file = File::create(&out_path)
            .unwrap_or_else(|_| panic!("Error creating output file {out_path}"));

        // for debugging:
        // file.write_all(&dtrace_stacks[..]).unwrap();

        println!("Folding dtrace stacks and saving to {out_path}...");
        let mut inferno_options = Options::default();
        inferno_options.includeoffset = INCLUDE_OFFSETS;
        let mut folder = Folder::from(inferno_options);

        folder
            .collapse(&dtrace_stacks[..], file)
            .expect("Error folding dtrace stacks");

        println!("Finished folding");
    }
}
