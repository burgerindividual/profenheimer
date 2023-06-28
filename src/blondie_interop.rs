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

use blondie::CollectionResults;
use std::ffi::OsString;
use std::mem::transmute;
use std::os::windows::io::OwnedHandle;
use std::sync::atomic::AtomicBool;

pub const MAX_STACK_DEPTH: usize = 200;

/// map[array_of_stacktrace_addrs] = sample_count
pub type StackMap = rustc_hash::FxHashMap<[u64; MAX_STACK_DEPTH], u64>;

/// (image_path, image_base, image_size)
pub type LoadedImage = (OsString, u64, u64);

// TODO: make this repr(C) and copy the rust layout of the original TraceContext?
#[derive(Debug)]
pub struct TraceContext {
    pub target_process_handle: OwnedHandle,
    pub stack_counts_hashmap: StackMap,
    pub target_proc_pid: u32,
    pub trace_running: AtomicBool,
    pub show_kernel_samples: bool,

    /// (image_path, image_base, image_size)
    pub image_paths: Vec<(OsString, u64, u64)>,
}

impl TraceContext {
    pub unsafe fn into_collection_results(self) -> CollectionResults {
        transmute(self)
    }
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
