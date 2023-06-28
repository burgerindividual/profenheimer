// CODE BELOW BASED OFF CRATE "atomic-wait"
//
// Copyright (c) 2022, Mara Bos <m-ou.se@m-ou.se>
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSEARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use core::sync::atomic::AtomicBool;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use windows::Win32::System::Threading::{
    WaitOnAddress, WakeByAddressAll, WakeByAddressSingle, INFINITE,
};

pub trait AtomicWait {
    type CompareWith;

    fn wait(&self, expected: Self::CompareWith);
    fn wait_timeout(&self, expected: Self::CompareWith, timeout: Duration);
    fn wake_one(&self);
    fn wake_all(&self);
}

impl AtomicWait for Pin<Arc<AtomicBool>> {
    type CompareWith = bool;

    #[inline(always)]
    fn wait(&self, expected: Self::CompareWith) {
        let ptr: *mut bool = self.as_ptr();
        let expected_ptr: *const bool = &expected;
        unsafe { WaitOnAddress(ptr.cast(), expected_ptr.cast(), 1, INFINITE) };
    }

    #[inline(always)]
    fn wait_timeout(&self, expected: Self::CompareWith, timeout: Duration) {
        let ptr: *mut bool = self.as_ptr();
        let expected_ptr: *const bool = &expected;
        unsafe {
            WaitOnAddress(
                ptr.cast(),
                expected_ptr.cast(),
                1,
                timeout.as_millis().try_into().expect("Duration too large"),
            )
        };
    }

    #[inline(always)]
    fn wake_one(&self) {
        let ptr: *mut bool = self.as_ptr();
        unsafe { WakeByAddressSingle(ptr.cast()) };
    }

    #[inline(always)]
    fn wake_all(&self) {
        let ptr: *mut bool = self.as_ptr();
        unsafe { WakeByAddressAll(ptr.cast()) };
    }
}
