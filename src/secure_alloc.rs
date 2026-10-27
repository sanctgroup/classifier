#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};

use zeroize::Zeroize;

pub struct ZeroizingAllocator;

unsafe impl GlobalAlloc for ZeroizingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            std::slice::from_raw_parts_mut(ptr, layout.size()).zeroize();
            System.dealloc(ptr, layout);
        }
    }
}
