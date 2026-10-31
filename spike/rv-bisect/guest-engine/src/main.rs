//! riscv32im guest entry: read a batch through ecall a7=63, run it, write results to OUT, halt a7=93.
//! OUT (0x03F0_0000, above the stack top): [0..8] state hash, [8] event words, [9] applied,
//! [10] rejected, [11] fills, [12] heap bytes used, [13..] event log.
#![cfg_attr(target_os = "none", no_std, no_main)]

#[cfg(not(target_os = "none"))]
fn main() {}

#[cfg(target_os = "none")]
mod rt {
    extern crate alloc;
    use core::alloc::{GlobalAlloc, Layout};
    core::arch::global_asm!(
        ".section .text._start", ".global _start", "_start:",
        "li sp, 0x3F00000", "call rmain", "li a7, 93", "ecall", "1: j 1b");
    fn read_word(i: u32) -> u32 {
        let r: u32;
        unsafe { core::arch::asm!("ecall", inlateout("a0") i => r, in("a7") 63u32); }
        r
    }
    // Deterministic bump allocator (never frees), as in ../guest.
    struct Bump;
    static mut HEAP: usize = 0;
    static mut HEAP0: usize = 0;
    extern "C" { static _heap_start: u8; }
    unsafe impl GlobalAlloc for Bump {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            if HEAP == 0 { HEAP = &_heap_start as *const u8 as usize; HEAP0 = HEAP; }
            let p = (HEAP + l.align() - 1) & !(l.align() - 1);
            HEAP = p + l.size();
            if HEAP >= 0x3E00000 { panic!() } // keep 1 MiB for the stack
            p as *mut u8
        }
        unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
    }
    #[global_allocator]
    static A: Bump = Bump;
    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        unsafe { core::arch::asm!("li a0, 77", "li a7, 93", "ecall", options(noreturn)); }
    }
    const OUT: *mut u32 = 0x03F0_0000 as *mut u32;
    #[no_mangle]
    extern "C" fn rmain() -> u32 {
        let mut n_ev: u32 = 0;
        let (h, st) = mnpilot::run_batch(&mut |i| read_word(i), &mut |w| unsafe {
            OUT.add(13 + n_ev as usize).write_volatile(w);
            n_ev += 1;
        });
        unsafe {
            for k in 0..8 {
                OUT.add(k).write_volatile(u32::from_le_bytes([h[4 * k], h[4 * k + 1], h[4 * k + 2], h[4 * k + 3]]));
            }
            OUT.add(8).write_volatile(n_ev);
            OUT.add(9).write_volatile(st.applied);
            OUT.add(10).write_volatile(st.rejected);
            OUT.add(11).write_volatile(st.fills);
            OUT.add(12).write_volatile((HEAP - HEAP0) as u32);
        }
        u32::from_le_bytes([h[0], h[1], h[2], h[3]])
    }
}
