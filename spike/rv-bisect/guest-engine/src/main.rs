//! riscv32im guest entry: read a batch through ecall a7=63, run it, write results to OUT, halt a7=93.
//! OUT (0x03F0_0000, above the stack top): [0..8] state hash, [8] event words, [9] applied,
//! [10] rejected, [11] fills, [12] heap bytes used, [13..] event log.
//! Witness (MNWIT1, default build): per-unit roots at OUT+0x20000 words (8 words each, unit order),
//! OUT[0x1FFFF] = units done (written after each unit, every mode), [0x1FFFE] = final root == from-scratch rebuild (1/0), [0x1FFFD] = leaves,
//! [0x1FFFC] = leaf updates, [0x1FFFB] = node hashes. Features: `nowit` = no commitment (2d01fe8
//! pilot), `legacywit` = legacy full rebuild per unit for units >= input word 3.
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
    #[cfg(not(feature = "embed"))]
    fn read_word(i: u32) -> u32 {
        let r: u32;
        unsafe { core::arch::asm!("ecall", inlateout("a0") i => r, in("a7") 63u32); }
        r
    }
    #[cfg(feature = "embed")]
    fn read_word(i: u32) -> u32 {
        unsafe { ((0x0300_0000 + 4 * i) as *const u32).read_volatile() }
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
            if HEAP >= 0x3000000 { panic!() } // below the embed input region; stack has 15 MiB
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
        #[cfg(feature = "nowit")]
        let mode = mnpilot::WitMode::Off;
        #[cfg(all(feature = "legacywit", not(feature = "nowit")))]
        let mode = mnpilot::WitMode::Legacy { skip: read_word(3) & 0xFF_FFFF };
        #[cfg(not(any(feature = "nowit", feature = "legacywit")))]
        let mode = mnpilot::WitMode::Incremental;
        const ROOTS: usize = 0x20000;
        let (h, st, wo) = mnpilot::run_batch_wit(
            &mut |i| read_word(i),
            &mut |w| unsafe {
                OUT.add(13 + n_ev as usize).write_volatile(w);
                n_ev += 1;
            },
            &mut |i, _, r| unsafe {
                if mode != mnpilot::WitMode::Off {
                    for k in 0..8 {
                        OUT.add(ROOTS + 8 * i as usize + k)
                            .write_volatile(u32::from_le_bytes([r[4 * k], r[4 * k + 1], r[4 * k + 2], r[4 * k + 3]]));
                    }
                }
                // unit counter, written after every unit in every mode (the bench's unit boundary)
                OUT.add(ROOTS - 1).write_volatile(i + 1);
            },
            mode,
        );
        unsafe {
            OUT.add(ROOTS - 2).write_volatile(wo.scratch_ok as u32);
            OUT.add(ROOTS - 3).write_volatile(wo.leaves);
            OUT.add(ROOTS - 4).write_volatile(wo.leaf_updates as u32);
            OUT.add(ROOTS - 5).write_volatile(wo.node_hashes as u32);
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
