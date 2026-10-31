//! Host-side simulation of the guest allocators (loop round 1, G3): wraps the system allocator and
//! replays every alloc/dealloc through (a) the guest's size-class free-list arithmetic and (b) the
//! old never-freeing bump allocator, while `ON` is set. Host sizes are 64-bit (pointers/Vec headers
//! twice the rv32 size), so the numbers are an UPPER bound of the riscv32 guest's.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

pub static ON: AtomicBool = AtomicBool::new(false);
static TOP: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static BUMP: AtomicUsize = AtomicUsize::new(0);
static FREE: [AtomicUsize; 40] = [const { AtomicUsize::new(0) }; 40];
// loop round 2 (A3): per-class live / peak bytes. Carved bytes of a size-class allocator without
// coalescing are bounded by SUM over classes of that class's peak live bytes (+ alignment pads).
static LIVEC: [AtomicUsize; 40] = [const { AtomicUsize::new(0) }; 40];
static PEAKC: [AtomicUsize; 40] = [const { AtomicUsize::new(0) }; 40];

fn class(l: &Layout) -> usize {
    let sz = l.size().max(l.align()).max(16).next_power_of_two();
    sz.trailing_zeros() as usize - 4
}
pub struct Sim;
unsafe impl GlobalAlloc for Sim {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if ON.load(Relaxed) {
            let c = class(&l);
            let sz = 16usize << c;
            if FREE[c].load(Relaxed) > 0 {
                FREE[c].fetch_sub(1, Relaxed);
            } else {
                let a = sz.min(64);
                let t = TOP.load(Relaxed);
                TOP.store(((t + a - 1) & !(a - 1)) + sz, Relaxed);
            }
            let lc = LIVEC[c].fetch_add(sz, Relaxed) + sz;
            PEAKC[c].fetch_max(lc, Relaxed);
            let lv = LIVE.fetch_add(sz, Relaxed) + sz;
            PEAK.fetch_max(lv, Relaxed);
            let b = BUMP.load(Relaxed);
            BUMP.store(((b + l.align() - 1) & !(l.align() - 1)) + l.size(), Relaxed);
        }
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if ON.load(Relaxed) {
            let c = class(&l);
            FREE[c].fetch_add(1, Relaxed);
            LIVEC[c].fetch_sub((16usize << c).min(LIVEC[c].load(Relaxed)), Relaxed);
            LIVE.fetch_sub((16usize << c).min(LIVE.load(Relaxed)), Relaxed);
        }
        System.dealloc(p, l)
    }
}
pub fn reset() {
    for f in FREE.iter().chain(LIVEC.iter()).chain(PEAKC.iter()) {
        f.store(0, Relaxed);
    }
    TOP.store(0, Relaxed);
    LIVE.store(0, Relaxed);
    PEAK.store(0, Relaxed);
    BUMP.store(0, Relaxed);
}
/// (size-class high-water, peak live, bump total)
pub fn read() -> (usize, usize, usize) {
    (TOP.load(Relaxed), PEAK.load(Relaxed), BUMP.load(Relaxed))
}
/// sum over classes of each class's peak live bytes (the carve bound without pads)
pub fn sum_class_peaks() -> usize {
    PEAKC.iter().map(|p| p.load(Relaxed)).sum()
}
