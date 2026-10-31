//! riscv32im guest entry: read a batch through ecall a7=63, run it, write results to OUT, halt a7=93.
//! OUT (0x03F0_0000, above the stack top): [0..8] state hash, [8] event words, [9] applied,
//! [10] rejected, [11] fills, [12] heap bytes used, [13..] event log.
//! Witness (MNWIT1, default build): per-unit roots at OUT+0x20000 words (8 words each, unit order),
//! OUT[0x1FFFF] = units done (written after each unit, every mode), [0x1FFFE] = final root == from-scratch rebuild (1/0), [0x1FFFD] = leaves,
//! [0x1FFFC] = leaf updates, [0x1FFFB] = node hashes, [0x1FFFA] = peak live heap bytes,
//! [0x1FFF9] = status (mnpilot::ST_*: 0 ok, 1 bad magic, 2 n_accounts > MAX_ACCOUNTS, 3 n_ops >
//! MAX_UNITS; 0xFFFF0077 = abort: panic or out of memory, exit code a0 = 77), [0x1FFF8] = event
//! log overflow (never 1 within MAX_UNITS). [12] = heap high-water (bytes carved). Features: `nowit` = no commitment (2d01fe8
//! pilot), `legacywit` = legacy full rebuild per unit for units >= input word 3, `prod` = header flags must be 0.
//! Segments (loop round 3): [0x1FFF0..8] = segment start root (MNWIT1 root before the first unit of
//! this run), [0x1FFE8..8] = segment end root (after the last unit; = start root if no unit ran),
//! [0x1FFE7] = segments run by this session (1 = genesis run). The session (engine + witness tree +
//! allocator) persists in memory: the rollup's s0 for height h carries the final memory of h-1, the
//! guest restarts at pc 0 and resumes from `SESS` (a .data pointer). `.bss` is zeroed in `_start`
//! (round 2 A4); every value that must survive a run lives in `.data`. A run that aborts (panic /
//! OOM, status 0xFFFF0077) or traps (status stays 0xFFFF0001 = running, segment roots stay 0) marks the session
//! dead: later runs execute nothing (status ST_DEAD = 5). Loop round 3 review R3-G1/G2.
//! Loop round 4 (R3-H2, snapshot.rs): input word 0 = EXPORT_MAGIC -> export run (needs a live session:
//! digest of the canonical snapshot at OUT[0x1FFD8..8], its length in words at [0x1FFD7], kind 1 at
//! [0x1FFD6], session root as both segment roots); word 0 = SNAP_MAGIC -> import run, accepted only as
//! an upgrade image built with MNPILOT_IMPORT_DIGEST=<export digest hex>:<words> while it has no session
//! (review R4-S1: the digest is part of the image, so the governance-chosen GENMEM decides which state may
//! be imported; any other image -> ST_IMPORT_LOCKED, a mismatching / malformed snapshot -> ST_BAD_SNAP; the
//! words are hashed BEFORE they are decoded). An upgrade image refuses batch runs until it imported
//! (ST_NEED_IMPORT, R4-S2: else its first batch would start a genesis session = wipe the state). A dead
//! image stays dead (ST_DEAD); recovery is an upgrade to a new image that imports the last good export.
//! [0x1FFD6..0x1FFE0] are zero in every other run. Event log cap lowered to 0x1FFD6 (EV_CAP).
#![cfg_attr(target_os = "none", no_std, no_main)]

#[cfg(not(target_os = "none"))]
fn main() {}

#[cfg(target_os = "none")]
mod rt {
    extern crate alloc;
    use core::alloc::{GlobalAlloc, Layout};
    core::arch::global_asm!(
        ".section .text._start", ".global _start", "_start:",
        // loop round 3 (A4): zero .bss (word-aligned bounds, link.x) before any Rust code runs
        "la t0, _bss_start", "la t1, _bss_end",
        "2: bgeu t0, t1, 3f", "sw zero, 0(t0)", "addi t0, t0, 4", "j 2b",
        "3: li sp, 0x3F00000", "call rmain", "li a7, 93", "ecall", "1: j 1b");
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
    // Deterministic size-class free-list allocator (loop round 1, finding G3). The 2d01fe8 bump
    // allocator never freed, so heap use grew with the TOTAL bytes ever allocated: e.g. the book's
    // undo journal clones a whole price level on every touch, so k orders resting at one price
    // cost O(k^2) bytes and ~1 700 orders at one level exhausted the 48 MiB heap (guest abort on a
    // batch the real engine accepts). Now: every request is rounded up to a power-of-two class
    // (16 B .. 32 MiB), freed blocks go to that class's LIFO free list and are reused first, new
    // blocks are carved from the top. Heap use is bounded by the live bytes per class (<= 2x
    // internal rounding) -- a pure function of the allocation sequence, hence of the input.
    // Out of memory (top would pass 0x0300_0000): alloc returns null -> alloc error -> panic ->
    // exit a0 = 77 with OUT[0x1FFF9] = ST_ABORT (deterministic on every RISC-V implementation).
    struct Heap;
    const NCLASS: usize = 22;
    // loop round 3: allocator state persists across runs (the heap holds the session) -> .data
    #[link_section = ".data.alloc"]
    static mut FREE: [usize; NCLASS] = [0; NCLASS];
    #[link_section = ".data.alloc"]
    pub static mut HEAP: usize = 0; // top of carved region
    #[link_section = ".data.alloc"]
    pub static mut HEAP0: usize = 0;
    #[link_section = ".data.alloc"]
    pub static mut LIVE: usize = 0; // bytes in live blocks (class sizes)
    #[link_section = ".data.alloc"]
    pub static mut PEAK: usize = 0;
    /// the persistent session (Box<mnpilot::Session> leaked), 0 = none yet (genesis run)
    #[link_section = ".data.sess"]
    static mut SESS: usize = 0;
    /// 1 after an aborted run (panic / OOM)
    #[link_section = ".data.sess"]
    static mut DEAD: u32 = 0;
    /// loop round 3 review (R3-G1): 1 while a run is in progress. A run that ends WITHOUT reaching the clean exit --
    /// panic, OOM, or a trap (illegal instruction, misaligned access: the machine stops at pc = TRAP and the rollup
    /// still carries its memory into the next height) -- leaves it at 1; the session may then be torn mid-unit (or
    /// moved out of its box: SESS points at freed memory), so every later run refuses to execute (ST_DEAD).
    #[link_section = ".data.sess"]
    static mut IN_RUN: u32 = 0;
    /// loop round 4 (R4-S1): "<digest hex>:<words>" of the export an upgrade image may import (compiled in, so
    /// the image's memory root commits it); None = ordinary image, imports refused
    const IMPORT_DIGEST: Option<&str> = option_env!("MNPILOT_IMPORT_DIGEST");
    extern "C" { static _heap_start: u8; }
    const HEAP_END: usize = 0x0300_0000; // below the embed input region; stack has 15 MiB above
    #[inline]
    fn class(l: &Layout) -> Option<usize> {
        let sz = l.size().max(l.align()).max(16).checked_next_power_of_two()?;
        let c = sz.trailing_zeros() as usize - 4;
        if c < NCLASS { Some(c) } else { None }
    }
    unsafe impl GlobalAlloc for Heap {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            if HEAP == 0 { HEAP = &_heap_start as *const u8 as usize; HEAP0 = HEAP; }
            let Some(c) = class(&l) else { return core::ptr::null_mut() };
            // loop round 2 (A1): every block of a class is aligned to min(size, 64), so an
            // alignment above 64 is refused up front -- before, only the carve path refused it and
            // a free-list hit returned a block aligned to 64 only (latent: no such type here)
            if l.align() > 64 { return core::ptr::null_mut(); }
            let sz = 16usize << c;
            let p = if FREE[c] != 0 {
                let p = FREE[c];
                FREE[c] = *(p as *const usize);
                p
            } else {
                // blocks are aligned to min(size, 64): every class's blocks satisfy any align <= 64
                let a = sz.min(64); // >= l.align(): sz >= align and align <= 64
                let p = (HEAP + a - 1) & !(a - 1);
                if p + sz > HEAP_END { return core::ptr::null_mut(); }
                HEAP = p + sz;
                p
            };
            LIVE += sz;
            if LIVE > PEAK { PEAK = LIVE; }
            p as *mut u8
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            if let Some(c) = class(&l) {
                *(p as *mut usize) = FREE[c];
                FREE[c] = p as usize;
                LIVE -= 16usize << c;
            }
        }
        unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
            let nl = Layout::from_size_align_unchecked(new_size, l.align());
            if class(&l).is_some() && class(&l) == class(&nl) {
                return p; // same class: the block already has room
            }
            let q = self.alloc(nl);
            if !q.is_null() {
                core::ptr::copy_nonoverlapping(p, q, l.size().min(new_size));
                self.dealloc(p, l);
            }
            q
        }
    }
    #[global_allocator]
    static A: Heap = Heap;
    const OUT: *mut u32 = 0x03F0_0000 as *mut u32;
    const ROOTS: usize = 0x20000;
    /// OUT[0x1FFF9]: batch status (mnpilot::ST_*), ST_ABORT on panic / out of memory.
    const ST_ABORT: u32 = 0xFFFF_0077;
    /// OUT[0x1FFF9] while a run is in progress (left there if the run traps)
    const ST_RUNNING: u32 = 0xFFFF_0001;
    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        unsafe {
            DEAD = 1;
            OUT.add(ROOTS - 7).write_volatile(ST_ABORT);
            core::arch::asm!("li a0, 77", "li a7, 93", "ecall", options(noreturn));
        }
    }
    const SEG_START: usize = 0x1FFF0;
    const SEG_END: usize = 0x1FFE8;
    const SEG_N: usize = 0x1FFE7;
    const SNAP_KIND: usize = 0x1FFD6;
    const SNAP_N: usize = 0x1FFD7;
    const SNAP_DIGEST: usize = 0x1FFD8;
    fn put_root(at: usize, r: &[u8; 32]) {
        for k in 0..8 {
            unsafe { OUT.add(at + k).write_volatile(u32::from_le_bytes([r[4 * k], r[4 * k + 1], r[4 * k + 2], r[4 * k + 3]])) };
        }
    }
    #[no_mangle]
    extern "C" fn rmain() -> u32 {
        let mut n_ev: u32 = 0;
        // this run's counters start at 0 (OUT words survive from the previous run)
        unsafe {
            OUT.add(ROOTS - 1).write_volatile(0);
            OUT.add(ROOTS - 8).write_volatile(0);
            OUT.add(8).write_volatile(0);
            // R3-G2: until the clean exit rewrites them, the status word says "running" and the segment roots are
            // zero -- a run that traps must not leave the previous height's status 0 / end root behind (rv_witbind
            // would bind the previous root for the trapped height)
            OUT.add(ROOTS - 7).write_volatile(ST_RUNNING);
            put_root(SEG_START, &[0; 32]);
            put_root(SEG_END, &[0; 32]);
            put_root(SNAP_DIGEST, &[0; 32]);
            OUT.add(SNAP_N).write_volatile(0);
            OUT.add(SNAP_KIND).write_volatile(0);
            if DEAD != 0 || IN_RUN != 0 {
                DEAD = 1;
                OUT.add(ROOTS - 7).write_volatile(mnpilot::ST_DEAD);
                return 0;
            }
            IN_RUN = 1;
        }
        let mut sess: Option<mnpilot::Session> = unsafe {
            if SESS == 0 { None } else { Some(*alloc::boxed::Box::from_raw(SESS as *mut mnpilot::Session)) }
        };
        let w0 = read_word(0);
        let expect = IMPORT_DIGEST.and_then(mnpilot::parse_expect);
        if w0 == mnpilot::snapshot::EXPORT_MAGIC || w0 == mnpilot::snapshot::SNAP_MAGIC {
            let so = if w0 == mnpilot::snapshot::EXPORT_MAGIC {
                mnpilot::run_export(&mut |i| read_word(i), &mut sess)
            } else {
                mnpilot::run_import(&mut |i| read_word(i), &mut sess, expect.as_ref())
            };
            unsafe {
                let segs = sess.as_ref().map(|s| s.segs).unwrap_or(0);
                if let Some(s) = sess {
                    SESS = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(s)) as usize;
                }
                OUT.add(SEG_N).write_volatile(segs);
                if so.status == mnpilot::ST_OK {
                    put_root(SEG_START, &so.root);
                    put_root(SEG_END, &so.root);
                    put_root(SNAP_DIGEST, &so.digest);
                    OUT.add(SNAP_N).write_volatile(so.words);
                    OUT.add(SNAP_KIND).write_volatile(if w0 == mnpilot::snapshot::EXPORT_MAGIC { 1 } else { 2 });
                }
                for k in 0..13 {
                    OUT.add(k).write_volatile(0);
                }
                OUT.add(12).write_volatile((HEAP - HEAP0) as u32);
                OUT.add(ROOTS - 6).write_volatile(PEAK as u32);
                OUT.add(ROOTS - 7).write_volatile(so.status);
                IN_RUN = 0; // clean exit
            }
            return so.status;
        }
        // R4-S2: an upgrade image (MNPILOT_IMPORT_DIGEST set, even if malformed) without a session runs no
        // units: run_segment would start a fresh genesis session (= the rollup state wiped). Nothing is
        // allocated or kept; the image stays importable.
        if IMPORT_DIGEST.is_some() && sess.is_none() {
            unsafe {
                OUT.add(SEG_N).write_volatile(0);
                for k in 0..13 {
                    OUT.add(k).write_volatile(0);
                }
                OUT.add(12).write_volatile((HEAP - HEAP0) as u32);
                OUT.add(ROOTS - 6).write_volatile(PEAK as u32);
                OUT.add(ROOTS - 7).write_volatile(mnpilot::ST_NEED_IMPORT);
                IN_RUN = 0; // clean exit
            }
            return mnpilot::ST_NEED_IMPORT;
        }
        #[cfg(feature = "nowit")]
        let mode = mnpilot::WitMode::Off;
        #[cfg(all(feature = "legacywit", not(feature = "nowit")))]
        let mode = mnpilot::WitMode::Legacy { skip: read_word(3) & 0xFF_FFFF };
        #[cfg(not(any(feature = "nowit", feature = "legacywit")))]
        let mode = mnpilot::WitMode::Incremental;
        let (h, st, wo) = mnpilot::run_segment(
            &mut |i| read_word(i),
            &mut |w| unsafe {
                // bounded: never reaches the counters at 0x1FFF0.. (cannot trigger within
                // MAX_UNITS since a unit emits <= 7 words; n_ev keeps counting, overflow flagged)
                if n_ev < mnpilot::EV_CAP {
                    OUT.add(13 + n_ev as usize).write_volatile(w);
                }
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
            &mut sess,
        );
        unsafe {
            let segs = sess.as_ref().map(|s| s.segs).unwrap_or(0);
            if let Some(s) = sess {
                SESS = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(s)) as usize;
            }
            OUT.add(SEG_N).write_volatile(segs);
            if st.status == mnpilot::ST_OK {
                put_root(SEG_START, &wo.start_root);
                put_root(SEG_END, &wo.root);
            } else {
                put_root(SEG_START, &[0; 32]);
                put_root(SEG_END, &[0; 32]);
            }
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
            OUT.add(12).write_volatile((HEAP - HEAP0) as u32); // heap high-water (carved bytes)
            OUT.add(ROOTS - 6).write_volatile(PEAK as u32); // peak live bytes (class sizes)
            OUT.add(ROOTS - 7).write_volatile(st.status);
            OUT.add(ROOTS - 8).write_volatile((n_ev > mnpilot::EV_CAP) as u32);
            IN_RUN = 0; // clean exit
        }
        u32::from_le_bytes([h[0], h[1], h[2], h[3]])
    }
}
