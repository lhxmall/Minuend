#![no_std]
#![no_main]
extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
mod vec;

// ---- runtime: entry, exit, input ecall, bump allocator (deterministic, never frees) ----
core::arch::global_asm!(
    ".section .text._start", ".global _start", "_start:",
    "li sp, 0x3F00000", "call rmain", "li a7, 93", "ecall", "1: j 1b");
fn read_word(i: u32) -> u32 { let r: u32; unsafe { core::arch::asm!("ecall", inlateout("a0") i => r, in("a7") 63u32); } r }
struct Bump;
static mut HEAP: usize = 0;
extern "C" { static _heap_start: u8; }
unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if HEAP == 0 { HEAP = &_heap_start as *const u8 as usize; }
        let p = (HEAP + l.align() - 1) & !(l.align() - 1); HEAP = p + l.size(); p as *mut u8 }
    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}
#[global_allocator] static A: Bump = Bump;
#[panic_handler] fn panic(_: &core::panic::PanicInfo) -> ! { unsafe { core::arch::asm!("li a0, 77", "li a7, 93", "ecall", options(noreturn)); } }

// ---- workloads ----
fn w_sha() -> u32 { use sha2::Digest; let h = sha2::Sha256::digest(&vec::MSG); u32::from_le_bytes([h[0], h[1], h[2], h[3]]) }
fn w_sig() -> u32 {
    use ed25519_dalek::{Signature, VerifyingKey};
    let vk = VerifyingKey::from_bytes(&vec::PK).unwrap();
    let sig = Signature::from_bytes(&vec::SIG);
    if vk.verify_strict(&vec::MSG, &sig).is_ok() { 1 } else { 0 }
}
// order-book-like work: n limit orders into a BTreeMap price ladder, then a taker sweeps; i128 notional math
fn w_book(n: u32) -> u32 {
    let mut bids: BTreeMap<(i64, u64), (u64, i128)> = BTreeMap::new();
    let mut x: u64 = 0x9E3779B97F4A7C15;
    for i in 0..n as u64 { x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        let px = 60_000_000_000i64 + (x % 1_000_000) as i64; let qty = 1 + (x >> 40) % 1000;
        bids.insert((-px, i), (qty, px as i128 * qty as i128)); }
    let mut want: u64 = 50_000; let mut cash: i128 = 0; let mut keys = Vec::new();
    for (k, v) in bids.iter() { if want == 0 { break; } let f = v.0.min(want); want -= f; cash += (-k.0) as i128 * f as i128 / 1_000_000; keys.push(*k); }
    for k in keys { bids.remove(&k); }
    (cash as u32) ^ (bids.len() as u32)
}
#[no_mangle] extern "C" fn rmain() -> u32 {
    let mode = read_word(0); let arg = read_word(1);
    match mode { 0 => w_sha(), 1 => w_sig(), 2 => w_book(arg), _ => 0xdead }
}
