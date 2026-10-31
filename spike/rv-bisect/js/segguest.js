// Loop round 3: run the segments of one upstream batch through the riscv32im guest (JS model) as
// consecutive rollup heights -- ONE memory image carried from run to run (pc 0, registers 0, a new
// input each time), as rv_rollup chains s0(h) on the final memory of h-1 -- and compare every
// segment with the host's expectation (engine-diff segrun <batch> <S> <dir> -> dir/manifest.json):
// status, state hash, start / end MNWIT1 roots (OUT[0x1FFF0..8] / OUT[0x1FFE8..8]), the session's
// segment counter OUT[0x1FFE7], every per-unit root and the event log.
// usage: node segguest.js <elf> <dir> [extra.bin ...]   (extra: run these after the manifest's segments,
//        e.g. a malformed batch, and just print the outputs)
// TRAP=k:n (loop round 3 review R3-G1/G2 PoC): segment k is stopped after n steps as if it had trapped (pc = TRAP,
//        memory as it is at that step -- what the rollup carries into the next height); the remaining segments then
//        run on that memory and the trapped segment's OUT words (status, segment roots) are printed.
const ref = require('./ref.js'); const fs = require('fs'); const path = require('path'); const { FastMem, load } = require('./elfrun.js');
const OUT = 0x03F00000 / 4; const ROOTS = OUT + 0x20000; const CNT = ROOTS - 1;
const hexw = (ws) => ws.map(v => [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, v >>> 24].map(x => x.toString(16).padStart(2, '0')).join('')).join('');
const [ELF, DIR, ...EXTRA] = process.argv.slice(2);
const man = JSON.parse(fs.readFileSync(path.join(DIR, 'manifest.json'), 'utf8'));
const mem = new FastMem(); const entry = load(ELF, mem);
function runOne(file, maxSteps = 2e10) {
  const b = fs.readFileSync(file); const inp = new FastMem();
  for (let i = 0; i < b.length / 4; i++) inp.set(i, b.readUInt32LE(4 * i));
  const st = { pc: entry, regs: Array(32).fill(0), step: 0, inp };
  const t0 = Date.now();
  while (st.pc !== ref.HALT && st.pc !== ref.TRAP && st.step < maxSteps) ref.step(st, mem);
  if (st.pc !== ref.HALT && st.pc !== ref.TRAP) st.pc = ref.TRAP; // TRAP=k:n -- forced trap
  const g = (k) => mem.get(OUT + k) >>> 0; const r8 = (k) => hexw(Array.from({ length: 8 }, (_, j) => g(k + j)));
  const units = mem.get(CNT) >>> 0; const roots = [];
  for (let u = 0; u < units; u++) roots.push(hexw(Array.from({ length: 8 }, (_, k) => mem.get(ROOTS + 8 * u + k) >>> 0)));
  const nev = g(8); const ev = []; for (let k = 0; k < nev; k++) ev.push(g(13 + k));
  return { halted: st.pc === ref.HALT, a0: st.regs[10] >>> 0, steps: st.step, status: g(0x1FFF9), hash: r8(0), start_root: r8(0x1FFF0), end_root: r8(0x1FFE8),
    segs: g(0x1FFE7), applied: g(9), rejected: g(10), fills: g(11), roots, ev, heap: g(12), heap_peak_live: g(0x1FFFA), ms: Date.now() - t0 };
}
let ok = 0; let steps = 0; const [TK, TN] = (process.env.TRAP || '-1:0').split(':').map(Number);
for (const [k, m] of man.entries()) {
  if (k === TK) { const r = runOne(path.join(DIR, m.file), TN); delete r.roots; delete r.ev;
    console.log(JSON.stringify({ seg: m.file, forced_trap_after: TN, status: r.status, status_hex: r.status.toString(16), start_root: r.start_root, end_root: r.end_root, prev_end_root: k ? man[k - 1].end_root : null }));
    continue; }
  const r = runOne(path.join(DIR, m.file));
  const zero = '0'.repeat(64);
  const same = r.halted && r.a0 !== 77 && r.status === m.status && r.hash === m.hash && r.segs === m.segs &&
    r.start_root === (m.status === 0 ? m.start_root : zero) && r.end_root === (m.status === 0 ? m.end_root : zero) &&
    JSON.stringify(r.roots) === JSON.stringify(m.roots) && JSON.stringify(r.ev) === JSON.stringify(m.ev) && r.applied === m.applied;
  if (same) ok++; steps += r.steps;
  if (TK >= 0 && k > TK) { console.log(JSON.stringify({ seg: m.file, after_trap: true, status: r.status, halted: r.halted, a0: r.a0, units: r.roots.length, steps: r.steps })); continue; }
  console.log(JSON.stringify({ seg: m.file, match: same, status: r.status, segs: r.segs, units: r.roots.length, steps: r.steps, heap: r.heap, heap_peak_live: r.heap_peak_live, ms: r.ms }));
}
for (const f of EXTRA) { const r = runOne(f); delete r.roots; delete r.ev; console.log(JSON.stringify({ extra: f, ...r })); }
console.log(JSON.stringify({ dir: DIR, segments: man.length, match: ok, steps }));
