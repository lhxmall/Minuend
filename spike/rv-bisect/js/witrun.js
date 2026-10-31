// Run the mnpilot riscv32im guest (bin rvengine; default build = MNWIT1 incremental witness) on a
// batch in the JS reference model and return the pilotrun.js JSON plus the witness outputs:
// per-unit roots (hex), the step count at the end of every unit (the guest writes the unit counter
// OUT[0x1FFFF] after each unit's commit), scratch_ok, leaves, leaf/node hash counts.
// usage: node witrun.js <elf> <batch.bin> [maxSteps]
const ref = require('./ref.js'); const fs = require('fs'); const { FastMem, load } = require('./elfrun.js');
const OUT = 0x03F00000 / 4; const ROOTS = OUT + 0x20000; const CNT = ROOTS - 1;
const hexw = (ws) => ws.map(v => [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, v >>> 24].map(x => x.toString(16).padStart(2, '0')).join('')).join('');
function run(elf, batchPath, maxSteps = 2e10) {
  const b = fs.readFileSync(batchPath); const inp = new FastMem();
  for (let i = 0; i < b.length / 4; i++) inp.set(i, b.readUInt32LE(4 * i));
  const st = { pc: 0, regs: Array(32).fill(0), step: 0, inp }; const unitEnd = [];
  class M extends FastMem { set(i, v) { if (i === CNT) unitEnd[(v >>> 0) - 1] = st.step + 1; super.set(i, v); } }
  const mem = new M(); st.pc = load(elf, mem); const t0 = Date.now();
  while (st.pc !== ref.HALT && st.pc !== ref.TRAP && st.step < maxSteps) ref.step(st, mem);
  const g = (k) => mem.get(OUT + k) >>> 0;
  const hash = hexw(Array.from({ length: 8 }, (_, k) => g(k)));
  const nev = g(8); const ev = []; for (let k = 0; k < nev; k++) ev.push(g(13 + k));
  const units = mem.get(CNT) >>> 0; const roots = [];
  for (let u = 0; u < units; u++) roots.push(hexw(Array.from({ length: 8 }, (_, k) => mem.get(ROOTS + 8 * u + k) >>> 0)));
  return { hash, applied: g(9), rejected: g(10), fills: g(11), ev, steps: st.step, halted: st.pc === ref.HALT, a0: st.regs[10] >>> 0,
    heap: g(12), units, unitEnd, roots, scratch_ok: mem.get(CNT - 1) >>> 0, leaves: mem.get(CNT - 2) >>> 0,
    leaf_updates: mem.get(CNT - 3) >>> 0, node_hashes: mem.get(CNT - 4) >>> 0, ms: Date.now() - t0 };
}
module.exports = { run };
if (require.main === module) {
  const r = run(process.argv[2], process.argv[3], process.argv[4] ? Number(process.argv[4]) : undefined);
  delete r.unitEnd; console.log(JSON.stringify(r));
}
