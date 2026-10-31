// Run the mnpilot riscv32im guest (guest-engine, bin rvengine) on a batch file in the JS
// reference model (fast mode, no Merkle) and print the same JSON as `engine-diff real|port`,
// plus the executed step count.  usage: node pilotrun.js <elf> <batch.bin> [maxSteps]
const ref = require('./ref.js'); const fs = require('fs'); const { FastMem, load } = require('./elfrun.js');
const OUT = 0x03F00000 / 4;
function run(elf, batchPath, maxSteps = 4e9) {
  const b = fs.readFileSync(batchPath); const inp = new FastMem();
  for (let i = 0; i < b.length / 4; i++) inp.set(i, b.readUInt32LE(4 * i));
  const mem = new FastMem(); const entry = load(elf, mem);
  const st = { pc: entry, regs: Array(32).fill(0), step: 0, inp }; const t0 = Date.now();
  while (st.pc !== ref.HALT && st.pc !== ref.TRAP && st.step < maxSteps) ref.step(st, mem);
  const g = (k) => mem.get(OUT + k) >>> 0;
  const hash = Array.from({ length: 8 }, (_, k) => { const v = g(k); return [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, v >>> 24].map(x => x.toString(16).padStart(2, '0')).join(''); }).join('');
  const nev = g(8); const ev = []; for (let k = 0; k < nev; k++) ev.push(g(13 + k));
  return { hash, applied: g(9), rejected: g(10), fills: g(11), ev, steps: st.step, halted: st.pc === ref.HALT, a0: st.regs[10] >>> 0,
           heap: g(12), words: mem.w.size, ms: Date.now() - t0 };
}
module.exports = { run };
if (require.main === module) {
  const r = run(process.argv[2], process.argv[3], process.argv[4] ? Number(process.argv[4]) : undefined);
  console.log(JSON.stringify(r));
}
