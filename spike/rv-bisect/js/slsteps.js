// Loop round 14 (R4-H1 production direction): riscv32im steps per segment, SESSION guest vs STATELESS guest.
// usage: node slsteps.js <session elf> <stateless elf> <dir>   (dir from `engine-diff sldump <seed> <ord> <S> <dir>`)
// Session: the segments run as consecutive heights on ONE memory image (as rv_rollup carries it); stateless: every
// segment on a FRESH image with its witness (no carried memory). Checks: both status 0, events == manifest, the
// stateless start / end roots == the MNWIT-S roots the host computed from the session state.
const ref = require('./ref.js'); const fs = require('fs'); const path = require('path'); const { FastMem, load } = require('./elfrun.js');
const OUT = 0x03F00000 / 4; const ROOTS = OUT + 0x20000;
const hexw = (ws) => ws.map(v => [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, v >>> 24].map(x => x.toString(16).padStart(2, '0')).join('')).join('');
const [ELF_S, ELF_L, DIR] = process.argv.slice(2);
const man = JSON.parse(fs.readFileSync(path.join(DIR, 'manifest.json'), 'utf8'));
function runOn(mem, entry, file, maxSteps = 4e10) {
  const b = fs.readFileSync(file); const inp = new FastMem();
  for (let i = 0; i < b.length / 4; i++) inp.set(i, b.readUInt32LE(4 * i));
  const st = { pc: entry, regs: Array(32).fill(0), step: 0, inp };
  while (st.pc !== ref.HALT && st.pc !== ref.TRAP && st.step < maxSteps) ref.step(st, mem);
  const g = (k) => mem.get(OUT + k) >>> 0; const r8 = (k) => hexw(Array.from({ length: 8 }, (_, j) => g(k + j)));
  const nev = g(8); const ev = []; for (let k = 0; k < nev; k++) ev.push(g(13 + k));
  return { halted: st.pc === ref.HALT, steps: st.step, status: g(0x1FFF9), start_root: r8(0x1FFF0), end_root: r8(0x1FFE8), ev,
    heap: g(12), peak: g(0x1FFFA), verified: g(0x1FFFD), leaf_hashes: g(0x1FFFC), node_hashes: g(0x1FFFB) };
}
const memS = new FastMem(); const entryS = load(ELF_S, memS);
let ok = 0, tS = 0, tL = 0, units = 0; const rows = [];
for (const m of man) {
  const s = runOn(memS, entryS, path.join(DIR, m.seg));
  const memL = new FastMem(); const entryL = load(ELF_L, memL);
  const l = runOn(memL, entryL, path.join(DIR, m.sl));
  const evOk = JSON.stringify(s.ev) === JSON.stringify(m.ev) && JSON.stringify(l.ev) === JSON.stringify(m.ev);
  const good = s.halted && l.halted && s.status === 0 && l.status === 0 && evOk && l.start_root === m.s_start && l.end_root === m.s_end;
  if (good) ok++;
  tS += s.steps; tL += l.steps; units += m.units;
  rows.push({ seg: m.seg, units: m.units, session_steps: s.steps, stateless_steps: l.steps, ratio: +(l.steps / s.steps).toFixed(3),
    witness_bytes: m.witness_bytes, leaves_verified: l.verified, node_hashes: l.node_hashes, sl_peak_heap: l.peak, session_heap: s.heap, ok: good,
    ...(good ? {} : { s_status: s.status, l_status: l.status, evOk, roots: [l.start_root === m.s_start, l.end_root === m.s_end] }) });
}
for (const r of rows) console.log(JSON.stringify(r));
console.log(JSON.stringify({ dir: DIR, segments: man.length, ok, units, session_steps: tS, stateless_steps: tL, ratio: +(tL / tS).toFixed(3),
  session_steps_per_unit: Math.round(tS / units), stateless_steps_per_unit: Math.round(tL / units) }));
