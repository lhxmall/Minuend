// Loop round 15: guest-level MNWIT-S migration + height hook (stateless image, riscv32im, JS reference model).
// usage: node slmig.js <stateless elf built with MNPILOT_IMPORT_DIGEST=$(cat dir/digest.txt)> <dir from slmigdump> [neg]
// One memory image carried from run to run (as rv_rollup does): run 1 = the migration (input [SL_MIG_MAGIC, snapshot
// words]) -> status 0, SEG_START = SEG_END = the host MNWIT-S root, SNAP_KIND 3; then every stateless segment chained
// on it (the image's SL_ROOT; in a prod image SL_RUNS gives heights segs + 1, ...) -> status 0, events and roots equal
// to the session reference. `neg`: a second migration on the live lineage is refused (ST_SESSION_LIVE 8), and a
// migration with one tampered snapshot word on a fresh image is refused (ST_BAD_SNAP 7).
const ref = require('./ref.js'); const fs = require('fs'); const path = require('path'); const { FastMem, load } = require('./elfrun.js');
const OUT = 0x03F00000 / 4;
const hexw = (ws) => ws.map(v => [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, v >>> 24].map(x => x.toString(16).padStart(2, '0')).join('')).join('');
const [ELF, DIR, NEG] = process.argv.slice(2);
const man = JSON.parse(fs.readFileSync(path.join(DIR, 'manifest.json'), 'utf8'));
function runOn(mem, entry, words, maxSteps = 4e10) {
  const inp = new FastMem(); words.forEach((w, i) => inp.set(i, w >>> 0));
  const st = { pc: entry, regs: Array(32).fill(0), step: 0, inp };
  while (st.pc !== ref.HALT && st.pc !== ref.TRAP && st.step < maxSteps) ref.step(st, mem);
  const g = (k) => mem.get(OUT + k) >>> 0; const r8 = (k) => hexw(Array.from({ length: 8 }, (_, j) => g(k + j)));
  const nev = g(8); const ev = []; for (let k = 0; k < nev; k++) ev.push(g(13 + k));
  return { halted: st.pc === ref.HALT, steps: st.step, status: g(0x1FFF9), start_root: r8(0x1FFF0), end_root: r8(0x1FFE8), ev };
}
const words = (f) => { const b = fs.readFileSync(path.join(DIR, f)); return Array.from({ length: b.length / 4 }, (_, i) => b.readUInt32LE(4 * i)); };
const mem = new FastMem(); const entry = load(ELF, mem);
const res = []; let ok = 0;
const mw = words(man.migration.mig);
const m = runOn(mem, entry, mw);
const mOk = m.halted && m.status === 0 && m.start_root === man.migration.root && m.end_root === man.migration.root;
res.push({ run: 'migration', ok: mOk, status: m.status, steps: m.steps, root_ok: m.end_root === man.migration.root, words: man.migration.words });
for (const s of man.segments) {
  const r = runOn(mem, entry, words(s.sl));
  const good = r.halted && r.status === 0 && JSON.stringify(r.ev) === JSON.stringify(s.ev) && r.start_root === s.s_start && r.end_root === s.s_end;
  if (good) ok++;
  res.push({ run: s.sl, height: s.height, units: s.units, ok: good, status: r.status, steps: r.steps, ...(good ? {} : { roots: [r.start_root === s.s_start, r.end_root === s.s_end] }) });
}
let negOk = true;
if (NEG) {
  const again = runOn(mem, entry, mw);
  const fresh = new FastMem(); const e2 = load(ELF, fresh);
  const t = mw.slice(); t[1 + Math.floor(mw.length / 2)] ^= 1;
  const bad = runOn(fresh, e2, t);
  negOk = again.status === 8 && bad.status === 7;
  res.push({ run: 'neg', ok: negOk, second_migration_status: again.status, tampered_status: bad.status });
}
for (const r of res) console.log(JSON.stringify(r));
console.log(JSON.stringify({ dir: DIR, migration_ok: mOk, segments: man.segments.length, ok, neg_ok: negOk, all_ok: mOk && negOk && ok === man.segments.length }));
