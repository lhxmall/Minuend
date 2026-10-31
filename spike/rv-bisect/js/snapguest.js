// Loop round 4 (R3-H2): session export / import through the riscv32im guest (JS model).
// Input: a dir from `engine-diff snapdir <batch> <S> <k> <dir>` (seg000.., export.bin, snap.bin, manifest.json
// = expectations of the UNINTERRUPTED session on the host). Three images:
//   A  one memory image runs every manifest entry in order (segments, the export run, the rest): every
//      output must equal the manifest (the export run publishes digest / words / root at OUT[0x1FFD6..]).
//   B  upgrade: a FRESH upgrade image (IMPORT_ELF, built with MNPILOT_IMPORT_DIGEST = the export digest)
//      imports snap.bin as its first run, then runs the segments after the export: the import must publish
//      the export's digest, words and root (start = end root), and every later segment must equal the manifest.
//   G  (review R4-S1) an ordinary fresh image -- the genesis image -- refuses the import (ST_IMPORT_LOCKED 10).
//   C  a dead upgrade image (imported, then a trap forced after TRAPN steps) refuses the import (ST_DEAD 5):
//      no in-place revive.
//   D  truncated snapshot -> ST_BAD_SNAP 7 (and the image stays importable);  F  another valid snapshot -> 7.
//   E  (review R4-S2) a batch run on an upgrade image before its import -> ST_NEED_IMPORT 11, no session is
//      started (no genesis wipe); the import afterwards still succeeds and the batch then matches the manifest.
//   Also: an import over the live session of A is refused (ST_SESSION_LIVE = 8, nothing changes).
// usage: node snapguest.js <elf> <dir> [trap_steps]   PROD=1: the image is the prod build (zero state hash)
const ref = require('./ref.js'); const fs = require('fs'); const path = require('path'); const { FastMem, load } = require('./elfrun.js');
const OUT = 0x03F00000 / 4; const ROOTS = OUT + 0x20000; const CNT = ROOTS - 1;
const hexw = (ws) => ws.map(v => [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, v >>> 24].map(x => x.toString(16).padStart(2, '0')).join('')).join('');
const [ELF, DIR, TRAPN] = process.argv.slice(2); const trapN = TRAPN ? Number(TRAPN) : 2000000;
const man = JSON.parse(fs.readFileSync(path.join(DIR, 'manifest.json'), 'utf8'));
const zero = '0'.repeat(64);
const IMPORT_ELF = process.env.IMPORT_ELF || ELF;
function image(elf = ELF) { const mem = new FastMem(); const entry = load(elf, mem); return { mem, entry }; }
function runOne(img, words, maxSteps = 2e10) {
  const { mem, entry } = img; const inp = new FastMem();
  for (let i = 0; i < words.length; i++) inp.set(i, words[i]);
  const st = { pc: entry, regs: Array(32).fill(0), step: 0, inp };
  const t0 = Date.now();
  while (st.pc !== ref.HALT && st.pc !== ref.TRAP && st.step < maxSteps) ref.step(st, mem);
  const forced = st.pc !== ref.HALT && st.pc !== ref.TRAP; if (forced) st.pc = ref.TRAP;
  const g = (k) => mem.get(OUT + k) >>> 0; const r8 = (k) => hexw(Array.from({ length: 8 }, (_, j) => g(k + j)));
  const units = mem.get(CNT) >>> 0; const roots = [];
  for (let u = 0; u < units; u++) roots.push(hexw(Array.from({ length: 8 }, (_, k) => mem.get(ROOTS + 8 * u + k) >>> 0)));
  const nev = g(8); const ev = []; for (let k = 0; k < nev; k++) ev.push(g(13 + k));
  return { halted: st.pc === ref.HALT, forced, a0: st.regs[10] >>> 0, steps: st.step, status: g(0x1FFF9), hash: r8(0), start_root: r8(0x1FFF0),
    end_root: r8(0x1FFE8), segs: g(0x1FFE7), applied: g(9), roots, ev, snap_kind: g(0x1FFD6), snap_words: g(0x1FFD7), snap_digest: r8(0x1FFD8),
    heap: g(12), heap_peak_live: g(0x1FFFA), ms: Date.now() - t0 };
}
const words = (f) => { const b = fs.readFileSync(path.join(DIR, f)); const w = []; for (let i = 0; i < b.length / 4; i++) w.push(b.readUInt32LE(4 * i)); return w; };
function segOk(r, m) {
  const hashOk = process.env.PROD ? r.hash === zero : r.hash === m.hash;
  return r.halted && r.a0 !== 77 && r.status === m.status && hashOk && r.segs === m.segs && r.start_root === m.start_root &&
    r.end_root === m.end_root && JSON.stringify(r.roots) === JSON.stringify(m.roots) && JSON.stringify(r.ev) === JSON.stringify(m.ev) &&
    r.applied === m.applied && r.snap_kind === 0 && r.snap_digest === zero;
}
const ei = man.findIndex(m => m.kind === 'export'); const ex = man[ei];
const checks = {}; const note = (k, v) => { checks[k] = v; console.log(JSON.stringify({ check: k, ok: v })); };
let steps = 0;
// A: uninterrupted, with the export run in between
{ const A = image(); let ok = true;
  for (const m of man) {
    const r = runOne(A, words(m.file)); steps += r.steps;
    if (m.kind === 'export') ok = ok && r.halted && r.status === 0 && r.snap_kind === 1 && r.snap_digest === m.digest && r.snap_words === m.words &&
      r.start_root === m.root && r.end_root === m.root && r.segs === m.segs;
    else ok = ok && segOk(r, m);
    console.log(JSON.stringify({ image: 'A', file: m.file, ok, status: r.status, steps: r.steps, heap: r.heap, ms: r.ms }));
  }
  note('A_uninterrupted_with_export', ok);
  const r = runOne(A, words('snap.bin')); note('A_import_over_live_refused', r.halted && r.status === 8 && r.snap_kind === 0);
  // A must still run normally after the refused import: rerun-free check -- export again equals a fresh export count+1
  const r2 = runOne(A, words('export.bin')); note('A_session_intact_after_refused_import', r2.status === 0 && r2.snap_kind === 1 && r2.end_root === man[man.length - 1].end_root);
}
// B: upgrade -- a fresh UPGRADE image (built with MNPILOT_IMPORT_DIGEST = the export digest, env IMPORT_ELF)
//    imports the snapshot as its first run, then continues
{ const B = image(IMPORT_ELF); let ok = true;
  const im = runOne(B, words('snap.bin')); steps += im.steps;
  ok = im.halted && im.status === 0 && im.snap_kind === 2 && im.snap_digest === ex.digest && im.snap_words === ex.words && im.start_root === ex.root &&
    im.end_root === ex.root && im.segs === ex.segs;
  console.log(JSON.stringify({ image: 'B', file: 'snap.bin', ok, status: im.status, steps: im.steps, heap: im.heap, ms: im.ms }));
  for (const m of man.slice(ei + 1)) { const r = runOne(B, words(m.file)); steps += r.steps; ok = ok && segOk(r, m);
    console.log(JSON.stringify({ image: 'B', file: m.file, ok, status: r.status, steps: r.steps, heap: r.heap, ms: r.ms })); }
  note('B_upgrade_import_then_continue', ok);
}
// R4-S1 (import lock): an ordinary fresh image (the genesis image of height 1) refuses the import
{ const G = image(); const r = runOne(G, words('snap.bin')); const e = runOne(G, words('export.bin'));
  note('G_genesis_image_import_locked', r.halted && r.status === 10 && e.status === 6); }
// C: a dead image stays dead: an import does not revive it (recovery = a NEW upgrade image)
{ const C = image(IMPORT_ELF); let ok = true;
  const im0 = runOne(C, words('snap.bin')); ok = im0.status === 0;
  const nxt = man[ei + 1];
  if (nxt) {
    const t = runOne(C, words(nxt.file), trapN);
    const d = runOne(C, words(nxt.file));
    const im = runOne(C, words('snap.bin'));
    ok = ok && t.forced && d.halted && d.status === 5 && im.halted && im.status === 5;
    console.log(JSON.stringify({ image: 'C', trapped_after: trapN, dead_status: d.status, import_status: im.status }));
  }
  // and an ordinary (genesis) image that died likewise stays dead
  { const C2 = image(); let ok2 = true;
    for (const m of man.slice(0, ei - 1)) { const r = runOne(C2, words(m.file)); ok2 = ok2 && segOk(r, m); }
    const t = runOne(C2, words(man[ei - 1].file), 20000); const d = runOne(C2, words(man[ei - 1].file));
    ok = ok && ok2 && t.forced && d.status === 5; }
  note('C_dead_image_import_refused', ok);
}
// D: the upgrade image refuses a truncated snapshot and stays without a session
{ const D = image(IMPORT_ELF); const w = words('snap.bin'); const cut = w.slice(0, Math.floor(w.length / 2));
  const r = runOne(D, cut); const e = runOne(D, words('export.bin')); const g = runOne(D, words('snap.bin'));
  note('D_truncated_import_refused', r.halted && r.status === 7 && e.status === 6 && g.status === 0 && g.snap_digest === ex.digest); }
// E (R4-S2): an upgrade image runs no batch before its import (else: a fresh genesis session = state wiped)
{ const E = image(IMPORT_ELF); const nxt = man[ei + 1] || man[0];
  const b = runOne(E, words(nxt.file)); const x = runOne(E, words('export.bin'));
  const im = runOne(E, words('snap.bin')); let ok = b.halted && b.status === 11 && b.segs === 0 && b.ev.length === 0 && b.roots.length === 0 &&
    b.end_root === zero && x.status === 6 && im.status === 0 && im.snap_digest === ex.digest;
  if (man[ei + 1]) { const r = runOne(E, words(nxt.file)); ok = ok && segOk(r, nxt); }
  note('E_batch_before_import_refused', ok); }
// F: the upgrade image refuses another well-formed snapshot (OTHER_SNAP, e.g. a later export)
if (process.env.OTHER_SNAP) { const F = image(IMPORT_ELF); const b = fs.readFileSync(process.env.OTHER_SNAP); const w = [];
  for (let i = 0; i < b.length / 4; i++) w.push(b.readUInt32LE(4 * i));
  const r = runOne(F, w); note('F_other_snapshot_refused', r.halted && r.status === 7); }
const all = Object.values(checks).every(Boolean);
console.log(JSON.stringify({ dir: DIR, checks: Object.keys(checks).length, pass: Object.values(checks).filter(Boolean).length, ok: all, steps }));
