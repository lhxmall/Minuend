// Loop round 5 (R4-M4, replaces the round-4 R4-H2 checks): the PROD guest binds the engine height to the rollup height.
// Every run of an image lineage is one rollup height (the rollup carries the final memory of h-1 into s0 of h); the guest
// counts its runs (RUNS) and every batch run first runs the batch-commit hook with height = run number, so the operator no
// longer decides the engine clock: SetHeight (kind 10) is refused in prod, export / import heights are skipped by the next
// batch's hook. OUT[0x1FFE6] = engine height, OUT[0x1FFE7] = segs (= run number). Also R4-M2: in prod an MNP1 Liquidate is
// refused (BadAccount 2: no unit id), the MNP2 one runs (here: target without an account -> NotFound 10).
// A test image (no binding) keeps SetHeight jumps (fixtures).
// usage: node prodheight.js <prod elf> <test elf>   -> one JSON line per check + summary
const ref = require('./ref.js'); const { FastMem, load } = require('./elfrun.js');
const OUT = 0x03F00000 / 4; const MAGIC = 0x4D4E5031, MAGIC2 = 0x4D4E5032, EXPORT = 0x4D4E5845;
const [PROD, TEST] = process.argv.slice(2);
function image(elf) { const mem = new FastMem(); const entry = load(elf, mem); return { mem, entry }; }
function runOne(img, words) { const { mem, entry } = img; const inp = new FastMem(); words.forEach((w, i) => inp.set(i, w >>> 0));
  const st = { pc: entry, regs: Array(32).fill(0), step: 0, inp }; while (st.pc !== ref.HALT && st.pc !== ref.TRAP) ref.step(st, mem);
  const g = k => mem.get(OUT + k) >>> 0; const ev = []; for (let k = 0; k < g(8); k++) ev.push(g(13 + k));
  return { halted: st.pc === ref.HALT, status: g(0x1FFF9), ev, height: g(0x1FFE6), segs: g(0x1FFE7) }; }
const H = (h) => [10, h, 0, 0, 0, 0, 0, 0];
const ACCTS = [11, 22, 33, 44, 55, 66, 77, 88, 12, 23, 34, 45, 56, 67, 78, 89];
const batch = (ops) => [MAGIC, 2, ops.length, 0, ...ACCTS, ...ops.flat()];
const batch2 = (ops, uids) => [MAGIC2, 2, ops.length, 0, ...ACCTS, ...ops.flat(), ...uids.flat()];
const LIQ = [7 | (0 << 8), 1, 0, 0, 0, 0, 0, 1];   // account 0 liquidates account 1 in BTC_USD
const EVH = 0x40000000; const checks = [];
const chk = (name, r, want) => { const ok = r.halted && Object.keys(want).every(k => JSON.stringify(r[k]) === JSON.stringify(want[k]));
  checks.push(ok); console.log(JSON.stringify({ check: name, ok, status: r.status, ev: r.ev, height: r.height, segs: r.segs })); };
{ const P = image(PROD);
  chk('prod run 1 (height 1): empty batch -> engine height 1', runOne(P, batch([])), { status: 0, ev: [], height: 1, segs: 1 });
  chk('prod run 2: SetHeight 5 refused, engine height = 2', runOne(P, batch([H(5)])), { status: 0, ev: [2], height: 2, segs: 2 });
  chk('prod run 3: SetHeight 4 (= +1) refused too, height 3', runOne(P, batch([H(4), H(4)])), { status: 0, ev: [2, 2], height: 3, segs: 3 });
  chk('prod run 4: export (height unchanged, segs 4)', runOne(P, [EXPORT, 0, 0, 0]), { status: 0, height: 3, segs: 4 });
  chk('prod run 5: next batch jumps over the export height -> 5', runOne(P, batch([])), { status: 0, ev: [], height: 5, segs: 5 });
  chk('prod run 6: refused header (bad magic) still counts as a height', runOne(P, [0x1234, 0, 0, 0]), { status: 1, segs: 6 });
  chk('prod run 7: -> height 7', runOne(P, batch([])), { status: 0, height: 7, segs: 7 });
  chk('prod: MNP1 Liquidate refused (no unit id) -> 2', runOne(P, batch([LIQ])), { status: 0, ev: [2], height: 8 });
  chk('prod: MNP2 Liquidate runs past the gate (target has no account -> NotFound 10)', runOne(P, batch2([LIQ], [[1, 2, 3, 4, 5, 6, 7, 8]])), { status: 0, ev: [10], height: 9 }); }
{ const P = image(PROD);
  chk('prod fresh image: refused header at height 1, genesis at height 2 -> height 2', (runOne(P, [0x1234, 0, 0, 0]), runOne(P, batch([]))), { status: 0, height: 2, segs: 2 }); }
{ const T = image(TEST);
  chk('test image: SetHeight jumps allowed (fixtures), going back refused', runOne(T, batch([H(5), H(9), H(9), H(3)])), { status: 0, ev: [EVH, EVH, EVH, 2], height: 9, segs: 1 });
  chk('test image: no binding (height stays 9 in run 2)', runOne(T, batch([])), { status: 0, ev: [], height: 9, segs: 2 }); }
console.log(JSON.stringify({ checks: checks.length, pass: checks.filter(Boolean).length, ok: checks.every(Boolean) }));
