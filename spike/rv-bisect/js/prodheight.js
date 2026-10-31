// Loop round 4 (R4-H2): the batch-commit hook SetHeight (kind 10) in the PROD guest only advances the engine height by
// exactly one and only as a segment's first unit; a test image accepts any height >= current (fixtures).
// usage: node prodheight.js <prod elf> <test elf>   -> one JSON line per check + summary
const ref = require('./ref.js'); const { FastMem, load } = require('./elfrun.js');
const OUT = 0x03F00000 / 4; const MAGIC = 0x4D4E5031; // mnpilot::MAGIC "MNP1"
const [PROD, TEST] = process.argv.slice(2);
function image(elf) { const mem = new FastMem(); const entry = load(elf, mem); return { mem, entry }; }
function runOne(img, words) { const { mem, entry } = img; const inp = new FastMem(); words.forEach((w, i) => inp.set(i, w >>> 0));
  const st = { pc: entry, regs: Array(32).fill(0), step: 0, inp }; while (st.pc !== ref.HALT && st.pc !== ref.TRAP) ref.step(st, mem);
  const g = k => mem.get(OUT + k) >>> 0; const ev = []; for (let k = 0; k < g(8); k++) ev.push(g(13 + k));
  return { halted: st.pc === ref.HALT, status: g(0x1FFF9), ev }; }
const H = (h) => [10, h, 0, 0, 0, 0, 0, 0];
const batch = (ops) => [MAGIC, 1, ops.length, 0, 11, 22, 33, 44, 55, 66, 77, 88, ...ops.flat()];
const EVH = 0x40000000; const checks = []; const chk = (name, r, ev) => { const ok = r.halted && r.status === 0 && JSON.stringify(r.ev) === JSON.stringify(ev);
  checks.push(ok); console.log(JSON.stringify({ check: name, ok, status: r.status, ev: r.ev })); };
{ const P = image(PROD);
  chk('prod: SetHeight 1 as unit 0 ok; a second SetHeight (unit 1) refused', runOne(P, batch([H(1), H(2)])), [EVH, 2]);
  chk('prod: jump 1 -> 3 refused; +1 as unit 1 refused', runOne(P, batch([H(3), H(2)])), [2, 2]);
  chk('prod: 1 -> 2 as unit 0 ok', runOne(P, batch([H(2)])), [EVH]);
  chk('prod: same height again refused', runOne(P, batch([H(2)])), [2]);
  chk('prod: going back refused', runOne(P, batch([H(1)])), [2]); }
{ const T = image(TEST);
  chk('test image: jumps allowed (fixtures), going back refused', runOne(T, batch([H(5), H(9), H(9), H(3)])), [EVH, EVH, EVH, 2]); }
console.log(JSON.stringify({ checks: checks.length, pass: checks.filter(Boolean).length, ok: checks.every(Boolean) }));
