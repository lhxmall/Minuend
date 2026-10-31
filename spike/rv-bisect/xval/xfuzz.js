// Random single-step differential fuzz: JS reference model vs sail-riscv vs rv_step (real ocore evaluator).
// Each case = one tiny ELF: a 62-instruction preamble (lui+addi per register) that loads a random/edge register file,
// then the fuzzed instruction at a random pc, then a second random instruction at pc+4, plus planted data words
// around the load/store effective address. The ELF runs on sail (trace) and on the JS model; every executed step
// (preamble included) is compared on pc/regs/memory; the 2 fuzzed steps are also checked by rv_step on ocore.
// usage: N=10000 SEED=1 [SHARD=0 SHARDS=1] [RVSTEP=0] node xfuzz.js  -> JSON lines for failures + a summary line
'use strict';
const fs = require('fs'), path = require('path');
const ref = require(process.env.XREF || '../js/ref.js'); const L = require('./lib.js');   // XREF: mutant model (harness self-test)
const N = +(process.env.N || 1000), SHARD = +(process.env.SHARD || 0), SHARDS = +(process.env.SHARDS || 1);
const RVSTEP = process.env.RVSTEP !== '0';
const TMP = process.env.XTMP || path.join(__dirname, 'tmp'); fs.mkdirSync(TMP, { recursive: true });
let seed = (+(process.env.SEED || 1) * 7919 + SHARD * 104729) >>> 0;
const rnd = () => { seed ^= seed << 13; seed >>>= 0; seed ^= seed >>> 17; seed ^= seed << 5; seed >>>= 0; return seed / 4294967296; };
const ri = n => Math.floor(rnd() * n), pick = a => a[ri(a.length)], chance = p => rnd() < p;
const MEMB = 2 ** 26;                                   // rv_step memory = 2^24 words = 64 MiB
const EDGE = [0, 1, 2, 3, 4, 0x7fffffff, 0x80000000, 0xffffffff, 0xfffffffe, 31, 32, 33, 63, 64, 0xffffffe0, 0x8000, 0x7fff,
  0xffff, 0x10000, 0x80, 0x7f, 0xff, 0xfffff800, 0x800, 0x7ff, 0x80000001, 0xaaaaaaaa, 0x55555555];
const DATA = [0, 0xffffffff, 0x80808080, 0x7f7f7f7f, 0x00ff00ff, 0xff00ff00, 0x80000000, 0x7fffffff, 0x8000, 0x80, 0x12345678, 0xdeadbeef];
const r32 = () => chance(0.55) ? pick(EDGE) : ri(2 ** 32);
const reg = () => ri(32);
const sx = (v, b) => v >= 2 ** (b - 1) ? v - 2 ** b : v;
// encoders
const R = (op, rd, f3, rs1, rs2, f7) => ((f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op) >>> 0;
const I = (op, rd, f3, rs1, imm) => (((imm & 0xfff) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op) >>> 0;
const S = (f3, rs1, rs2, imm) => ((((imm >> 5) & 127) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | ((imm & 31) << 7) | 0x23) >>> 0;
const B = (f3, rs1, rs2, imm) => ((((imm >> 12) & 1) << 31) | (((imm >> 5) & 63) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (((imm >> 1) & 15) << 8) | (((imm >> 11) & 1) << 7) | 0x63) >>> 0;
const J = (rd, imm) => ((((imm >> 20) & 1) << 31) | (((imm >> 1) & 1023) << 21) | (((imm >> 11) & 1) << 20) | (((imm >> 12) & 255) << 12) | (rd << 7) | 0x6f) >>> 0;
const U = (op, rd, imm20) => (((imm20 & 0xfffff) << 12) | (rd << 7) | op) >>> 0;
const simm = n => ri(2 ** n) - 2 ** (n - 1);
const RR = { add: [0, 0], sub: [0, 32], sll: [1, 0], slt: [2, 0], sltu: [3, 0], xor: [4, 0], srl: [5, 0], sra: [5, 32], or: [6, 0], and: [7, 0],
  mul: [0, 1], mulh: [1, 1], mulhsu: [2, 1], mulhu: [3, 1], div: [4, 1], divu: [5, 1], rem: [6, 1], remu: [7, 1] };
const II = { addi: 0, slti: 2, sltiu: 3, xori: 4, ori: 6, andi: 7 };
const SH = { slli: [1, 0], srli: [5, 0], srai: [5, 32] };
const BR = { beq: 0, bne: 1, blt: 4, bge: 5, bltu: 6, bgeu: 7 };
const LD = { lb: 0, lh: 1, lw: 2, lbu: 4, lhu: 5 }, ST = { sb: 0, sh: 1, sw: 2 };
const MN = [...Object.keys(RR), ...Object.keys(II), ...Object.keys(SH), ...Object.keys(BR), ...Object.keys(LD), ...Object.keys(ST),
  'lui', 'auipc', 'jal', 'jalr', 'ecall', 'ebreak', 'fence', 'fence.i', 'csr', 'mret', 'illegal', 'random'];

// one fuzz case: returns {pc, regs, insn, insn2, words(Map), mn, edges[]}
function gen() {
  const regs = Array.from({ length: 32 }, (_, i) => i ? r32() : 0);
  let pc = chance(0.05) ? MEMB - 4 : chance(0.05) ? 256 + 4 * ri(64) : 4 * (64 + ri(MEMB / 4 - 128));
  const mn = pick(MN), edges = []; let w; let rd = chance(0.18) ? 0 : reg(); if (rd === 0) edges.push('x0-write');
  const rs1 = reg(), rs2 = reg(); const words = new Map(); let ea = null;
  if (RR[mn]) {
    const [f3, f7] = RR[mn]; w = R(0x33, rd, f3, rs1, rs2, f7);
    if (f7 === 1 && f3 >= 4) { if (chance(0.25)) { regs[rs2] = 0; } else if (chance(0.35)) { regs[rs1] = 0x80000000; regs[rs2] = 0xffffffff; } }
    if (f7 === 1 && f3 < 4 && chance(0.3)) { regs[rs1] = pick([0x80000000, 0xffffffff, 0x7fffffff]); regs[rs2] = pick([0x80000000, 0xffffffff, 0x7fffffff]); }
    if (['sll', 'srl', 'sra'].includes(mn) && chance(0.6)) regs[rs2] = pick([31, 32, 33, 63, 64, 0xffffffff, 0xffffffe0, 0x80000020]);
    if (['add', 'sub'].includes(mn) && chance(0.3)) { regs[rs1] = pick([0x7fffffff, 0x80000000]); regs[rs2] = pick([1, 0xffffffff, 0x80000000]); }
  } else if (II[mn] !== undefined) w = I(0x13, rd, II[mn], rs1, chance(0.4) ? pick([0, 1, -1, 2047, -2048, 0x7ff, -1]) : simm(12));
  else if (SH[mn]) { const [f3, f7] = SH[mn]; w = I(0x13, rd, f3, rs1, (f7 << 5) | ri(32)); }
  else if (BR[mn] !== undefined) {
    let imm = chance(0.3) ? pick([-4, 0, 4, 8, -8, 2, 6, -2, 4094, -4096]) : simm(12) * 2;
    w = B(BR[mn], rs1, rs2, imm); if (imm % 4) edges.push('misaligned-branch-target');
    if (chance(0.35)) regs[rs2] = regs[rs1]; else if (chance(0.3)) { regs[rs1] = pick([0x7fffffff, 0x80000000, 0, 0xffffffff]); regs[rs2] = pick([0x7fffffff, 0x80000000, 0, 0xffffffff]); }
  } else if (LD[mn] !== undefined || ST[mn] !== undefined) {
    const isS = ST[mn] !== undefined; const imm = chance(0.3) ? pick([0, 1, 2, 3, -1, 2047, -2048]) : simm(12);
    w = isS ? S(ST[mn], rs1, rs2, imm) : I(0x03, rd, LD[mn], rs1, imm);
    const kind = ri(6); let t;
    if (kind === 0) t = MEMB - 4 + ri(8);               // last word / just past the end
    else if (kind === 1) t = pick([0xfffffffc, 0x80000000, MEMB + 4 * ri(1000), 0xffffffff]);   // out of range
    else if (kind === 2) t = pc + 4 * (ri(5) - 2) + ri(4);   // code next to the instruction (self-modifying / load code)
    else t = 4 * ri(MEMB / 4) + (chance(0.4) ? ri(4) : 0);
    t >>>= 0;
    if (rs1) regs[rs1] = (t - imm) >>> 0; else t = (imm >>> 0) >>> 0;   // x0 base: ea = sign-extended imm
    if (rs1 && chance(0.1)) { regs[rs1] = (0xffffffff - ri(64)) >>> 0; edges.push('ea-wrap'); }   // base near 2^32, positive imm wraps
    ea = (regs[rs1] + imm) >>> 0;
    if (ea % 4) edges.push(isS ? 'unaligned-store' : 'unaligned-load');
    if (ea >= MEMB - 8 && ea < MEMB + 8) edges.push('mem-end');
    if (ea >= MEMB) edges.push('ea-out-of-range');
    const wi = Math.floor(ea / 4); for (const k of [wi - 1, wi, wi + 1]) if (k >= 0 && k < MEMB / 4) words.set(k, pick(DATA));
    if (!isS && (mn === 'lb' || mn === 'lh')) edges.push('sign-ext-load');
    if (isS && chance(0.4)) regs[rs2] = pick([0xffffffff, 0x80, 0x8000, 0x12345678, 0x7f7f7f7f]);
  } else if (mn === 'lui' || mn === 'auipc') w = U(mn === 'lui' ? 0x37 : 0x17, rd, chance(0.3) ? pick([0, 0xfffff, 0x80000, 0x7ffff]) : ri(2 ** 20));
  else if (mn === 'jal') { const imm = chance(0.2) ? pick([0, 4, -4, 2, -2, 0x0ffffe, -0x100000]) : simm(20) * 2; w = J(rd, imm); if (imm % 4) edges.push('misaligned-jump'); }
  else if (mn === 'jalr') {
    const imm = chance(0.3) ? pick([0, 1, 2, 3, -1, -2, 2047, -2048]) : simm(12); w = I(0x67, rd, chance(0.05) ? 1 + ri(7) : 0, rs1, imm);
    if (rs1 && chance(0.6)) regs[rs1] = ((4 * ri(MEMB / 4) + ri(4)) - imm) >>> 0;
    if (((regs[rs1] + imm) & ~1) % 4) edges.push('misaligned-jump'); if (rd === rs1 && rd) edges.push('jalr-rd=rs1');
  } else if (mn === 'ecall') { w = 0x73; const k = ri(3); regs[17] = k === 0 ? 93 : k === 1 ? 63 : r32(); if (regs[17] === 63 && chance(0.5)) regs[10] = ri(16); }
  else if (mn === 'ebreak') w = 0x00100073;
  else if (mn === 'fence') w = I(0x0f, 0, 0, 0, chance(0.5) ? 0x0ff : ri(4096));
  else if (mn === 'fence.i') w = I(0x0f, 0, 1, 0, 0);
  else if (mn === 'csr') w = I(0x73, rd, pick([1, 2, 3, 5, 6, 7]), rs1, pick([0x300, 0x305, 0x341, 0xc00, 0xf14, ri(4096)]));
  else if (mn === 'mret') w = pick([0x30200073, 0x10500073 /* wfi */, 0x10200073 /* sret */]);
  else if (mn === 'illegal') w = pick([R(0x33, rd, ri(8), rs1, rs2, pick([2, 0x40, 0x7f, 0x21])), I(0x13, rd, 1, rs1, (pick([1, 0x10, 0x40]) << 5) | ri(32)),
    I(0x13, rd, 5, rs1, (pick([1, 0x10, 0x21]) << 5) | ri(32)), B(pick([2, 3]), rs1, rs2, simm(12) * 2), I(0x03, rd, pick([3, 6, 7]), rs1, 0),
    S(pick([3, 4, 5, 6, 7]), rs1, rs2, 0), I(0x67, rd, 1 + ri(7), rs1, 0), 0, 0xffffffff, (ri(2 ** 16)) >>> 0 /* compressed */]);
  else w = ri(2 ** 32) >>> 0;
  regs[0] = 0;
  if (rd === 0 && !/^(b|s[bhw]$|fence|ecall|ebreak|mret|illegal|random)/.test(mn)) edges.push('x0-dest');
  if (RR[mn] && RR[mn][1] === 1 && RR[mn][0] >= 4 && regs[rs2] === 0) edges.push('div-by-zero');
  if ((mn === 'div' || mn === 'rem') && regs[rs1] === 0x80000000 && regs[rs2] === 0xffffffff) edges.push('INT_MIN/-1');
  if (['sll', 'srl', 'sra'].includes(mn) && regs[rs2] >= 32) edges.push('shift>=32-via-reg');
  if (['add', 'sub', 'addi'].includes(mn)) { const a = sx(regs[rs1], 32), b = mn === 'addi' ? sx(w >>> 20, 12) : sx(regs[rs2], 32); const r = mn === 'sub' ? a - b : a + b; if (r > 0x7fffffff || r < -0x80000000) edges.push('signed-overflow'); }
  if (regs[rs1] === undefined) throw new Error('bad');
  return { pc, regs, w: w >>> 0, w2: genSecond(), words, mn, edges };
}
function genSecond() { // a plain ALU / M / load-of-x0-area instruction for the second step
  const k = ri(4); const rd = reg(), a = reg(), b = reg();
  if (k === 0) return R(0x33, rd, ri(8), a, b, 1);
  if (k === 1) { const f3 = ri(8); return R(0x33, rd, f3, a, b, (f3 === 0 || f3 === 5) && chance(0.5) ? 32 : 0); }
  if (k === 2) return I(0x13, rd, pick([0, 2, 3, 4, 6, 7]), a, simm(12));
  return U(0x37, rd, ri(2 ** 20));
}

function buildElf(c, file) {
  const words = new Map(); const pre = (c.pc - 248) / 4;
  for (let r = 1; r < 32; r++) { const v = c.regs[r] >>> 0; const lo = sx(v & 0xfff, 12); const hi = ((v - lo) >>> 12) & 0xfffff;
    words.set(pre + 2 * (r - 1), U(0x37, r, hi)); words.set(pre + 2 * (r - 1) + 1, I(0x13, r, 0, r, lo)); }
  words.set(c.pc / 4, c.w); if (c.pc + 4 < MEMB) words.set(c.pc / 4 + 1, c.w2);
  for (const [k, v] of c.words) if (!words.has(k) && v) words.set(k, v);
  for (const [k, v] of [...words]) if (!v) words.delete(k);
  L.writeElf(file, words, c.pc - 248); return words;
}

(async () => {
  const tot = { cases: 0, steps: 0, fuzzSteps: 0, rvstep: 0, rvstepBad: 0, bugs: 0, cls: {}, fuzzCls: {}, mn: {}, edges: {} };
  const t0 = Date.now(); const file = path.join(TMP, `case-${process.pid}.elf`);
  for (let t = 0; t < N; t++) {
    const c = gen(); if (t % SHARDS !== SHARD) continue;
    const image = buildElf(c, file);
    const mem = new ref.Mem(); for (const [k, v] of image) mem.set(k, v); mem.root();
    const inp = new ref.Mem(); for (let j = 0; j < 16; j++) inp.set(j, (j * 0x9e3779b9) >>> 0); inp.root();
    const st = { pc: c.pc - 248, regs: Array(32).fill(0), step: 0, inp };
    const recs = [];
    for (let i = 0; i < 64 && st.pc !== ref.HALT && st.pc !== ref.TRAP; i++) {
      const pre = { pc: st.pc, regs: [...st.regs], step: st.step, root: ref.stateRoot(st, mem) };
      const j = L.jsStep(st, mem);
      const rec = { pre, js: { ...j, after: { pc: st.pc, regs: [...st.regs] }, writes: new Map([...j.memW].map(k => [k, mem.get(k)])) } };
      if (i >= 62 && RVSTEP) { const r = await L.checkRvStep(pre, j.wit, st, mem, inp); tot.rvstep++; if (!r.ok) { tot.rvstepBad++; rec.rv = r; } }
      recs.push(rec);
    }
    const sail = L.runSail(file, recs.length + 1).steps;
    const sh = new L.Shadow(image); const mirror = new Map(image); let bad = null;
    for (let i = 0; i < recs.length; i++) {
      const s = sail[i]; if (!s) { bad = { i, cls: 'BUG:sail-trace-short', why: 'sail trace ended early' }; break; }
      const js = recs[i].js; for (const [k, v] of js.writes) mirror.set(k, v); js.mem = { get: k => mirror.get(k) || 0 };
      const cmp = L.compareStep(js, s, sail[i + 1] || null, sh); tot.steps++;
      tot.cls[cmp.cls] = (tot.cls[cmp.cls] || 0) + 1;
      if (i === 62) { tot.fuzzSteps++; tot.fuzzCls[cmp.cls] = (tot.fuzzCls[cmp.cls] || 0) + 1; tot.mn[c.mn] = (tot.mn[c.mn] || 0) + 1; for (const e of c.edges) tot.edges[e] = (tot.edges[e] || 0) + 1; }
      if (i === 63) tot.fuzzSteps++;
      if (!cmp.ok) { bad = { i, cls: cmp.cls, why: cmp.why }; break; }
      if (recs[i].rv) { bad = { i, cls: 'BUG:rv_step', why: recs[i].rv.err }; break; }
      if (cmp.stop) break;
    }
    tot.cases++;
    if (bad) { tot.bugs++; console.log(JSON.stringify({ case: t, mn: c.mn, w: L.hex(c.w), pc: L.hex(c.pc), bad, regs: c.regs.map(L.hex) }));
      if (process.env.KEEP) fs.copyFileSync(file, path.join(TMP, `fail-${t}.elf`)); }
  }
  try { fs.unlinkSync(file); } catch (e) {}
  console.log(JSON.stringify({ summary: { ...tot, seed: process.env.SEED || 1, shard: SHARD, shards: SHARDS, ms: Date.now() - t0 } }));
  process.exit(0);
})();
