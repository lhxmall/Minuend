// Batch traces for the rollup prototype. Memory carries over between heights; each batch starts at pc 0,
// registers 0, step 0, with its own input tree. The program reads N input words, folds them into an
// accumulator and stores running sums in memory (so the carried memory depends on every past batch).
'use strict';
const ref = require('./ref.js');
const I=(op,rd,f3,rs1,imm)=>(((imm&0xfff)<<20)|(rs1<<15)|(f3<<12)|(rd<<7)|op)>>>0;
const R=(op,rd,f3,rs1,rs2,f7)=>((f7<<25)|(rs2<<20)|(rs1<<15)|(f3<<12)|(rd<<7)|op)>>>0;
const S=(f3,rs1,rs2,imm)=>((((imm>>5)&127)<<25)|(rs2<<20)|(rs1<<15)|(f3<<12)|((imm&31)<<7)|35)>>>0;
const B=(f3,rs1,rs2,imm)=>((((imm>>12)&1)<<31)|(((imm>>5)&63)<<25)|(rs2<<20)|(rs1<<15)|(f3<<12)|(((imm>>1)&15)<<8)|(((imm>>11)&1)<<7)|99)>>>0;
const N = 4;
const program = [ I(19,1,0,0,0), I(19,2,0,0,N), ((0x40000>>>12)<<12|(4<<7)|55)>>>0, I(19,11,0,0,0),
  /*loop*/ R(51,1,0,1,2,0), R(51,3,0,1,2,1), I(19,10,0,11,0), I(19,17,0,0,63), 0x73, R(51,7,0,7,10,0),
  I(3,5,2,4,0), R(51,5,0,5,7,0), R(51,5,0,5,3,0), S(2,4,5,0), I(19,11,0,11,1), I(19,4,0,4,4), I(19,2,0,2,-1), B(1,2,0,-52),
  I(19,17,0,0,93), 0x73 ];
const cloneMem = m => { const c = new ref.Mem(); for (const [i, v] of m.w) c.set(i, v); c.root(); return c; };
function genesis() { const m = new ref.Mem(); program.forEach((w, i) => m.set(i, w)); m.root(); return m; }
const ZR = Array(32).fill(0).join(',');
// loop round 7 (R6-M2): the rollup binds an operator-declared timestamp per height into s0 as register x10 (a0) = ts;
// every other register stays 0. regsTs(ts) = the s0 register list rv_rollup hashes.
const regsTs = ts => { const r = Array(32).fill(0); r[10] = ts >>> 0; return r; };
// batch(prevMem, seed, {k, mut, extra, ts}) -> trace of one height. mut(st,mem) is applied right after step k-1 -> k
function batch(prevMem, seed, o = {}) {
  const ts = o.ts || 0;
  const mem = cloneMem(prevMem); const inp = new ref.Mem(); for (let i = 0; i < 16; i++) inp.set(i, (Math.imul(seed + 1, 2654435761) + i * 40503) >>> 0); inp.root();
  const st = { pc: 0, regs: regsTs(ts), step: 0, inp }; const inpRoot = inp.root(); // the committed input root (an 'inp' lie swaps words later)
  const roots = [ref.stateRoot(st, mem)], wits = [];
  const limit = o.limit || 10000; let halt = -1;
  for (let i = 0; i < limit; i++) {
    if (halt >= 0 && i >= halt + (o.extra || 0)) break;
    const pre = { pc: st.pc, regs: [...st.regs], step: st.step, mem: mem.root(), inp: inp.root() };
    const w = ref.step(st, mem); const d = { pc: pre.pc, regs: pre.regs, mem: pre.mem, inp: pre.inp, step: pre.step };
    if (w.wsib) { d.w = w.w; d.wsib = w.wsib; } if (w.msib) { d.mw = w.mword; d.msib = w.msib; if (((w.w >>> 0) & 127) === 35) d.nroot = mem.root(); }
    if (w.isib) { d.iw = w.iw; d.isib = w.isib; } wits.push(d);
    if (o.k != null && i + 1 === o.k) o.mut(st, mem);
    roots.push(ref.stateRoot(st, mem));
    if (halt < 0 && (st.pc === ref.HALT || st.pc === ref.TRAP)) halt = i + 1;
  }
  const steps = roots.length - 1;
  const s0 = s0Of(ts, prevMem.root(), inpRoot);
  if (s0 !== roots[0]) throw Error('s0 formula mismatch');
  return { s0, roots, wits, steps, inpRoot, mem, fpc: st.pc, fregs: st.regs.join(','), fmem: mem.root(), final: roots[steps], ts, args: [prevMem, seed, o] };
}
// rv_rollup's s0 (loop round 7): pc 0, registers 0 except x10 = ts, memory carried, this height's input, step 0
const s0Of = (ts, pmem, inp) => ref.H('0:' + regsTs(ts).join(',') + ':' + pmem + ':' + inp + ':0');
// retime(tr, ts): re-run the same trace with s0 register x10 = ts (in place). The test program overwrites x10 before
// any use, so memory, final registers and the final root do not depend on ts; s0 and the intermediate roots do.
function retime(tr, ts) {
  if (tr.ts === ts) return tr;
  const [pm, seed, o] = tr.args; const n = batch(pm, seed, { ...o, ts });
  // (a non-program memory image traps at once: its final registers then carry x10 = ts, so the final state follows)
  if (n.fmem !== tr.fmem) throw Error('retime changed the final memory');
  Object.assign(tr, { s0: n.s0, roots: n.roots, wits: n.wits, steps: n.steps, fpc: n.fpc, fregs: n.fregs, final: n.final, ts }); return tr;
}
// at(tr, ts): a retimed copy (tr unchanged); objects that are not traces (e.g. a list of believed roots) pass through
const at = (tr, ts) => !tr || !tr.args || ts === undefined || tr.ts === ts ? tr : retime({ ...tr }, ts);
const MUT = {
  reg: st => { st.regs[20] = (st.regs[20] ^ 1) >>> 0; },
  pc: st => { st.pc = (st.pc + 4) >>> 0; },
  mem: (st, mem) => { mem.set(0x30000, 4242); },     // hidden memory corruption: carried into the next height
  step: st => { st.step += 1; },
  inp: st => { st.inp.set(3, 777); },
};
module.exports = { program, genesis, batch, cloneMem, MUT, ZR, regsTs, s0Of, retime, at };
