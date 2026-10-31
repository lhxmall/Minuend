// Cross-validation helpers: run sail-riscv (independent reference), parse its trace, write tiny ELFs,
// and compare one executed step of the JS reference model (js/ref.js, == rv_step bit-for-bit via state roots)
// against the same step in sail.
'use strict';
const fs = require('fs'), path = require('path'), cp = require('child_process');
const ref = require(process.env.XREF || '../js/ref.js');   // XREF: mutant model for the harness self-test

const SAIL = process.env.SAIL || '/data/hark/spike-rv/xval/sail-riscv-0.16/build/c_emulator/sail_riscv_sim';
const CFG = process.env.SAILCFG || path.join(__dirname, 'rv32im-strict.json');

// ---- sail ----------------------------------------------------------------------------------------
// Returns array of steps: {n, pc, insn, regw: [[r, v]], memw: [[addr, val, bytes]], exc: string|null}
// Trace produced with --trace-step: one blank-line separated block per step. A step whose instruction fetch faults
// has no "[n] [M]: pc (insn)" line; its pc is the exception's tval.
function parseTrace(txt) {
  const steps = [];
  for (const blk of txt.split(/\n\s*\n/)) {
    let cur = { pc: null, insn: null, regw: [], memw: [], exc: null, text: '' }, any = false;
    for (const line of blk.split('\n')) {
      let m;
      if ((m = /^\[(\d+)\] \[M\]: 0x([0-9A-Fa-f]+) \(0x([0-9A-Fa-f]+)\)/.exec(line))) {
        cur.n = +m[1]; cur.pc = parseInt(m[2], 16); cur.insn = parseInt(m[3], 16) >>> 0; cur.text = line.slice(0, 90).trim(); any = true; }
      else if ((m = /^x(\d+) <- 0x([0-9A-Fa-f]+)/.exec(line))) cur.regw.push([+m[1], parseInt(m[2], 16) >>> 0]);
      else if ((m = /^mem\[W,0x([0-9A-Fa-f]+)\] <- 0x([0-9A-Fa-f]+)/.exec(line))) cur.memw.push([parseInt(m[1], 16), parseInt(m[2], 16) >>> 0, m[2].length / 2]);
      else if ((m = /^trapping from \S+ to \S+ to handle (\S+)/.exec(line))) { cur.exc = m[1]; any = true; }
      else if ((m = /^handling exc#(\S+) .*tval=0x([0-9A-Fa-f]+)/.exec(line))) { if (cur.pc === null) { cur.pc = parseInt(m[2], 16); cur.fetchFault = true; cur.text = 'fetch fault @' + m[2]; } }
    }
    if (any) steps.push(cur);
  }
  return steps;
}
function runSail(elf, limit, cfg = CFG) {
  const r = cp.spawnSync(SAIL, ['--config', cfg, '--inst-limit', String(limit), '--trace-instr', '--trace-gpr', '--trace-mem',
    '--trace-exception', '--trace-step', '--disable-trap-loop-detection', elf], { encoding: 'utf8', maxBuffer: 1 << 28 });
  if (r.error) throw r.error;
  return { steps: parseTrace(r.stdout + '\n' + r.stderr), raw: r.stdout, status: r.status };
}

// ---- minimal ELF32 (EM_RISCV) writer: words = Map(wordIndex -> value), one PT_LOAD per contiguous run ----
function writeElf(file, words, entry) {
  const idx = [...words.keys()].sort((a, b) => a - b); const runs = [];
  for (const i of idx) { const r = runs[runs.length - 1]; if (r && r.end === i) { r.vals.push(words.get(i)); r.end++; } else runs.push({ start: i, end: i + 1, vals: [words.get(i)] }); }
  const ehs = 52, phs = 32, phoff = ehs; let off = phoff + phs * runs.length; const parts = [];
  const ph = Buffer.alloc(phs * runs.length);
  runs.forEach((r, k) => { const o = k * phs, sz = r.vals.length * 4;
    ph.writeUInt32LE(1, o); ph.writeUInt32LE(off, o + 4); ph.writeUInt32LE(r.start * 4, o + 8); ph.writeUInt32LE(r.start * 4, o + 12);
    ph.writeUInt32LE(sz, o + 16); ph.writeUInt32LE(sz, o + 20); ph.writeUInt32LE(7, o + 24); ph.writeUInt32LE(4, o + 28);
    const b = Buffer.alloc(sz); r.vals.forEach((v, j) => b.writeUInt32LE(v >>> 0, 4 * j)); parts.push(b); off += sz; });
  const eh = Buffer.alloc(ehs);
  eh.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1, 0]); eh.writeUInt16LE(2, 16); eh.writeUInt16LE(243, 18); eh.writeUInt32LE(1, 20);
  eh.writeUInt32LE(entry >>> 0, 24); eh.writeUInt32LE(phoff, 28); eh.writeUInt32LE(0, 32); eh.writeUInt32LE(0, 36);
  eh.writeUInt16LE(ehs, 40); eh.writeUInt16LE(phs, 42); eh.writeUInt16LE(runs.length, 44); eh.writeUInt16LE(40, 46);
  fs.writeFileSync(file, Buffer.concat([eh, ph, ...parts]));
}

// ---- shadow state rebuilt from sail's trace -----------------------------------------------------
class Shadow {
  constructor(image) { this.regs = Array(32).fill(0); this.mem = new Map(image); }   // image: Map word -> value
  word(i) { return this.mem.get(i) || 0; }
  apply(s) { // returns set of word indices touched
    const touched = new Set();
    for (const [r, v] of s.regw) if (r) this.regs[r] = v >>> 0;
    for (const [a, v, n] of s.memw) for (let k = 0; k < n; k++) { const ba = a + k, wi = Math.floor(ba / 4), sh = 8 * (ba % 4);
      const byte = Math.floor(v / 2 ** (8 * k)) % 256; const old = this.word(wi);
      const nw = (old - (Math.floor(old / 2 ** sh) % 256) * 2 ** sh + byte * 2 ** sh) >>> 0; this.mem.set(wi, nw); touched.add(wi); }
    return touched;
  }
}

// ---- spec-choice classification for steps where only one side traps -----------------------------
// rv_step's documented choices (README "State commitment" / design doc): misaligned access, FENCE / FENCE.I / CSR /
// EBREAK / other SYSTEM -> TRAP; ecall a7=93 -> HALT (pc 2), ecall a7=63 -> input-tree read; everything else is rv32im.
function classify(w, sailExc, jsKind, regs) {
  const op = w & 127, f3 = (w >>> 12) & 7;
  if (w === 0x73 && regs[17] === 93) return sailExc === 'm-call' ? 'spec:ecall-halt' : 'BUG:ecall-halt-vs-' + sailExc;
  if (w === 0x73 && regs[17] === 63) return sailExc === 'm-call' ? 'spec:ecall-input' : 'BUG:ecall-input-vs-' + sailExc;
  if (op === 0x0f) return 'spec:fence' + (f3 === 1 ? '.i' : '') + (sailExc ? '(sail ' + sailExc + ')' : '(sail nop)');
  if (op === 0x73 && f3 !== 0) return 'spec:csr' + (sailExc ? '(sail ' + sailExc + ')' : '(sail executes)');
  if (op === 0x73) return 'spec:system' + (sailExc ? '(sail ' + sailExc + ')' : '(sail executes)');
  if ((op === 0x03 || op === 0x23) && sailExc === null) return 'spec:misaligned-access-allowed-by-sail';
  return null;
}

// Compare one step. js = {pc, regsBefore, after: st (after ref.step), memW: Set(word idx written by JS), mem}, s = sail step,
// next = next sail step (for pc) or null. Returns {ok, cls, why}
function compareStep(js, s, next, shadow) {
  const w = s.insn === null ? (js.wit && js.wit.w !== undefined ? js.wit.w : 0) : s.insn;
  if (s.pc !== js.pc) return { ok: false, cls: 'BUG:desync', why: `pc sail ${hex(s.pc)} js ${hex(js.pc)}` };
  const jsTrap = js.after.pc === ref.TRAP, jsHalt = js.after.pc === ref.HALT, jsSys = js.kind === 'sys';
  if (jsTrap || jsHalt || (jsSys && !jsTrap)) {             // JS left the normal path (trap / halt / input ecall)
    const c = classify(w, s.exc, js.kind, js.regsBefore);
    if (s.exc && jsTrap) {                                   // both trap: nothing architectural may change
      const t = shadow.apply(s);
      if (s.regw.some(([r]) => r) || t.size) return { ok: false, cls: 'BUG:trap-side-effect', why: 'sail wrote state on a trap' };
      if (js.memW.size) return { ok: false, cls: 'BUG:trap-side-effect', why: 'js wrote memory on a trap' };
      for (let r = 0; r < 32; r++) if ((js.after.regs[r] >>> 0) !== shadow.regs[r]) return { ok: false, cls: 'BUG:trap-side-effect', why: 'js reg x' + r };
      return { ok: true, cls: 'agree-trap:' + s.exc, stop: true };
    }
    if (c) return { ok: !c.startsWith('BUG'), cls: c, stop: true };
    return { ok: false, cls: 'BUG:js-trap-sail-exec', why: `${hex(w)} js ${js.after.pc} sail ${s.exc} ${s.text}`, stop: true };
  }
  if (s.exc) return { ok: false, cls: 'BUG:sail-trap-js-exec', why: `${hex(w)} sail ${s.exc} js kind ${js.kind} ${s.text}`, stop: true };
  const touched = shadow.apply(s);
  for (let r = 0; r < 32; r++) if ((js.after.regs[r] >>> 0) !== shadow.regs[r]) return { ok: false, cls: 'BUG:reg', why: `x${r} js ${hex(js.after.regs[r])} sail ${hex(shadow.regs[r])} ${s.text}` };
  for (const wi of new Set([...touched, ...js.memW])) if ((js.mem.get(wi) >>> 0) !== shadow.word(wi)) return { ok: false, cls: 'BUG:mem', why: `word ${hex(wi * 4)} js ${hex(js.mem.get(wi))} sail ${hex(shadow.word(wi))} ${s.text}` };
  if (next && next.pc !== js.after.pc) return { ok: false, cls: 'BUG:pc', why: `next pc js ${hex(js.after.pc)} sail ${hex(next.pc)} ${s.text}` };
  return { ok: true, cls: 'agree:' + js.kind, checkedPc: !!next };
}
const hex = v => '0x' + ((v >>> 0).toString(16));

// run one JS step recording memory writes
function jsStep(st, mem) {
  const memW = new Set(); const orig = mem.set; mem.set = function (i, v) { memW.add(i); return orig.call(this, i, v); };
  const pc = st.pc, regsBefore = [...st.regs];
  let wit; try { wit = ref.step(st, mem); } finally { mem.set = orig; }
  return { pc, regsBefore, after: st, memW, mem, kind: wit.kind, wit };
}

// rv_step on the real ocore evaluator for one step (pre/post roots must equal the JS model's)
let _oc, _body;
async function checkRvStep(pre, wit, st, mem, inp) {
  if (!_oc) { _oc = require('../js/oc.js'); _body = fs.readFileSync(path.join(__dirname, '../aa/rv_step.oscript'), 'utf8'); }
  const data = { pc: pre.pc, regs: pre.regs, mem: wit.mem_root, inp: inp.root(), step: pre.step };
  if (wit.w !== undefined) { data.w = wit.w; data.wsib = wit.wsib; }
  if (wit.msib) { data.mw = wit.mword; data.msib = wit.msib; data.nroot = mem.root(); }
  if (wit.isib) { data.iw = wit.iw; data.isib = wit.isib; }
  const r = await _oc.evalInit(_body, data);
  const ok = !r.err && _oc.val(r.locals, 'pre') === pre.root && _oc.val(r.locals, 'post') === ref.stateRoot(st, mem);
  return { ok, err: r.err && String((r.err.formattedError || r.err).message || r.err).slice(0, 160) };
}

module.exports = { SAIL, CFG, parseTrace, runSail, writeElf, Shadow, classify, compareStep, jsStep, checkRvStep, hex };
