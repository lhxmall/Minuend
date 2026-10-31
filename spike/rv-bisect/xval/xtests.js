// riscv-tests (rv32ui / rv32um ELFs built by ../rvtests/build.sh) on three implementations, every step:
//   JS reference model (js/ref.js)  vs  sail-riscv (trace -> shadow pc/regs/mem)   and
//   rv_step on the real ocore evaluator (pre/post state roots == JS model's)   [RVSTEP=0 to skip]
// usage: node xtests.js a.elf b.elf ...   -> one JSON line per test, then a summary line
'use strict';
const ref = require(process.env.XREF || '../js/ref.js'); const { load } = require('../js/elfrun.js'); const L = require('./lib.js');
const fs = require('fs'), os = require('os'), path = require('path');
const RVSTEP = process.env.RVSTEP !== '0', MAX = +(process.env.MAX || 200000);
(async () => {
  const tot = { tests: 0, steps: 0, sailCompared: 0, rvstep: 0, rvstepBad: 0, bugs: 0, cls: {} };
  for (const f of process.argv.slice(2)) {
    const mem = new ref.Mem(); const entry = load(f, mem); const image = new Map(mem.w); mem.root();
    const inp = new ref.Mem(); inp.root();
    const st = { pc: entry, regs: Array(32).fill(0), step: 0, inp };
    // JS run first (recording each step), then one sail run with the same number of steps + 1
    const recs = [];
    while (st.pc !== ref.HALT && st.pc !== ref.TRAP && st.step < MAX) {
      const pre = { pc: st.pc, regs: [...st.regs], step: st.step, root: ref.stateRoot(st, mem) };
      const j = L.jsStep(st, mem);
      const rec = { pre, js: { ...j, after: { pc: st.pc, regs: [...st.regs] }, writes: new Map([...j.memW].map(i => [i, mem.get(i)])) } };
      if (RVSTEP) { const r = await L.checkRvStep(pre, j.wit, st, mem, inp); tot.rvstep++; if (!r.ok) { tot.rvstepBad++; rec.rv = r; } }
      recs.push(rec);
    }
    const sail = L.runSail(f, recs.length + 1).steps;
    const sh = new L.Shadow(image); const mirror = new Map(image); let bad = null; const cls = {};
    for (let i = 0; i < recs.length; i++) {
      const s = sail[i]; if (!s) { bad = { i, why: 'sail trace ended early' }; break; }
      const js = recs[i].js; for (const [k, v] of js.writes) mirror.set(k, v); js.mem = { get: k => mirror.get(k) || 0 };
      const c = L.compareStep(js, s, sail[i + 1] || null, sh); cls[c.cls] = (cls[c.cls] || 0) + 1; tot.sailCompared++;
      if (!c.ok) { bad = { i, cls: c.cls, why: c.why }; tot.bugs++; break; }
      if (recs[i].rv) { bad = { i, cls: 'BUG:rv_step', why: recs[i].rv.err }; tot.bugs++; break; }
      if (c.stop) break;
    }
    for (const k in cls) tot.cls[k] = (tot.cls[k] || 0) + cls[k];
    tot.tests++; tot.steps += recs.length;
    const name = path.basename(f, '.elf');
    console.log(JSON.stringify({ test: name, end: st.pc === ref.HALT ? 'HALT' : st.pc === ref.TRAP ? 'TRAP' : 'MAX', pass: st.pc === ref.HALT && st.regs[10] === 0, steps: recs.length, sailSteps: sail.length, last: recs.length && sail[recs.length - 1] ? (sail[recs.length - 1].exc || '-') : null, bad, cls }));
  }
  console.log(JSON.stringify({ summary: tot }));
  process.exit(0);
})();
