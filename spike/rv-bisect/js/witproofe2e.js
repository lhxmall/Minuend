// Loop round 3, end to end: the REAL guest (prod build) runs a batch; its full final memory image (every word the
// run touched: code, heap with the engine state, stack, OUT) becomes the height's fmem in the simulated rollup; the
// height is finalized; rv_witbind binds the segment end root from that memory (memory Merkle proofs at the guest's
// OUT slots) and rv_witproof verifies real MNWIT1 proofs (engine-diff proofdump of the same batch) against it.
// usage: node witproofe2e.js <elf> <batch.bin> <proofs.json>
'use strict';
const fs = require('fs'); const ref = require('./ref.js'); const { FastMem, load } = require('./elfrun.js');
const { Chain, ROLL, BIND, PROOF } = require('./chain.js'); const T = require('./rolltrace.js'); const K = require('./witkit.js');
const [ELF, BATCH, PROOFS] = process.argv.slice(2);
const OBOND = 200000, WIN = 86400; const W = 'WATCHERADDRESSXXXXXXXXXXXXXXXXXX', OP = 'OPERATORADDRESSXXXXXXXXXXXXXXXXX';
const out = []; const rec = (n, e, a, x) => { const p = JSON.stringify(e) === JSON.stringify(a); out.push(p); console.log(p ? 'PASS' : 'FAIL', n, JSON.stringify(a), x ? JSON.stringify(x) : ''); };
(async () => {
  const mem = new FastMem(); const entry = load(ELF, mem); const b = fs.readFileSync(BATCH); const inp = new FastMem();
  for (let i = 0; i < b.length / 4; i++) inp.set(i, b.readUInt32LE(4 * i));
  const TS = 1e9 - 30; // loop round 7 (R6-M2): the height's timestamp enters as register x10 (a0)
  const st = { pc: entry, regs: T.regsTs(TS), step: 0, inp }; while (st.pc !== ref.HALT && st.pc !== ref.TRAP && st.step < 2e10) ref.step(st, mem);
  const P = JSON.parse(fs.readFileSync(PROOFS, 'utf8'));
  const words = Array.from({ length: 8 }, (_, k) => mem.get(K.OUTW + k));
  rec('guest halted, status 0', [true, 0], [st.pc === ref.HALT, mem.get(K.STW)], { steps: st.step });
  rec('guest OUT[0x1FFE8..8] = proofdump root (host real-engine state)', P.root, K.wordsRoot(words));
  rec('loop 7: guest published ts at OUT[0x1FFE5]', TS, mem.get(K.OUTW - 3));
  const M = new ref.Mem(); for (const [i, v] of mem.w) M.set(i, v); const t0 = Date.now(); const root = M.root();
  rec('memory image words / Merkle root built', true, M.w.size > 1000, { words: M.w.size, ms: Date.now() - t0 });
  const C = new Chain(); const G0 = T.genesis(); const b1 = T.batch(G0, 1, { ts: TS }); // s0 = toy trace (rv_rollup checks only its formula)
  const final = ref.H(st.pc + ':' + st.regs.join(',') + ':' + root + ':' + b1.inpRoot + ':' + b1.steps);
  let r = await C.send(OP, ROLL, OBOND, { submit: 1, ts: TS, s0: b1.s0, steps: b1.steps, final, inp: b1.inpRoot, fpc: st.pc, fregs: st.regs.join(','), fmem: root, prev: 'genesis', units: 1 });
  rec('height 1 with the guest memory as fmem', 'ok', r.err || 'ok');
  C.ts += WIN; r = await C.send(W, ROLL, 0, { finalize: 1 }); rec('finalized', 'ok', r.err || 'ok');
  r = await C.send(W, BIND, 0, K.bindData(M, 1)); rec('bind from the real guest memory', ['ok', P.root], [r.err || 'ok', C.v(BIND, 'W1')]);
  const kidJs = l => { const p = l.split(':'); const f = l.startsWith('pos:') ? 3 : 2; return p.length <= f ? l : p.slice(0, f).join(':'); };
  let ok = 0; for (const m of P.members) { const q = await C.send(W, PROOF, 0, { prove: 1, leaf: m.leaf, sib: m.sib }); if (!q.err && C.v(PROOF, 'L1:' + kidJs(m.leaf)) === m.leaf) ok++; }
  rec('every proofdump membership verifies', P.members.length, ok);
  r = await C.send(W, PROOF, 0, { prove: 1, leaf: P.absent.term, sib: P.absent.sib, key: P.absent.key }); rec('absence verifies', 'ok', r.err || 'ok');
  console.log('E2E ' + JSON.stringify({ pass: out.filter(x => x).length, total: out.length })); process.exit(0);
})();
