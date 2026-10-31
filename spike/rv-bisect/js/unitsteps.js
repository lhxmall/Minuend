// Loop round 3 (S1b): per-unit guest step counts of one batch (JS model), e.g. the cancel units at
// the end of `engine-diff crowdc`. usage: node unitsteps.js <elf> <batch.bin> [tail]
// prints total steps, hash, the max unit (index, steps), and the steps of the last `tail` units.
const { run } = require('./witrun.js');
const [ELF, BATCH, TAIL] = process.argv.slice(2); const tail = Number(TAIL || 8);
const r = run(ELF, BATCH);
const per = r.unitEnd.map((e, i) => e - (i ? r.unitEnd[i - 1] : 0));
let mi = 0; per.forEach((s, i) => { if (s > per[mi]) mi = i; });
const body = per.slice(0, per.length - tail);
let bi = 0; body.forEach((s, i) => { if (s > body[bi]) bi = i; });
console.log(JSON.stringify({ batch: BATCH, halted: r.halted, status: r.status, hash: r.hash, units: r.units, applied: r.applied, rejected: r.rejected,
  steps: r.steps, heap: r.heap, heap_peak_live: r.heap_peak_live, max_unit: { i: mi, steps: per[mi] }, max_unit_before_tail: { i: bi, steps: body[bi] },
  tail_steps: per.slice(-tail), tail_ev: r.ev.slice(-tail), ms: r.ms }));
