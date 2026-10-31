// MNWIT1 bench + host/guest diff. For each (cfg, N): engine-diff gen -> batch (setup + N flow ops);
//  - real engine (std) hash/events and per-unit MNWIT1 roots rebuilt from scratch over the REAL
//    state's leaves (engine-diff wroots, independent smt_ref)  vs  guest (JS model) incremental roots;
//  - steps per flow unit with the commitment (rvengine), without it (rvengine-nowit) and, for
//    N in LEGACY_NS, with the legacy full rebuild (rvengine-legacywit, roots checked vs upstream
//    obyte_merkle over the real leaves).
// Steps are read at unit boundaries inside one run: flow = end(last unit) - end(last setup unit).
// usage: node witbench.js <engine-diff> <elf-inc> <elf-nowit> <elf-legacy> <outdir> <cfgs json>
const { execFileSync } = require('child_process'); const fs = require('fs'); const path = require('path');
const { run } = require('./witrun.js');
const [BIN, EINC, ENOW, ELEG, OUTDIR, CFG] = process.argv.slice(2);
const cfgs = JSON.parse(CFG); const Ns = process.env.NS ? JSON.parse(process.env.NS) : [10, 100, 1000];
const LNs = process.env.LEGACY_NS ? JSON.parse(process.env.LEGACY_NS) : [10];
fs.mkdirSync(OUTDIR, { recursive: true });
const sh = (args) => execFileSync(BIN, args, { maxBuffer: 1 << 30 }).toString();
const R = (s) => Math.ceil(Math.log(s) / Math.log(16)); const cost = (r) => r * 3372 + 11467;
const same = (a, b) => a.hash === b.hash && a.applied === b.applied && a.rejected === b.rejected && JSON.stringify(a.ev) === JSON.stringify(b.ev);
function flow(r, nSetup, N) {
  const e = r.unitEnd; const base = nSetup > 0 ? e[nSetup - 1] : 0; const per = [];
  for (let u = nSetup; u < nSetup + N; u++) per.push(e[u] - (u > 0 ? e[u - 1] : 0));
  per.sort((a, b) => a - b);
  return { flow: e[nSetup + N - 1] - base, avg: Math.round((e[nSetup + N - 1] - base) / N), med: per[per.length >> 1], max: per[per.length - 1] };
}
for (const c of cfgs) for (const N of Ns) {
  const f = path.join(OUTDIR, `${c.name}-n${N}.bin`);
  const g = JSON.parse(sh(['gen', String(c.seed || 7), String(c.makers), String(c.levels), String(c.per), String(N), f].concat(c.stress ? ['stress'] : [])));
  const nSetup = g.setup_ops;
  const real = JSON.parse(sh(['real', f])); const wr = JSON.parse(sh(['wroots', f]));
  const inc = run(EINC, f); const now = run(ENOW, f);
  const fi = flow(inc, nSetup, N), fn = flow(now, nSetup, N);
  const r = { cfg: c.name, resting_setup: nSetup - (c.makers + 16), N, ops: g.ops, setup_ops: nSetup,
    match_real_guest: same(real, inc), match_real_nowit: same(real, now), roots_equal: JSON.stringify(wr.roots) === JSON.stringify(inc.roots),
    roots: inc.roots.length, scratch_ok: inc.scratch_ok, final_root: inc.roots[inc.roots.length - 1],
    leaves: wr.leaves, live_orders: wr.live_orders, depth_max: wr.depth_max, depth_avg: wr.depth_avg,
    flow_applied: real.applied - (nSetup), fills: real.fills, leaf_updates: inc.leaf_updates, node_hashes: inc.node_hashes,
    steps_flow_inc: fi.flow, steps_unit_inc: fi.avg, steps_unit_inc_med: fi.med, steps_unit_inc_max: fi.max,
    steps_flow_nowit: fn.flow, steps_unit_nowit: fn.avg, steps_unit_wit: fi.avg - fn.avg,
    R_flow: R(fi.flow), cost_flow: cost(R(fi.flow)), R_unit_max: R(fi.max), cost_unit_max: cost(R(fi.max)),
    R_full: R(inc.steps), steps_full: inc.steps, heap: inc.heap, halted: inc.halted && now.halted, js_ms: inc.ms + now.ms };
  if (LNs.includes(N)) {
    const w = fs.readFileSync(f); w.writeUInt32LE(nSetup, 12); const lf = f.replace('.bin', '.legacy.bin'); fs.writeFileSync(lf, w);
    const leg = run(ELEG, lf); const lwr = JSON.parse(sh(['wroots', f, 'legacy', String(nSetup)]));
    const fl = flow(leg, nSetup, N);
    Object.assign(r, { legacy_roots_equal: JSON.stringify(lwr.roots) === JSON.stringify(leg.roots), legacy_match_real: same(real, leg),
      steps_unit_legacy: fl.avg, steps_unit_legacy_wit: fl.avg - fn.avg, R_unit_legacy: R(fl.max), legacy_js_ms: leg.ms });
  }
  console.log(JSON.stringify(r));
}
