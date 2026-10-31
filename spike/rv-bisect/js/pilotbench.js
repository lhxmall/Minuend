// Step-count benchmark + 3-way differential check for the mnpilot guest.
// For each (depth, N): engine-diff gen -> batch (setup + N flow orders) and batch.setup;
// real engine (std) vs port (native) vs guest (JS model) must agree on hash + event log;
// steps per order = (steps(full) - steps(setup)) / N.
// usage: node pilotbench.js <engine-diff bin> <rvengine elf> <outdir> [configs json]
const { execFileSync } = require('child_process'); const fs = require('fs'); const path = require('path');
const { run } = require('./pilotrun.js');
const [BIN, ELF, OUTDIR] = process.argv.slice(2);
const cfgs = process.argv[5] ? JSON.parse(process.argv[5]) : [
  { name: 'depth200', makers: 10, levels: 50, per: 2 }, { name: 'depth800', makers: 16, levels: 200, per: 2 }];
const Ns = process.env.NS ? JSON.parse(process.env.NS) : [10, 100, 1000];
fs.mkdirSync(OUTDIR, { recursive: true });
const sh = (args) => execFileSync(BIN, args, { maxBuffer: 1 << 28 }).toString();
for (const c of cfgs) for (const N of Ns) {
  const f = path.join(OUTDIR, `${c.name}-n${N}.bin`);
  const g = JSON.parse(sh(['gen', String(c.seed || 7), String(c.makers), String(c.levels), String(c.per), String(N), f].concat(c.stress ? ['stress'] : [])));
  const real = JSON.parse(sh(['real', f])); const port = JSON.parse(sh(['port', f]));
  const full = run(ELF, f); const setup = run(ELF, f.replace('.bin', '.setup.bin'));
  const realSetup = JSON.parse(sh(['real', f.replace('.bin', '.setup.bin')]));
  const same = (a, b) => a.hash === b.hash && a.applied === b.applied && a.rejected === b.rejected && JSON.stringify(a.ev) === JSON.stringify(b.ev);
  const r = { cfg: c.name, resting_setup: g.setup_ops - (c.makers + 16), N, ops: g.ops, setup_ops: g.setup_ops,
    match_real_port: same(real, port), match_real_guest: same(real, full), match_setup: same(realSetup, setup),
    hash: real.hash, applied: real.applied, rejected: real.rejected, fills: real.fills,
    flow_applied: real.applied - realSetup.applied, flow_rejected: real.rejected - realSetup.rejected, flow_fills: real.fills - realSetup.fills,
    steps_full: full.steps, steps_setup: setup.steps, steps_flow: full.steps - setup.steps,
    steps_per_order: Math.round((full.steps - setup.steps) / N), steps_per_setup_op: Math.round(setup.steps / g.setup_ops),
    heap_full: full.heap, halted: full.halted && setup.halted, js_ms: full.ms + setup.ms };
  console.log(JSON.stringify(r));
}
