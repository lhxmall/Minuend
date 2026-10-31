// Host vs guest on a directory of batches (e.g. the upstream-scenario replays written by
// `engine-diff scen <file> <dir>`): real engine hash + events and per-unit MNWIT1 roots rebuilt
// from scratch over the real state (engine-diff wroots) vs the riscv32im guest in the JS model.
// usage: node witscen.js <engine-diff> <rvengine elf> <dir>
const { execFileSync } = require('child_process'); const fs = require('fs'); const path = require('path');
const { run } = require('./witrun.js');
const [BIN, ELF, DIR] = process.argv.slice(2);
const sh = (args) => JSON.parse(execFileSync(BIN, args, { maxBuffer: 1 << 28 }).toString());
let ok = 0, n = 0, units = 0, steps = 0;
for (const f of fs.readdirSync(DIR).filter(x => x.endsWith('.bin')).sort()) {
  const p = path.join(DIR, f); const real = sh(['real', p]); const wr = sh(['wroots', p]); const g = run(ELF, p);
  const same = real.hash === g.hash && JSON.stringify(real.ev) === JSON.stringify(g.ev) && real.applied === g.applied;
  const roots = JSON.stringify(wr.roots) === JSON.stringify(g.roots) && g.scratch_ok === 1;
  n++; if (same && roots && g.halted) ok++; units += g.units; steps += g.steps;
  console.log(JSON.stringify({ batch: f, units: g.units, engine_match: same, roots_match: roots, steps: g.steps, halted: g.halted }));
}
console.log(JSON.stringify({ batches: n, match: ok, units, steps }));
