// Loop round 1 (findings/rv-loop-1.md G1/G2): malformed / limit batches through the riscv32im guest
// (JS model) vs the host port (`engine-diff portout`, same mnpilot code natively). Every batch must
// HALT normally (no trap, no abort) and agree with the host on status, hash, counters, event log
// and every per-unit root; the step count must stay bounded.
// usage: node robust.js <engine-diff> <rvengine elf> <dir> [maxSteps]
const { execFileSync } = require('child_process'); const fs = require('fs'); const path = require('path');
const { run } = require('./witrun.js');
const [BIN, ELF, DIR, MAXS] = process.argv.slice(2); const maxSteps = MAXS ? Number(MAXS) : 2e10;
let ok = 0, n = 0;
for (const f of fs.readdirSync(DIR).filter(x => x.endsWith('.bin')).sort()) {
  const p = path.join(DIR, f);
  const h = JSON.parse(execFileSync(BIN, ['portout', p], { maxBuffer: 1 << 30 }).toString());
  const g = run(ELF, p, maxSteps);
  const same = g.halted && !g.trapped && g.a0 !== 77 && g.status === h.status && g.hash === h.hash && g.applied === h.applied &&
    g.rejected === h.rejected && g.fills === h.fills && JSON.stringify(g.ev) === JSON.stringify(h.ev) &&
    JSON.stringify(g.roots) === JSON.stringify(h.roots) && g.ev_overflow === 0 && (h.status !== 0 || g.scratch_ok === 1);
  n++; if (same) ok++;
  console.log(JSON.stringify({ batch: f, match: same, status: g.status, host_status: h.status, halted: g.halted, trapped: g.trapped, a0: g.a0,
    units: g.units, applied: g.applied, rejected: g.rejected, steps: g.steps, heap: g.heap, heap_peak_live: g.heap_peak_live, ms: g.ms }));
}
console.log(JSON.stringify({ batches: n, match: ok }));
