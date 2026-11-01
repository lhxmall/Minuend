#!/usr/bin/env python3
"""Loop round 18: guard mutants of the stateless governance code (pglob: / pexc: / prop: counts, Finalize completeness,
PERP balance-change guard, R6-H2). Each mutant must be KILLED: slpoc18 not ok, sladv gov unsound, or slfuzz gov a bad
segment. usage (box): python3 loop18-mut.py /data/hark/spike-rv/loop18mut  -> stdout (MUTDONE at the end)"""
import os, re, subprocess, sys
W = sys.argv[1]; SRC = os.path.join(W, 'guest-engine/src/stateless.rs'); ORIG = open(SRC).read()
B = '/data/hark/target-l18mut/release/engine-diff'
ENV = dict(os.environ, CARGO_TARGET_DIR='/data/hark/target-l18mut')
MUTS = [
  ('finalize-count-off', 'if have != nx {', 'if false {'),
  ('balance-guard-off', 'if eng.state.perp_balances.get(a).copied().unwrap_or(0) != *b0 {', 'if false {'),
  ('vote-pexc-off', """            need_gov(sl, Some(&author))?;
        }
        // finalize""", """            need_gov(sl, None)?;
        }
        // finalize"""),
  ('populate-voted-off', """            if v {
                p.voted.insert(*a);
            }""", ''),
  ('populate-weight-zero', '.unwrap_or((bal, false));', '.unwrap_or((0, false));'),
  ('r6h2-off', 'vn < sn + crate::MAX_ZERO_VOTERS', 'true'),
  ('new-prop-snap-count+1', 'sl.pcnt.insert(id, (0, h, 0));', 'sl.pcnt.insert(id, (0, h + 1, 0));'),
  ('pexc-without-pglob', 'if !sl.pexc.is_empty() && sl.pglob.is_none() {', 'if false {'),
  ('vote-count-delta-off', 'vn0 + p.voted.len() - pv0, sn);', 'vn0, sn);'),
  ('create-pglob-off', """        CreateProposal { market, .. } => {
            need_acct(sl, s, &author).map_err(Ok)?;
            need_gov(sl, None)?;""", """        CreateProposal { market, .. } => {
            need_acct(sl, s, &author).map_err(Ok)?;"""),
]
sel = os.environ.get('MUTS')
def run(cmd, t):
    try:
        return subprocess.run(cmd, cwd=W, capture_output=True, text=True, timeout=t).stdout
    except subprocess.TimeoutExpired:
        return 'TIMEOUT'
killed = 0; n = 0
try:
    for name, a, b in MUTS:
        if sel and name not in sel.split(','):
            continue
        n += 1
        pairs = a if isinstance(a, list) else [(a, b)]
        bad = [x for x, _ in pairs if ORIG.count(x) != 1]
        if bad:
            print(f'{name}: PATTERN COUNT {[ORIG.count(x) for x in bad]}', flush=True); continue
        src = ORIG
        for x, y in pairs:
            src = src.replace(x, y)
        open(SRC, 'w').write(src)
        r = subprocess.run(['cargo', 'build', '--release', '--features', 'stateless'], cwd=os.path.join(W, 'engine-diff'), env=ENV, capture_output=True, text=True)
        if r.returncode != 0:
            print(f'{name}: BUILD FAILED {r.stderr[-400:]}', flush=True); continue
        outs = []
        for cmd, t in [([B, 'slpoc18', '200'], 300), ([B, 'slfuzz', '20', '300', 'gov'], 900), ([B, 'sladv', '4', '300', 'gov'], 900), ([B, 'slfuzz', '20', '1000', 'gov'], 900)]:
            o = run(cmd, t)
            outs.append(o)
            un = re.search(r'"unsound":(\d+)', o); bad = re.search(r'"bad_segments":(\d+)', o)
            if o == 'TIMEOUT' or 'panicked' in o or '"ok":false' in o or (un and int(un.group(1)) > 0) or (bad and int(bad.group(1)) > 0) or not o.strip():
                killed += 1
                print(f'{name}: KILLED by {" ".join(cmd[1:])}: {o.strip()[:300]}', flush=True)
                break
        else:
            print(f'{name}: SURVIVED: {" | ".join(x.strip()[:160] for x in outs)}', flush=True)
finally:
    open(SRC, 'w').write(ORIG)
print(f'MUTDONE killed {killed} / {n}', flush=True)
