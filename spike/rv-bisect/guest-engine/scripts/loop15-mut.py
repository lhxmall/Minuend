#!/usr/bin/env python3
"""Loop round 15: guard mutants of the round-15 stateless code (light insurance record R14-M2, wdl: withdrawal records,
lazy expiry). Each mutant must be KILLED: slpoc15 not ok, sladv (gen / wd) unsound, or slfuzz (gen / wd) a bad segment.
usage (box): python3 loop15-mut.py /data/hark/spike-rv/loop15mut  -> stdout (MUTDONE at the end)"""
import os, re, subprocess, sys
W = sys.argv[1]; SRC = os.path.join(W, 'guest-engine/src/stateless.rs'); ORIG = open(SRC).read()
B = '/data/hark/target-l15-mut/release/engine-diff'
ENV = dict(os.environ, CARGO_TARGET_DIR='/data/hark/target-l15-mut')
UPD = [('P::L(_, _, false) => Err(()),\n            P::L(k2, lh2, true) => {', 'P::L(k2, lh2, _) => {'),
       ('P::L(_, _, false) => Err(()),\n            P::L(k, _, true) =>', 'P::L(k, _, _) =>')]
MUTS = [
  ('light-any-account', '''            if id != INSURANCE_ACCOUNT {
                return Err(ST_SL_BADWIT);
            }''', ''),
  ('light-apos-unchecked', '''            apos_leaf_d(&mut b, &id, flags, npos, &dg);
            sl.check(&b, true)?;''', '''            apos_leaf_d(&mut b, &id, flags, npos, &dg);
            let _ = sl.check(&b, true);'''),
  ('light-apos-unchecked+update-unverified', [('''            apos_leaf_d(&mut b, &id, flags, npos, &dg);
            sl.check(&b, true)?;''', '''            apos_leaf_d(&mut b, &id, flags, npos, &dg);
            let _ = sl.check(&b, true);''')] + UPD, None),
  ('light-acct-unchecked+update-unverified', [('''            wit::acct_leaf(&mut b, &id, coll, perp, wd);
            sl.check(&b, true)?;
            apos_leaf_d(''', '''            wit::acct_leaf(&mut b, &id, coll, perp, wd);
            let _ = sl.check(&b, true);
            apos_leaf_d(''')] + UPD, None),
  ('light-end-check-off', 'if flags != f0 || a.is_some_and(|a| !a.positions.is_empty() || !a.isolated_margin.is_empty()) {', 'if false {'),
  ('wdl-pre-off', '''            if !sl.wdl.contains_key(&author) {
                return Err(Ok(Need::Wdl(author)));
            }''', ''),
  ('wdl-pre+post-off', [('''            if !sl.wdl.contains_key(&author) {
                return Err(Ok(Need::Wdl(author)));
            }''', ''), ('''                if !sl.wdl.contains_key(a) {
                    return Err(Need::Wdl(*a));
                }''', 'let _ = a;')], None),
  ('wdl-unchecked+update-unverified', [('''            wdl_leaf(&mut b, &id, &es);
            sl.check(&b, true)?;''', '''            wdl_leaf(&mut b, &id, &es);
            let _ = sl.check(&b, true);''')] + UPD, None),
  ('wdl-expiry-filter-off', '.filter(|e| e.3.saturating_add(REPLAY_WINDOW) > s.height)', ''),
  ('wdl-rewrite-always', '        if now != *live0 {', '        if true {'),
  ('withdraw-aord-pre-off', '''            need_aord_full(sl, &author).map_err(Ok)?;
            for m in s.books.keys() {
                if !sl.markets.contains_key(&m.0) {
                    return Err(Ok(Need::Market(m.0)));
                }
            }
            if s.accounts.get(&author).is_some_and(|a| a.positions.keys().any(''', '''            if s.accounts.get(&author).is_some_and(|a| a.positions.keys().any('''),
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
        for cmd, t in [([B, 'slpoc15'], 300), ([B, 'sladv', '6', '120', 'wd'], 900), ([B, 'slfuzz', '40', '300', 'wd'], 900), ([B, 'sladv', '6', '120'], 900), ([B, 'slfuzz', '30', '300'], 900)]:
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
