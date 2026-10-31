#!/usr/bin/env python3
"""Loop round 14: guard mutants of the stateless prototype (guest-engine/src/stateless.rs). Each mutant must be KILLED
by the harness: sladv reports an unsound case, or slfuzz (gen / adv / ora) reports a bad segment.
usage (box): python3 loop14-mut.py /data/hark/spike-rv/loop14  -> stdout (MUTDONE at the end)"""
import os, re, shutil, subprocess, sys
W = sys.argv[1]; SRC = os.path.join(W, 'guest-engine/src/stateless.rs'); ORIG = open(SRC).read()
B = '/data/hark/target-l14-mut/release/engine-diff'
ENV = dict(os.environ, CARGO_TARGET_DIR='/data/hark/target-l14-mut')
MUTS = [
  ('walk-check-off', 'walk_check(&sl, m.0, ts.opposite().as_u8(), *last)?;', 'let _ = (m, ts, last);'),
  ('dirty-acct-guard-off', '''                if !sl.accts.contains_key(a) {
                    return Err(Need::Account(*a));
                }
            }
            for m in &d.markets {''', '''                let _ = a;
            }
            for m in &d.markets {'''),
  ('own-orders-pre-off', 'need_aord_full(sl, &author).map_err(Ok)?;', ''),
  ('trie-update-off', 'trie_set(&mut sl, mm, sd, p, now)?;', 'let _ = &mut sl;'),
  ('collapse-opaque-ok', '[P::O(_), P::E] | [P::E, P::O(_)] => Err(()),', ''),
  ('resting-trie-check-off', '''                    if trie_has(&sl, mm, sd, p)? {
                        return Err(Need::Level(mm, sd, p));
                    }''', ''),
  ('oracled-not-loaded', 'if orc {', 'if orc && false {'),
  # both resting-level checks (the GTC pre-guard makes the post check alone redundant: equivalent mutant)
  ('resting-level-checks-off', [('''                if price != 0 && !sl.levels.contains_key(&(market, side.as_u8(), price)) {''', '''                if false && price != 0 && !sl.levels.contains_key(&(market, side.as_u8(), price)) {'''),
      ('''                    if trie_has(&sl, mm, sd, p)? {
                        return Err(Need::Level(mm, sd, p));
                    }''', '')], None),
  ('C1-unverified-absent', 'else if v { Look::Absent } else { Look::Unknown }', 'else { Look::Absent }'),
  ('lvl-digest-skipped', '''        lvl_leaf(&mut b, m, sd, price, &ids);
        sl.leaf_hashes += k as u64 / 2; // ids digest (64 B per 2 ids ~ one compression each)
        sl.check(&b, true)?;''', '''        lvl_leaf(&mut b, m, sd, price, &ids);
        sl.leaf_hashes += k as u64 / 2; // ids digest (64 B per 2 ids ~ one compression each)
        let _ = sl.check(&b, true);'''),
  ('cancel-order-pre-off', '''            if !sl.oloc.contains_key(&oid) && !sl.ordx.contains(&oid) {
                return Err(Ok(Need::Order(oid)));
            }''', 'let _ = oid;'),
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
        for cmd, t in [([B, 'sladv', '6', '120'], 900), ([B, 'slfuzz', '40', '300'], 900), ([B, 'slfuzz', '60', '200', 'adv'], 900), ([B, 'slfuzz', '30', '300', 'ora'], 900)]:
            o = run(cmd, t)
            outs.append(o)
            un = re.search(r'"unsound":(\d+)', o); bad = re.search(r'"bad_segments":(\d+)', o)
            if o == 'TIMEOUT' or 'panicked' in o or (un and int(un.group(1)) > 0) or (bad and int(bad.group(1)) > 0) or not o.strip():
                killed += 1
                print(f'{name}: KILLED by {" ".join(cmd[1:])}: {o.strip()[:300]}', flush=True)
                break
        else:
            print(f'{name}: SURVIVED: {" | ".join(x.strip()[:200] for x in outs)}', flush=True)
finally:
    open(SRC, 'w').write(ORIG)
print(f'MUTDONE killed {killed} / {n}', flush=True)
