#!/usr/bin/env python3
"""Loop round 23: guard mutants of the eager commit expiry (cexp:<u> groups, cmt: deletion, gcnt:0 commit count,
MAX_STATE_COMMITS mirrored; stateless.rs). Each mutant = a list of
(file, old, new) edits; it must be KILLED by one of the tests (status / root / events / unsound / ok:false).
usage (box): python3 loop23-mut.py /data/hark/spike-rv/loop23mut -> stdout (MUTDONE at the end); MUTS=a,b selects"""
import os, re, subprocess, sys
W = sys.argv[1]
A = os.path.join(W, 'guest-engine/src/stateless/adl.rs'); S = os.path.join(W, 'guest-engine/src/stateless.rs')
A2 = os.path.join(W, 'guest-engine/src/stateless/ora.rs'); L = os.path.join(W, 'guest-engine/src/lib.rs'); ST = os.path.join(W, 'guest-engine/src/state.rs')
ORIG = {f: open(f).read() for f in (A, S, A2, L, ST)}
T = '/data/hark/target-spike'
B = os.path.join(W, 'bin-mut/engine-diff')
ENV = dict(os.environ, CARGO_TARGET_DIR=T)
MUTS2 = [
  ('cexp-hook-off', S, """            cexp_hook(&sl, &eng.state)?;
""", ""),
  ('cexp-hook-ttl-check-off', S, """            if e.ttl_height != u {
                return Err(Err(ST_SL_BADWIT));
            }
            if !sl.acmt.contains_key(&e.account) {""", """            if !sl.acmt.contains_key(&e.account) {"""),
  ('cexp-hook-acmt-off', S, """            if !sl.acmt.contains_key(&e.account) {
                return Err(Ok(Need::Acmt(e.account)));
            }
        }
    }
    Ok(())""", """        }
    }
    Ok(())"""),
  ('cexp-hook-cmt-off', S, """            let Some(e) = sl.cmtx.get(h) else { return Err(Ok(Need::Cmt(*h))) };""", """            let Some(e) = sl.cmtx.get(h) else { continue };"""),
  ('cexp-hook-skip-h0', S, "    for u in h0..end {", "    for u in h0 + 1..end {"),
  ('cexp-hook-end-short', S, "    let end = s.height.min(h0.saturating_add(COMMIT_TTL_HEIGHTS + 1));", "    let end = s.height.min(h0.saturating_add(COMMIT_TTL_HEIGHTS));"),
  ('cmtx-del-off', S, """        if !s.commits.contains_key(h) {
            wit::cmt_kid(&mut b, h);
            dels.push(kid_key(&b));
        }""", """        let _ = h;"""),
  ('cmtx-del-recreated', S, """    for h in sl.cmtx.keys() {
        if !s.commits.contains_key(h) {""", """    for h in sl.cmtx.keys() {
        {"""),
  ('cmtx-insert-off', S, """            } else {
                sl.cmtx.insert(h, e);
            }""", """            }"""),
  ('cexp-end-expired-kept', S, """        let mut now: Vec<H> = Vec::new();
        if *u >= s.height {""", """        let mut now: Vec<H> = Vec::new();
        if true {"""),
  ('cexp-end-created-off', S, """                if e.ttl_height == *u && !sl.cmt0.contains(h) {
                    now.push(*h);
                }""", """                let _ = (h, e);"""),
  ('cexp-catchall-off', S, """                if !sl.cmt0.contains(h) && !sl.cx.contains_key(&e.ttl_height) {
                    return Err(Need::Cexp(e.ttl_height));
                }""", ""),
  ('cexp-load-check-off', S, """            cexp_leaf(&mut b, u, &hs);
            sl.check(&b, true)?;""", """            cexp_leaf(&mut b, u, &hs);"""),
  ('cexp-load-absent-off', S, """            cexp_kid(&mut b, u);
            sl.absent(&b)?;""", """            cexp_kid(&mut b, u);"""),
  ('cexp-load-order-off', S, """            if hs.last().is_some_and(|x| *x >= h) {
                return Err(ST_SL_BADWIT);
            }
            hs.push(h);""", """            hs.push(h);"""),
  ('acmt-rewrite-vs-live', S, """    for (id, all0) in &sl.acmt_all {""", """    for (id, all0) in &sl.acmt {"""),
  ('gcnt-commits-delta-off', S, "    d[4] = s.commits.len() as i64 - sl.cmt0.len() as i64 - cexp_gone(sl, s) as i64;", ""),
  ('gcnt-commits-gone-off', S, "    d[4] = s.commits.len() as i64 - sl.cmt0.len() as i64 - cexp_gone(sl, s) as i64;", "    d[4] = s.commits.len() as i64 - sl.cmt0.len() as i64;"),
  ('gcap-commit-off', S, "        B::Commit { ttl, .. } => now(4) < c.commits && (!ttl_ok(s, ttl) || cexp_now(sl, s, ttl) < c.commit_group),", ""),
  ('gcap-commit-total-off', S, "        B::Commit { ttl, .. } => now(4) < c.commits && (", "        B::Commit { ttl, .. } => ("),
  ('gcap-commit-le', S, "        B::Commit { ttl, .. } => now(4) < c.commits && (", "        B::Commit { ttl, .. } => now(4) <= c.commits && ("),
  ('gcap-group-off', S, "(!ttl_ok(s, ttl) || cexp_now(sl, s, ttl) < c.commit_group)", "(true || ttl_ok(s, ttl))"),
  ('gcap-group-le', S, "cexp_now(sl, s, ttl) < c.commit_group)", "cexp_now(sl, s, ttl) <= c.commit_group)"),
  ('cexp-now-created-off', S, "    g0 + s.commits.iter().filter(|(h, e)| e.ttl_height == u && !sl.cmt0.contains(*h)).count() as u64", "    let _ = s;\n    g0"),
  ('gcap-commit-cexp-need-off', S, """            if ttl_ok(s, ttl) && !sl.cx.contains_key(&ttl) {
                return Err(Ok(Need::Cexp(ttl)));
            }""", ""),
  ('gcap-commit-gcnt-off', S, """            false
        }
        B::Stake { .. } => {""", """            true
        }
        B::Stake { .. } => {"""),
  ('ttl-ok-upper-off', S, "    ttl > s.height && ttl <= s.height.saturating_add(COMMIT_TTL_HEIGHTS)", "    ttl > s.height"),
  # R23-H1 / R23-H2 fixes
  ('cmt-recs-bound-accounts', S, "pub const SL_MAX_CMT_RECS: usize = 2 * SL_MAX_CMT_LIVE;", "pub const SL_MAX_CMT_RECS: usize = SL_MAX_ACCOUNTS;"),
  ('ora-hook-limit-off', A2, """            if taken == SL_MAX_UNSTAKES {
                break 'q;
            }""", """            if taken == usize::MAX {
                break 'q;
            }"""),
  ('ora-prune-n-full', S, "            eng.state.prune_oracle_unbonding_n(h, ora::SL_MAX_UNSTAKES);", "            eng.state.prune_oracle_unbonding(h);"),
  ('session-bound-hook-full', L, "    s.prune_oracle_unbonding_n(height, MAX_UNSTAKES_PER_HEIGHT);\n    s.prune_commits(height);", "    s.prune_oracle_unbonding(height);\n    s.prune_commits(height);"),
  ('prune-n-order-desc', ST, "        due.sort_unstable();\n        due.truncate(max);", "        due.sort_unstable_by(|x, y| y.cmp(x));\n        due.truncate(max);"),
  ('mig-group-bound-off', S, " || cexp_groups(st).values().any(|g| g.len() as u64 > c.commit_group) {", " {"),
  ('mig-ttl-bound-off', S, "            if st.commits.values().any(|e| e.ttl_height < st.height || e.ttl_height > st.height.saturating_add(COMMIT_TTL_HEIGHTS)) ||", "            if false ||"),
  ('mig-count-bound-off', S, "|| g[3] > c.oracles || g[4] > c.commits {", "|| g[3] > c.oracles {"),
]
TESTS = [(['slpoc23'], 900), (['slpoc20'], 900), (['slcr', '6', '300', '0'], 900), (['slcr', '4', '300', '2'], 900), (['slcr', '3', '300', '1', 'adv'], 1200), (['slpoc22'], 600), (['slfuzz', '10', '300', 'perp'], 900), (['slmig', '5', '300', '0'], 900), (['slora', '10', '300', '40'], 900)]

def norm(m):
    return m[0], [(m[1], m[2], m[3])]
sel = os.environ.get('MUTS')
def run(cmd, t):
    try:
        return subprocess.run(cmd, cwd=W, capture_output=True, text=True, timeout=t).stdout
    except subprocess.TimeoutExpired:
        return 'TIMEOUT'
killed = 0; n = 0
os.makedirs(os.path.dirname(B), exist_ok=True)
try:
    for m in MUTS2:
        name, eds = norm(m)
        if sel and name not in sel.split(','):
            continue
        n += 1
        cur = dict(ORIG)
        bad = False
        for f, a, b in eds:
            if cur[f].count(a) != 1:
                print(f'{name}: PATTERN COUNT {cur[f].count(a)} in {os.path.basename(f)}', flush=True); bad = True; break
            cur[f] = cur[f].replace(a, b)
        if bad:
            continue
        for f in cur:
            open(f, 'w').write(cur[f])
        r = subprocess.run(['cargo', 'build', '--profile', 'l23m', '--features', 'stateless'], cwd=os.path.join(W, 'engine-diff'), env=ENV, capture_output=True, text=True)
        if r.returncode != 0:
            print(f'{name}: BUILD FAILED {r.stderr[-400:]}', flush=True); continue
        subprocess.run(['cp', os.path.join(T, 'l23m/engine-diff'), B])
        outs = []
        for args, t in TESTS:
            cmd = [B] + args
            o = run(cmd, t)
            outs.append(o)
            un = re.search(r'"(?:adv_)?unsound":(\d+)', o); bd = re.search(r'"bad_segments":(\d+)', o)
            nok = re.search(r'"batches":(\d+),"ok":(\d+)', o)
            if o == 'TIMEOUT' or 'panicked' in o or '"ok":false' in o or '"slpoc23":false' in o or (un and int(un.group(1)) > 0) or (bd and int(bd.group(1)) > 0) or (nok and nok.group(1) != nok.group(2)) or not o.strip():
                killed += 1
                print(f'{name}: KILLED by {" ".join(args)}: {o.strip()[:300]}', flush=True)
                break
        else:
            print(f'{name}: SURVIVED: {" | ".join(x.strip()[:160] for x in outs)}', flush=True)
finally:
    for f in ORIG:
        open(f, 'w').write(ORIG[f])
print(f'MUTDONE killed {killed} / {n}', flush=True)
