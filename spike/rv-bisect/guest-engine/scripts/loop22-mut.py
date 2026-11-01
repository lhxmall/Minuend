#!/usr/bin/env python3
"""Loop round 22: guard mutants of the stateless global caps (gcnt:0, stateless.rs) + the round-21 survivors that the
round-22 tests target (end-del-off: slpoc22 P0; load-absent-check-off: slpoc21 t_adrop 5). Each mutant = a list of
(file, old, new) edits; it must be KILLED by one of the tests (status / root / events / unsound / ok:false).
usage (box): python3 loop22-mut.py /data/hark/spike-rv/loop22mut -> stdout (MUTDONE at the end); MUTS=a,b selects"""
import os, re, subprocess, sys
W = sys.argv[1]
A = os.path.join(W, 'guest-engine/src/stateless/adl.rs'); S = os.path.join(W, 'guest-engine/src/stateless.rs')
ORIG = {f: open(f).read() for f in (A, S)}
T = '/data/hark/target-spike'
B = os.path.join(W, 'bin-mut/engine-diff')
ENV = dict(os.environ, CARGO_TARGET_DIR=T)
MUTS2 = [
  # round-21 survivors re-tested
  ('end-del-off', A, """        } else if *present {
            adlr_kid(&mut b, *m, *sd);
            dels.push(kid_key(&b));
        }""", """        } else if *present {
            let _ = &b;
        }"""),
  ('load-absent-check-off', A, """            adlr_kid(b, m, sd);
            sl.absent(b)?;""", """            adlr_kid(b, m, sd);"""),
  ('leftmost-skip-stub', A, "                p = if a == P::E { b } else { a };", "                p = if matches!(a, P::E | P::O(_)) { b } else { a };"),
  ('removed-count-off', A, "        *sl.adl.removed.entry((m, sd)).or_insert(0) += 1;", ""),
  ('insurance-in-tree', A, """    for a in dirty {
        if *a == INSURANCE_ACCOUNT {
            continue;
        }""", """    for a in dirty {"""),
  # round 22: gcnt
  ('gcnt-load-check-off', S, """            gcnt_leaf(&mut b, &g);
            sl.check(&b, true)?;
            sl.gcnt = Some(g);""", """            gcnt_leaf(&mut b, &g);
            sl.gcnt = Some(g);"""),
  ('gcnt-end-need-off', S, "        let Some(g0) = sl.gcnt else { return Err(Need::Gcnt) };", "        let g0 = sl.gcnt.unwrap_or([0; 4]);"),
  ('gcnt-end-put-off', S, """        gcnt_leaf(&mut b, &gcnt_add(&g0, &gd));
        puts.push(kh(&b));""", """        let _ = (g0, gd);"""),
  ('gcap-pre-need-off', S, """    if !member && sl.gcnt.is_none() {
        return Err(Ok(Need::Gcnt));
    }""", """    let _ = member;"""),
  ('gcap-ok-off', S, "                let rule_ok = |o: &crate::BatchOp| rule_ok(o) && gcap_ok(&sl, st, o, &a);", "                let rule_ok = |o: &crate::BatchOp| rule_ok(o);"),
  ('gcap-inner-off', S, """                match inner {
                    Some(io) => gcap_pre(&sl, &eng.state, &io, &a),
                    None => Ok(()),
                }""", """                Ok(())"""),
  ('gcap-acct-member-off', S, "        B::Deposit { .. } | B::Liquidate { .. } => s.accounts.contains_key(a) || now(0) < c.accounts,", "        B::Deposit { .. } | B::Liquidate { .. } => now(0) < c.accounts,"),
  ('gcap-perp-uses-acct', S, "        B::GovDeposit { .. } | B::GovWithdraw { .. } | B::Slash { .. } => s.perp_balances.contains_key(a) || now(1) < c.accounts,", "        B::GovDeposit { .. } | B::GovWithdraw { .. } | B::Slash { .. } => s.perp_balances.contains_key(a) || now(0) < c.accounts,"),
  ('gcap-stake-off', S, "        B::Stake { .. } => s.oracle_bonds.contains_key(a) || now(3) < c.oracles,", "        B::Stake { .. } => true,"),
  ('gcap-market-le', S, "        B::CreateMarket { .. } => now(2) < c.markets,", "        B::CreateMarket { .. } => now(2) <= c.markets,"),
  ('delta-acct-off', S, "        d[0] += s.accounts.contains_key(a) as i64 - (rec.f0 & 1) as i64;", ""),
  ('delta-perp-off', S, "        d[1] += s.perp_balances.contains_key(a) as i64 - ((rec.f0 >> 1) & 1) as i64;", ""),
  ('delta-mkt-off', S, "        d[2] += s.markets.contains_key(&MarketId(*m)) as i64 - *p0 as i64;", ""),
  ('delta-bond-off', S, "        d[3] += s.oracle_bonds.contains_key(a) as i64 - sl.o.bonds0.contains_key(a) as i64;", ""),
  ('f0-full-zero', S, """            f0 = flags;
""", ""),
  ('f0-light-zero', S, "sl.accts.insert(id, AcctRec { present: true, f0: flags, start_pos, light: Some((flags, npos, dg)) });", "sl.accts.insert(id, AcctRec { present: true, f0: 0, start_pos, light: Some((flags, npos, dg)) });"),
  ('catchall-acct-off', S, """    for a in s.accounts.keys().chain(s.perp_balances.keys()) {
        if !sl.accts.contains_key(a) {
            return Err(Need::Account(*a));
        }
    }""", ""),
  ('catchall-mkt-off', S, """    for m in s.markets.keys() {
        if !sl.markets.contains_key(&m.0) {
            return Err(Need::Market(m.0));
        }
    }""", ""),
]
TESTS = [(['slpoc22'], 600), (['slpoc21', '6', '300', '8', '200'], 600), (['slfuzz', '10', '300'], 900), (['slfuzz', '6', '300', 'ora'], 900), (['slfuzz', '10', '300', 'gov'], 900), (['slmig', '5', '300', '0'], 900), (['sladv', '2', '200', 'gov'], 900), (['slora', '10', '300', '40'], 900)]

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
        r = subprocess.run(['cargo', 'build', '--profile', 'l22m', '--features', 'stateless'], cwd=os.path.join(W, 'engine-diff'), env=ENV, capture_output=True, text=True)
        if r.returncode != 0:
            print(f'{name}: BUILD FAILED {r.stderr[-400:]}', flush=True); continue
        subprocess.run(['cp', os.path.join(T, 'l22m/engine-diff'), B])
        outs = []
        for args, t in TESTS:
            cmd = [B] + args
            o = run(cmd, t)
            outs.append(o)
            un = re.search(r'"(?:adv_)?unsound":(\d+)', o); bd = re.search(r'"bad_segments":(\d+)', o)
            nok = re.search(r'"batches":(\d+),"ok":(\d+)', o)
            if o == 'TIMEOUT' or 'panicked' in o or '"ok":false' in o or (un and int(un.group(1)) > 0) or (bd and int(bd.group(1)) > 0) or (nok and nok.group(1) != nok.group(2)) or not o.strip():
                killed += 1
                print(f'{name}: KILLED by {" ".join(args)}: {o.strip()[:300]}', flush=True)
                break
        else:
            print(f'{name}: SURVIVED: {" | ".join(x.strip()[:160] for x in outs)}', flush=True)
finally:
    for f in ORIG:
        open(f, 'w').write(ORIG[f])
print(f'MUTDONE killed {killed} / {n}', flush=True)
