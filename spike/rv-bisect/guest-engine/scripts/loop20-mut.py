#!/usr/bin/env python3
"""Loop round 20: guard mutants of the stateless ORACLE code (stateless/ora.rs + the hook / funding wiring in stateless.rs).
Each mutant must be KILLED: slpoc20 not ok, slora a bad segment / adv unsound, or slfuzz ora / liq a bad segment.
usage (box): python3 loop20-mut.py /data/hark/spike-rv/loop20mut  -> stdout (MUTDONE at the end)
Builds in the shared CARGO_TARGET_DIR /data/hark/target-spike (user rule, round 19)."""
import os, re, subprocess, sys
W = sys.argv[1]
ORA = os.path.join(W, 'guest-engine/src/stateless/ora.rs'); SLR = os.path.join(W, 'guest-engine/src/stateless.rs')
ORIG = {ORA: open(ORA).read(), SLR: open(SLR).read()}
T = '/data/hark/target-spike'
B = os.path.join(W, 'bin-mut/engine-diff')
ENV = dict(os.environ, CARGO_TARGET_DIR=T)
O, S = ORA, SLR
MUTS = [
  ('hook-off-by-one', O, '        if u > s.height {\n            break;\n        }', '        if u >= s.height {\n            break;\n        }'),
  ('hook-stk-off', O, """        for a in &grp.2 {
            need_stk(sl, a)?;""", """        for a in &grp.2 {"""),
  ('hook-acct-off', O, """            if !sl.accts.contains_key(a) {
                return Err(Ok(Need::Account(*a)));
            }""", ''),
  ('gone-off', O, '    sl.o.gone.extend(gone);', '    let _ = gone;'),
  ('post-a-off', O, """        if s.oracle_bonds.get(a) != sl.o.bonds0.get(a) || s.oracle_unbonding.get(a) != sl.o.unb0.get(a) {""", """        if false {"""),
  ('post-b-off', O, """        if s.oracle_bonds.contains_key(a) != sl.o.bonds0.contains_key(a) {
            let Some(l)""", """        if false {
            let Some(l)"""),
  ('post-c-orep-off', O, """    for (m, a) in &pairs {
        if !sl.o.rep.contains_key(&m.0) {
            return nd(Need::Orep(m.0));
        }""", """    for (m, a) in &pairs {"""),
  ('post-c-orm-off', O, """        for a in now.symmetric_difference(&was) {
            if !sl.o.rm.contains_key(a) {""", """        for a in now.symmetric_difference(&was) {
            if false {"""),
  ('post-d-off', O, """        if !sl.o.mk.contains(&m.0) {
            return nd(Need::Omk(m.0));
        }
    }""", """        let _ = m;
    }"""),
  ('post-e-off', O, 'if oracled(s, MarketId(*m)) != *o0 && !sl.markets.contains_key(m) {', 'if false {'),
  ('sync-unlink-prev-off', O, '                    gp.1 = n;', '                    let _ = (&gp, n);'),
  ('sync-tail-link-off', O, '                        gt.1 = Some(u);', '                        let _ = &gt;'),
  ('sync-off', O, """    if ch.is_empty() {
        return Ok(());
    }""", """    if true {
        return Ok(());
    }"""),
  ('pre-report-orep-off', O, """    if !sl.o.rep.contains_key(&market) {
        return nd(Need::Orep(market));
    }
    if !sl.o.hist.contains(&(market, *a)) {""", """    if !sl.o.hist.contains(&(market, *a)) {"""),
  ('pre-report-ohist-off', O, """    if !sl.o.hist.contains(&(market, *a)) {
        return nd(Need::Ohist(market, *a));
    }
    if !sl.o.rm.contains_key(a) {
        return nd(Need::Orm(*a));
    }
    if !sl.o.mk""", """    if !sl.o.rm.contains_key(a) {
        return nd(Need::Orm(*a));
    }
    if !sl.o.mk"""),
  ('pre-report-omk-off', O, """    if !sl.o.mk.contains(&market) {
        return nd(Need::Omk(market));
    }
    Ok(())""", """    Ok(())"""),
  ('pre-report-orm-off', O, """    if !sl.o.rm.contains_key(a) {
        return nd(Need::Orm(*a));
    }
    if !sl.o.mk""", """    if !sl.o.mk"""),
  ('pre-stake-off', O, """pub(super) fn pre_stake(sl: &Sl, s: &ChainState, a: &AccountId, unstake: bool) -> G {
    need_stk(sl, a)?;""", """pub(super) fn pre_stake(sl: &Sl, s: &ChainState, a: &AccountId, unstake: bool) -> G {"""),
  ('load-flag-check-off', O, '                if s.oracle_bonds.contains_key(o) != *bd {', '                if false {'),
  ('load-pseudo-keep', O, 'let pseudo = s.oracle_reports.remove(&(mid, pseudo_oracle())).is_some();', 'let pseudo = s.oracle_reports.contains_key(&(mid, pseudo_oracle()));'),
  ('load-placeholder-off', O, '                s.oracle_bonds.insert(*o, crate::types::ORACLE_BOND_PERP);', '                let _ = o;'),
  ('hist-verify-off', O, 'if hn as usize != k || dg != hist_digest(Some(&q)) {', 'if false {'),
  ('entries-gone-off', O, '*n > 0 && !sl.o.hist.contains(&(m, *o)) && !sl.o.gone.contains(o)', '*n > 0 && !sl.o.hist.contains(&(m, *o))'),
  ('cap-unstake-off', O, 'sl.o.exp.get(&u).map(|g| g.2.len()).unwrap_or(0) < SL_MAX_UNSTAKES', 'true'),
  ('cap-reporters-off', O, 'if !es.iter().any(|e| e.0 == *a) && es.len() >= SL_MAX_REPORTERS {', 'if false {'),
  ('cap-mkts-off', O, 'now.contains(&market) || now.len() < SL_MAX_ORACLE_MKTS', 'true'),
  ('end-oexp-del-off', O, """        if !sl.o.exp.contains_key(u) {
            oexp_kid(&mut b, *u);""", """        if false {
            oexp_kid(&mut b, *u);"""),
  ('end-ostk-del-off', O, """        if bd.is_none() && u.is_none() {
            ostk_kid(&mut b, a);
            dels.push(kid_key(&b));
        }""", """        if bd.is_none() && u.is_none() {
        }"""),
  ('funding-flag-off', S, '        if unsafe { SL_FUNDING_REACHED } {', '        if false {'),
  ('hook-off', S, '    if eng.state.height > sl.o.h0 {', '    if false {'),
  ('hook-balance-guard-off', S, """            for (a, b0) in &sl.bal0 {
                if eng.state.perp_balances.get(a).copied().unwrap_or(0) != *b0 {
                    if sl.pglob.is_none() {
                        return Err(Ok(Need::Pglob));""", """            for (a, b0) in &sl.bal0 {
                if false && eng.state.perp_balances.get(a).copied().unwrap_or(0) != *b0 {
                    if sl.pglob.is_none() {
                        return Err(Ok(Need::Pglob));"""),
]
sel = os.environ.get('MUTS')
def run(cmd, t):
    try:
        return subprocess.run(cmd, cwd=W, capture_output=True, text=True, timeout=t).stdout
    except subprocess.TimeoutExpired:
        return 'TIMEOUT'
killed = 0; n = 0
os.makedirs(os.path.dirname(B), exist_ok=True)
try:
    for name, f, a, b in MUTS:
        if sel and name not in sel.split(','):
            continue
        n += 1
        if ORIG[f].count(a) != 1:
            print(f'{name}: PATTERN COUNT {ORIG[f].count(a)}', flush=True); continue
        for g in ORIG:
            open(g, 'w').write(ORIG[g])
        open(f, 'w').write(ORIG[f].replace(a, b))
        r = subprocess.run(['cargo', 'build', '--release', '--features', 'stateless'], cwd=os.path.join(W, 'engine-diff'), env=ENV, capture_output=True, text=True)
        if r.returncode != 0:
            print(f'{name}: BUILD FAILED {r.stderr[-400:]}', flush=True); continue
        subprocess.run(['cp', os.path.join(T, 'release/engine-diff'), B])
        outs = []
        for cmd, t in [([B, 'slpoc20'], 300), ([B, 'slora', '10', '300', '40'], 900), ([B, 'slora', '4', '200', '40', 'adv'], 900), ([B, 'slora', '10', '300', '300'], 900), ([B, 'slfuzz', '20', '300', 'ora'], 900), ([B, 'slmig', '10', '300', '5'], 900), ([B, 'slfuzz', '6', '300', 'liq'], 900)]:
            o = run(cmd, t)
            outs.append(o)
            un = re.search(r'"(?:adv_)?unsound":(\d+)', o); bad = re.search(r'"bad_segments":(\d+)', o)
            nok = re.search(r'"batches":(\d+),"ok":(\d+)', o)
            if o == 'TIMEOUT' or 'panicked' in o or '"ok":false' in o or (un and int(un.group(1)) > 0) or (bad and int(bad.group(1)) > 0) or (nok and nok.group(1) != nok.group(2)) or not o.strip():
                killed += 1
                print(f'{name}: KILLED by {" ".join(cmd[1:])}: {o.strip()[:300]}', flush=True)
                break
        else:
            print(f'{name}: SURVIVED: {" | ".join(x.strip()[:160] for x in outs)}', flush=True)
finally:
    for g in ORIG:
        open(g, 'w').write(ORIG[g])
print(f'MUTDONE killed {killed} / {n}', flush=True)
