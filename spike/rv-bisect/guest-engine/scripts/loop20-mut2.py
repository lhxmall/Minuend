#!/usr/bin/env python3
"""Loop round 20, pass 2 (final code): slash guards, the R20-L1 session rule, the revealed-Slash refusal, the history-sample
check (forge20:ohist-samples) and the pre / post guard PAIRS whose single mutants survive pass 1 (defence in depth: a
Report's records are required by pre_report AND by the post guards (c) / (d); the hook's account record by hook_pre AND
the dirty-account guard). Each mutant = a list of (file, old, new) edits; must be KILLED (as loop20-mut.py).
usage (box): python3 loop20-mut2.py /data/hark/spike-rv/loop20mut2 -> stdout (MUTDONE at the end)"""
import os, re, subprocess, sys
W = sys.argv[1]
O = os.path.join(W, 'guest-engine/src/stateless/ora.rs'); S = os.path.join(W, 'guest-engine/src/stateless.rs'); L = os.path.join(W, 'guest-engine/src/lib.rs')
ORIG = {f: open(f).read() for f in (O, S, L)}
T = '/data/hark/target-spike'
B = os.path.join(W, 'bin-mut/engine-diff')
ENV = dict(os.environ, CARGO_TARGET_DIR=T)
MUTS2 = [
  ('pre-slash-stk-off', O, """    let Some(present) = sl.markets.get(&market) else { return nd(Need::Market(market)) };
    need_stk(sl, t)?;""", """    let Some(present) = sl.markets.get(&market) else { return nd(Need::Market(market)) };"""),
  ('pre-slash-omk-off', O, """    if !sl.o.mk.contains(&market) {
        return nd(Need::Omk(market));
    }
    if !sl.o.rep.contains_key(&market) {
        return nd(Need::Orep(market));
    }
    if !sl.o.hist.contains(&(market, *t)) {""", """    if !sl.o.rep.contains_key(&market) {
        return nd(Need::Orep(market));
    }
    if !sl.o.hist.contains(&(market, *t)) {"""),
  ('pre-slash-hist-off', O, """    if !sl.o.hist.contains(&(market, *t)) {
        return nd(Need::Ohist(market, *t));
    }""", ''),
  ('reveal-slash-unsup-off', S, """                    Some(crate::BatchOp::Slash { .. }) if runs => Err(Err(ST_SL_UNSUPPORTED)),""", ''),
  ('session-unstake-cap-off', L, """< MAX_UNSTAKES_PER_HEIGHT
        }""", """< usize::MAX
        }"""),
  ('hist-verify-off', O, 'if hn as usize != k || dg != hist_digest(Some(&q)) {', 'if false {'),
  ('report-orep-both-off', O, [("""    if !sl.o.rep.contains_key(&market) {
        return nd(Need::Orep(market));
    }
    if !sl.o.hist.contains(&(market, *a)) {""", """    if !sl.o.hist.contains(&(market, *a)) {"""), ("""    for (m, a) in &pairs {
        if !sl.o.rep.contains_key(&m.0) {
            return nd(Need::Orep(m.0));
        }""", """    for (m, a) in &pairs {""")]),
  ('report-ohist-both-off', O, [("""    if !sl.o.hist.contains(&(market, *a)) {
        return nd(Need::Ohist(market, *a));
    }
    if !sl.o.rm""", """    if !sl.o.rm"""), ("""        if s.oracle_report_history.contains_key(&(*m, *a)) && !sl.o.hist.contains(&(m.0, *a)) {""", """        if false {""")]),
  ('report-omk-both-off', O, [("""    if !sl.o.mk.contains(&market) {
        return nd(Need::Omk(market));
    }
    Ok(())
}
/// Slash (step 3)""", """    Ok(())
}
/// Slash (step 3)"""), ("""        if !sl.o.mk.contains(&m.0) {
            return nd(Need::Omk(m.0));
        }
    }""", """        let _ = m;
    }""")]),
  ('report-orm-both-off', O, [("""    if !sl.o.rm.contains_key(a) {
        return nd(Need::Orm(*a));
    }
    if !sl.o.mk.contains(&market) {
        return nd(Need::Omk(market));
    }
    Ok(())
}
/// Slash (step 3)""", """    if !sl.o.mk.contains(&market) {
        return nd(Need::Omk(market));
    }
    Ok(())
}
/// Slash (step 3)"""), ("""        for a in now.symmetric_difference(&was) {
            if !sl.o.rm.contains_key(a) {""", """        for a in now.symmetric_difference(&was) {
            if false {""")]),
  ('hook-acct-both-off', S, [("""            for a in &d.accounts {
                if !sl.accts.contains_key(a) {
                    return Err(Ok(Need::Account(*a)));
                }
            }
            for (a, b0) in &sl.bal0 {
                if eng.state.perp_balances.get(a).copied().unwrap_or(0) != *b0 {
                    if sl.pglob.is_none() {
                        return Err(Ok(Need::Pglob));""", """            let _ = &d;
            for (a, b0) in &sl.bal0 {
                if eng.state.perp_balances.get(a).copied().unwrap_or(0) != *b0 {
                    if sl.pglob.is_none() {
                        return Err(Ok(Need::Pglob));""")], O, [("""            if !sl.accts.contains_key(a) {
                return Err(Ok(Need::Account(*a)));
            }""", '')]),
]

def norm(m):
    name = m[0]
    if isinstance(m[2], list):
        eds = [(m[1], a, b) for a, b in m[2]]
        if len(m) > 3:
            eds += [(m[3], a, b) for a, b in m[4]]
        return name, eds
    return name, [(m[1], m[2], m[3])]
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
        r = subprocess.run(['cargo', 'build', '--release', '--features', 'stateless'], cwd=os.path.join(W, 'engine-diff'), env=ENV, capture_output=True, text=True)
        if r.returncode != 0:
            print(f'{name}: BUILD FAILED {r.stderr[-400:]}', flush=True); continue
        subprocess.run(['cp', os.path.join(T, 'release/engine-diff'), B])
        outs = []
        for cmd, t in [([B, 'slpoc20'], 300), ([B, 'slora', '10', '300', '40'], 900), ([B, 'slora', '4', '200', '40', 'adv'], 900), ([B, 'slora', '10', '300', '1'], 900), ([B, 'slfuzz', '20', '300', 'ora'], 900), ([B, 'slmig', '10', '300', '5'], 900), ([B, 'slfuzz', '6', '300', 'liq'], 900)]:
            o = run(cmd, t)
            outs.append(o)
            un = re.search(r'"(?:adv_)?unsound":(\d+)', o); bd = re.search(r'"bad_segments":(\d+)', o)
            nok = re.search(r'"batches":(\d+),"ok":(\d+)', o)
            if o == 'TIMEOUT' or 'panicked' in o or '"ok":false' in o or (un and int(un.group(1)) > 0) or (bd and int(bd.group(1)) > 0) or (nok and nok.group(1) != nok.group(2)) or not o.strip():
                killed += 1
                print(f'{name}: KILLED by {" ".join(cmd[1:])}: {o.strip()[:300]}', flush=True)
                break
        else:
            print(f'{name}: SURVIVED: {" | ".join(x.strip()[:160] for x in outs)}', flush=True)
finally:
    for f in ORIG:
        open(f, 'w').write(ORIG[f])
print(f'MUTDONE killed {killed} / {n}', flush=True)
