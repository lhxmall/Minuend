#!/usr/bin/env python3
"""Loop round 21: guard mutants of the stateless ADL (stateless/adl.rs + the run-loop wiring in stateless.rs). Each mutant
= a list of (file, old, new) edits; it must be KILLED by one of the tests (status / root / events / unsound / ok:false).
usage (box): python3 loop21-mut.py /data/hark/spike-rv/loop21mut -> stdout (MUTDONE at the end); MUTS=a,b selects"""
import os, re, subprocess, sys
W = sys.argv[1]
A = os.path.join(W, 'guest-engine/src/stateless/adl.rs'); S = os.path.join(W, 'guest-engine/src/stateless.rs')
ORIG = {f: open(f).read() for f in (A, S)}
T = '/data/hark/target-spike'
B = os.path.join(W, 'bin-mut/engine-diff')
ENV = dict(os.environ, CARGO_TARGET_DIR=T)
MUTS2 = [
  ('pick-tree-need-off', A, "let Some((_, t)) = sl.adl.t.get(&(m, sd)) else { return Err(Ok(Need::Adl(m, sd))) };", "let Some((_, t)) = sl.adl.t.get(&(m, sd)) else { return Ok(None) };"),
  ('pick-top-acct-off', A, """    match sl.accts.get(&a) {
        Some(r) if r.light.is_none() => {}
        _ => return Err(Ok(Need::Account(a))),
    }""", ''),
  ('pick-cur-check-off', A, "        Some((sd2, q)) if *sd2 == sd && rkey(*q, &a) == k => Ok(Some(a)),", "        Some(_) => Ok(Some(a)),"),
  ('leftmost-unverified-ok', A, "            P::L(k, _, v) => return if v { Ok(Some(k)) } else { Err(()) },", "            P::L(k, _, _) => return Ok(Some(k)),"),
  ('leftmost-skip-stub', A, "                p = if a == P::E { b } else { a };", "                p = if matches!(a, P::E | P::O(_)) { b } else { a };"),
  ('adl-check-off', S, """        if adl {
            let (am, asd) = unsafe { SL_ADL_SIDE };""", """        if false {
            let (am, asd) = unsafe { SL_ADL_SIDE };"""),
  ('fill-maker-check-off', S, "if f.iter().any(|x| x.kind == 2 && Some(x.maker) != top) {", "if false {"),
  ('maint-off', S, "        if let Err(e) = adl::maint(&mut sl, &eng.state, &dirty_accts) {", "        if let Err(e) = adl::maint(&mut sl, &eng.state, &[]) {"),
  ('maint-present-check-off', A, """            Look::Present(h) if h == rleaf(&k, a) => {}
            Look::Unknown => return Err(Ok(Need::AdlKey(m, sd, k))),
            _ => return Err(Err(ST_SL_BADWIT)),""", """            Look::Unknown => return Err(Ok(Need::AdlKey(m, sd, k))),
            _ => {}"""),
  ('maint-absent-check-off', A, """            Look::Absent => {}
            Look::Unknown => return Err(Ok(Need::AdlKey(m, sd, k))),
            // R21-I2""", """            Look::Absent | Look::Present(_) => {}
            Look::Unknown => return Err(Ok(Need::AdlKey(m, sd, k))),
            // R21-I2"""),
  ('load-root-check-off', A, "if seen > SL_MAX_TREE_NODES || st.root_hash() != root {", "if seen > SL_MAX_TREE_NODES {"),
  ('load-leaf-check-off', A, """            adlr_leaf(b, m, sd, &h);
            sl.check(b, true)?;""", """            adlr_leaf(b, m, sd, &h);"""),
  ('load-absent-check-off', A, """            adlr_kid(b, m, sd);
            sl.absent(b)?;""", """            adlr_kid(b, m, sd);"""),
  ('cur-init-off', A, """                if p.qty != 0 {
                    sl.adl.cur.insert((*a, m.0), (sgn(p.qty), p.qty.unsigned_abs()));
                }""", """                let _ = p;"""),
  ('removed-count-off', A, "        *sl.adl.removed.entry((m, sd)).or_insert(0) += 1;", ""),
  ('end-del-off', A, """        } else if *present {
            adlr_kid(&mut b, *m, *sd);
            dels.push(kid_key(&b));
        }""", """        } else if *present {
            let _ = &b;
        }"""),
  ('insurance-in-tree', A, """    for a in dirty {
        if *a == INSURANCE_ACCOUNT {
            continue;
        }""", """    for a in dirty {"""),
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
        for cmd, t in [([B, 'slpoc21', '6', '300', '8', '200'], 600), ([B, 'slpoc17', '20', '300'], 600), ([B, 'slfuzz', '6', '300', 'liq'], 900), ([B, 'sladv', '3', '200', 'liq'], 900), ([B, 'slmig', '10', '300', '5'], 900)]:
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
