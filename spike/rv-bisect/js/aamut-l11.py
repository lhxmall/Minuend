#!/usr/bin/env python3
# Loop round 11: mutation test of the R10-M1 bond escalation + priority window in rv_rollup (from aamut-l7.py) (rolltest on the real ocore evaluator).
# usage: python3 js/aamut-l9.py  (from spike/rv-bisect); restores the sources after every mutant
import subprocess, re, json, os, shutil
R = os.path.dirname(os.path.abspath(__file__)) + '/..'
F = {'o': R + '/aa/rv_rollup.oscript', 'm': R + '/js/mkrollup.js'}
muts = [
 ('o', "$bond = $OBOND * 2^min(var['v' || $h] OTHERWISE 0, $MAXESC);", "$bond = $OBOND;"),
 ('o', "$bond = $OBOND * 2^min(var['v' || $h] OTHERWISE 0, $MAXESC);", "$bond = $OBOND * 2^(var['v' || $h] OTHERWISE 0);"),
 ('o', "$MAXESC = 10;", "$MAXESC = 11;"),
 ('o', "require(length($pw) != 2 OR $now >= +$pw[1] OR trigger.address == $pw[0], 'priority: ' || $pw[0]);", "require(true, 'priority: ' || $pw[0]);"),
 ('o', "require(length($pw) != 2 OR $now >= +$pw[1] OR trigger.address == $pw[0], 'priority: ' || $pw[0]);", "require(length($pw) != 2 OR $now > +$pw[1] OR trigger.address == $pw[0], 'priority: ' || $pw[0]);"),
 ('o', "require(length($pw) != 2 OR $now >= +$pw[1] OR trigger.address == $pw[0], 'priority: ' || $pw[0]);", "require(length($pw) != 2 OR $now >= +$pw[1], 'priority: ' || $pw[0]);"),
 ('o', "$PRIO = 1800;", "$PRIO = 1799;"),
 ('o', "rf: max($paid - $bond - $FEE, 0)", "rf: max($paid - $OBOND - $FEE, 0)"),
 ('o', "amt: $CBOND - $GF - $FEE + ($first ? $bd / 2 : 0)};", "amt: $CBOND - $GF - $FEE + ($first ? $OBOND / 2 : 0)};"),
 ('o', "\t$st = {sid: $sid, pay: $r[1], amt: $bondOf($sid) - $FEE};\n}\n// ---- reclaim", "\t$st = {sid: $sid, pay: $r[1], amt: $OBOND - $FEE};\n}\n// ---- reclaim"),
 ('o', "require(!var['f' || $sid] AND !var['r' || $sid] AND !var['n' || $sid], 'cannot reclaim');\n\t$st = {sid: $sid, pay: $r[1], amt: $bondOf($sid) - $FEE};", "require(!var['f' || $sid] AND !var['r' || $sid] AND !var['n' || $sid], 'cannot reclaim');\n\t$st = {sid: $sid, pay: $r[1], amt: $OBOND - $FEE};"),
 ('m', "\t\tif ($st.bd > $OBOND) var['b' || $st.sid] = $st.bd;   // loop round 11 (R10-M1): escalated bond\n", ""),
 ('m', "if ($st.first) var['burned'] += $st.bd - $st.bd / 2;", "if ($st.first) var['burned'] += $OBOND - $OBOND / 2;"),
 ('m', "\t\t\tvar['v' || $st.h] += 1;", ""),
 ('m', "\t\t\tvar['p' || $st.h] = $g[1] || ':' || ($now + $PRIO);", ""),
 ('m', "\t\t\tvar['v' || $st.h] += 1;", "\t\t\tvar['v' || $st.h] += 2;"),
]
orig = {k: open(v).read() for k, v in F.items()}
out = []
try:
    sel = os.environ.get('MUTS', '').split()
    for i, (f, a, b) in enumerate(muts, 1):
        if sel and str(i) not in sel: continue
        assert orig[f].count(a) == 1, a
        open(F[f], 'w').write(orig[f].replace(a, b))
        r = subprocess.run(['node', 'rolltest.js'], cwd=R + '/js', capture_output=True, text=True, timeout=300)
        m = re.search(r'SUMMARY (\{.*\})', r.stdout); s = json.loads(m.group(1)) if m else {'fail': 'crash'}
        fails = [l.split('|')[1].strip()[:70] for l in r.stdout.splitlines() if l.startswith('FAIL')][:3]
        line = 'aamut %d [%s -> %s] %s -> %s %s' % (i, a, b, json.dumps(s), 'KILLED' if s.get('fail') else 'no', fails)
        print(line, flush=True); out.append(line)
        for k, v in F.items(): open(v, 'w').write(orig[k])
finally:
    for k, v in F.items(): open(v, 'w').write(orig[k])
    subprocess.run(['node', 'rolltest.js', 'ts'], cwd=R + '/js', capture_output=True)  # regenerates every .aa
