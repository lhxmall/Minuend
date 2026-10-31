#!/usr/bin/env python3
# Loop round 7: mutation test of the R6-M2 timestamp rules in rv_rollup (rolltest on the real ocore evaluator).
# usage: python3 js/aamut-l7.py  (from spike/rv-bisect); restores the sources after every mutant
import subprocess, re, json, os, shutil
R = os.path.dirname(os.path.abspath(__file__)) + '/..'
F = {'o': R + '/aa/rv_rollup.oscript', 'm': R + '/js/mkrollup.js'}
muts = [
 ('o', "$d.ts <= $now AND", "$d.ts <= $now + 1 AND"),
 ('o', "$d.ts >= $now - $TSLACK", "$d.ts > $now - $TSLACK"),
 ('o', "+ $MINGAP, 'ts gap'", "+ $MINGAP - 1, 'ts gap'"),
 ('o', "require($h == 1 OR $d.ts >=", "require(true OR $d.ts >="),
 ('o', "$Z10 || ',' || $d.ts || ',' || $Z21", "$Z10 || ',0,' || $Z21"),
 ('o', "$d.ts < 4294967296", "$d.ts < 1e15"),
 ('o', "require(is_integer($d.ts) AND", "require("),
 ('m', "var['t' || $st.sid] = $d.ts;", "var['t' || $st.sid] = $d.ts - 60;"),
 ('o', "$TSLACK = 600;", "$TSLACK = 6000;"),
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
