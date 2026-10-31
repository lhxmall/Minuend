#!/usr/bin/env python3
# Loop round 9: mutation test of the R9-H1 cancel command in rv_rollup (from aamut-l7.py) (rolltest on the real ocore evaluator).
# usage: python3 js/aamut-l9.py  (from spike/rv-bisect); restores the sources after every mutant
import subprocess, re, json, os, shutil
R = os.path.dirname(os.path.abspath(__file__)) + '/..'
F = {'o': R + '/aa/rv_rollup.oscript', 'm': R + '/js/mkrollup.js'}
muts = [
 ('o', "else if ($d.cancel) {\n\trequire(trigger.address == $GOV, 'not governance');", "else if ($d.cancel) {\n\trequire(true, 'not governance');"),
 ('o', "require($p > $lf, 'no pending upgrade');", "require($p >= $lf, 'no pending upgrade');"),
 ('o', "ctop: min($top, $p - 1)}", "ctop: $p - 1}"),
 ('m', "\t\tvar['U' || $st.cx] = false;   // loop round 9 (R9-H1): cancel the pending upgrade\n", ""),
 ('m', "\t\tvar['uh'] = false;\n\t\tvar['top'] = $st.ctop;", "\t\tvar['top'] = $st.ctop;"),
 ('m', "\t\tvar['top'] = $st.ctop;\n", ""),
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
