#!/usr/bin/env python3
# Loop round 16 (R15-I1): MNWIT-S migration (snapshot kind 3) accepted by rv_rollup on the export / migration digest binding.
# usage: python3 js/aamut-l16.py (from spike/rv-bisect); runs rolltest groups r16mig + upgrade per mutant (real ocore evaluator);
# restores the sources after every mutant.
import subprocess, re, json, os
R = os.path.dirname(os.path.abspath(__file__)) + '/..'
F = {'o': R + '/aa/rv_rollup.oscript'}
FIN = "($xi[0] == '2' OR $xi[0] == '3') AND $xe[0] == '1' AND $xi[1] == $xe[1]"
muts = [
 ('o', FIN, "$xi[0] == '2' AND $xe[0] == '1' AND $xi[1] == $xe[1]"),
 ('o', FIN, "($xi[0] == '2' OR $xi[0] == '3' OR $xi[0] == '1') AND $xe[0] == '1' AND $xi[1] == $xe[1]"),
 ('o', FIN, "($xi[0] == '2' OR $xi[0] == '3') AND ($xe[0] == '1' OR $xe[0] == '3') AND $xi[1] == $xe[1]"),
 ('o', FIN, "($xi[0] == '2' OR $xi[0] == '3') AND $xe[0] == '1'"),
 ('o', FIN, "($xi[0] == '2' OR $xi[0] == '3') AND $xe[0] != '2' AND $xi[1] == $xe[1]"),
 ('o', "require($w[0] >= 1 AND $w[0] <= 3, 'kind');", "require($w[0] >= 1 AND $w[0] <= 4, 'kind');"),
 ('o', "require($w[0] >= 1 AND $w[0] <= 3, 'kind');", "require($w[0] >= 0 AND $w[0] <= 3, 'kind');"),
 ('o', "require($w[0] >= 1 AND $w[0] <= 3, 'kind');", "require($w[0] == 1 OR $w[0] == 2, 'kind');"),
]
orig = {k: open(v).read() for k, v in F.items()}
try:
    for i, (f, a, b) in enumerate(muts, 1):
        assert orig[f].count(a) == 1, a
        open(F[f], 'w').write(orig[f].replace(a, b))
        tot = {'total': 0, 'fail': 0}; fails = []
        for grp in ['r16mig', 'upgrade']:
            r = subprocess.run(['node', 'rolltest.js', grp], cwd=R + '/js', capture_output=True, text=True, timeout=600)
            m = re.search(r'SUMMARY (\{.*\})', r.stdout); s = json.loads(m.group(1)) if m else {'total': 0, 'fail': 'crash'}
            tot['total'] += s.get('total', 0); tot['fail'] = (tot['fail'] or 0) + (s['fail'] if isinstance(s['fail'], int) else 999)
            fails += [l.split('|')[1].strip()[:70] for l in r.stdout.splitlines() if l.startswith('FAIL')][:2]
        print('aamut %d [%s -> %s] %s -> %s %s' % (i, a, b, json.dumps(tot), 'KILLED' if tot['fail'] else 'no', fails), flush=True)
        for k, v in F.items(): open(v, 'w').write(orig[k])
finally:
    for k, v in F.items(): open(v, 'w').write(orig[k])
    subprocess.run(['node', 'rolltest.js', 'ts'], cwd=R + '/js', capture_output=True)  # regenerates every .aa
