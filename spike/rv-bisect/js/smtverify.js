// Loop round 2 (W2): MNWIT1 proof verifier in Oscript, measured with the real ocore 0.4.8 validator
// (static complexity / ops, aa_validation.validateAADefinition) and run on real-engine proofs
// (engine-diff proofdump / grind). Usage:
//   node smtverify.js measure                      static complexity/ops for D in {16..96}, binary + 4-ary
//   node smtverify.js run <proofs.json>...         verify member/absent proofs + forgeries (binary, D=64)
// Verifier = design §7.3.3 / §7.5: key derived from the leaf text, ONE sha256 per level (the left/right
// order is chosen by string concatenation, so a ternary with two sha256 calls -- 2x static complexity --
// is avoided), member and absent share the key + leaf hashes (complexity D + 2 for both).
'use strict';
const { validate, run } = require('./oc.js');

function verifierBinary(D) {
  return `
	$D = ${D};
	$HX = '0123456789abcdef';
	$T = trigger.data;
	require(is_array($T.sib) AND length($T.sib) <= $D, 'sib');
	// kid = text before the 2nd ':' (3rd for pos:), whole text if there are fewer. NOT split():
	// ocore turns numeric-looking parts into numbers ('000..0' -> 0), which mis-derives the key of
	// any leaf whose id has no a-f digit -- e.g. the insurance account's acct:000...0 (finding W5).
	$kid = ($l) => {
		$i1 = index_of($l, ':');
		$r1 = substring($l, $i1 + 1);
		$i2 = index_of($r1, ':');
		$r2 = substring($r1, $i2 + 1);
		$i3 = index_of($r2, ':');
		($i1 < 0 OR $i2 < 0) ? $l : (starts_with($l, 'pos:') ? (($i3 < 0) ? $l : substring($l, 0, $i1 + $i2 + $i3 + 2)) : substring($l, 0, $i1 + $i2 + 1))
	};
	$nib = ($k, $d) => index_of($HX, substring($k, floor($d / 4), 1));
	// terminal leaf text: the member leaf, or (absence) another leaf; '' = EMPTY terminal
	$t = $T.leaf;
	$kt = sha256('~K1:' || $kid($t), 'hex');
	$ht = sha256('~L1:' || $kt || ':' || $t, 'base64');
	$n = length($T.sib);
	if (exists($T.key)) {
		// absence of key $T.key: terminal EMPTY, or a leaf with a different key sharing the first n bits
		$k = $T.key;
		require(length($k) == 64, 'key'); // the calling AA derives $k from the kid it cares about
		if ($t != '') {
			require($kt != $k, 'own leaf');
			require(substring($kt, 0, floor($n / 4)) == substring($k, 0, floor($n / 4)), 'prefix');
			$P16 = [16, 8, 4, 2];
			require(floor($nib($kt, $n) / $P16[$n % 4]) == floor($nib($k, $n) / $P16[$n % 4]), 'prefix bits');
		}
	}
	$path = exists($T.key) ? $T.key : $kt;
	$h0 = (exists($T.key) AND $t == '') ? 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' : $ht;
	// path bits as a '0'/'1' string (ops: a per-level hex->bit extraction costs ~20 static ops x D)
	// (an object literal {'0':'0000',...} does NOT work: ocore turns numeric-looking string values into
	// numbers, '0100' -> 100; so slice a 64-char table instead)
	$BS = '0000000100100011010001010110011110001001101010111100110111101111';
	$bits = reduce(${JSON.stringify([...Array(Math.ceil(D / 4)).keys()])}, ${Math.ceil(D / 4)}, ($a, $j) => $a || substring($BS, 4 * index_of($HX, substring($path, $j, 1)), 4), '');
	// siblings deepest-first: element i is the sibling at depth n-1-i
	$root = reduce($T.sib, $D, ($acc, $i, $s) => sha256('~N1:' || ((substring($bits, $n - 1 - $i, 1) == '0') ? $acc || $s : $s || $acc), 'base64'), $h0);
	require($root == $T.root, 'root');
`;
}

// 4-ary variant (proposal MNWIT2, not implemented in the guest): node = sha256('~N2:' || 4 x b64),
// a level consumes 2 key bits; the prover sends the 3 siblings of a level as ONE 132-char string.
function verifierQuad(D) {
  const L = Math.ceil(D / 2);
  return `
	$L = ${L};
	$HX = '0123456789abcdef';
	$T = trigger.data;
	require(is_array($T.sib) AND length($T.sib) <= $L, 'sib');
	// kid = text before the 2nd ':' (3rd for pos:), whole text if there are fewer. NOT split():
	// ocore turns numeric-looking parts into numbers ('000..0' -> 0), which mis-derives the key of
	// any leaf whose id has no a-f digit -- e.g. the insurance account's acct:000...0 (finding W5).
	$kid = ($l) => {
		$i1 = index_of($l, ':');
		$r1 = substring($l, $i1 + 1);
		$i2 = index_of($r1, ':');
		$r2 = substring($r1, $i2 + 1);
		$i3 = index_of($r2, ':');
		($i1 < 0 OR $i2 < 0) ? $l : (starts_with($l, 'pos:') ? (($i3 < 0) ? $l : substring($l, 0, $i1 + $i2 + $i3 + 2)) : substring($l, 0, $i1 + $i2 + 1))
	};
	$q = ($k, $lv) => floor(index_of($HX, substring($k, floor($lv / 2), 1)) / (($lv % 2 == 0) ? 4 : 1)) % 4;
	$t = $T.leaf;
	$kt = sha256('~K1:' || $kid($t), 'hex');
	$ht = sha256('~L1:' || $kt || ':' || $t, 'base64');
	$n = length($T.sib);
	$path = exists($T.key) ? $T.key : $kt;
	$h0 = (exists($T.key) AND $t == '') ? 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' : $ht;
	$root = reduce($T.sib, $L, ($acc, $i, $s) => {
		$c = $q($path, $n - 1 - $i);
		sha256('~N2:' || substring($s, 0, 44 * $c) || $acc || substring($s, 44 * $c), 'base64')
	}, $h0);
	require($root == $T.root, 'root');
`;
}

const strip = f => f.split('\n').map(l => l.replace(/\s\/\/.*$/, '')).join(' ');
const aa = f => `{init:"{${strip(f).replace(/"/g, '\\"')}}", messages:[{app:'state', state:"{var['ok']=1;}"}]}`;

async function measure() {
  const out = [];
  for (const D of [16, 24, 32, 48, 64, 80, 96]) {
    const b = await validate(aa(verifierBinary(D)));
    const q = await validate(aa(verifierQuad(D)));
    out.push({ D_bits: D, binary: b.err ? String(b.err).slice(0, 80) : { complexity: b.complexity, ops: b.count_ops },
      quad: q.err ? String(q.err).slice(0, 80) : { levels: Math.ceil(D / 2), complexity: q.complexity, ops: q.count_ops } });
  }
  return out;
}

async function verify(data, D = 64) {
  const r = await run(strip(verifierBinary(D)), { data });
  return !r.err ? true : String(r.err);
}

async function runFiles(files) {
  const res = { files: 0, member_ok: 0, member_fail: 0, absent_ok: 0, absent_fail: 0, forgeries: 0, forged: 0, depths: [], ms: [] };
  for (const f of files) {
    const p = JSON.parse(require('fs').readFileSync(f, 'utf8'));
    res.files++;
    for (const m of p.members) {
      const t0 = Date.now();
      const ok = await verify({ root: p.root, leaf: m.leaf, sib: m.sib });
      res.ms.push(Date.now() - t0);
      res.depths.push(m.depth);
      if (ok === true) res.member_ok++; else { res.member_fail++; console.log('member fail', f, m.depth, ok); }
      // forgeries: tampered text; dropped deepest sibling; claim absence of a present key; swapped sibling
      const tries = [
        { root: p.root, leaf: m.leaf + '0', sib: m.sib },
        { root: p.root, leaf: m.leaf, sib: m.sib.slice(1) },
        { root: p.root, leaf: m.leaf, sib: m.sib, key: require('crypto').createHash('sha256').update('~K1:' + kidJs(m.leaf)).digest('hex') },
      ];
      if (m.sib.length > 1) tries.push({ root: p.root, leaf: m.leaf, sib: [m.sib[1], m.sib[0], ...m.sib.slice(2)] });
      for (const t of tries) { res.forgeries++; if ((await verify(t)) === true) { res.forged++; console.log('FORGED', f, JSON.stringify(t).slice(0, 120)); } }
    }
    const a = p.absent;
    const okA = await verify({ root: p.root, leaf: a.term, sib: a.sib, key: a.key });
    if (okA === true) res.absent_ok++; else { res.absent_fail++; console.log('absent fail', f, okA); }
    res.depths.push(a.depth);
    // absence forgery: EMPTY terminal where the real terminal is a leaf (or vice versa: a member leaf)
    res.forgeries++;
    if ((await verify({ root: p.root, leaf: a.term === '' ? p.members[0].leaf : '', sib: a.sib, key: a.key })) === true) { res.forged++; console.log('FORGED absent', f); }
  }
  res.max_depth = Math.max(...res.depths); res.max_ms = Math.max(...res.ms); delete res.depths; delete res.ms;
  return res;
}
// Independent JS fold (node crypto) for synthetic proofs at full depth: a leaf + d random siblings
// define a root; the Oscript verifier must accept it and reject tampering. Exercises the bit/path
// logic at every depth 0..63 (real ground proofs only reach ~20-36 bits on a laptop).
const H = (s, enc) => require('crypto').createHash('sha256').update(s).digest(enc);
function synth(d, seed) {
  const leaf = `acct:${H('seed' + seed, 'hex')}:${1000 + seed}:0:0`;
  const kt = H('~K1:' + kidJs(leaf), 'hex');
  const bits = [...kt].map(c => parseInt(c, 16).toString(2).padStart(4, '0')).join('');
  let h = H('~L1:' + kt + ':' + leaf, 'base64');
  const sibRoot = [...Array(d).keys()].map(i => H('sib' + seed + ':' + i, 'base64')); // s_0 .. s_{d-1}
  for (let i = d - 1; i >= 0; i--) h = H('~N1:' + (bits[i] === '0' ? h + sibRoot[i] : sibRoot[i] + h), 'base64');
  return { root: h, leaf, sib: sibRoot.slice().reverse() };
}
async function runSynth() {
  const r = { synth_ok: 0, synth_fail: 0, synth_forged: 0, depths: [] , ms: 0};
  for (const d of [0, 1, 7, 8, 31, 32, 33, 63, 64]) {
    const p = synth(d, d);
    const t0 = Date.now(); const ok = await verify(p); r.ms = Math.max(r.ms, Date.now() - t0);
    if (ok === true) r.synth_ok++; else { r.synth_fail++; console.log('synth fail', d, ok); }
    if (d > 0) {
      const bad = { ...p, sib: p.sib.map((x, i) => i === Math.floor(d / 2) ? H('x', 'base64') : x) };
      if ((await verify(bad)) === true) r.synth_forged++;
    }
  }
  const p65 = synth(65, 65); // over MAX depth: must be refused even though it folds correctly
  r.depth65_rejected = (await verify(p65)) !== true;
  return r;
}
function kidJs(l) { const p = l.split(':'); const f = l.startsWith('pos:') ? 3 : 2; return p.length <= f ? l : p.slice(0, f).join(':'); }

module.exports = { verifierBinary, verifierQuad, measure, verify };
if (require.main === module) {
  (async () => {
    const [cmd, ...rest] = process.argv.slice(2);
    if (cmd === 'measure') console.log(JSON.stringify(await measure(), null, 1));
    else if (cmd === 'run') console.log(JSON.stringify(await runFiles(rest)));
    else if (cmd === 'synth') console.log(JSON.stringify(await runSynth()));
    else console.log('usage: measure | run <proofs.json>...');
    process.exit(0);
  })();
}
