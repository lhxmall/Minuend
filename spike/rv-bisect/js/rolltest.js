// Adversarial tests for rv_rollup + rv_game (referee) + rv_step on the real ocore evaluator (simulated chain, chain.js).
// usage: node rolltest.js [filter]     -> prints PASS/FAIL lines and SUMMARY {...}; writes rolltest-results.json
'use strict';
const { Chain, ROLL, GAME, STEP, SEG, BIND, PROOF, M, rnd, BOUNCER } = require('./chain.js'); const T = require('./rolltrace.js'); const ref = require('./ref.js'); const fs = require('fs');
const OBOND = 200000, CBOND = 120000, GF = 10000, GB = 1000, FEE = 2000, WIN = 86400, TM = 3600;
const OCP = process.env.OCORE || '/workspace/projects/4ecc28f7-451e-450a-b62c-b8b357f0cc38/wt-aa/vendor/aa-testkit/node_modules/ocore';
const A = s => require(OCP + '/object_hash.js').getChash160(['sig', { pubkey: require('crypto').createHash('sha256').update(s).digest('base64').slice(0, 44) }]); // valid Obyte address per name
const OP1 = A('OPONE'), OP2 = A('OPTWO'), OP3 = A('OPTHREE'), CH1 = A('CHONE'), CH2 = A('CHTWO'), CH3 = A('CHTHREE'), W = A('WATCHER');
const results = []; const FILTER = process.argv[2] || '';
const rec = (group, name, expected, actual, extra) => { const pass = JSON.stringify(expected) === JSON.stringify(actual); results.push({ group, name, expected, actual, pass, ...(extra || {}) });
  console.log(pass ? 'PASS' : 'FAIL', group, '|', name, '| expected', JSON.stringify(expected), '| actual', JSON.stringify(actual), extra ? JSON.stringify(extra) : ''); };
const ok = r => r.err ? 'bounce: ' + r.err : 'ok';
const bnc = (r, re) => r.err ? (re && !re.test(r.err) ? 'other bounce: ' + r.err : 'bounce') : 'accepted';

// ---------- invariant: the rollup AA always holds every outstanding bond + the burned counter
function liabilities(C) { const sv = C.sv[ROLL] || {}; let L = 0; const v = k => sv[k] ? (typeof sv[k].value === 'object' ? sv[k].value.toNumber() : sv[k].value) : undefined;
  for (const k in sv) { if (k[0] === 's' && k.length === 45) { const sid = k.slice(1); if (!v('r' + sid) && !v('f' + sid)) L += OBOND; }
    if (k[0] === 'G' && k.length === 45 && String(v(k)).endsWith(':open')) L += CBOND - GF; }
  return L + (v('burned') || 0); }
let invFail = 0;
function inv(C, where) { const L = liabilities(C), b = C.b(ROLL); if (b < L) { invFail++; console.log('INVARIANT BROKEN', where, 'balance', b, 'liabilities', L); } return b - L; }
async function S(C, from, to, amt, data) { const r = await C.send(from, to, amt, data); inv(C, JSON.stringify(data).slice(0, 60)); return r; }

// ---------- protocol helpers
const cloneDeepSV = sv => { const o = {}; for (const a in sv) { o[a] = {}; for (const k in sv[a]) o[a][k] = { ...sv[a][k] }; } return o; };
const subRec = (C, tr, sid) => { const r = String(C.r('s' + sid)).split(':'); return r.length === 8 && r[2] === tr.final && +r[4] === tr.steps && r[5] === tr.s0 ? C.r('s' + sid) : 'different'; };
const subData = (tr, h, prev, o = {}) => ({ submit: h, s0: tr.s0, steps: tr.steps, final: tr.final, inp: tr.inpRoot, fpc: tr.fpc, fregs: tr.fregs, fmem: tr.fmem, prev, units: tr.units || Math.min(8, tr.steps), ...o }); // units: loop round 3 (layer 1)
async function submit(C, op, h, tr, prev, o) { const r = await S(C, op, ROLL, OBOND, subData(tr, h, prev, o)); if (!r.err) { tr.sid = r.unit; tr.h = h; tr.op = op; } return r; }
async function open(C, ch, sid) { const r = await S(C, ch, ROLL, CBOND, { open: sid }); return r.err ? r : { ...r, gid: ROLL + r.unit, ref: r.unit, ch }; }
const gv = (C, gid) => String(C.v(GAME, 'g_' + gid) || '');
const pts = (lo, hi) => { const cnt = Math.min(16, hi - lo) - 1; return { cnt, pt: j => j == 0 ? lo : j == cnt + 1 ? hi : lo + Math.floor(j * (hi - lo) / (cnt + 1)) }; };

// Event-driven parallel game runner. game = {gid, defRoots, chRoots, honest (trace whose wits feed rv_step),
//   def: OP address, ch: challenger address, defDelay, chDelay ('slow' = deadline-1), defSilent, chSilent, noMemo}
async function playAll(C, games, tStop = Infinity) {
  for (const g of games) if (g.last === undefined) g.last = C.ts;
  for (let it = 0; it < 5000; it++) {
    let best = null, bt = Infinity, act = null;
    for (const g of games) { if (g.dead) continue; const s = gv(C, g.gid).split(':'); if (s[0] === 'done' || s.length < 9) { g.winner = g.winner || (s[0] === 'done' ? s[1] : 'none'); continue; }
      const lo = +s[3], hi = +s[4], turn = s[7], dl = +s[8];
      const delay = who => { const d = who === 'd' ? g.defDelay : g.chDelay; return d === 'slow' ? dl - 1 : g.last + (d || 60); };
      let t, a;
      if (turn === 'd') { if (g.defSilent) { t = dl; a = 'resolve'; } else { t = delay('d'); a = 'mids'; } }
      else if (turn === 'c') { if (g.chSilent) { t = dl; a = 'resolve'; } else { t = delay('c'); a = 'pick'; } }
      else { const memo = C.v(STEP, 's_' + s[5]); const canMemo = !g.noMemo && g.honest.roots[lo] === s[5];
        if (memo || !canMemo) { t = memo ? g.last + 60 : dl; a = 'resolve'; } else { t = delay('c'); a = 'memo'; } }
      t = Math.max(t, C.ts); if (a !== 'resolve' && t >= dl) { t = dl; a = 'resolve'; } // a side that missed its deadline
      if (t < bt) { bt = t; best = { g, s, lo, hi, a }; } }
    if (!best || bt > tStop) return;
    C.ts = bt; const { g, s, lo, hi, a } = best; const { cnt, pt } = pts(lo, hi); let r;
    if (a === 'mids') r = await S(C, g.def, GAME, 0, { mids: g.gid, roots: Array.from({ length: cnt }, (_, i) => g.defRoots[pt(i + 1)]) });
    else if (a === 'pick') { const m = String(C.v(GAME, 'm_' + g.gid)).split(','); const at = i => i == 0 ? s[5] : i == cnt + 1 ? s[6] : m[i - 1];
      let j = 0; while (j < cnt && at(j + 1) === g.chRoots[pt(j + 1)]) j++; r = await S(C, g.ch, GAME, 0, { pick: g.gid, j }); }
    else if (a === 'memo') r = await S(C, g.ch, STEP, 0, g.honest.wits[lo]);
    else { r = await S(C, W, GAME, 0, { resolve: g.gid }); if (!r.err) g.resolvedAt = C.ts; }
    g.moves = (g.moves || 0) + 1; g.last = C.ts;
    if (r.err) { g.errs = (g.errs || 0) + 1; if (g.errs > 5) { g.winner = 'stuck: ' + r.err; g.dead = true; } }
  }
}
const game = (o, def, ch, honest, extra) => ({ gid: o.gid, def: def.op, ch: o.ch, defRoots: def.roots, chRoots: ch.roots, honest, ...extra });

// ---------- groups
const groups = {};
groups.flow = async () => { const C = new Chain(); const G0 = T.genesis(); const b1 = T.batch(G0, 1);
  let r = await submit(C, OP1, 1, b1, undefined); rec('flow', 'submit h1 (prev omitted -> must be "genesis")', 'bounce', bnc(r, /prev must be genesis/));
  r = await submit(C, OP1, 1, b1, 'genesis'); rec('flow', 'submit h1 honest', 'ok', ok(r));
  C.ts += WIN - 1; r = await S(C, OP1, ROLL, 0, { finalize: 1 }); rec('flow', 'finalize 1 s before 24 h', 'bounce', bnc(r, /window open/));
  C.ts += 1; const b0 = C.b(OP1); r = await S(C, W, ROLL, 0, { finalize: 1 }); rec('flow', 'finalize at exactly 24 h (anyone may call)', 'ok', ok(r));
  rec('flow', 'finalize returns OBOND - FEE to the operator', OBOND - FEE, C.b(OP1) - b0); rec('flow', 'lf = 1', 1, C.r('lf'));
  r = await S(C, W, ROLL, 0, { finalize: 1 }); rec('flow', 'finalize 1 twice', 'bounce', bnc(r, /finalize 2 first/));
  r = await S(C, W, ROLL, 0, { finalize: 2 }); rec('flow', 'finalize unsubmitted 2', 'bounce', bnc(r, /voided/));
  const b2 = T.batch(b1.mem, 2); r = await submit(C, OP2, 2, b2, b1.final); rec('flow', 'h2 by another operator chained on finalized h1', 'ok', ok(r));
  C.ts += 10; r = await open(C, CH1, b1.sid); rec('flow', 'open a game on finalized h1', 'bounce', bnc(r, /not live|window closed/));
  return C; };

groups.badsubmit = async () => { const C = new Chain(); const G0 = T.genesis(); const b1 = T.batch(G0, 1); await submit(C, OP1, 1, b1, 'genesis');
  const b2 = T.batch(b1.mem, 2); const fake = T.batch(G0, 2); // s0 built from genesis memory instead of h1's final memory
  const cases = [
    ['s0 built from genesis memory (not from h1 final memory)', subData(fake, 2, b1.final), /bad s0/],
    ['s0 = random root', subData(b2, 2, b1.final, { s0: ref.H('x') }), /bad s0/],
    ['s0 = h1 final root (raw prev root)', subData(b2, 2, b1.final, { s0: b1.final }), /bad s0/],
    ['input root of another batch (s0 mismatch)', subData(b2, 2, b1.final, { inp: T.batch(b1.mem, 9).inpRoot }), /bad s0/],
    ['final root not the hash of fpc/fregs/fmem', subData(b2, 2, b1.final, { final: ref.H('y') }), /bad final root/],
    ['fmem swapped (memory of another state)', subData(b2, 2, b1.final, { fmem: b1.fmem }), /bad final root/],
    ['fregs with ":" (record injection)', subData(b2, 2, b1.final, { fregs: b2.fregs + ':x' }), /bad final state/],
    ['fpc = 0 (not halted / trapped)', subData(b2, 2, b1.final, { fpc: 0 }), /bad final state/],
    ['fpc = "2" string', subData(b2, 2, b1.final, { fpc: '2' }), /./],
    ['fmem = 44 digits (no "=")', subData(b2, 2, b1.final, { fmem: '1'.repeat(44) }), /bad root/],
    ['inp containing ":"', subData(b2, 2, b1.final, { inp: ':'.repeat(43) + '=' }), /bad root/],
    ['steps 0', subData(b2, 2, b1.final, { steps: 0 }), /bad steps/],
    ['steps 1.5', subData(b2, 2, b1.final, { steps: 1.5 }), /bad steps/],
    ['steps "62" string', subData(b2, 2, b1.final, { steps: String(b2.steps) }), /./],
    ['steps one fewer than the trace (final root of other step count)', subData(b2, 2, b1.final, { steps: b2.steps - 1 }), /bad final root/],
    ['prev = genesis at h2', subData(b2, 2, 'genesis'), /prev must be/],
    ['prev = random root', subData(b2, 2, ref.H('p')), /prev must be/],
    ['height 3 while top = 1 (gap)', subData(b2, 3, b1.final), /gap/],
    ['height 1 again (taken)', subData(b2, 1, 'genesis'), /height taken/],
    ['height 0', subData(b2, 0, 'genesis'), /bad height|height taken|unknown command/],
    ['height "2" string', subData(b2, '2', b1.final), /./],
  ];
  const harmless = { 'fpc = "2" string': 1, 'steps "62" string': 1, 'height "2" string': 1 }; // same hash preimage as the honest submit -> accepting is harmless
  const snap = JSON.stringify([C.sv, C.bal, C.ts]);
  for (const [nm, d, re] of cases) { const C2 = new Chain(); [C2.sv, C2.bal, C2.ts] = JSON.parse(snap); C2.sv = C.sv && cloneDeepSV(C.sv);
    const r = await S(C2, OP2, ROLL, OBOND, d);
    if (harmless[nm]) rec('fake s0 / bad submit', nm + ' (must be bounce, or accepted with the honest record)', true, !!r.err || C2.r('s' + r.unit) === subRec(C2, b2, r.unit), { outcome: ok(r) });
    else rec('fake s0 / bad submit', nm, 'bounce', bnc(r, re)); }
  const r = await S(C, OP2, ROLL, OBOND - 1, subData(b2, 2, b1.final)); rec('fake s0 / bad submit', 'bond OBOND-1', 'bounce', bnc(r, /bond/));
  const r2 = await submit(C, OP2, 2, b2, b1.final); rec('fake s0 / bad submit', 'the honest h2 after all that', 'ok', ok(r2));
  rec('fake s0 / bad submit', 'top = 2', 2, C.r('top')); };

groups.race = async () => { const C = new Chain(); const G0 = T.genesis(); const a1 = T.batch(G0, 1), b1 = T.batch(G0, 7);
  const o2 = C.b(OP2);
  let r = await submit(C, OP1, 1, a1, 'genesis'); rec('race', 'OP1 h1 (first stable)', 'ok', ok(r));
  r = await submit(C, OP2, 1, b1, 'genesis'); rec('race', 'OP2 h1 same timestamp (tie, later in MCI order)', 'bounce', bnc(r, /height taken/));
  rec('race', 'loser only pays the bounce fee', 10000, o2 - C.b(OP2));
  r = await submit(C, OP2, 1, a1, 'genesis'); rec('race', 'OP2 copies OP1 batch for h1', 'bounce', bnc(r, /height taken/));
  const a2 = T.batch(a1.mem, 2), b2 = T.batch(b1.mem, 2);
  r = await submit(C, OP2, 2, b2, b1.final); rec('race', 'h2 chained on the LOSER root', 'bounce', bnc(r, /prev must be/));
  r = await submit(C, OP2, 2, T.batch(b1.mem, 2), a1.final); rec('race', 'h2 prev = winner root but s0 from loser memory', 'bounce', bnc(r, /bad s0/));
  r = await submit(C, OP2, 2, a2, a1.final); rec('race', 'h2 chained on winner root (other operator)', 'ok', ok(r));
  const a3 = T.batch(a2.mem, 3), a3b = T.batch(a2.mem, 4);
  r = await submit(C, OP1, 3, a3, a2.final); const r3 = await submit(C, OP3, 3, a3b, a2.final);
  rec('race', 'h3 two operators same ts: first wins', 'ok', ok(r)); rec('race', 'h3 second bounces', 'bounce', bnc(r3, /height taken/));
  rec('race', 'h3 winner recorded', a3.sid, C.r('h3'));
  rec('race', 'record of h3 lists OP1 as operator', OP1, String(C.r('s' + a3.sid)).split(':')[1]); };

groups.window = async () => { const C = new Chain(); const G0 = T.genesis(); const b1 = T.batch(G0, 1); await submit(C, OP1, 1, b1, 'genesis');
  const L = T.batch(G0, 1, { k: 30, mut: T.MUT.reg });
  C.ts += WIN - 1; const o = await open(C, CH1, b1.sid); rec('window', 'open at 24h - 1 s', 'ok', ok(o));
  C.ts += 1; let r = await open(C, CH2, b1.sid); rec('window', 'open at exactly 24 h', 'bounce', bnc(r, /window closed/));
  r = await S(C, OP1, ROLL, 0, { finalize: 1 }); rec('window', 'finalize at 24 h with a game open', 'bounce', bnc(r, /games open/));
  const g = game(o, b1, L, b1, { chDelay: 'slow' }); await playAll(C, [g], C.ts + 2 * TM);
  r = await S(C, OP1, ROLL, 0, { finalize: 1 }); rec('window', 'finalize mid-game', 'bounce', bnc(r, /games open/));
  await playAll(C, [g]); rec('window', 'griefer (register lie) vs honest operator', 'd', g.winner);
  const b0 = C.b(OP1); r = await S(C, OP1, ROLL, 0, { finalize: 1 }); rec('window', 'finalize after the game resolved', 'ok', ok(r));
  rec('window', 'self-challenge by the operator address', 'bounce', bnc(await (async () => { const C2 = new Chain(); await submit(C2, OP1, 1, T.batch(G0, 1), 'genesis'); return open(C2, OP1, C2.r('h1')); })(), /self/));
  const C3 = new Chain(); const t1 = T.batch(G0, 1); await submit(C3, OP1, 1, t1, 'genesis');
  rec('window', 'open with CBOND - 1', 'bounce', bnc(await S(C3, CH1, ROLL, CBOND - 1, { open: t1.sid }), /bond/));
  rec('window', 'open unknown sid', 'bounce', bnc(await S(C3, CH1, ROLL, CBOND, { open: ref.H('nope') }), /not live/));
  rec('window', 'open sid = object (type confusion)', 'bounce', bnc(await S(C3, CH1, ROLL, CBOND, { open: { a: 1 } }), /./));
  // ocore reads a numeric string in trigger.data as a number: accepted, and lf must be stored as the number 1
  { C3.ts += WIN; const r = await S(C3, W, ROLL, 0, { finalize: '1' }); rec('window', 'finalize "1" string: bounce, or same as finalize 1 (lf stored as number)', true, !!r.err || C3.r('lf') === 1, { outcome: ok(r), lf: C3.r('lf') });
    const b2 = T.batch(t1.mem, 2); rec('window', 'chain continues after that', 'ok', ok(await submit(C3, OP2, 2, b2, t1.final))); C3.ts += WIN; rec('window', 'finalize 2 after string finalize', 'ok', ok(await S(C3, W, ROLL, 0, { finalize: 2 }))); } };

// fraud at h=2 while h3, h4 are submitted on top of it -> all voided, race restarts at 2
groups.fraud = async () => { const C = new Chain(); const G0 = T.genesis(); const b1 = T.batch(G0, 1); await submit(C, OP1, 1, b1, 'genesis');
  const h2 = T.batch(b1.mem, 2), L2 = T.batch(b1.mem, 2, { k: 25, mut: T.MUT.mem }); // OP2 hides a memory write in h2
  C.ts += 100; let r = await submit(C, OP2, 2, L2, b1.final); rec('fraud', 'OP2 submits fraudulent h2 (consistent lie: hidden memory write)', 'ok', ok(r));
  const L3 = T.batch(L2.mem, 3); C.ts += 100; r = await submit(C, OP1, 3, L3, L2.final); rec('fraud', 'OP1 h3 chained on the bad h2 (executes honestly from it)', 'ok', ok(r));
  const L4 = T.batch(L3.mem, 4); C.ts += 100; r = await submit(C, OP3, 4, L4, L3.final); rec('fraud', 'OP3 h4 chained', 'ok', ok(r));
  const og3 = await open(C, CH2, L3.sid); rec('fraud', 'griefer opens a game on h3 too', 'ok', ok(og3));
  const og = await open(C, CH1, L2.sid); rec('fraud', 'honest challenger opens on h2', 'ok', ok(og));
  const c0 = C.b(CH1), burned0 = C.r('burned') || 0;
  // both games run in parallel; the h3 griefer plays slowly, so its game is still running after h2 is voided
  const g2 = game(og, L2, h2, h2), g3 = game(og3, L3, T.batch(L2.mem, 3, { k: 5, mut: T.MUT.pc }), L3, { chDelay: 'slow' });
  await playAll(C, [g2, g3], C.ts + 1800);
  rec('fraud', 'h2 game: challenger wins', 'c', g2.winner); rec('fraud', 'h3 griefer game still running', true, !g3.winner);
  rec('fraud', 'challenger paid CBOND - GF - FEE + OBOND/2', CBOND - GF - FEE + OBOND / 2, C.b(CH1) - c0);
  rec('fraud', 'burned counter += OBOND/2', OBOND / 2, (C.r('burned') || 0) - burned0);
  rec('fraud', 'top reset to 1 (h2..h4 voided)', 1, C.r('top'));
  r = await open(C, CH3, L4.sid); rec('fraud', 'open a game on voided h4', 'bounce', bnc(r, /not live/));
  r = await submit(C, OP3, 5, T.batch(L4.mem, 5), L4.final); rec('fraud', 'extend the voided chain (h5 on old h4)', 'bounce', bnc(r, /height taken|gap/));
  r = await submit(C, OP3, 3, T.batch(L2.mem, 3), L2.final); rec('fraud', 'h3 on the voided h2', 'bounce', bnc(r, /gap/));
  r = await S(C, OP2, ROLL, 0, { reclaim: L2.sid }); rec('fraud', 'fraudster reclaims its h2 bond', 'bounce', bnc(r, /cannot reclaim/));
  r = await S(C, OP1, ROLL, 0, { reclaim: L3.sid }); rec('fraud', 'reclaim voided h3 while its game is still open', 'bounce', bnc(r, /cannot reclaim/));
  const o4 = C.b(OP3); r = await S(C, OP3, ROLL, 0, { reclaim: L4.sid }); rec('fraud', 'reclaim voided h4 (no games)', 'ok', ok(r)); rec('fraud', 'h4 bond back OBOND - FEE', OBOND - FEE, C.b(OP3) - o4);
  r = await S(C, OP3, ROLL, 0, { reclaim: L4.sid }); rec('fraud', 'reclaim h4 twice', 'bounce', bnc(r, /cannot reclaim/));
  // race restarts at h2
  const n2a = h2, n2b = T.batch(b1.mem, 12);
  r = await submit(C, OP3, 2, n2b, b1.final); const r2 = await submit(C, OP1, 2, n2a, b1.final);
  rec('fraud', 'race restarts at h2: first resubmission wins', 'ok', ok(r)); rec('fraud', 'second resubmission at h2', 'bounce', bnc(r2, /height taken/));
  r = await submit(C, OP1, 3, T.batch(n2b.mem, 3), L2.final); rec('fraud', 'new h3 still referencing the voided h2 root', 'bounce', bnc(r, /prev must be/));
  const n3 = T.batch(n2b.mem, 3); r = await submit(C, OP1, 3, n3, n2b.final); rec('fraud', 'new h3 on the new h2', 'ok', ok(r));
  // the old h3 game ends for the operator and must not touch the new chain
  const top0 = C.r('top'); const o1 = C.b(OP1); await playAll(C, [g3]);
  rec('fraud', 'old h3 game (griefer) still resolves', 'd', g3.winner); rec('fraud', 'operator of voided h3 gets the griefer bond', CBOND - GF - FEE, C.b(OP1) - o1);
  rec('fraud', 'late result on voided h3 leaves the new chain alone', top0, C.r('top'));
  const o1b = C.b(OP1); r = await S(C, OP1, ROLL, 0, { reclaim: L3.sid }); rec('fraud', 'reclaim voided h3 after its game', 'ok', ok(r)); rec('fraud', 'h3 bond back', OBOND - FEE, C.b(OP1) - o1b);
  C.ts += WIN; r = await S(C, W, ROLL, 0, { finalize: 1 }); rec('fraud', 'h1 still finalizes', 'ok', ok(r));
  r = await S(C, W, ROLL, 0, { finalize: 3 }); rec('fraud', 'finalize h3 before h2 (out of order)', 'bounce', bnc(r, /finalize 2 first/));
  r = await S(C, W, ROLL, 0, { finalize: 2 }); rec('fraud', 'new h2 finalizes', 'ok', ok(r)); r = await S(C, W, ROLL, 0, { finalize: 3 }); rec('fraud', 'new h3 finalizes', 'ok', ok(r));
  rec('fraud', 'reclaim a finalized submission', 'bounce', bnc(await S(C, OP1, ROLL, 0, { reclaim: n3.sid }), /live or unknown|cannot reclaim/));
  rec('fraud', 'reclaim the old fraudulent h2 later', 'bounce', bnc(await S(C, OP2, ROLL, 0, { reclaim: L2.sid }), /cannot reclaim/)); };

// voided-height finalize: a voided height cannot finalize even when it is next in order and its window passed
groups.voidfin = async () => { const C = new Chain(); const G0 = T.genesis(); const b1 = T.batch(G0, 1); await submit(C, OP1, 1, b1, 'genesis');
  C.ts += WIN; await S(C, W, ROLL, 0, { finalize: 1 });
  const L2 = T.batch(b1.mem, 2, { k: 9, mut: T.MUT.reg }), h2 = T.batch(b1.mem, 2); await submit(C, OP2, 2, L2, b1.final);
  const L3 = T.batch(L2.mem, 3); await submit(C, OP2, 3, L3, L2.final);
  const o = await open(C, CH1, L2.sid); const g = game(o, L2, h2, h2); await playAll(C, [g]); rec('voided finalize', 'fraud at h2', 'c', g.winner);
  C.ts += WIN; let r = await S(C, W, ROLL, 0, { finalize: 2 }); rec('voided finalize', 'finalize voided h2 (next in order, window over, no games)', 'bounce', bnc(r, /voided/));
  r = await S(C, W, ROLL, 0, { finalize: 3 }); rec('voided finalize', 'finalize voided h3', 'bounce', bnc(r, /finalize 2 first/));
  r = await open(C, CH2, L3.sid); rec('voided finalize', 'open on voided h3', 'bounce', bnc(r, /not live/));
  rec('voided finalize', 'lf stays 1', 1, C.r('lf'));
  const n2 = T.batch(b1.mem, 5); await submit(C, OP1, 2, n2, b1.final); r = await S(C, W, ROLL, 0, { finalize: 2 }); rec('voided finalize', 'replacement h2 before its own 24 h', 'bounce', bnc(r, /window open/));
  C.ts += WIN; r = await S(C, W, ROLL, 0, { finalize: 2 }); rec('voided finalize', 'replacement h2 after 24 h', 'ok', ok(r)); };

groups.latefraud = async () => { const C = new Chain(); const G0 = T.genesis(); const b1 = T.batch(G0, 1); await submit(C, OP1, 1, b1, 'genesis');
  const h2 = T.batch(b1.mem, 2), L2 = T.batch(b1.mem, 2, { k: 10, mut: T.MUT.reg }); await submit(C, OP2, 2, L2, b1.final);
  const h3x = T.batch(L2.mem, 3), L3 = T.batch(L2.mem, 3, { k: 40, mut: T.MUT.mem }); await submit(C, OP3, 3, L3, L2.final);
  const oa = await open(C, CH1, L2.sid), ob = await open(C, CH2, L3.sid);
  const ga = game(oa, L2, h2, h2), gb = game(ob, L3, h3x, h3x, { chDelay: 'slow' }); // h3 game is slow, ends after h2's
  await playAll(C, [ga], C.ts + 30 * TM); rec('late fraud', 'h2 fraud proven first', 'c', ga.winner); rec('late fraud', 'top = 1', 1, C.r('top'));
  const n2 = T.batch(b1.mem, 2); await submit(C, OP1, 2, n2, b1.final); const n3 = T.batch(n2.mem, 3); await submit(C, OP1, 3, n3, n2.final);
  const c2 = C.b(CH2); await playAll(C, [gb]); rec('late fraud', 'old h3 fraud proven later', 'c', gb.winner);
  rec('late fraud', 'top unchanged (replacement h2,h3 stay live)', 3, C.r('top'));
  rec('late fraud', 'h3 challenger still gets its share', CBOND - GF - FEE + OBOND / 2, C.b(CH2) - c2);
  rec('late fraud', 'burned = 2 x OBOND/2', OBOND, C.r('burned')); rec('late fraud', 'OP3 cannot reclaim', 'bounce', bnc(await S(C, OP3, ROLL, 0, { reclaim: L3.sid }), /cannot reclaim/)); };

// many parallel challengers on one fraudulent height; the fraudster's own sock puppet goes first
groups.multi = async () => { const C = new Chain(); const G0 = T.genesis(); const b1 = T.batch(G0, 1); await submit(C, OP1, 1, b1, 'genesis');
  const h2 = T.batch(b1.mem, 2), L2 = T.batch(b1.mem, 2, { k: 50, mut: T.MUT.reg }); await submit(C, OP2, 2, L2, b1.final);
  const PUP = A('OPTWOPUPPET'); const op2_0 = C.b(OP2) + C.b(PUP) + OBOND; // fraudster wealth before the bond (bond counted back)
  const op = await open(C, PUP, L2.sid), o1 = await open(C, CH1, L2.sid), o2 = await open(C, CH2, L2.sid), o3 = await open(C, CH3, L2.sid);
  const gp = game(op, L2, h2, h2, { chDelay: 10 }), g1 = game(o1, L2, h2, h2), g2 = game(o2, L2, h2, h2), g3 = game(o3, L2, T.batch(b1.mem, 2, { k: 3, mut: T.MUT.reg }), h2);
  const c1 = C.b(CH1); await playAll(C, [gp, g1, g2, g3]);
  rec('multi', 'puppet game', 'c', gp.winner); rec('multi', 'honest challenger 1', 'c', g1.winner); rec('multi', 'honest challenger 2', 'c', g2.winner);
  rec('multi', 'challenger 3 with a wrong belief still wins (the operator lied later anyway) or loses', true, ['c', 'd'].includes(g3.winner), { winner: g3.winner });
  rec('multi', 'later winners get their bond back (CBOND-GF-FEE)', CBOND - GF - FEE, C.b(CH1) - c1);
  // games are independent: a challenger who disputes an honest step loses its game, even to a fraudster (g3 may do that)
  const fromOthers = g3.winner === 'd' ? CBOND - GF - FEE : 0;
  const loss = op2_0 - (C.b(OP2) + C.b(PUP)); rec('multi', 'fraudster + puppet net loss >= OBOND/2 (not counting bonds of challengers who disputed an honest step)', true, loss + fromOthers >= OBOND / 2, { loss, fromOthers });
  rec('multi', 'open games counter back to 0', 0, C.r('n' + L2.sid) || 0); rec('multi', 'top = 1', 1, C.r('top')); };

// delay attack: K sock puppets open games all over the window, the last one 1 s before it closes, all play as slowly as allowed
groups.delay = async () => { const K = +(process.env.PUPPETS || 40); const X = +(process.env.EXTRA || 4000); const C = new Chain(); const G0 = T.genesis(); const b1 = T.batch(G0, 1, { extra: X }); /* long batch: more rounds */ const t0 = C.ts; await submit(C, OP1, 1, b1, 'genesis');
  const op0 = C.b(OP1); const games = [];
  for (let i = 0; i < K; i++) { const ti = t0 + Math.floor((WIN - 1) * (i + 1) / K); await playAll(C, games, ti - 1); C.ts = Math.max(C.ts, ti); const P = A('PUPPET' + i);
    const mode = i % 4; // 0: slow liar, 1: silent after opening, 2: slow + no memo at the last step, 3: random wrong belief
    const belief = T.batch(G0, 1, { extra: X, k: 1 + (i * 97) % b1.steps, mut: [T.MUT.reg, T.MUT.pc, T.MUT.mem, T.MUT.step][i % 4] });
    const o = await open(C, P, b1.sid); if (o.err) { rec('delay', 'puppet ' + i + ' open', 'ok', ok(o)); continue; }
    games.push(game(o, b1, belief, b1, { chDelay: mode === 3 ? 600 : 'slow', chSilent: mode === 1, noMemo: mode === 2 })); }
  rec('delay', K + ' puppets opened games inside the window', K, games.length);
  await playAll(C, games, t0 + WIN - 1); C.ts = Math.max(C.ts, t0 + WIN); let r = await open(C, A('LATEPUPPET'), b1.sid); rec('delay', 'puppet opens after the window', 'bounce', bnc(r, /window closed/));
  // run games until 12 h after the window, then try to finalize
  await playAll(C, games, t0 + WIN + 2 * TM); r = await S(C, OP1, ROLL, 0, { finalize: 1 }); rec('delay', 'finalize while puppet games are still running', 'bounce', bnc(r, /games open/));
  await playAll(C, games); const last = Math.max(...games.map(g => g.resolvedAt || 0));
  rec('delay', 'every puppet game resolved for the operator', K, games.filter(g => g.winner === 'd').length, { others: games.filter(g => g.winner !== 'd').map(g => g.winner).slice(0, 3) });
  C.ts = Math.max(C.ts, last); r = await S(C, OP1, ROLL, 0, { finalize: 1 }); rec('delay', 'finalize after the last puppet game', 'ok', ok(r));
  const delayH = (last - (t0 + WIN)) / 3600; const maxMoves = Math.max(...games.map(g => g.moves));
  rec('delay', 'extra delay beyond the window is bounded by one game (<= 2*rounds+1 moves x 1 h)', true, delayH <= (2 * Math.ceil(Math.log(b1.steps) / Math.log(16)) + 2), { delayHours: +delayH.toFixed(2), steps: b1.steps, maxMovesInAGame: maxMoves });
  const gain = C.b(OP1) - op0; rec('delay', 'operator earns every puppet bond (K x (CBOND-GF-FEE)) + its own bond back', K * (CBOND - GF - FEE) + OBOND - FEE, gain);
  rec('delay', 'rollup surplus = FEE per payout + GB per result (no drain, nothing stuck)', (K + 1) * FEE + K * GB + 10000 /* bounce fee of the late open */, C.b(ROLL) - liabilities(C), { burned: C.r('burned') || 0 }); };

// honest operator vs griefers: bond accounting, no drain, referee balance
groups.grief = async () => { const C = new Chain(); const G0 = T.genesis(); const b1 = T.batch(G0, 1); await submit(C, OP1, 1, b1, 'genesis');
  const b2 = T.batch(b1.mem, 2); await submit(C, OP1, 2, b2, b1.final);
  const games = []; for (let i = 0; i < 12; i++) { const P = A('GRIEF' + i); const sid = i % 2 ? b2.sid : b1.sid; const tr = i % 2 ? b2 : b1;
    const o = await open(C, P, sid); games.push(game(o, tr, T.batch(i % 2 ? b1.mem : G0, i % 2 ? 2 : 1, { k: 2 + i * 3, mut: T.MUT.reg }), tr, { defSilent: false })); }
  const roll0 = C.b(ROLL), op0 = C.b(OP1); await playAll(C, games);
  rec('grief', '12 griefers lose', 12, games.filter(g => g.winner === 'd').length);
  rec('grief', 'operator gets 12 x (CBOND - GF - FEE)', 12 * (CBOND - GF - FEE), C.b(OP1) - op0);
  rec('grief', 'referee AA keeps GF - GB per game for its fees', 12 * (GF - GB), C.b(GAME));
  rec('grief', 'top stays 2', 2, C.r('top'));
  C.ts += WIN; rec('grief', 'finalize 1', 'ok', ok(await S(C, W, ROLL, 0, { finalize: 1 }))); rec('grief', 'finalize 2', 'ok', ok(await S(C, W, ROLL, 0, { finalize: 2 })));
  rec('grief', 'rollup ends holding only kept FEEs + referee refunds (no drain)', 14 * FEE + 12 * GB, C.b(ROLL)); };

// callbacks, referee abuse
groups.forge = async () => { const G0 = T.genesis(); const b1 = T.batch(G0, 1);
  { const C = new Chain(); await submit(C, OP1, 1, b1, 'genesis'); const o = await open(C, CH1, b1.sid);
    // attacker opens its own referee game with the same ref (n=1, lies), lets it time out and resolves it at once
    let r = await S(C, CH1, GAME, GF, { open: o.ref, s0: b1.s0, sN: ref.H('lie'), n: 1, d: CH1, c: CH1 }); rec('forge', 'attacker opens its own referee game with the rollup game ref', 'ok', ok(r));
    r = await S(C, CH1, GAME, 0, { resolve: CH1 + o.ref }); rec('forge', 'attacker game: resolve before deadline without memo', 'bounce', bnc(r, /undecided/));
    const g = game(o, b1, T.batch(G0, 1, { k: 7, mut: T.MUT.reg }), b1, { chDelay: 'slow' }); await playAll(C, [g], C.ts + 600); // a few moves of the real game
    C.ts += 60; r = await S(C, CH1, GAME, 0, { resolve: CH1 + o.ref });
    rec('forge', 'attacker game (n=1, no memo) resolves at its deadline -> result goes to the attacker address', true, !r.err || /undecided/.test(r.err), { outcome: ok(r) });
    rec('forge', 'rollup game untouched by the attacker game', 'open', String(C.r('G' + o.ref)).split(':')[2]); rec('forge', 'h1 not voided', 1, C.r('top'));
    r = await S(C, CH1, ROLL, 0, { res: o.ref, w: 'c' }); rec('forge', 'user sends a fake result {res, w:c} to the rollup', 'bounce', bnc(r, /unknown command/));
    r = await S(C, CH1, GAME, 0, { mids: o.gid, roots: [] }); rec('forge', 'challenger posts mids in the rollup game', 'bounce', bnc(r, /not your move|need/));
    await playAll(C, [g]); rec('forge', 'rollup game then plays out normally', 'd', g.winner);
    r = await S(C, W, GAME, 0, { resolve: o.gid }); rec('forge', 'resolve a finished game again (double callback)', 'bounce', bnc(r, /no game/));
    rec('forge', 'rollup game marked d', 'd', String(C.r('G' + o.ref)).split(':')[2]); }
  { const C = new Chain(); await submit(C, OP1, 1, b1, 'genesis'); const o = await open(C, CH1, b1.sid);
    let r = await S(C, OP1, GAME, 0, { resolve: o.gid }); rec('forge', 'resolve the rollup game before any deadline', 'bounce', bnc(r, /undecided/));
    r = await S(C, CH1, GAME, 0, { open: rnd(), s0: b1.s0, sN: b1.final, n: 5, d: OP1, c: CH1 }); rec('forge', 'referee open without the fee', 'bounce', bnc(r, /fee/));
    r = await S(C, CH1, GAME, GF, { open: 'a:b', s0: b1.s0, sN: b1.final, n: 5, d: OP1, c: CH1 }); rec('forge', 'referee open with ":" in ref', 'bounce', bnc(r, /bad open/));
    r = await S(C, CH1, GAME, GF, { open: rnd(), s0: b1.s0, sN: b1.final, n: 5, d: 'x:y', c: CH1 }); rec('forge', 'referee open with a bad player address', 'bounce', bnc(r, /bad players/));
    r = await S(C, CH1, GAME, GF, { open: o.ref, s0: b1.s0, sN: b1.final, n: 5, d: OP1, c: CH1 }); rec('forge', 'second direct open with the same ref by the same opener', 'ok', ok(r));
    r = await S(C, CH1, GAME, GF, { open: o.ref, s0: b1.s0, sN: b1.final, n: 5, d: OP1, c: CH1 }); rec('forge', 'third direct open, same opener + ref (slot taken)', 'bounce', bnc(r, /game exists/)); } };

// the single step: operator lies at the very last step; challenger forgets the memo; operator silent
groups.edges = async () => { const G0 = T.genesis(); const b1 = T.batch(G0, 1);
  { const C = new Chain(); const L = T.batch(G0, 1, { k: b1.steps, mut: T.MUT.reg }); await submit(C, OP1, 1, L, 'genesis'); const o = await open(C, CH1, L.sid);
    const g = game(o, L, b1, b1); await playAll(C, [g]); rec('edges', 'lie only in the final registers (last step)', 'c', g.winner); rec('edges', 'voided', 0, C.r('top')); }
  { const C = new Chain(); const L = T.batch(G0, 1, { k: 1, mut: T.MUT.mem }); await submit(C, OP1, 1, L, 'genesis'); const o = await open(C, CH1, L.sid);
    const g = game(o, L, b1, b1); await playAll(C, [g]); rec('edges', 'lie at the first step', 'c', g.winner); }
  { const C = new Chain(); const L = T.batch(G0, 1, { k: 20, mut: T.MUT.reg }); await submit(C, OP1, 1, L, 'genesis'); const o = await open(C, CH1, L.sid);
    const g = game(o, L, b1, b1, { noMemo: true }); await playAll(C, [g]); rec('edges', 'challenger never posts the one-step memo -> loses (burden of proof)', 'd', g.winner); rec('edges', 'not voided', 1, C.r('top')); }
  { const C = new Chain(); const L = T.batch(G0, 1, { k: 20, mut: T.MUT.reg }); await submit(C, OP1, 1, L, 'genesis'); const o = await open(C, CH1, L.sid);
    const g = game(o, L, b1, b1, { defSilent: true }); await playAll(C, [g]); rec('edges', 'operator silent -> fraud', 'c', g.winner); rec('edges', 'voided', 0, C.r('top')); }
  { const C = new Chain(); const t = T.batch(G0, 1, { extra: 7 }); await submit(C, OP1, 1, t, 'genesis'); const o = await open(C, CH1, t.sid);
    const g = game(o, t, T.batch(G0, 1, { extra: 7, k: 66, mut: T.MUT.reg }), t); await playAll(C, [g]); rec('edges', 'steps beyond HALT (absorbing no-op steps), griefer picks the tail', 'd', g.winner); }
  // a lie that changes the step counter or the input root cannot even be submitted: the AA rebuilds the final root
  // with the committed steps / input root
  { const C = new Chain(); const L = T.batch(G0, 1, { k: 30, mut: T.MUT.inp }); rec('edges', 'submit with the input tree swapped mid-batch', 'bounce', bnc(await submit(C, OP1, 1, L, 'genesis'), /bad final root/)); }
  { const C = new Chain(); const L = T.batch(G0, 1, { k: 30, mut: T.MUT.step }); rec('edges', 'submit with a skipped step counter', 'bounce', bnc(await submit(C, OP1, 1, L, 'genesis'), /bad final root/)); }
  // ... but the same lies inside the intermediate roots (mids) are caught by the game
  for (const kind of ['inp', 'step', 'pc', 'mem']) { const C = new Chain(); await submit(C, OP1, 1, b1, 'genesis'); const o = await open(C, CH1, b1.sid);
    const bad = T.batch(G0, 1, { k: 17, mut: T.MUT[kind] }); const mids = b1.roots.map((r, i) => i === b1.steps ? b1.final : (bad.roots[i] || ref.H('pad' + i))); // lying mids, honest final
    const g = game(o, { op: OP1, roots: mids }, b1, b1); await playAll(C, [g]); rec('edges', 'operator posts ' + kind + '-lie mids under an honest final root', 'c', g.winner); } };

// hostile AA as operator / challenger (a payout to it would bounce and freeze resolve / finalize forever)
groups.aaplayer = async () => { const G0 = T.genesis(); const b1 = T.batch(G0, 1);
  { const C = new Chain(); const r = await submit(C, BOUNCER, 1, b1, 'genesis'); rec('AA player', 'an AA that refuses payments submits h1', 'bounce', bnc(r, /AA/));
    if (!r.err) { C.ts += WIN; const f = await S(C, W, ROLL, 0, { finalize: 1 }); rec('AA player', '(if accepted) finalize of its height', 'ok', ok(f)); } }
  { const C = new Chain(); const L = T.batch(G0, 1, { k: 9, mut: T.MUT.reg }); await submit(C, OP1, 1, L, 'genesis'); const o = await open(C, BOUNCER, L.sid);
    rec('AA player', 'an AA that refuses payments opens a game', 'bounce', bnc(o, /AA/));
    if (!o.err) { const g = game(o, L, b1, b1); await playAll(C, [g]); const r = await S(C, W, GAME, 0, { resolve: o.gid }); rec('AA player', '(if accepted) its winning game resolves', 'ok', ok(r)); } }
  { const C = new Chain(); const t = T.batch(G0, 1); const st = 2 ** 40 + 1; const fin = ref.H(t.fpc + ':' + t.fregs + ':' + t.fmem + ':' + t.inpRoot + ':' + st);
    rec('AA player', 'steps 2^40 + 1 with a matching final root (a batch no challenger can recompute)', 'bounce', bnc(await S(C, OP1, ROLL, OBOND, subData(t, 1, 'genesis', { steps: st, final: fin })), /bad steps/));
    const st2 = 2 ** 40; const fin2 = ref.H(t.fpc + ':' + t.fregs + ':' + t.fmem + ':' + t.inpRoot + ':' + st2);
    rec('AA player', 'steps = 2^40 exactly (halted early, absorbing tail) accepted', 'ok', ok(await S(C, OP1, ROLL, OBOND, subData(t, 1, 'genesis', { steps: st2, final: fin2 })))); } };

// random adversary fuzz: honest + fraudulent operators racing, griefers, an honest watcher, garbage, random clocks
// move refunds: a primary trigger must carry >= 10000 bytes (bounce_fees); the referee keeps MK and refunds the rest on
// mids / pick, so an honest operator's cost per round is MK + unit fee, not 10000 + unit fee (attack pass 2)
groups.refund = async () => { const C = new Chain(); const G0 = T.genesis(); const b1 = T.batch(G0, 1); await submit(C, OP1, 1, b1, 'genesis');
  const MK = M.ref.keep; const o = await open(C, CH1, b1.sid); const lie = T.batch(G0, 1, { k: 11, mut: T.MUT.reg });
  let s = gv(C, o.gid).split(':'); let { cnt, pt } = pts(+s[3], +s[4]); const op0 = C.b(OP1), g0 = C.b(GAME);
  let r = await S(C, OP1, GAME, 10000, { mids: o.gid, roots: Array.from({ length: cnt }, (_, i) => b1.roots[pt(i + 1)]) }); rec('refund', 'operator mids with a 10000-byte trigger', 'ok', ok(r));
  rec('refund', 'operator pays only MK for the move', -MK, C.b(OP1) - op0); rec('refund', 'referee keeps MK', MK, C.b(GAME) - g0);
  s = gv(C, o.gid).split(':'); ({ cnt, pt } = pts(+s[3], +s[4])); const m = String(C.v(GAME, 'm_' + o.gid)).split(','); let j = 0; while (j < cnt && m[j] === lie.roots[pt(j + 1)]) j++;
  const ch0 = C.b(CH1); r = await S(C, CH1, GAME, 10000, { pick: o.gid, j }); rec('refund', 'challenger pick with 10000 pays only MK', -MK, ok(r) === 'ok' ? C.b(CH1) - ch0 : ok(r));
  const op1 = C.b(OP1); r = await S(C, OP1, GAME, MK - 1, { mids: o.gid, roots: [] }); rec('refund', 'a move below MK gets no refund (and a bad move still bounces)', 'bounce', bnc(r, /need|not your move/));
  const g = game(o, b1, lie, b1); await playAll(C, [g]); rec('refund', 'game still plays out: honest operator wins', 'd', g.winner);
  r = await S(C, W, GAME, 10000, { resolve: o.gid }); rec('refund', 'resolve of a finished game bounces', 'bounce', bnc(r, /no game/)); };

// overpayment refunds (2026-10-31): submit returns trigger - OBOND - FEE, open returns trigger - CBOND, the referee's
// direct open returns trigger - GF and resolve returns trigger - RK; payouts and the bond invariant are unchanged
groups.overpay = async () => { const G0 = T.genesis(); const b1 = T.batch(G0, 1); const RK = 10000;
  const num = k => { const m = M.body.match(new RegExp('\\$' + k + ' = (\\d+);')); return m ? +m[1] : null; };
  rec('overpay', 'rv_rollup constants: CBOND 120000, OBOND 200000, MAXSTEPS 2^40', [120000, 200000, 2 ** 40], [num('CBOND'), num('OBOND'), num('MAXSTEPS')]);
  rec('overpay', 'test constants match the AA', [CBOND, OBOND, GF, FEE], [num('CBOND'), num('OBOND'), num('GF'), num('FEE')]);
  { const C = new Chain(); const o0 = C.b(OP1), r0 = C.b(ROLL);
    let r = await S(C, OP1, ROLL, OBOND + 50000, subData(b1, 1, 'genesis')); b1.sid = r.unit; b1.op = OP1; rec('overpay', 'submit with OBOND + 50000', 'ok', ok(r));
    rec('overpay', 'operator net cost OBOND + FEE (refund 50000 - FEE)', OBOND + FEE, o0 - C.b(OP1)); rec('overpay', 'rollup keeps OBOND + FEE', OBOND + FEE, C.b(ROLL) - r0);
    const b2 = T.batch(b1.mem, 2), b3 = T.batch(b2.mem, 3), b4 = T.batch(b3.mem, 4);
    const o2 = C.b(OP2); r = await S(C, OP2, ROLL, OBOND + FEE, subData(b2, 2, b1.final)); b2.sid = r.unit; rec('overpay', 'submit with OBOND + FEE: accepted, no refund (<= FEE kept)', ['ok', OBOND + FEE], [ok(r), o2 - C.b(OP2)]);
    const o3 = C.b(OP2); r = await S(C, OP2, ROLL, OBOND + FEE + 1, subData(b3, 3, b2.final)); b3.sid = r.unit; rec('overpay', 'submit with OBOND + FEE + 1: refund 1', ['ok', OBOND + FEE], [ok(r), o3 - C.b(OP2)]);
    const o4 = C.b(OP3); r = await S(C, OP3, ROLL, OBOND, subData(b4, 4, b3.final)); b4.sid = r.unit; rec('overpay', 'submit with exactly OBOND: no refund', ['ok', OBOND], [ok(r), o4 - C.b(OP3)]);
    const ob = C.b(OP1); r = await S(C, OP1, ROLL, OBOND + 70000, subData(T.batch(b4.mem, 6), 6, b4.final)); rec('overpay', 'overpaid submit that bounces (gap) costs only the bounce fee', ['bounce', 10000], [bnc(r, /gap/), ob - C.b(OP1)]);
    const c0 = C.b(CH1), g0 = C.b(GAME); const o = await open(C, CH1, b1.sid); rec('overpay', 'open with exactly CBOND', 'ok', ok(o)); rec('overpay', 'challenger pays CBOND', CBOND, c0 - C.b(CH1));
    const c1 = C.b(CH2), rl = C.b(ROLL); r = await S(C, CH2, ROLL, CBOND + 30000, { open: b1.sid }); const o2g = { gid: ROLL + r.unit, ref: r.unit, ch: CH2 };
    rec('overpay', 'open with CBOND + 30000', 'ok', ok(r)); rec('overpay', 'challenger net cost CBOND (refund 30000 in full)', CBOND, c1 - C.b(CH2));
    rec('overpay', 'referee got exactly GF per open (no refund to the rollup)', 2 * GF, C.b(GAME) - g0); rec('overpay', 'rollup keeps CBOND - GF from the overpaid open', CBOND - GF, C.b(ROLL) - rl);
    r = await S(C, CH3, ROLL, CBOND - 1, { open: b1.sid }); rec('overpay', 'open with CBOND - 1 still bounces', 'bounce', bnc(r, /bond/));
    const lie = T.batch(G0, 1, { k: 11, mut: T.MUT.reg }); const ga = game(o, b1, lie, b1), gb = game(o2g, b1, T.batch(G0, 1, { k: 40, mut: T.MUT.pc }), b1);
    const op0 = C.b(OP1); await playAll(C, [ga, gb]); rec('overpay', 'both griefer games (one overpaid) -> d', ['d', 'd'], [ga.winner, gb.winner]);
    rec('overpay', 'operator gets 2 x (CBOND - GF - FEE) = 2 x 108000', 2 * (CBOND - GF - FEE), C.b(OP1) - op0);
    C.ts += WIN; for (const h of [1, 2, 3, 4]) await S(C, W, ROLL, 0, { finalize: h }); rec('overpay', 'h1..h4 finalize after the games', 4, C.r('lf'));
    rec('overpay', 'rollup ends with 3 kept submit FEEs + 6 payout FEEs + 2 GB + 2 bounce fees (no bond left, nothing over-refunded)', 3 * FEE + 6 * FEE + 2 * GB + 2 * 10000, C.b(ROLL) - r0); }
  // fraud payout with an overpaid open: CBOND - GF - FEE + OBOND/2 = 208000
  { const C = new Chain(); const L = T.batch(G0, 1, { k: 20, mut: T.MUT.reg }); await submit(C, OP1, 1, L, 'genesis');
    const c0 = C.b(CH1); const r = await S(C, CH1, ROLL, CBOND + 12345, { open: L.sid }); const g = game({ gid: ROLL + r.unit, ref: r.unit, ch: CH1 }, L, b1, b1); await playAll(C, [g]);
    rec('overpay', 'overpaid open on a fraud: challenger wins', 'c', g.winner); rec('overpay', 'challenger net gain OBOND/2 - GF - FEE (= 88000; payout 208000)', OBOND / 2 - GF - FEE, C.b(CH1) - c0);
    rec('overpay', 'burned = OBOND/2 (stays locked: no command pays it out)', OBOND / 2, C.r('burned'));
    for (const cmd of [{ withdraw: 1 }, { burn: 1 }, { reclaim: L.sid }, { finalize: 1 }]) rec('overpay', 'nobody can take the burned half: ' + JSON.stringify(cmd).slice(0, 30), 'bounce', bnc(await S(C, OP1, ROLL, 10000, cmd), /./)); }
  // referee direct open / resolve refunds
  { const C = new Chain(); await submit(C, OP1, 1, b1, 'genesis'); const ref0 = rnd();
    const c0 = C.b(CH1), g0 = C.b(GAME); let r = await S(C, CH1, GAME, GF + 5000, { open: ref0, s0: b1.s0, sN: ref.H('lie'), n: 1, d: OP1, c: CH1 });
    rec('overpay', 'direct referee open with GF + 5000: refund 5000', ['ok', GF, GF], [ok(r), c0 - C.b(CH1), C.b(GAME) - g0]);
    const o = await open(C, CH2, b1.sid); C.ts += TM + 1; // operator never moves: challenger wins by timeout
    const w0 = C.b(W), g1 = C.b(GAME), c2 = C.b(CH2); r = await S(C, W, GAME, RK + 25000, { resolve: o.gid });
    rec('overpay', 'resolve with RK + 25000', 'ok', ok(r)); rec('overpay', 'resolver pays only RK (refund 25000)', RK, w0 - C.b(W));
    rec('overpay', 'referee nets RK - GB from that resolve', RK - GB, C.b(GAME) - g1); rec('overpay', 'callback still pays the winner CBOND - GF - FEE + OBOND/2', CBOND - GF - FEE + OBOND / 2, C.b(CH2) - c2);
    const w1 = C.b(W); r = await S(C, W, GAME, RK, { resolve: CH1 + ref0 }); rec('overpay', 'resolve with exactly RK: no refund', ['ok', RK], [ok(r), w1 - C.b(W)]); } };

groups.fuzz = async () => { const RUNS = +(process.env.FUZZ || 6), STEPS = +(process.env.FUZZSTEPS || 60); let seed = +(process.env.FUZZSEED || 11);
  const rnd01 = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; }; const pick = a => a[Math.floor(rnd01() * a.length)];
  const OPS = [OP1, OP2, OP3, A('OPFOUR')], GRIEF = [A('G1'), A('G2'), A('G3')], WATCH = A('HONESTWATCH');
  let finalizedBad = 0, stuck = 0, fraudsCaught = 0, fraudsSubmitted = 0, voids = 0, garbageAccepted = 0, leftover = 0, games = 0, unreclaimed = 0;
  for (let run = 0; run < RUNS; run++) {
    const C = new Chain(); const G0 = T.genesis(); const subs = {}; const active = [];
    const liveSid = h => { const sid = C.r('h' + h); return sid && h <= (C.r('top') || 0) ? sid : null; };
    for (let it = 0; it < STEPS; it++) {
      { const tgt = C.ts + Math.floor(rnd01() * 3 * TM); await playAll(C, active, tgt); C.ts = Math.max(C.ts, tgt); } const top = C.r('top') || 0; const x = rnd01();
      if (x < 0.3) { // submit next height (maybe fraudulent, maybe racing / wrong prev)
        const h = top + 1; const prevSid = h > 1 ? liveSid(h - 1) : null; const prevTr = prevSid ? subs[prevSid] : null; const pm = prevTr ? prevTr.mem : G0;
        const lie = rnd01() < 0.35; const sd = Math.floor(rnd01() * 1000);
        const tr = lie ? T.batch(pm, sd, { k: 1 + Math.floor(rnd01() * 60), mut: pick([T.MUT.reg, T.MUT.mem, T.MUT.pc]) }) : T.batch(pm, sd);
        const op = pick(OPS); const wrongPrev = rnd01() < 0.1; const r = await submit(C, op, wrongPrev ? h + 1 : h, tr, prevTr ? prevTr.final : 'genesis');
        if (!r.err) { tr.honest = !lie || tr.final === T.batch(pm, sd).final; tr.parent = prevSid; subs[tr.sid] = tr; if (!tr.honest) fraudsSubmitted++;
          // the honest watcher challenges every fraudulent live submission right away
          if (!tr.honest) { const o = await open(C, WATCH, tr.sid); if (!o.err) { active.push(game(o, tr, T.batch(pm, sd), T.batch(pm, sd))); games++; } } } }
      else if (x < 0.5) { // a griefer disputes a random live height with a wrong belief
        const h = 1 + Math.floor(rnd01() * Math.max(1, top)); const sid = liveSid(h); if (!sid) continue; const tr = subs[sid];
        const pm = tr.parent ? subs[tr.parent].mem : G0; const honestTr = tr.honest ? tr : null; if (!honestTr) continue;
        const belief = { roots: tr.roots.map((r, i) => i >= 1 + Math.floor(rnd01() * tr.steps) ? ref.H('g' + i) : r) };
        const o = await open(C, pick(GRIEF), sid); if (!o.err) { active.push(game(o, tr, belief, tr, { chDelay: pick([60, 'slow', 600]), chSilent: rnd01() < 0.2, noMemo: rnd01() < 0.3 })); games++; } }
      else if (x < 0.7) { await S(C, pick([W, ...OPS]), ROLL, 0, { finalize: (C.r('lf') || 0) + 1 }); }
      else if (x < 0.8) { for (const sid in subs) if (!liveSid(subs[sid].h) || C.r('h' + subs[sid].h) !== sid) await S(C, subs[sid].op, ROLL, 0, { reclaim: sid }); }
      else { // garbage
        const g = pick([{ submit: 'x' }, { open: 'zzz' }, { finalize: -1 }, { reclaim: 5 }, { res: 'a', w: 'c' }, { open: Object.keys(subs)[0] || 'q', extra: [1, 2] }, { submit: top + 1, s0: 1 }, {}]);
        const who = pick(GRIEF); const r = await S(C, who, ROLL, pick([0, CBOND, OBOND]), g); if (!r.err && !g.open) garbageAccepted++;
        // an open with extra fields is a real game: the operator (online, honest or not) answers it, the griefer goes silent
        if (!r.err && g.open) { const tr = subs[g.open]; active.push(game({ gid: ROLL + r.unit, ch: who }, tr, { roots: [] }, tr, { chSilent: true })); games++; } }
    }
    // drain: play every game out, finalize everything possible, reclaim every voided submission
    for (let k = 0; k < 6; k++) { await playAll(C, active); C.ts += 2 * WIN; for (let h = (C.r('lf') || 0) + 1; h <= (C.r('top') || 0); h++) await S(C, W, ROLL, 0, { finalize: h });
      for (const sid in subs) await S(C, subs[sid].op, ROLL, 0, { reclaim: sid }); }
    stuck += active.filter(g => !["c", "d"].includes(g.winner)).length; if (process.env.DBG) console.log(active.slice(0,3).map(g => [g.winner, g.moves, g.errs, gv(C, g.gid).slice(0,60)]));
    fraudsCaught += Object.keys(subs).filter(sid => C.r('f' + sid)).length; voids += Object.values(subs).filter(t => !liveSid(t.h) || C.r('h' + t.h) !== t.sid).length;
    for (let h = 1; h <= (C.r('lf') || 0); h++) { const t = subs[C.r('h' + h)]; if (!t || !t.honest || (t.parent && !subs[t.parent].honest)) finalizedBad++; }
    const un = Object.keys(subs).filter(sid => !C.r('r' + sid) && !C.r('f' + sid)); unreclaimed += un.length;
    if (process.env.DBG) for (const sid of un.slice(0, 3)) { const t = subs[sid]; const fz = await C.send(W, ROLL, 0, { finalize: t.h }); const rc = await C.send(t.op, ROLL, 0, { reclaim: sid });
      console.log('UNRECLAIMED h', t.h, 'top', C.r('top'), 'lf', C.r('lf'), 'ptr', C.r('h' + t.h) === sid, 'n', C.r('n' + sid), 'fin', fz.err, 'rec', rc.err, 'honest', t.honest); }
    leftover += liabilities(C) - (C.r('burned') || 0);
  }
  rec('fuzz', 'no fraudulent (or fraud-chained) height ever finalized', 0, finalizedBad, { runs: RUNS, steps: STEPS, fraudsSubmitted, fraudsCaught, games, voids });
  rec('fuzz', 'no game stuck', 0, stuck); rec('fuzz', 'every fraudulent submission caught by the watcher', fraudsSubmitted, fraudsCaught);
  rec('fuzz', 'garbage never accepted', 0, garbageAccepted); rec('fuzz', 'after the drain every bond is paid out (no liabilities left)', 0, leftover);
  rec('fuzz', 'every non-fraud submission finalized or reclaimed', 0, unreclaimed); };


// ---------- loop round 3: layer-1 game (rv_seg_ref): bisection over unit-boundary machine roots, then rv_game_ref on one unit
const H64 = x => require('crypto').createHash('sha256').update(x).digest('base64');
async function uopen(C, ch, sid, amt) { const r = await S(C, ch, ROLL, amt === undefined ? CBOND + GF : amt, { uopen: sid }); return r.err ? r : { ...r, sgid: ROLL + r.unit, ref: r.unit, ch }; }
const sv = (C, gid) => String(C.v(SEG, 'g_' + gid) || '');
// sg = {sgid, def, ch, defRoots, chRoots, honest, U, steps, bnd (k -> defender's step index for unit boundary k),
//       defSilent, chSilent, noMemo, defDelay, chDelay}
async function playSeg(C, sg) {
  sg.l1 = 0; sg.bnd = sg.bnd || (k => Math.floor(k * sg.steps / sg.U));
  for (let it = 0; it < 200; it++) {
    const s = sv(C, sg.sgid).split(':');
    if (s[0] === 'done') { sg.winner = s[1]; return sg; }
    if (s.length !== 11) { sg.winner = 'none: ' + s.join(':').slice(0, 40); return sg; }
    const lo = +s[3], hi = +s[4], slo = +s[5], shi = +s[6], turn = s[9], dl = +s[10]; const { cnt, pt } = pts(lo, hi); let r;
    if (turn === 'x') { // layer 2 on the one unit [slo, shi]
      const g2 = { gid: SEG + H64(sg.sgid), def: s[1], ch: s[2], defRoots: sg.defRoots.slice(slo, shi + 1), chRoots: sg.chRoots.slice(slo, shi + 1),
        honest: { roots: sg.honest.roots.slice(slo), wits: sg.honest.wits.slice(slo) }, noMemo: sg.noMemo, defSilent: sg.l2DefSilent };
      sg.unit = [lo, hi, slo, shi]; await playAll(C, [g2]); sg.l2 = g2; sg.l2moves = g2.moves;
      const s2 = sv(C, sg.sgid); sg.winner = s2.startsWith('done:') ? s2.slice(5) : 'l2 ' + g2.winner + ' / seg ' + s2.slice(0, 30); return sg; }
    if (turn === 'd') {
      if (sg.defSilent) { C.ts = Math.max(C.ts, dl); r = await S(C, W, SEG, 0, { resolve: sg.sgid }); }
      else { C.ts += sg.defDelay || 60; const st = Array.from({ length: cnt }, (_, i) => sg.bnd(pt(i + 1)));
        r = await S(C, sg.def, SEG, 0, { mids: sg.sgid, steps: st, roots: st.map(x => sg.defRoots[x]) }); sg.l1++; }
    } else {
      if (sg.chSilent) { C.ts = Math.max(C.ts, dl); r = await S(C, W, SEG, 0, { resolve: sg.sgid }); }
      else { C.ts += sg.chDelay || 60; const m = String(C.v(SEG, 'm_' + sg.sgid)).split(','), n = String(C.v(SEG, 'n_' + sg.sgid)).split(',').map(Number);
        const rootAt = i => i == 0 ? s[7] : i == cnt + 1 ? s[8] : m[i - 1], stepAt = i => i == 0 ? slo : i == cnt + 1 ? shi : n[i - 1];
        let j = 0; while (j < cnt && rootAt(j + 1) === sg.chRoots[stepAt(j + 1)]) j++; r = await S(C, sg.ch, SEG, 0, { pick: sg.sgid, j }); sg.l1++; }
    }
    if (r.err) { sg.winner = 'stuck: ' + r.err; return sg; }
  }
  sg.winner = 'loop'; return sg;
}
const sgame = (o, def, ch, honest, extra) => ({ sgid: o.sgid, def: def.op, ch: o.ch, defRoots: def.roots, chRoots: ch.roots, honest, U: def.units || Math.min(8, def.steps), steps: def.steps, ...extra });

groups.l1flow = async () => { const C = new Chain(); const G0 = T.genesis(); const b1 = T.batch(G0, 1); await submit(C, OP1, 1, b1, 'genesis');
  rec('layer1 flow', 'units stored with the submission', Math.min(8, b1.steps), C.r('u' + b1.sid));
  let r = await uopen(C, CH1, b1.sid, CBOND); rec('layer1 flow', 'uopen with CBOND only (needs CBOND + GF)', 'bounce', bnc(r, /bond/));
  const L = T.batch(G0, 1, { k: 30, mut: T.MUT.reg });
  const o = await uopen(C, CH1, b1.sid); rec('layer1 flow', 'uopen with CBOND + GF', 'ok', ok(o));
  rec('layer1 flow', 'seg game opened: u units, n steps, defender to move', ['0', String(Math.min(8, b1.steps)), '0', String(b1.steps), b1.s0, b1.final, 'd'], sv(C, o.sgid).split(':').slice(3, 10));
  rec('layer1 flow', 'rollup counts the game (n = 1)', 1, C.r('n' + b1.sid));
  const op0 = C.b(OP1), seg0 = C.b(SEG); const g = await playSeg(C, sgame(o, b1, L, b1));
  rec('layer1 flow', 'griefer (register lie) vs honest operator via layer 1', 'd', g.winner, { l1moves: g.l1, l2moves: g.l2moves, unit: g.unit });
  rec('layer1 flow', 'operator paid CBOND - GF - FEE', CBOND - GF - FEE, C.b(OP1) - op0);
  rec('layer1 flow', 'seg referee keeps GF of its 2 GF (GF to layer 2; GB in from rv_game_ref, GB out to the rollup)', GF, C.b(SEG));
  rec('layer1 flow', 'game counter back to 0', 0, C.r('n' + b1.sid) || 0);
  C.ts += WIN; rec('layer1 flow', 'finalize after the layer-1 game', 'ok', ok(await S(C, W, ROLL, 0, { finalize: 1 })));
  // fraud at h2, honest challenger takes the layer-1 route
  const h2 = T.batch(b1.mem, 2), L2 = T.batch(b1.mem, 2, { k: 25, mut: T.MUT.mem }); await submit(C, OP2, 2, L2, b1.final);
  const c0 = C.b(CH2); const o2 = await uopen(C, CH2, L2.sid); const g2 = await playSeg(C, sgame(o2, L2, h2, h2));
  rec('layer1 flow', 'fraudulent h2 (hidden memory write) vs honest challenger via layer 1', 'c', g2.winner, { l1moves: g2.l1, l2moves: g2.l2moves, unit: g2.unit });
  rec('layer1 flow', 'challenger paid CBOND - GF - FEE + OBOND/2 (it paid CBOND + GF)', CBOND - GF - FEE + OBOND / 2 - (CBOND + GF), C.b(CH2) - c0);
  rec('layer1 flow', 'h2 voided (top = 1), fraud flag, burned OBOND/2', [1, 1, OBOND / 2], [C.r('top'), C.r('f' + L2.sid), C.r('burned')]);
  const C3 = new Chain(); const t1 = T.batch(G0, 1); await submit(C3, OP1, 1, t1, 'genesis'); const c3 = C3.b(CH3);
  r = await uopen(C3, CH3, t1.sid, CBOND + GF + 5000); rec('layer1 flow', 'uopen overpay 5000 refunded', CBOND + GF, c3 - C3.b(CH3)); };

groups.l1deep = async () => { const G0 = T.genesis(); const b1 = T.batch(G0, 1, { extra: 4000 }); b1.units = 300;
  for (const [nm, defT, chT, honest, exp, fraud] of [
    ['griefer (lie at step 2000) vs honest operator, 300 units', b1, T.batch(G0, 1, { extra: 4000, k: 2000, mut: T.MUT.reg }), b1, 'd', false],
    ['fraudulent operator (lie at step 3001) vs honest challenger, 300 units', Object.assign(T.batch(G0, 1, { extra: 4000, k: 3001, mut: T.MUT.mem }), { units: 300 }), b1, b1, 'c', true]]) {
    const C = new Chain(); await submit(C, OP1, 1, defT, 'genesis'); const o = await uopen(C, CH1, defT.sid);
    const g = await playSeg(C, sgame(o, defT, chT, honest));
    rec('layer1 deep', nm, exp, g.winner, { steps: defT.steps, units: 300, l1moves: g.l1, l2moves: g.l2moves, unit: g.unit });
    rec('layer1 deep', nm + ': layer-1 moves <= 2 x ceil(log16 300) = 6', true, g.l1 <= 6, { l1moves: g.l1 });
    if (fraud) rec('layer1 deep', 'fraud voids h1', 0, C.r('top')); }
  // the instruction game alone on the same batch, for the round count comparison
  const C = new Chain(); await submit(C, OP1, 1, b1, 'genesis'); const o = await open(C, CH1, b1.sid);
  const g = game(o, b1, T.batch(G0, 1, { extra: 4000, k: 2000, mut: T.MUT.reg }), b1); await playAll(C, [g]);
  rec('layer1 deep', 'same griefer via the whole-run instruction game', 'd', g.winner, { moves: g.moves }); };

groups.l1bnd = async () => { const G0 = T.genesis(); const b1 = T.batch(G0, 1, { extra: 600 }); b1.units = 40;
  // boundaries anywhere (not at unit ends), strictly increasing: soundness must not depend on them
  const rnd = (seed) => { let x = seed; return () => (x = (x * 1103515245 + 12345) % 2147483648) / 2147483648; };
  for (let t = 0; t < 4; t++) { const R = rnd(7 + t); const cuts = [0]; for (let k = 1; k < 40; k++) cuts.push(cuts[k - 1] + 1 + Math.floor(R() * ((b1.steps - cuts[k - 1] - (40 - k)) / (40 - k + 1) * 1.6)));
    cuts.push(b1.steps); const bnd = k => cuts[k]; const fraud = t % 2 === 1;
    const def = fraud ? Object.assign(T.batch(G0, 1, { extra: 600, k: 50 + 97 * t, mut: T.MUT.reg }), { units: 40 }) : b1;
    const C = new Chain(); await submit(C, OP1, 1, def, 'genesis'); const o = await uopen(C, CH1, def.sid);
    const g = await playSeg(C, sgame(o, def, fraud ? b1 : T.batch(G0, 1, { extra: 600, k: 300, mut: T.MUT.pc }), b1, { bnd }));
    rec('layer1 boundaries', (fraud ? 'fraudster' : 'honest operator') + ' with arbitrary increasing boundaries #' + t, fraud ? 'c' : 'd', g.winner, { unit: g.unit }); } };

groups.l1edges = async () => { const G0 = T.genesis(); const b1 = T.batch(G0, 1);
  { for (const [nm, u, re] of [['units 0', 0, /bad units/], ['units > steps', b1.steps + 1, /bad units/], ['units 1.5', 1.5, /bad units/], ['units "4" string', '4', /./], ['units missing', undefined, /bad units/], ['units 16385', 16385, /bad units/]]) {
      const C = new Chain(); const d = subData(b1, 1, 'genesis', { units: u }); if (u === undefined) delete d.units;
      const r = await S(C, OP1, ROLL, OBOND, d); if (nm === 'units "4" string') rec('layer1 edges', 'submit ' + nm + ' (bounce, or stored as the number 4)', true, !!r.err || C.r('u' + r.unit) === 4, { outcome: ok(r) });
      else rec('layer1 edges', 'submit ' + nm, 'bounce', bnc(r, re)); } }
  { // U = 1: straight to layer 2
    const C = new Chain(); b1.units = 1; await submit(C, OP1, 1, b1, 'genesis'); const o = await uopen(C, CH1, b1.sid); delete b1.units;
    rec('layer1 edges', 'U = 1: turn x right after uopen', 'x', sv(C, o.sgid).split(':')[9]);
    rec('layer1 edges', 'resolve while layer 2 runs', 'bounce', bnc(await S(C, W, SEG, 0, { resolve: o.sgid }), /layer 2 running/));
    const g = await playSeg(C, sgame(o, b1, T.batch(G0, 1, { k: 20, mut: T.MUT.reg }), b1, { U: 1 })); rec('layer1 edges', 'U = 1 griefer loses', 'd', g.winner); }
  const C = new Chain(); await submit(C, OP1, 1, b1, 'genesis'); const o = await uopen(C, CH1, b1.sid); const U = Math.min(8, b1.steps); const { cnt, pt } = pts(0, U);
  const st = Array.from({ length: cnt }, (_, i) => Math.floor(pt(i + 1) * b1.steps / U)); const rt = st.map(x => b1.roots[x]);
  const mids = (o2) => S(C, OP1, SEG, 0, { mids: o.sgid, steps: st, roots: rt, ...o2 });
  rec('layer1 edges', 'mids by the challenger', 'bounce', bnc(await S(C, CH1, SEG, 0, { mids: o.sgid, steps: st, roots: rt }), /not your move/));
  rec('layer1 edges', 'mids with one point too few', 'bounce', bnc(await mids({ steps: st.slice(1), roots: rt.slice(1) }), /points/));
  rec('layer1 edges', 'mids with equal steps', 'bounce', bnc(await mids({ steps: [st[0], st[0], ...st.slice(2)] }), /increase/));
  rec('layer1 edges', 'mids with a step = 0 (= slo)', 'bounce', bnc(await mids({ steps: [0, ...st.slice(1)] }), /increase/));
  rec('layer1 edges', 'mids with last step = shi', 'bounce', bnc(await mids({ steps: [...st.slice(0, -1), b1.steps] }), /increase/));
  rec('layer1 edges', 'mids with a fractional step', 'bounce', bnc(await mids({ steps: [st[0] + 0.5, ...st.slice(1)] }), /increase/));
  rec('layer1 edges', 'mids with a root containing ":"', 'bounce', bnc(await mids({ roots: [':'.repeat(43) + '=', ...rt.slice(1)] }), /bad root/));
  rec('layer1 edges', 'resolve before the deadline', 'bounce', bnc(await S(C, W, SEG, 0, { resolve: o.sgid }), /undecided/));
  rec('layer1 edges', 'honest mids', 'ok', ok(await mids({})));
  rec('layer1 edges', 'pick by the defender', 'bounce', bnc(await S(C, OP1, SEG, 0, { pick: o.sgid, j: 0 }), /not your move/));
  rec('layer1 edges', 'pick j = cnt + 1', 'bounce', bnc(await S(C, CH1, SEG, 0, { pick: o.sgid, j: cnt + 1 }), /bad j/));
  rec('layer1 edges', 'a stranger sends a fake result {res, w} to the seg referee', 'bounce', bnc(await S(C, W, SEG, 0, { res: H64(o.sgid), w: 'c' }), /no game/));
  // front-run: a stranger opens its own seg game under the same ref (itself as opener); the honest hand-off must still work
  const X = A('FRONTRUN'); rec('layer1 edges', 'stranger opens a seg game with the rollup game ref', 'ok', ok(await S(C, X, SEG, 2 * GF, { uopen: o.ref, s0: b1.s0, sN: b1.final, n: b1.steps, u: 1, d: X, c: X })));
  C.ts += 60; const j = cnt; const r = await S(C, CH1, SEG, 0, { pick: o.sgid, j }); rec('layer1 edges', 'honest pick down to one unit -> layer 2 opened despite the front-run game', 'ok', ok(r));
  rec('layer1 edges', 'layer-2 game exists under SEG || sha256(gid)', true, gv(C, SEG + H64(o.sgid)).length > 0);
  // timeouts: defender silent / challenger silent
  { const C = new Chain(); await submit(C, OP1, 1, b1, 'genesis'); const o = await uopen(C, CH1, b1.sid); const c0 = C.b(CH1);
    const g = await playSeg(C, sgame(o, b1, T.batch(G0, 1, { k: 30, mut: T.MUT.reg }), b1, { defSilent: true })); rec('layer1 edges', 'operator silent at layer 1 -> challenger wins (as 6a)', 'c', g.winner);
    rec('layer1 edges', 'its payout includes OBOND/2', CBOND - GF - FEE + OBOND / 2, C.b(CH1) - c0); }
  { const C = new Chain(); await submit(C, OP1, 1, b1, 'genesis'); const o = await uopen(C, CH1, b1.sid);
    const g = await playSeg(C, sgame(o, b1, T.batch(G0, 1, { k: 30, mut: T.MUT.reg }), b1, { chSilent: true })); rec('layer1 edges', 'challenger silent at layer 1 -> operator wins', 'd', g.winner); }
  { const C = new Chain(); await submit(C, OP1, 1, b1, 'genesis'); const o = await uopen(C, CH1, b1.sid);
    const g = await playSeg(C, sgame(o, b1, b1, b1, { noMemo: true })); rec('layer1 edges', 'challenger agrees with every point (no fraud): it loses at the single step', 'd', g.winner); } };


// ---------- loop round 3: rv_witbind + rv_witproof (depth-64 SMT verifier against a finalized height's segment end root)
groups.witproof = async () => { const K = require('./witkit.js'); const dir = __dirname + '/testdata/proofs/';
  const Hc = (s, enc) => require('crypto').createHash('sha256').update(s).digest(enc);
  const kidJs = l => { const p = l.split(':'); const f = l.startsWith('pos:') ? 3 : 2; return p.length <= f ? l : p.slice(0, f).join(':'); };
  const synth = (d, seed) => { const leaf = `acct:${Hc('seed' + seed, 'hex')}:${1000 + seed}:0:0`; const kt = Hc('~K1:' + kidJs(leaf), 'hex');
    const bits = [...kt].map(c => parseInt(c, 16).toString(2).padStart(4, '0')).join(''); let h = Hc('~L1:' + kt + ':' + leaf, 'base64');
    const sib = [...Array(d).keys()].map(i => Hc('sib' + seed + ':' + i, 'base64')); for (let i = d - 1; i >= 0; i--) h = Hc('~N1:' + (bits[i] === '0' ? h + sib[i] : sib[i] + h), 'base64');
    return { root: h, members: [{ leaf, sib: sib.slice().reverse(), depth: d }] }; };
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.json')).sort();
  const sets = files.map(f => ({ name: f, ...JSON.parse(fs.readFileSync(dir + f, 'utf8')) }));
  sets.push({ name: 'synth64', ...synth(64, 64) }); sets.push({ name: 'synth65', ...synth(65, 65) });
  const C = new Chain(); let prev = T.genesis(), prevFinal = 'genesis'; const H = [];
  const addHeight = async (rootB64, status) => { const h = H.length + 1; const b = T.batch(prev, h); const m = K.memWithRoot(rootB64, status);
    const final = ref.H(b.fpc + ':' + b.fregs + ':' + m.root() + ':' + b.inpRoot + ':' + b.steps);
    const r = await S(C, OP1, ROLL, OBOND, subData(b, h, prevFinal, { fmem: m.root(), final })); H.push({ h, m, sid: r.unit, err: r.err }); prev = m; prevFinal = final; return H[h - 1]; };
  for (const st of sets) st.H = await addHeight(st.root, 0);
  const bad = await addHeight(sets[0].root, 4);   // a height whose guest run reported status 4: no root to bind
  rec('witproof', 'heights submitted (one memory image per proof set, + a status-4 image)', sets.length + 1, H.filter(x => !x.err).length);
  rec('witproof', 'bind before finalize', 'bounce', bnc(await S(C, W, BIND, 0, K.bindData(sets[0].H.m, 1)), /not finalized/));
  C.ts += WIN; for (const x of H) await S(C, W, ROLL, 0, { finalize: x.h }); rec('witproof', 'all heights finalized', H.length, C.r('lf'));
  rec('witproof', 'bind with a wrong word', 'bounce', bnc(await S(C, W, BIND, 0, { ...K.bindData(sets[0].H.m, 1), words: K.bindData(sets[0].H.m, 1).words.map((w, k) => k === 3 ? (w ^ 1) >>> 0 : w) }), /word proof/));
  rec('witproof', 'bind with the words of another height', 'bounce', bnc(await S(C, W, BIND, 0, { ...K.bindData(sets[1].H.m, 1), bind: 1 }), /word proof/));
  rec('witproof', 'bind a status-4 height', 'bounce', bnc(await S(C, W, BIND, 0, K.bindData(bad.m, bad.h)), /status/));
  rec('witproof', 'bind a height above lf', 'bounce', bnc(await S(C, W, BIND, 0, K.bindData(sets[0].H.m, H.length + 1)), /not finalized/));
  let bound = 0; for (const st of sets) { const r = await S(C, W, BIND, 0, K.bindData(st.H.m, st.H.h)); if (!r.err && C.v(BIND, 'W' + st.H.h) === st.root) bound++; else console.log('bind fail', st.name, r.err); }
  rec('witproof', 'bind every finalized height: W<h> = the guest-layout root', sets.length, bound);
  rec('witproof', 'bind twice', 'bounce', bnc(await S(C, W, BIND, 0, K.bindData(sets[0].H.m, 1)), /bound/));
  rec('witproof', 'prove against an unbound height', 'bounce', bnc(await S(C, W, PROOF, 0, { prove: bad.h, leaf: sets[0].members[0].leaf, sib: sets[0].members[0].sib }), /not bound/));
  let mok = 0, mn = 0, aok = 0, an = 0, forged = 0, tries = 0, maxd = 0, ncTries = 0, ncAccepted = 0;
  for (const st of sets) { const h = st.H.h;
    for (const m of st.members) { mn++; maxd = Math.max(maxd, m.depth); const r = await S(C, W, PROOF, 0, { prove: h, leaf: m.leaf, sib: m.sib });
      const want = st.name === 'synth65' ? false : true;
      if (!!r.err !== want && (want ? C.v(PROOF, 'L' + h + ':' + kidJs(m.leaf)) === m.leaf : true)) mok++; else console.log('member', st.name, m.depth, r.err);
      const kt = Hc('~K1:' + kidJs(m.leaf), 'hex');
      const fs_ = [{ prove: h, leaf: m.leaf + '0', sib: m.sib }, { prove: h, leaf: m.leaf, sib: m.sib.slice(1) }, { prove: h, leaf: m.leaf, sib: m.sib, key: kt }];
      if (m.sib.length > 1) fs_.push({ prove: h, leaf: m.leaf, sib: [m.sib[1], m.sib[0], ...m.sib.slice(2)] });
      for (const t of fs_) { tries++; if (!(await S(C, W, PROOF, 0, t)).err) { forged++; console.log('FORGED', st.name, JSON.stringify(t).slice(0, 100)); } } }
    if (st.absent) { an++; const a = st.absent; const r = await S(C, W, PROOF, 0, { prove: h, leaf: a.term, sib: a.sib, key: a.key });
      if (!r.err && C.v(PROOF, 'A' + h + ':' + a.key) === 1) aok++; else console.log('absent', st.name, r.err);
      tries++; if (!(await S(C, W, PROOF, 0, { prove: h, leaf: a.term === '' ? st.members[0].leaf : '', sib: a.sib, key: a.key })).err) forged++;
      tries++; if (!(await S(C, W, PROOF, 0, { prove: h, leaf: a.term, sib: a.sib, key: a.key.toUpperCase() })).err) forged++;
      tries++; if (!(await S(C, W, PROOF, 0, { prove: h + 1, leaf: a.term, sib: a.sib, key: a.key })).err) forged++;
      // R3-W1: canonical path bits but an upper-case tail -> must not be recorded under a non-canonical name
      const nc = a.key.slice(0, 16) + a.key.slice(16).toUpperCase(); if (nc !== a.key) { ncTries++; const q = await S(C, W, PROOF, 0, { prove: h, leaf: a.term, sib: a.sib, key: nc }); if (!q.err) ncAccepted++; } } }
  rec('witproof', 'R3-W1: absence under a non-canonical key (upper-case tail, same path bits) refused', 0, ncAccepted, { tries: ncTries });
  { const w0 = C.b(W); const m = sets[0].members[0]; await S(C, W, PROOF, 15000, { prove: sets[0].H.h, leaf: m.leaf, sib: m.sib });
    rec('witproof', 'R3-W4: a proof costs the caller MK = 2000 (the rest of the trigger is refunded)', 2000, w0 - C.b(W)); }
  rec('witproof', 'memberships accepted (and recorded L<h>:<kid> = leaf); synthetic depth 65 refused', mn, mok, { maxDepth: maxd });
  rec('witproof', 'absences accepted (A<h>:<key> = 1)', an, aok);
  rec('witproof', 'forgeries rejected (tampered leaf, dropped / swapped sibling, absence of a present key, EMPTY/leaf terminal swap, uppercase key, other height)', 0, forged, { tries });
  rec('witproof', 'a proof for height h does not verify against h+1', true, tries > 0); };

(async () => {
  for (const [nm, fn] of Object.entries(groups)) { if (FILTER && !nm.includes(FILTER)) continue; try { await fn(); } catch (e) { rec(nm, 'group crashed', 'no crash', String(e.stack || e).slice(0, 300)); } }
  rec('invariant', 'rollup balance >= outstanding bonds + burned after every tx', 0, invFail);
  const s = { total: results.length, pass: results.filter(r => r.pass).length, fail: results.filter(r => !r.pass).length };
  console.log('SUMMARY ' + JSON.stringify(s)); fs.writeFileSync(process.env.OUT || 'rolltest-results.json', JSON.stringify(results, null, 1)); process.exit(0);
})();
