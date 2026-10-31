// Adversarial tests for rv_rollup + rv_game (referee) + rv_step on the real ocore evaluator (simulated chain, chain.js).
// usage: node rolltest.js [filter]     -> prints PASS/FAIL lines and SUMMARY {...}; writes rolltest-results.json
'use strict';
const { Chain, ROLL, GAME, STEP, M, rnd, BOUNCER } = require('./chain.js'); const T = require('./rolltrace.js'); const ref = require('./ref.js'); const fs = require('fs');
const OBOND = 200000, CBOND = 100000, GF = 10000, GB = 1000, FEE = 2000, WIN = 86400, TM = 3600;
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
const subData = (tr, h, prev, o = {}) => ({ submit: h, s0: tr.s0, steps: tr.steps, final: tr.final, inp: tr.inpRoot, fpc: tr.fpc, fregs: tr.fregs, fmem: tr.fmem, prev, ...o });
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

(async () => {
  for (const [nm, fn] of Object.entries(groups)) { if (FILTER && !nm.includes(FILTER)) continue; try { await fn(); } catch (e) { rec(nm, 'group crashed', 'no crash', String(e.stack || e).slice(0, 300)); } }
  rec('invariant', 'rollup balance >= outstanding bonds + burned after every tx', 0, invFail);
  const s = { total: results.length, pass: results.filter(r => r.pass).length, fail: results.filter(r => !r.pass).length };
  console.log('SUMMARY ' + JSON.stringify(s)); fs.writeFileSync(process.env.OUT || 'rolltest-results.json', JSON.stringify(results, null, 1)); process.exit(0);
})();
