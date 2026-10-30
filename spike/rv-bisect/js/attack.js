// Adversarial suite for the spike AAs on the real ocore evaluator (rv_game + rv_step, shared state vars).
// Each case: expected outcome, actual outcome, PASS/FAIL. Prints a JSON summary at the end.
// usage: node attack.js [filter]
'use strict';
const { run, val, validate } = require('./oc.js'); const ref = require('./ref.js'); const T = require('./trace.js'); const fs = require('fs');
const crypto = require('crypto');
const G = require('./mkgame.js'); const GAME = G.body + '\n' + G.state;
const STEPBODY = fs.readFileSync(__dirname + '/../aa/rv_step.oscript', 'utf8');
const STEPF = STEPBODY + "\nvar['s_' || $pre] = $post;";
const STEP = G.stepAddr, GA = 'GAMEAAXXXXXXXXXXXXXXXXXXXXXXXXXX';
const OP = 'OPERATORXXXXXXXXXXXXXXXXXXXXXXXX', CH = 'CHALLENGERXXXXXXXXXXXXXXXXXXXXXX', CH2 = 'CHALLENGER2XXXXXXXXXXXXXXXXXXXXX', CH3 = 'CHALLENGER3XXXXXXXXXXXXXXXXXXXXX', W = 'WATCHERXXXXXXXXXXXXXXXXXXXXXXXXX';
const BOND = 100000, TMOVE = 3600, WIN = 86400;
const rnd = () => crypto.randomBytes(32).toString('base64');
const results = []; const FILTER = process.argv[2] || '';
function rec(group, name, expected, actual, extra) { const pass = expected === actual; results.push({ group, name, expected, actual, pass, ...(extra || {}) }); console.log((pass ? 'PASS' : 'FAIL'), group, '|', name, '| expected', expected, '| actual', actual, extra ? JSON.stringify(extra) : ''); }
const cloneSV = sv => { const o = {}; for (const a in sv) { o[a] = {}; for (const k in sv[a]) o[a][k] = { ...sv[a][k] }; } return o; };
const errMsg = e => e && String((e.formattedError || e).message || e.bounce_message || JSON.stringify(e)).slice(0, 100);

// What a real unit can carry: JSON values without null (ocore string_utils throws on null; Infinity/NaN serialize to null).
const hasNull = o => o === null || (typeof o === 'object' && Object.values(o).some(hasNull));
const asUnit = d => { const j = JSON.parse(JSON.stringify(d)); return hasNull(j) ? null : j; };
class Game {
  constructor() { this.sv = {}; this.ts = 1e9; this.bal = 0; this.cin = {}; this.cout = {}; this.gclaim = {}; this.paid = {}; }
  async call(data, from, amt = 0, unit) {
    unit = unit || rnd(); data = asUnit(data); if (!data) return { err: 'unsendable: null/Infinity cannot be in a unit', unit };
    const snap = cloneSV(this.sv);
    const r = await run(GAME, { data, address: from, ts: this.ts, stateVars: this.sv, unit, aa: GA, outputs: { base: amt } });
    if (r.err) { this.sv = snap; return { err: errMsg(r.err), unit }; }
    const st = val(r.locals, 'st'); this.bal += amt;
    let cid = data.claim ? unit : data.open ? data.open : data.finalize ? data.finalize : this.gclaim[data.mids || data.pick || data.resolve];
    if (data.open) this.gclaim[unit] = data.open;
    if (cid) this.cin[cid] = (this.cin[cid] || 0) + amt;
    if (st && st.pay) { const a = st.amt !== undefined ? +st.amt : (data.finalize ? BOND : 2 * BOND - 2000);
      if (a > 0) { this.bal -= a; this.paid[st.pay] = (this.paid[st.pay] || 0) + a; this.cout[cid] = (this.cout[cid] || 0) + a; } }
    return { unit, st, resp: st && st.v };
  }
  async step(data, from = W) { data = asUnit(data); if (!data) return { err: 'unsendable: null/Infinity cannot be in a unit' }; const snap = cloneSV(this.sv);
    const r = await run(STEPF, { data, address: from, ts: this.ts, stateVars: this.sv, aa: STEP });
    if (r.err) { this.sv = snap; return { err: errMsg(r.err) }; } return { pre: val(r.locals, 'pre'), post: val(r.locals, 'post') }; }
  g(gid) { const v = this.sv[GA] && this.sv[GA]['g_' + gid]; return v ? String(v.value) : ''; }
  memo(pre) { const v = this.sv[STEP] && this.sv[STEP]['s_' + pre]; return v ? String(v.value) : undefined; }
  claimNet(cid) { return (this.cin[cid] || 0) - (this.cout[cid] || 0); }
}
const pts = (lo, hi) => { const cnt = Math.min(16, hi - lo) - 1; return { cnt, pt: j => j == 0 ? lo : j == cnt + 1 ? hi : lo + Math.floor(j * (hi - lo) / (cnt + 1)) }; };

// Play a game to the end. def/ch: root arrays (defender's and challenger's beliefs). honest: honest trace (roots+wits).
// opts.defMoves/chMoves=false -> that side goes silent; watcher posts the one-step memo if the pre root is an honest root.
async function play(Gm, gid, def, ch, honest, opts = {}) {
  let moves = 0;
  for (let it = 0; it < 200; it++) {
    const g = Gm.g(gid).split(':'); if (g[0] === 'done') break;
    const lo = +g[3], hi = +g[4], turn = g[7]; const { cnt, pt } = pts(lo, hi);
    if (turn === 'd') {
      if (opts.defSilent) { Gm.ts += TMOVE; await Gm.call({ resolve: gid }, W); continue; }
      Gm.ts += 60; const r = await Gm.call({ mids: gid, roots: Array.from({ length: cnt }, (_, i) => (opts.midsFn ? opts.midsFn(pt(i + 1), def) : def[pt(i + 1)])) }, OP); if (r.err) { if (!opts.timeoutOnErr) return { err: 'mids ' + r.err }; Gm.ts += TMOVE; await Gm.call({ resolve: gid }, W); continue; }
    } else if (turn === 'c') {
      if (opts.chSilent) { Gm.ts += TMOVE; await Gm.call({ resolve: gid }, W); continue; }
      const m = String(Gm.sv[GA]['m_' + gid].value).split(','); const rootAt = i => i == 0 ? g[5] : i == cnt + 1 ? g[6] : m[i - 1];
      let j = 0; while (j < cnt && rootAt(j + 1) === ch[pt(j + 1)]) j++;
      Gm.ts += 60; const r = await Gm.call({ pick: gid, j }, opts.picker || CH); if (r.err) return { err: 'pick ' + r.err };
    } else if (turn === 's') {
      if (opts.stopAtStep) return { winner: 'stopped' };
      if (!opts.noMemo && honest.roots[lo] === g[5] && !Gm.memo(g[5])) { Gm.ts += 60; const s = await Gm.step(honest.wits[lo]); if (s.err) return { err: 'step ' + s.err }; }
      Gm.ts += 60; let r = await Gm.call({ resolve: gid }, W);
      if (r.err) { Gm.ts += TMOVE; r = await Gm.call({ resolve: gid }, W); if (r.err) return { err: 'resolve ' + r.err }; }
    }
    moves++;
  }
  const v = Gm.g(gid); return { winner: v.startsWith('done:') ? v.slice(5) : 'none(' + v.slice(0, 30) + ')', moves };
}
async function newClaim(Gm, roots, n, from = OP) { const r = await Gm.call({ claim: 1, s0: roots[0], sN: roots[n], n }, from, BOND); if (r.err) throw Error('claim ' + r.err); return r.unit; }
async function newGame(Gm, cid, from = CH) { const r = await Gm.call({ open: cid }, from, BOND); if (r.err) throw Error('open ' + r.err); return r.unit; }

const N = 6; const n = T.honestLen(N); const H = T.run(N, n); // honest trace: n steps, halts at the last
const liar = (kind, k) => kind === 'final' ? { roots: H.roots.map((r, i) => i === n ? ref.H('wrong-final') : r) } : T.run(N, n, k, T.MUT[kind]);

async function groupLies() {
  for (const kind of ['final', 'reg', 'pc', 'mem', 'step', 'inp']) for (const k of kind === 'final' ? [n] : [1, Math.floor(n / 2), n]) {
    const L = liar(kind, k); if (L.roots[n] === H.roots[n] && kind !== 'final') { rec('2 lying operator', `${kind} @${k}`, 'c', 'skip(same final)'); continue; }
    const Gm = new Game(); const cid = await newClaim(Gm, L.roots, n); const gid = await newGame(Gm, cid);
    const r = await play(Gm, gid, L.roots, H.roots, H); rec('2 lying operator', `lie in ${kind} at step ${k}/${n}`, 'c', r.winner || r.err, { moves: r.moves });
  }
}
async function groupLyingChallenger() {
  for (const kind of ['final', 'reg', 'pc', 'mem', 'step', 'inp']) for (const k of kind === 'final' ? [n] : [1, Math.floor(n / 2), n]) {
    const L = liar(kind, k); const Gm = new Game(); const cid = await newClaim(Gm, H.roots, n); const gid = await newGame(Gm, cid);
    const r = await play(Gm, gid, H.roots, L.roots, H); rec('3 lying challenger', `challenger believes ${kind} at ${k}`, 'd', r.winner || r.err, { moves: r.moves });
  }
}
async function groupBothLie() {
  const cases = [[5, 30, 'c'], [30, 5, 'd'], [17, 17, 'c'], [1, n, 'c'], [n, 1, 'd']];
  for (const [k1, k2, exp] of cases) { const D = T.run(N, n, k1, T.MUT.reg), C = T.run(N, n, k2, T.MUT.mem);
    const Gm = new Game(); const cid = await newClaim(Gm, D.roots, n); const gid = await newGame(Gm, cid);
    const r = await play(Gm, gid, D.roots, C.roots, H); rec('7 both lie', `defender wrong from ${k1} (reg), challenger wrong from ${k2} (mem)`, exp, r.winner || r.err); }
}
async function groupTimeouts() {
  { const L = liar('reg', 40); const Gm = new Game(); const cid = await newClaim(Gm, L.roots, n); const gid = await newGame(Gm, cid);
    const r = await play(Gm, gid, L.roots, H.roots, H, { defSilent: true }); rec('7 timeout', 'defender silent', 'c', r.winner || r.err); }
  { const Gm = new Game(); const cid = await newClaim(Gm, H.roots, n); const gid = await newGame(Gm, cid);
    const r = await play(Gm, gid, H.roots, liar('reg', 40).roots, H, { chSilent: true }); rec('7 timeout', 'challenger silent after mids', 'd', r.winner || r.err); }
  { const L = liar('reg', 40); const Gm = new Game(); const cid = await newClaim(Gm, L.roots, n); const gid = await newGame(Gm, cid);
    const r = await play(Gm, gid, L.roots, H.roots, H, { noMemo: true }); rec('7 timeout', 'one-step reached, nobody posts rv_step memo (challenger must) -> defender', 'd', r.winner || r.err); }
  // exact deadline boundaries
  { const Gm = new Game(); const cid = await newClaim(Gm, H.roots, n); const t0 = Gm.ts; const gid = await newGame(Gm, cid); const { cnt, pt } = pts(0, n);
    const mids = Array.from({ length: cnt }, (_, i) => H.roots[pt(i + 1)]);
    Gm.ts = t0 + TMOVE - 1; let r = await Gm.call({ resolve: gid }, W); rec('7 deadline', 'resolve at deadline-1 (turn d)', 'bounce', r.err ? 'bounce' : 'accepted');
    Gm.ts = t0 + TMOVE; r = await Gm.call({ mids: gid, roots: mids }, OP); rec('7 deadline', 'mids exactly at deadline', 'bounce', r.err ? 'bounce' : 'accepted');
    Gm.ts = t0 + TMOVE - 1; r = await Gm.call({ mids: gid, roots: mids }, OP); rec('7 deadline', 'mids at deadline-1', 'accepted', r.err ? 'bounce:' + r.err : 'accepted');
    const t1 = Gm.ts; Gm.ts = t1 + TMOVE; r = await Gm.call({ pick: gid, j: 0 }, CH); rec('7 deadline', 'pick exactly at deadline', 'bounce', r.err ? 'bounce' : 'accepted');
    r = await Gm.call({ resolve: gid }, W); rec('7 deadline', 'resolve exactly at deadline (turn c) -> defender', 'done:d', r.err ? 'bounce:' + r.err : r.resp);
    r = await Gm.call({ resolve: gid }, W); rec('7 protocol', 'resolve twice', 'bounce', r.err ? 'bounce' : 'accepted');
    r = await Gm.call({ mids: gid, roots: mids }, OP); rec('7 protocol', 'move after game done', 'bounce', r.err ? 'bounce' : 'accepted'); }
  { const Gm = new Game(); const t0 = Gm.ts; const cid = await newClaim(Gm, H.roots, n);
    Gm.ts = t0 + WIN; let r = await Gm.call({ open: cid }, CH, BOND); rec('7 deadline', 'open exactly at window end', 'bounce', r.err ? 'bounce' : 'accepted');
    Gm.ts = t0 + WIN - 1; r = await Gm.call({ finalize: cid }, W); rec('7 deadline', 'finalize at window end-1', 'bounce', r.err ? 'bounce' : 'accepted');
    Gm.ts = t0 + WIN; r = await Gm.call({ finalize: cid }, W); rec('7 deadline', 'finalize exactly at window end', 'accepted', r.err ? 'bounce:' + r.err : 'accepted');
    r = await Gm.call({ finalize: cid }, W); rec('7 protocol', 'finalize twice', 'bounce', r.err ? 'bounce' : 'accepted'); }
}
async function groupProtocol() {
  const L = liar('reg', 40);
  const Gm = new Game(); const cid = await newClaim(Gm, L.roots, n); const gid = await newGame(Gm, cid); const { cnt, pt } = pts(0, n);
  const mids = Array.from({ length: cnt }, (_, i) => L.roots[pt(i + 1)]);
  let r = await Gm.call({ mids: gid, roots: mids }, CH); rec('7 protocol', 'challenger posts defender\'s mids', 'bounce', r.err ? 'bounce' : 'accepted');
  r = await Gm.call({ mids: gid, roots: mids }, W); rec('7 protocol', 'third party posts mids', 'bounce', r.err ? 'bounce' : 'accepted');
  r = await Gm.call({ pick: gid, j: 0 }, CH); rec('7 protocol', 'challenger picks before mids', 'bounce', r.err ? 'bounce' : 'accepted');
  r = await Gm.call({ mids: gid, roots: mids.slice(1) }, OP); rec('7 protocol', 'mids with cnt-1 roots', 'bounce', r.err ? 'bounce' : 'accepted');
  r = await Gm.call({ mids: gid, roots: [...mids, mids[0]] }, OP); rec('7 protocol', 'mids with cnt+1 roots', 'bounce', r.err ? 'bounce' : 'accepted');
  r = await Gm.call({ mids: gid, roots: mids.map((x, i) => i ? x : x.slice(0, 43)) }, OP); rec('7 protocol', 'mids with a 43-char root', 'bounce', r.err ? 'bounce' : 'accepted');
  r = await Gm.call({ mids: gid, roots: mids.map((x, i) => i ? x : 12345) }, OP); rec('7 protocol', 'mids with a number root', 'bounce', r.err ? 'bounce' : 'accepted');
  r = await Gm.call({ mids: gid, roots: mids }, OP); rec('7 protocol', 'valid mids', 'accepted', r.err ? 'bounce:' + r.err : 'accepted');
  r = await Gm.call({ mids: gid, roots: mids }, OP); rec('7 protocol', 'defender moves twice', 'bounce', r.err ? 'bounce' : 'accepted');
  r = await Gm.call({ pick: gid, j: 0 }, OP); rec('7 protocol', 'defender picks', 'bounce', r.err ? 'bounce' : 'accepted');
  r = await Gm.call({ pick: gid, j: 0 }, CH2); rec('7 protocol', 'other challenger picks in someone else\'s game', 'bounce', r.err ? 'bounce' : 'accepted');
  for (const j of [cnt + 1, -1, 1.5, null, 1e300, true, '1.5', 'x', String(cnt + 1)]) { r = await Gm.call({ pick: gid, j }, CH); rec('7 protocol', 'pick j=' + JSON.stringify(j), 'bounce', r.err ? 'bounce' : 'accepted'); }
  r = await Gm.call({ resolve: gid }, W); rec('7 protocol', 'resolve on turn c before deadline', 'bounce', r.err ? 'bounce' : 'accepted');
  let jj = 0; while (jj < cnt && mids[jj] === H.roots[pt(jj + 1)]) jj++;   // honest choice: first disagreement
  r = await Gm.call({ pick: gid, j: jj }, CH); rec('7 protocol', 'valid pick', 'accepted', r.err ? 'bounce:' + r.err : 'accepted');
  r = await Gm.call({ pick: gid, j: jj }, CH); rec('7 protocol', 'challenger picks twice / replays old move', 'bounce', r.err ? 'bounce' : 'accepted');
  // replay of an old (round 1) mids message in round 2
  r = await Gm.call({ mids: gid, roots: mids }, OP); rec('7 protocol', 'replay round-1 mids in round 2 (wrong count)', 'bounce', r.err ? 'bounce' : 'accepted');
  r = await Gm.call({ resolve: 'nonexistent' }, W); rec('7 protocol', 'resolve unknown game', 'bounce', r.err ? 'bounce' : 'accepted');
  r = await Gm.call({ resolve: cid }, W); rec('7 protocol', 'resolve with a claim id as game id', 'bounce', r.err ? 'bounce' : 'accepted');
  r = await Gm.call({ open: cid }, OP, BOND); rec('7 protocol', 'claimant challenges own claim', 'bounce', r.err ? 'bounce' : 'accepted');
  r = await Gm.call({ open: cid }, CH2, BOND - 1); rec('7 protocol', 'open with bond-1', 'bounce', r.err ? 'bounce' : 'accepted');
  r = await Gm.call({ claim: 1, s0: H.roots[0], sN: H.roots[n], n }, OP, BOND - 1); rec('7 protocol', 'claim with bond-1', 'bounce', r.err ? 'bounce' : 'accepted');
  for (const nn of [0, -1, 1.5, '0', 'ten', 1e16]) { r = await Gm.call({ claim: 1, s0: H.roots[0], sN: H.roots[n], n: nn }, OP, BOND); rec('7 protocol', 'claim n=' + JSON.stringify(nn), 'bounce', r.err ? 'bounce' : 'accepted'); }
  { const Gx = new Game(); const c1 = await newClaim(Gx, L.roots, n); const g1 = await newGame(Gx, c1); await Gx.call({ mids: g1, roots: mids }, OP); const a = await Gx.call({ pick: g1, j: '3' }, CH);
    const Gy = new Game(); const c2 = await newClaim(Gy, L.roots, n); const g2 = await newGame(Gy, c2); await Gy.call({ mids: g2, roots: mids }, OP); const b = await Gy.call({ pick: g2, j: 3 }, CH);
    rec('5 malformed', 'pick j="3" (numeric string) is read as j=3 by ocore (same segment)', 'same', !a.err && !b.err && Gx.g(g1).split(':').slice(3, 7).join() === Gy.g(g2).split(':').slice(3, 7).join() ? 'same' : 'differs'); }
  r = await Gm.call({ open: 'nope' }, CH, BOND); rec('7 protocol', 'open unknown claim', 'bounce', r.err ? 'bounce' : 'accepted');
  r = await Gm.call({ finalize: cid }, W); rec('7 protocol', 'finalize with a live game', 'bounce', r.err ? 'bounce' : 'accepted');
  // finish: challenger should still win
  const rr = await play(Gm, gid, L.roots, H.roots, H); rec('7 protocol', 'after all abuse attempts, honest challenger still wins', 'c', rr.winner || rr.err);
  Gm.ts += WIN; r = await Gm.call({ finalize: cid }, W); rec('7 protocol', 'finalize a claim proven fraudulent', 'bounce', r.err ? 'bounce' : 'accepted');
  // inconsistent midpoints: liar posts its wrong final root at every interior point
  { const Gm2 = new Game(); const cid2 = await newClaim(Gm2, L.roots, n); const gid2 = await newGame(Gm2, cid2);
    const r2 = await play(Gm2, gid2, L.roots, H.roots, H, { midsFn: () => L.roots[n] }); rec('7 protocol', 'liar posts mids inconsistent with its own claim (all = sN)', 'c', r2.winner || r2.err);
    const Gm3 = new Game(); const cid3 = await newClaim(Gm3, L.roots, n); const gid3 = await newGame(Gm3, cid3);
    const r3 = await play(Gm3, gid3, L.roots, H.roots, H, { midsFn: (p) => p % 2 ? H.roots[p] : L.roots[p] }); rec('7 protocol', 'liar alternates honest / lying mids', 'c', r3.winner || r3.err); }
  // challenger "agrees" with nothing / picks last segment always (outside its real disagreement)
  { const Gm4 = new Game(); const cid4 = await newClaim(Gm4, H.roots, n); const gid4 = await newGame(Gm4, cid4);
    const r4 = await play(Gm4, gid4, H.roots, H.roots.map(() => 'x'), H); rec('7 protocol', 'griefer disagrees with every root vs honest claim', 'd', r4.winner || r4.err); }
}
async function groupBonds() {
  // (a) 3 honest challengers vs one fraudulent claim, all win; claim must not pay out more than came in
  { const L = liar('reg', 40); const Gm = new Game(); const cid = await newClaim(Gm, L.roots, n);
    const gids = [await newGame(Gm, cid, CH), await newGame(Gm, cid, CH2), await newGame(Gm, cid, CH3)];
    const ws = []; for (const gid of gids) { const r = await play(Gm, gid, L.roots, H.roots, H, { picker: Gm.g(gid).split(':')[2] }); ws.push(r.winner || r.err); }
    rec('7 bonds', '3 challengers vs fraud claim: winners', 'c,c,c', ws.join(','));
    rec('7 bonds', '3 challengers vs fraud claim: claim pays out <= paid in', 'ok', Gm.claimNet(cid) >= 0 ? 'ok' : 'DRAIN ' + (-Gm.claimNet(cid)), { in: Gm.cin[cid], out: Gm.cout[cid] }); }
  // (b) honest claim, 4 griefing challengers (sockpuppets of the operator possible), defender wins all, then finalize
  { const Gm = new Game(); const cid = await newClaim(Gm, H.roots, n); const L = liar('mem', 20); const gids = [];
    for (const c of [CH, CH2, CH3, W]) gids.push(await newGame(Gm, cid, c));
    const ws = []; for (const gid of gids) { const g = Gm.g(gid).split(':'); const r = await play(Gm, gid, H.roots, L.roots, H, { picker: g[2] }); ws.push(r.winner || r.err); }
    Gm.ts += WIN; const f = await Gm.call({ finalize: cid }, W);
    rec('7 bonds', '4 griefers vs honest claim: winners', 'd,d,d,d', ws.join(','));
    rec('7 bonds', 'griefed honest claim finalizes', 'accepted', f.err ? 'bounce:' + f.err : 'accepted');
    rec('7 bonds', 'griefed claim pays out <= paid in (operator + sockpuppet challengers cannot drain)', 'ok', Gm.claimNet(cid) >= 0 ? 'ok' : 'DRAIN ' + (-Gm.claimNet(cid)), { in: Gm.cin[cid], out: Gm.cout[cid] }); }
  // (c) single game each way: winner gets back own stake + loser's stake (minus fee), nothing more
  { const L = liar('reg', 40); const Gm = new Game(); const cid = await newClaim(Gm, L.roots, n); const gid = await newGame(Gm, cid); await play(Gm, gid, L.roots, H.roots, H);
    rec('7 bonds', 'single fraud game: challenger profit = half the claim bond - fee', BOND / 2 - 2000, (Gm.paid[CH] || 0) - BOND); }
  // (e) fraudster front-runs honest challengers with its own sock-puppet challenge and "loses" on purpose
  { const L = liar('reg', 40); const Gm = new Game(); const SOCK = 'SOCKPUPPETXXXXXXXXXXXXXXXXXXXXXX'; const cid = await newClaim(Gm, L.roots, n);
    const g1 = await newGame(Gm, cid, SOCK); const g2 = await newGame(Gm, cid, CH);
    await play(Gm, g1, L.roots, H.roots, H, { picker: SOCK }); await play(Gm, g2, L.roots, H.roots, H, { picker: CH });
    const fraudsterNet = (Gm.paid[OP] || 0) + (Gm.paid[SOCK] || 0) - 2 * BOND;
    rec('7 bonds', 'fraudster + sock-puppet challenger lose at least half a bond', 'loss>=50000', -fraudsterNet >= BOND / 2 ? 'loss>=50000' : 'loss ' + (-fraudsterNet));
    rec('7 bonds', 'honest late challenger still gets its stake back', BOND - 2000, Gm.paid[CH] || 0); }
  // (f) late memo: one-step reached, deadline passed, challenger posts memo then resolves (memo wins over timeout)
  { const L = liar('reg', 40); const Gm = new Game(); const cid = await newClaim(Gm, L.roots, n); const gid = await newGame(Gm, cid);
    const r = await play(Gm, gid, L.roots, H.roots, H, { noMemo: true, stopAtStep: true }); const g = Gm.g(gid).split(':');
    Gm.ts = +g[8] + 10; await Gm.step(H.wits[+g[3]]); const rr = await Gm.call({ resolve: gid }, CH);
    rec('7 deadline', 'memo posted after the one-step deadline still decides (before anyone resolved)', 'done:c', rr.err ? 'bounce:' + rr.err : rr.resp); }
  // (d) whole-AA solvency across a mixed run: total paid out <= total paid in
  { const Gm = new Game(); for (let i = 0; i < 2; i++) { const L = liar('pc', 10 + i); const cid = await newClaim(Gm, L.roots, n); for (const c of [CH, CH2]) { const gid = await newGame(Gm, cid, c); await play(Gm, gid, L.roots, H.roots, H, { picker: c }); } }
    const cid = await newClaim(Gm, H.roots, n); for (const c of [CH, CH2]) { const gid = await newGame(Gm, cid, c); await play(Gm, gid, H.roots, liar('inp', 7).roots, H, { picker: c }); } Gm.ts += WIN; await Gm.call({ finalize: cid }, W);
    rec('7 bonds', 'AA solvency over 3 claims / 6 games', 'ok', Gm.bal >= 0 ? 'ok' : 'INSOLVENT ' + Gm.bal); }
}
async function groupInjection() {
  // separator injection: ':' / ',' inside a 44-char "root"
  const L = liar('reg', 40);
  { const Gm = new Game(); const cid = await newClaim(Gm, L.roots, n); const gid = await newGame(Gm, cid);
    const bad = 'AAAA:BBBB' + L.roots[n].slice(9);
    const r = await play(Gm, gid, L.roots, H.roots, H, { midsFn: (p, d) => p > 40 ? bad : d[p], timeoutOnErr: true });
    rec('5 injection', 'liar puts \':\' inside a mids root at the disagreement point (bounced -> liar times out)', 'c', r.winner || r.err); }
  { const Gm = new Game(); const cid = await newClaim(Gm, L.roots, n); const gid = await newGame(Gm, cid);
    const bad = 'AAAA,BBBB' + L.roots[n].slice(9);
    const r = await play(Gm, gid, L.roots, H.roots, H, { midsFn: (p, d) => p > 40 ? bad : d[p], timeoutOnErr: true });
    rec('5 injection', 'liar puts \',\' inside a mids root', 'c', r.winner || r.err); }
  { const Gm = new Game(); const s0 = '::1:' + OP + ':10:open'; // 44 chars, forges claim fields
    const r = await Gm.call({ claim: 1, s0, sN: H.roots[n], n }, OP, BOND);
    let fin = 'n/a'; if (!r.err) { const f = await Gm.call({ finalize: r.unit }, W); fin = f.err ? 'bounce' : 'accepted (window skipped)'; }
    rec('5 injection', 'claim with s0 forging the record fields (\'::1:ADDR:10:open\') then immediate finalize', 'bounce', r.err ? 'bounce' : fin, { len: s0.length }); }
  { const Gm = new Game(); const r = await Gm.call({ claim: 1, s0: '"}],"x":{"', sN: H.roots[n], n }, OP, BOND); rec('5 injection', 'JSON-ish s0', 'bounce', r.err ? 'bounce' : 'accepted'); }
}
async function groupN() {
  // huge n: interior points must stay strictly increasing, else a segment can be empty / inverted
  const Gm = new Game(); const out = [];
  for (const nn of [2, 17, 1e6, 999999999999999, 1e15]) {
    const r = await Gm.call({ claim: 1, s0: H.roots[0], sN: H.roots[n], n: nn }, OP, BOND); if (r.err) { out.push(nn + ':claim bounce'); continue; }
    const gid = (await Gm.call({ open: r.unit }, CH, BOND)).unit; let ok = true, rounds = 0;
    for (let it = 0; it < 30; it++) { const g = Gm.g(gid).split(':'); if (g[7] === 's' || g[0] === 'done') break; const lo = +g[3], hi = +g[4];
      if (!(hi > lo)) { ok = false; break; }
      if (g[7] === 'd') { const cnt = Math.min(16, hi - lo) - 1; const x = await Gm.call({ mids: gid, roots: Array.from({ length: cnt }, () => H.roots[1]) }, OP); if (x.err) { ok = false; out.push(nn + ':mids ' + x.err); break; } }
      else { const x = await Gm.call({ pick: gid, j: rounds % 2 ? 0 : Math.min(15, hi - lo - 1) }, CH); rounds++; if (x.err) { ok = false; out.push(nn + ':pick ' + x.err); break; } } }
    const g = Gm.g(gid).split(':'); if (ok && g[7] === 's' && +g[4] - +g[3] !== 1) ok = false; if (ok && g[7] !== 's') ok = false;
    out.push(nn + ':' + (ok ? 'ok' : 'BROKEN ' + g.slice(3, 5).join('..') + ' turn ' + g[7]));
  }
  { const L1 = T.run(N, n, 1, T.MUT.reg); const Gm1 = new Game(); const r = await Gm1.call({ claim: 1, s0: L1.roots[0], sN: L1.roots[1], n: 1 }, OP, BOND);
    const gid = r.err ? null : (await Gm1.call({ open: r.unit }, CH, BOND)); const w = gid && !gid.err ? await play(Gm1, gid.unit, L1.roots, H.roots, H) : { err: 'open ' + (gid && gid.err) };
    rec('7 n range', 'n=1 fraudulent claim (one step) can be challenged and lost', 'c', w.winner || w.err, { turnAtOpen: gid && !gid.err ? Gm1.g(gid.unit).split(':')[7] : '' }); }
  rec('7 n range', 'bisection reaches a 1-step segment for n in {2,17,1e6,1e15-1,1e15}', 'all ok', out.every(x => x.endsWith(':ok')) ? 'all ok' : out.join(' | '));
}

// ---------------- rv_step: forged proofs / malformed inputs ----------------
const kindOf = d => { const op = (d.w >>> 0) & 127; return d.w === undefined ? 'noop' : op === 35 ? 'store' : op === 3 ? 'load' : d.isib ? 'ecall63' : 'other'; };
async function stepEval(data) { const Gm = new Game(); const r = await Gm.step(data); return r; }
async function groupStep() {
  const pick = k => H.wits.find(d => kindOf(d) === k);
  const base = { store: pick('store'), load: pick('load'), ecall63: pick('ecall63'), alu: H.wits[0] };
  const honest = {}; for (const k in base) honest[k] = await stepEval(base[k]);
  for (const k in honest) rec('4 proofs', 'honest ' + k + ' step accepted', 'ok', honest[k].err ? 'bounce:' + honest[k].err : 'ok');
  const sib = a => a.map((x, i) => i === 3 ? ref.H('evil') : x);
  const cases = [];
  const other = H.wits.filter(d => kindOf(d) === 'load')[3];
  for (const k of ['store', 'load', 'alu', 'ecall63']) {
    const d = base[k];
    cases.push([k, 'fetch: wrong sibling', { ...d, wsib: sib(d.wsib) }], [k, 'fetch: proof depth 23', { ...d, wsib: d.wsib.slice(0, 23) }], [k, 'fetch: depth 25', { ...d, wsib: [...d.wsib, ref.Z[24]] }],
      [k, 'fetch: wrong instruction word', { ...d, w: (d.w + 1) >>> 0 }], [k, 'fetch: missing wsib', { ...d, wsib: undefined }], [k, 'fetch: sibling empty string', { ...d, wsib: d.wsib.map((x, i) => i ? x : '') }]);
  }
  for (const k of ['store', 'load']) { const d = base[k];
    cases.push([k, 'mem: wrong sibling', { ...d, msib: sib(d.msib) }], [k, 'mem: wrong word', { ...d, mw: (d.mw + 1) >>> 0 }], [k, 'mem: depth 23', { ...d, msib: d.msib.slice(0, 23) }],
      [k, 'mem: proof for a different address', { ...d, mw: other.mw, msib: other.msib }], [k, 'mem: mw as string', { ...d, mw: String(d.mw) }], [k, 'mem: mw negative', { ...d, mw: -1 }], [k, 'mem: mw 2^32', { ...d, mw: 2 ** 32 }]); }
  { const d = base.store; cases.push(['store', 'stale nroot (= pre mem root)', { ...d, nroot: d.mem }], ['store', 'nroot for a different stored value', { ...d, nroot: (() => { const m = new ref.Mem(); return ref.H('x').slice(0, 44); })() }], ['store', 'nroot missing', { ...d, nroot: undefined }], ['store', 'nroot 43 chars', { ...d, nroot: d.nroot.slice(1) }]); }
  { const d = base.ecall63; cases.push(['ecall63', 'input: wrong word', { ...d, iw: (d.iw + 1) >>> 0 }], ['ecall63', 'input: wrong sibling', { ...d, isib: sib(d.isib) }], ['ecall63', 'input: proof from memory tree', { ...d, isib: d.wsib }]); }
  // malformed scalars (each on the alu and store steps)
  const mal = [['pc', -4], ['pc', 2 ** 32], ['pc', 1.5], ['pc', '0'], ['pc', Infinity], ['pc', null], ['pc', -0], ['step', -1], ['step', 1.5], ['step', '3'], ['step', Infinity], ['step', 1e400], ['step', 2 ** 60],
    ['mem', 'x'.repeat(43)], ['mem', 'x'.repeat(45)], ['mem', 'x'.repeat(4096)], ['mem', 12345], ['inp', 'y'.repeat(44)], ['inp', null], ['w', 2 ** 32], ['w', -1], ['w', 1.5], ['w', '19'], ['w', 1e400]];
  for (const k of ['alu', 'store']) for (const [f, v] of mal) cases.push([k, `${f}=${String(v).slice(0, 12)}${typeof v === 'string' ? '(str)' : ''}`, { ...base[k], [f]: v }]);
  const regM = [['regs len 31', r => r.slice(1)], ['regs len 33', r => [...r, 0]], ['x0 = 1', r => [1, ...r.slice(1)]], ['reg = -0', r => r.map((x, i) => i === 3 ? -0 : x)], ['reg = 2^32', r => r.map((x, i) => i === 3 ? 2 ** 32 : x)],
    ['reg = -1', r => r.map((x, i) => i === 3 ? -1 : x)], ['reg = 1.5', r => r.map((x, i) => i === 3 ? 1.5 : x)], ['reg = "5"', r => r.map((x, i) => i === 3 ? '5' : x)], ['reg = 1e400', r => r.map((x, i) => i === 3 ? 1e400 : x)],
    ['reg = null', r => r.map((x, i) => i === 3 ? null : x)], ['regs as object', r => Object.fromEntries(r.map((x, i) => [i, x]))], ['regs = "0,0,..." string', r => r.join(',')], ['reg = [1]', r => r.map((x, i) => i === 3 ? [1] : x)], ['huge regs array (4096)', r => Array(4096).fill(0)]];
  for (const k of ['alu', 'store']) for (const [nm, f] of regM) cases.push([k, nm, { ...base[k], regs: f(base[k].regs) }]);
  cases.push(['alu', 'extra unknown fields', { ...base.alu, zzz: 'x'.repeat(4000), __proto__x: 1 }]);
  // verdict: an attack is harmless if it bounces, or hashes to a different pre root, or yields the honest post
  for (const [k, nm, data] of cases) { const r = await stepEval(data); const h = honest[k];
    const verdict = r.err ? 'bounce' : r.pre !== h.pre ? 'different pre-root (harmless)' : r.post === h.post ? 'same honest post' : 'WRONG POST FOR HONEST PRE';
    rec(nm.startsWith('pc=') || nm.startsWith('step=') || nm.startsWith('reg') || nm.startsWith('x0') || nm.startsWith('mem=') || nm.startsWith('inp=') || nm.startsWith('w=') || nm.startsWith('huge') || nm.startsWith('extra') ? '5 malformed' : '4 proofs', `${k}: ${nm}`, 'harmless', verdict === 'WRONG POST FOR HONEST PRE' ? verdict : 'harmless', { verdict, err: r.err }); }
  // memo can never be overwritten with a different post for the same pre root
  { const Gm = new Game(); const d = base.store; await Gm.step(d); const before = Gm.memo(honest.store.pre);
    for (const [k, nm, data] of cases.filter(c => c[0] === 'store')) await Gm.step(data);
    rec('4 proofs', 'memo for honest store pre-root unchanged after all forged calls', 'same', Gm.memo(honest.store.pre) === before && before === honest.store.post ? 'same' : 'CHANGED'); }
}

// ---------------- instruction edge cases: Oscript vs reference AND vs explicit spec value ----------------
const enc = { I: (op, rd, f3, rs1, imm) => (((imm & 0xfff) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op) >>> 0, R: (op, rd, f3, rs1, rs2, f7) => ((f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op) >>> 0,
  S: (f3, rs1, rs2, imm) => ((((imm >> 5) & 127) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | ((imm & 31) << 7) | 35) >>> 0,
  B: (f3, rs1, rs2, imm) => ((((imm >> 12) & 1) << 31) | (((imm >> 5) & 63) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (((imm >> 1) & 15) << 8) | (((imm >> 11) & 1) << 7) | 99) >>> 0,
  J: (rd, imm) => ((((imm >> 20) & 1) << 31) | (((imm >> 1) & 1023) << 21) | (((imm >> 11) & 1) << 20) | (((imm >> 12) & 255) << 12) | (rd << 7) | 111) >>> 0 };
async function one(w, regs, pc = 0x1000, memInit = {}, step0 = 0) {
  const mem = new ref.Mem(); if (pc < 2 ** 26 && pc % 4 === 0) mem.set(pc / 4, w); for (const a in memInit) mem.set(+a, memInit[a]); mem.root();
  const R = Array(32).fill(0); for (const k in regs) R[k] = regs[k] >>> 0; const st = { pc, regs: R, step: step0, inp: new ref.Mem() }; st.inp.root();
  const data = { pc, regs: [...R], mem: mem.root(), inp: st.inp.root(), step: step0 }; const wit = ref.step(st, mem);
  if (wit.wsib) { data.w = wit.w; data.wsib = wit.wsib; } if (wit.msib) { data.mw = wit.mword; data.msib = wit.msib; data.nroot = mem.root(); }
  const r = await stepEval(data); return { st, osOk: !r.err && r.post === ref.stateRoot(st, mem), err: r.err, mem };
}
async function groupInsn() {
  const M = 0xffffffff, MIN = 0x80000000; const { I, R, S, B, J } = enc;
  const t = [
    ['addi x0,x0,5 (x0 write)', I(19, 0, 0, 0, 5), {}, s => s.regs[0] === 0 && s.pc === 0x1004],
    ['lui x0 (x0 write)', 0x12345037, {}, s => s.regs[0] === 0],
    ['lw misaligned (ea%4=2) -> TRAP', I(3, 5, 2, 1, 2), { 1: 0x2000 }, s => s.pc === 1],
    ['lh ea%4=2 (aligned) ok', I(3, 5, 1, 1, 2), { 1: 0x2000 }, s => s.pc === 0x1004],
    ['sh misaligned (ea odd) -> TRAP', S(1, 1, 2, 1), { 1: 0x2000 }, s => s.pc === 1],
    ['sw misaligned -> TRAP', S(2, 1, 2, 2), { 1: 0x2000 }, s => s.pc === 1],
    ['lw beyond 64 MiB -> TRAP', I(3, 5, 2, 1, 0), { 1: 0x04000000 }, s => s.pc === 1],
    ['lw at last word of memory', I(3, 5, 2, 1, 0), { 1: 0x03fffffc }, s => s.pc === 0x1004],
    ['compressed c.li (0x4501) -> TRAP', 0x4501, {}, s => s.pc === 1],
    ['amoadd.w -> TRAP', 0x0020a02f, {}, s => s.pc === 1],
    ['ecall a7=64 (unknown) -> TRAP', 0x73, { 17: 64 }, s => s.pc === 1],
    ['ecall a7=93 -> HALT', 0x73, { 17: 93 }, s => s.pc === 2],
    ['ebreak -> TRAP', 0x00100073, {}, s => s.pc === 1],
    ['csrrs rdcycle -> TRAP', 0xc0002573, {}, s => s.pc === 1],
    ['fence -> TRAP (spec: no-op; documented deviation)', 0x0ff0000f, {}, s => s.pc === 1],
    ['all-zero word -> TRAP', 0, {}, s => s.pc === 1],
    ['all-ones word -> TRAP', M, {}, s => s.pc === 1],
    ['div by 0 = -1', R(51, 3, 4, 1, 2, 1), { 1: 7, 2: 0 }, s => s.regs[3] === M],
    ['divu by 0 = 2^32-1', R(51, 3, 5, 1, 2, 1), { 1: 7, 2: 0 }, s => s.regs[3] === M],
    ['rem by 0 = dividend', R(51, 3, 6, 1, 2, 1), { 1: (-7) >>> 0, 2: 0 }, s => s.regs[3] === ((-7) >>> 0)],
    ['remu by 0 = dividend', R(51, 3, 7, 1, 2, 1), { 1: M, 2: 0 }, s => s.regs[3] === M],
    ['div INT_MIN/-1 = INT_MIN', R(51, 3, 4, 1, 2, 1), { 1: MIN, 2: M }, s => s.regs[3] === MIN],
    ['rem INT_MIN/-1 = 0', R(51, 3, 6, 1, 2, 1), { 1: MIN, 2: M }, s => s.regs[3] === 0],
    ['div -7/2 = -3 (trunc)', R(51, 3, 4, 1, 2, 1), { 1: (-7) >>> 0, 2: 2 }, s => s.regs[3] === ((-3) >>> 0)],
    ['rem -7/2 = -1', R(51, 3, 6, 1, 2, 1), { 1: (-7) >>> 0, 2: 2 }, s => s.regs[3] === M],
    ['mulh MIN*MIN = 0x40000000', R(51, 3, 1, 1, 2, 1), { 1: MIN, 2: MIN }, s => s.regs[3] === 0x40000000],
    ['mulhu M*M = 0xfffffffe', R(51, 3, 3, 1, 2, 1), { 1: M, 2: M }, s => s.regs[3] === 0xfffffffe],
    ['mulhsu -1*M = 0xffffffff', R(51, 3, 2, 1, 2, 1), { 1: M, 2: M }, s => s.regs[3] === M],
    ['mulhsu MIN*M = 0x80000000', R(51, 3, 2, 1, 2, 1), { 1: MIN, 2: M }, s => s.regs[3] === 0x80000000],
    ['mulh -1*-1 = 0', R(51, 3, 1, 1, 2, 1), { 1: M, 2: M }, s => s.regs[3] === 0],
    ['mul M*M low = 1', R(51, 3, 0, 1, 2, 1), { 1: M, 2: M }, s => s.regs[3] === 1],
    ['sll by 33 = by 1', R(51, 3, 1, 1, 2, 0), { 1: 3, 2: 33 }, s => s.regs[3] === 6],
    ['srl by 32 = by 0', R(51, 3, 5, 1, 2, 0), { 1: 0x80, 2: 32 }, s => s.regs[3] === 0x80],
    ['sra MIN by 31 = -1', R(51, 3, 5, 1, 2, 32), { 1: MIN, 2: 31 }, s => s.regs[3] === M],
    ['sra by 63 = by 31', R(51, 3, 5, 1, 2, 32), { 1: MIN, 2: 63 }, s => s.regs[3] === M],
    ['slli shamt[5]=1 -> TRAP (illegal on rv32)', I(19, 3, 1, 1, 32), { 1: 1 }, s => s.pc === 1],
    ['srai shamt[5]=1 -> TRAP', I(19, 3, 5, 1, 0x420), { 1: 1 }, s => s.pc === 1],
    ['srai by 31', I(19, 3, 5, 1, 0x41f), { 1: MIN }, s => s.regs[3] === M],
    ['beq x0,x0,0 (branch to self)', B(0, 0, 0, 0), {}, s => s.pc === 0x1000],
    ['jal x1,0 (jump to self, link)', J(1, 0), {}, s => s.pc === 0x1000 && s.regs[1] === 0x1004],
    ['jal backwards past 0 wraps to 0xfffffffc', J(0, -8), {}, s => s.pc === 0xfffffffc, 4],
    ['jalr to odd address clears bit0', I(103, 1, 0, 2, 0), { 2: 0x2001 }, s => s.pc === 0x2000 && s.regs[1] === 0x1004],
    ['jalr to 2 mod 4 -> TRAP, rd untouched', I(103, 1, 0, 2, 0), { 2: 0x2002 }, s => s.pc === 1 && s.regs[1] === 0],
    ['jalr rd==rs1', I(103, 1, 0, 1, 0), { 1: 0x2000 }, s => s.pc === 0x2000 && s.regs[1] === 0x1004],
    ['branch taken to 2 mod 4 -> TRAP', B(0, 0, 0, 2), {}, s => s.pc === 1],
    ['branch NOT taken with misaligned target -> ok', B(1, 0, 0, 2), {}, s => s.pc === 0x1004],
    ['auipc wraps mod 2^32', 0xfffff517, {}, s => s.regs[10] === ((0x1000 + 0xfffff000) >>> 0)],
    ['pc = last word 0x03fffffc executes', I(19, 3, 0, 0, 1), {}, s => s.pc === 0x04000000 && s.regs[3] === 1, 0x03fffffc],
    ['pc = 0x04000000 (outside memory) -> TRAP', 0, {}, s => s.pc === 1, 0x04000000],
    ['pc = 0xfffffffc -> TRAP', 0, {}, s => s.pc === 1, 0xfffffffc],
    ['pc = TRAP(1) absorbing', 0, {}, s => s.pc === 1 && s.step === 1, 1],
    ['pc = HALT(2) absorbing', 0, {}, s => s.pc === 2 && s.step === 1, 2],
    ['pc = 3 absorbing', 0, {}, s => s.pc === 3, 3],
    ['lb sign-extends 0x80', I(3, 5, 0, 1, 3), { 1: 0x2000 }, s => s.regs[5] === 0xffffff80, 0x1000, { [0x2000 / 4]: 0x80000000 }],
    ['lbu zero-extends', I(3, 5, 4, 1, 3), { 1: 0x2000 }, s => s.regs[5] === 0x80, 0x1000, { [0x2000 / 4]: 0x80000000 }],
    ['lhu upper half', I(3, 5, 5, 1, 2), { 1: 0x2000 }, s => s.regs[5] === 0xbeef, 0x1000, { [0x2000 / 4]: 0xbeef1234 }],
    ['sb into byte 2 keeps other bytes', S(0, 1, 2, 2), { 1: 0x2000, 2: 0x1ff }, (s, m) => m.get(0x800) === 0x11ff3344, 0x1000, { [0x2000 / 4]: 0x11223344 }],
    ['sw overwrites own instruction (self-modifying)', S(2, 1, 2, 0), { 1: 0x1000, 2: 0x13 }, (s, m) => m.get(0x400) === 0x13, 0x1000],
    ['step counter 1e15-1 -> 1e15 (no precision loss)', I(19, 3, 0, 0, 1), {}, s => s.step === 1e15, 0x1000, {}, 1e15 - 1],
    ['ecall 63 with a0 >= 2^24 -> TRAP', 0x73, { 17: 63, 10: 2 ** 24 }, s => s.pc === 1],
  ];
  for (const [nm, w, regs, spec, pc, memInit, step0] of t) { const o = await one(w, regs, pc, memInit, step0); const sp = spec(o.st, o.mem);
    rec('6 instructions', nm, 'oscript==ref && spec', o.osOk && sp ? 'oscript==ref && spec' : `oscript==ref:${o.osOk} spec:${sp}${o.err ? ' err:' + o.err : ''}`); }
}
async function groupOps() {
  { const OC = process.env.OCORE || '/workspace/projects/4ecc28f7-451e-450a-b62c-b8b357f0cc38/wt-aa/vendor/aa-testkit/node_modules/ocore'; let a;
    require(OC + '/formula/parse_ojson').parse(fs.readFileSync(__dirname + '/../aa/rv_step.aa', 'utf8'), (e, d) => { a = require(OC + '/object_hash.js').getChash160(d); });
    const m = /\$STEP = '([A-Z2-7]{32})'/.exec(fs.readFileSync(__dirname + '/../aa/rv_game.aa', 'utf8'));
    rec('8 ops', 'rv_game reads the memo from the real rv_step address', a, m && m[1]); }
  for (const f of ['rv_step.aa', 'rv_game.aa']) { const v = await validate(fs.readFileSync(__dirname + '/../aa/' + f, 'utf8'));
    rec('8 ops', f + ` ops ${v.count_ops} / complexity ${v.complexity}`, 'within', !v.err && v.count_ops <= 2000 && v.complexity <= 100 ? 'within' : 'OVER ' + JSON.stringify(v)); }
}

// ---------------- random adversary fuzz (pass 3) ----------------
// One side honest, the other side + any number of third parties send random (often junk) messages at random times.
// Invariants: honest side wins; per-claim payouts <= receipts; the memo never disagrees with the reference.
async function groupFuzz() {
  let seed = +(process.env.FUZZSEED || 7); const R = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; }; const ri = k => Math.floor(R() * k);
  const ADDRS = [OP, CH, CH2, W, 'RANDOMXXXXXXXXXXXXXXXXXXXXXXXXXX']; const GAMES = +(process.env.FUZZ || 40); let bad = 0, junkAccepted = 0, junkSent = 0;
  for (let t = 0; t < GAMES; t++) {
    const fraud = t % 2 === 0; const kinds = Object.keys(T.MUT); const L = T.run(N, n, 1 + ri(n), T.MUT[kinds[ri(kinds.length)]]);
    const claimRoots = fraud ? L.roots : H.roots; const Gm = new Game(); const cid = await newClaim(Gm, claimRoots, n); const gid = await newGame(Gm, cid, CH);
    const advRoots = () => [L.roots, H.roots, T.run(N, n, 1 + ri(n), T.MUT.mem).roots][ri(3)];
    for (let it = 0; it < 120; it++) {
      // junk from anybody
      for (let k = ri(3); k > 0; k--) { const g = Gm.g(gid).split(':'); const lo = +g[3] || 0, hi = +g[4] || 1; const cnt = Math.min(16, Math.max(hi - lo, 1)) - 1;
        const junk = [{ mids: gid, roots: Array.from({ length: [cnt, cnt + 1, 0, 15][ri(4)] }, () => [ref.H('j' + ri(9)), 'x', 'a:b'.padEnd(44, 'c'), H.roots[ri(n)]][ri(4)]) }, { pick: gid, j: [ri(17), -1, 'x', 1.5][ri(4)] }, { resolve: gid }, { finalize: cid }, { open: cid }, { resolve: [cid, 'zz'][ri(2)] }][ri(6)];
        const from = ADDRS[ri(ADDRS.length)]; const isAdv = (fraud ? from === OP : from === CH);
        if (!isAdv && (junk.mids || junk.pick)) { /* honest parties never send junk moves */ } else { junkSent++; const r = await Gm.call(junk, from, junk.open ? BOND : 0); if (!r.err && (junk.mids || junk.pick)) junkAccepted++; } }
      const g = Gm.g(gid).split(':'); if (g[0] === 'done') break;
      const lo = +g[3], hi = +g[4], turn = g[7], dl = +g[8]; const { cnt, pt } = pts(lo, hi);
      const advTurn = fraud ? turn === 'd' : turn === 'c';
      if (advTurn) { // adversary: random move, or stall (sometimes past the deadline)
        const a = ri(4); if (a === 0) { Gm.ts = dl + ri(2); await Gm.call({ resolve: gid }, W); continue; }
        Gm.ts = Math.min(dl - 1, Gm.ts + ri(3000));
        if (turn === 'd') { const rr = advRoots(); await Gm.call({ mids: gid, roots: Array.from({ length: cnt }, (_, i) => rr[pt(i + 1)]) }, OP); }
        else await Gm.call({ pick: gid, j: ri(cnt + 1) }, CH);
        continue; }
      Gm.ts = Math.min(dl - 1, Gm.ts + ri(600)); // honest side always answers in time
      if (turn === 'd') await Gm.call({ mids: gid, roots: Array.from({ length: cnt }, (_, i) => H.roots[pt(i + 1)]) }, OP);
      else if (turn === 'c') { const m = String(Gm.sv[GA]['m_' + gid].value).split(','); const rootAt = i => i == 0 ? g[5] : i == cnt + 1 ? g[6] : m[i - 1];
        let j = 0; while (j < cnt && rootAt(j + 1) === H.roots[pt(j + 1)]) j++; await Gm.call({ pick: gid, j }, CH); }
      else { if (H.roots[lo] === g[5] && !Gm.memo(g[5])) await Gm.step(H.wits[lo], fraud ? CH : OP); await Gm.call({ resolve: gid }, fraud ? CH : OP); }
    }
    const v = Gm.g(gid); const want = fraud ? 'done:c' : 'done:d';
    if (v !== want || Gm.claimNet(cid) < 0) { bad++; if (bad <= 5) process.stdout.write('FUZZFAIL '+JSON.stringify([, t, fraud, v.slice(0, 40), Gm.claimNet(cid)])+'\n'); }
    for (const k in (Gm.sv[STEP] || {})) { const pre = k.slice(2); const i = H.roots.indexOf(pre); if (i >= 0 && i < n && Gm.sv[STEP][k].value !== false && String(Gm.sv[STEP][k].value) !== H.roots[i + 1]) { bad++; process.stdout.write('MEMOBAD ' + JSON.stringify([t, i, String(Gm.sv[STEP][k].value), H.roots[i + 1], H.roots.indexOf(String(Gm.sv[STEP][k].value))]) + '\n'); } }
  }
  rec('9 fuzz', `${GAMES} random-adversary games (half fraud claims), ${junkSent} junk/adversarial messages, ${junkAccepted} accepted`, 'honest side always wins, no drain, memo sound', bad ? bad + ' violations' : 'honest side always wins, no drain, memo sound');
}

(async () => {
  const groups = { fuzz: groupFuzz, lies: groupLies, liechal: groupLyingChallenger, both: groupBothLie, timeouts: groupTimeouts, protocol: groupProtocol, bonds: groupBonds, inject: groupInjection, nrange: groupN, step: groupStep, insn: groupInsn, ops: groupOps };
  const _log = console.log; console.log = (...a) => { if (typeof a[0] === 'string' && /^(PASS|FAIL)/.test(a[0])) _log(...a); };
  for (const [k, f] of Object.entries(groups)) if (!FILTER || FILTER.split(',').includes(k)) { try { await f(); } catch (e) { rec(k, 'harness error', 'none', String(e.stack || e).slice(0, 300)); } }
  const s = {}; for (const r of results) { s[r.group] = s[r.group] || { pass: 0, fail: 0 }; s[r.group][r.pass ? 'pass' : 'fail']++; }
  _log('SUMMARY ' + JSON.stringify({ total: results.length, pass: results.filter(r => r.pass).length, fail: results.filter(r => !r.pass).length, groups: s }));
  fs.writeFileSync(process.env.OUT || 'attack-results.json', JSON.stringify(results, null, 1)); process.exit(0);
})();
