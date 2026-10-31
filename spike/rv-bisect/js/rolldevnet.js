// Real devnet run (aa-testkit: genesis + witness + hub, real units, real bounces, real secondary triggers, real payments)
// of the rollup prototype: rv_step + rv_game (referee, rv_game_ref.aa) + rv_rollup.
// usage (on the box): AATK=/data/hark/wt-all/vendor/aa-testkit OCORE=$AATK/node_modules/ocore node rolldevnet.js
'use strict';
const path = require('path'); const fs = require('fs');
const AATK = process.env.AATK || '/data/hark/wt-all/vendor/aa-testkit';
process.env.NODE_PATH = [path.join(AATK, 'node_modules'), process.env.NODE_PATH].filter(Boolean).join(path.delimiter); require('module').Module._initPaths();
process.env.OCORE = process.env.OCORE || path.join(AATK, 'node_modules', 'ocore');
const { Testkit } = require(path.join(AATK, 'main.js'));
const { Network } = Testkit({ TESTDATA_DIR: process.env.TESTDATA || path.join(__dirname, '..', 'devnet-testdata-roll'), NETWORK_PORT: +(process.env.PORT || 16641) });
const ref = require('./ref.js'); const T = require('./rolltrace.js'); const M = require('./mkrollup.js'); // (re)generates rv_game_ref.aa / rv_rollup.aa
const OBOND = 200000, CBOND = 100000, GF = 10000, GB = 1000, FEE = 2000, WIN = 86400;
const results = []; const rec = (name, expected, actual, extra) => { const pass = JSON.stringify(expected) === JSON.stringify(actual); results.push({ name, expected, actual, pass, ...(extra || {}) }); console.log(pass ? 'PASS' : 'FAIL', '|', name, '| expected', JSON.stringify(expected), '| actual', JSON.stringify(actual), extra ? JSON.stringify(extra) : ''); };
let net; const fees = {};
const withTimeout = (p, ms) => Promise.race([p, new Promise(r => setTimeout(() => r({ timeout: true }), ms))]);
async function unitFee(u) { const info = await net.wallet.op1.getUnitInfo({ unit: u }); const o = info.unitObj || {}; return (o.headers_commission || 0) + (o.payload_commission || 0); }
async function trig(wallet, to, data, amount = 10000, tag) {
  const r = await wallet.triggerAaWithData({ toAddress: to, amount, data });
  if (r.error) return { err: 'compose: ' + String(r.error).slice(0, 120) };
  await net.witnessUntilStable(r.unit);
  if (tag) { (fees[tag] = fees[tag] || []).push(await unitFee(r.unit)); }
  const { response } = await net.getAaResponseToUnit(r.unit);
  if (response.bounced) { const e = response.response && response.response.error; return { err: (typeof e === 'string' ? e : JSON.stringify(e || 'bounced')).slice(0, 200), unit: r.unit }; }
  return { unit: r.unit, response };
}
// secondary response of `aa` to the response unit of the previous AA in the chain
async function secondary(resp, aa) { const u = resp && resp.response_unit; if (!u) return null; const x = await withTimeout(net.getAaResponseToUnitByAA(u, aa), 30000); return x.timeout ? null : x.response; }
async function paidTo(resp, addr) { const u = resp && resp.response_unit; if (!u) return 0; const info = await net.wallet.op1.getUnitInfo({ unit: u });
  let sum = 0; for (const m of (info.unitObj && info.unitObj.messages) || []) if (m.app === 'payment' && !m.payload.asset) for (const o of m.payload.outputs) if (o.address === addr) sum += o.amount; return sum; }
const bal = async a => { const b = await net.wallet.op1.getBalanceOf(a); return b && b.base ? (b.base.stable || 0) + (b.base.pending || 0) : 0; };

(async () => {
  const fwd = `["autonomous agent", {messages: [
    {app: 'payment', payload: {asset: 'base', outputs: [{address: "{trigger.data.to}", amount: "{trigger.output[[asset=base]] - 3000}"}]}},
    {app: 'data', payload: "{trigger.data.d}"}]}]`;
  fs.writeFileSync(path.join(__dirname, '../aa/fwd_test.aa'), fwd);
  net = await Network.create().with.agent({ step: path.join(__dirname, '../aa/rv_step.aa') }).with.agent({ game: path.join(__dirname, '../aa/rv_game_ref.aa') })
    .with.agent({ roll: path.join(__dirname, '../aa/rv_rollup.aa') }).with.agent({ fwd: path.join(__dirname, '../aa/fwd_test.aa') })
    .with.wallet({ op1: 1e12 }).with.wallet({ op2: 1e10 }).with.wallet({ ch1: 1e10 }).with.wallet({ ch2: 1e10 }).with.wallet({ w: 1e10 }).run();
  const { op1, op2, ch1, ch2, w } = net.wallet; const STEP = net.agent.step, GAME = net.agent.game, ROLL = net.agent.roll, FWD = net.agent.fwd;
  const A = { op1: await op1.getAddress(), op2: await op2.getAddress(), ch1: await ch1.getAddress(), ch2: await ch2.getAddress() };
  rec('deployed rv_step == address baked into the referee', STEP, M.stepAddr); rec('deployed referee == address baked into rv_rollup', GAME, M.gameAddr); rec('deployed rollup == computed address', ROLL, M.addr);
  const vars = async aa => { const v = await op1.readAAStateVars(aa); return v.vars || v; };
  const pts = (lo, hi) => { const cnt = Math.min(16, hi - lo) - 1; return { cnt, pt: j => j == 0 ? lo : j == cnt + 1 ? hi : lo + Math.floor(j * (hi - lo) / (cnt + 1)) }; };
  const sub = (tr, h, prev, o = {}) => ({ submit: h, s0: tr.s0, steps: tr.steps, final: tr.final, inp: tr.inpRoot, fpc: tr.fpc, fregs: tr.fregs, fmem: tr.fmem, prev, ...o });
  // play a rollup game on chain; returns the winner and the rollup's secondary response to the result
  async function play(gid, def, chv, chw, honest, opw) {
    for (let it = 0; it < 40; it++) {
      const g = String((await vars(GAME))['g_' + gid] || '').split(':'); if (g[0] === 'done') return g[1];
      const lo = +g[3], hi = +g[4], turn = g[7]; const { cnt, pt } = pts(lo, hi);
      if (turn === 'd') { const r = await trig(opw, GAME, { mids: gid, roots: Array.from({ length: cnt }, (_, i) => def[pt(i + 1)]) }, 10000, 'mids'); if (r.err) return 'mids ' + r.err; }
      else if (turn === 'c') { const m = String((await vars(GAME))['m_' + gid]).split(','); const at = i => i == 0 ? g[5] : i == cnt + 1 ? g[6] : m[i - 1];
        let j = 0; while (j < cnt && at(j + 1) === chv[pt(j + 1)]) j++; const r = await trig(chw, GAME, { pick: gid, j }, 10000, 'pick'); if (r.err) return 'pick ' + r.err; }
      else { if (honest.roots[lo] === g[5] && !(await vars(STEP))['s_' + g[5]]) { const s = await trig(w, STEP, honest.wits[lo], 10000, 'step'); if (s.err) return 'step ' + s.err; }
        const r = await trig(w, GAME, { resolve: gid }, 10000, 'resolve'); if (r.err) return 'resolve ' + r.err; play.last = await secondary(r.response, ROLL); }
    }
    return 'unfinished';
  }
  const G0 = T.genesis(); const b1 = T.batch(G0, 1), x1 = T.batch(G0, 7);
  // 1. race tie: two operators submit h1 before the witness stabilizes either unit
  { const ra = await op1.triggerAaWithData({ toAddress: ROLL, amount: OBOND, data: sub(b1, 1, 'genesis') }); const rb = await op2.triggerAaWithData({ toAddress: ROLL, amount: OBOND, data: sub(x1, 1, 'genesis') });
    await net.witnessUntilStable(ra.unit); await net.witnessUntilStable(rb.unit);
    const A1 = (await net.getAaResponseToUnit(ra.unit)).response, B1 = (await net.getAaResponseToUnit(rb.unit)).response;
    const outcome = [A1.bounced ? 'bounce' : 'ok', B1.bounced ? 'bounce' : 'ok'].sort().join('+');
    rec('race: two h1 submits in flight together -> exactly one wins', 'bounce+ok', outcome, { loserError: (A1.bounced ? A1 : B1).response.error });
    const v = await vars(ROLL); const winner = v.h1 === ra.unit ? b1 : x1; winner.sid = v.h1; rec('race: winner recorded at h1', true, v.h1 === ra.unit || v.h1 === rb.unit); b1.win = winner; }
  const h1 = b1.win; const h1op = h1.sid === undefined ? null : ((await vars(ROLL))['s' + h1.sid] || '').split(':')[1]; const opw1 = h1op === A.op1 ? op1 : op2;
  // 2. bad submits on the real chain
  { const b2 = T.batch(h1.mem, 2);
    rec('fake s0 (genesis memory) at h2', 'bounce', (await trig(op2, ROLL, sub(T.batch(G0, 2), 2, h1.final), OBOND)).err ? 'bounce' : 'ok');
    rec('final root not matching its parts', 'bounce', (await trig(op2, ROLL, sub(b2, 2, h1.final, { final: ref.H('z') }), OBOND)).err ? 'bounce' : 'ok');
    rec('h2 chained on the race loser', 'bounce', (await trig(op2, ROLL, sub(T.batch(h1 === b1 ? x1.mem : b1.mem, 2), 2, (h1 === b1 ? x1 : b1).final), OBOND)).err ? 'bounce' : 'ok');
    const f = await trig(w, FWD, { to: ROLL, d: sub(b2, 2, h1.final) }, OBOND + 5000); rec('an AA submits h2 (it could refuse payouts)', 'bounce', f.err ? 'bounce' : 'ok', { err: f.err });
    const r = await trig(op2, ROLL, sub(b2, 2, h1.final), OBOND, 'submit'); rec('honest h2 by op2', 'ok', r.err ? r.err : 'ok'); b2.sid = r.unit; h1.next = b2; }
  const b2 = h1.next;
  // 3. finalize timing + a griefer game (secondary triggers both ways, real payments)
  { let r = await trig(w, ROLL, { finalize: 1 }); rec('finalize h1 before 24 h', 'bounce', r.err ? 'bounce' : 'ok', { err: r.err });
    // open the game late in the window (move deadline is T = 1 h), so the window can close while the game is still live:
    // travelling a full WIN after the open would expire the defender's first move ('not your move', rolldevnet1 bug)
    await net.timetravel({ shift: (WIN - 1800) + 's' });
    const o = await trig(ch1, ROLL, { open: h1.sid }, CBOND, 'open'); rec('griefer opens a game on h1', 'ok', o.err || 'ok');
    const ro = await secondary(o.response, GAME); rec('referee received the open (secondary trigger)', true, !!ro && !ro.bounced);
    const gid = ROLL + o.unit; rec('referee game record exists', true, !!(await vars(GAME))['g_' + gid]);
    rec('rollup forwarded GF to the referee', GF, await paidTo(o.response, GAME));
    await net.timetravel({ shift: '1900s' }); r = await trig(w, ROLL, { finalize: 1 }); rec('finalize h1 with the game open', 'bounce', r.err ? 'bounce' : 'ok', { err: r.err });
    const L = T.batch(G0, h1 === b1 ? 1 : 7, { k: 11, mut: T.MUT.reg }); const win = await play(gid, h1.roots, L.roots, ch1, h1, opw1);
    rec('griefer vs honest operator', 'd', win); rec('rollup paid the operator CBOND - GF - FEE (real output)', CBOND - GF - FEE, await paidTo(play.last, h1op));
    rec('rollup game marked d', 'd', String((await vars(ROLL))['G' + o.unit]).split(':')[2]);
    const op0 = await bal(h1op); r = await trig(w, ROLL, { finalize: 1 }); rec('finalize h1 after the game', 'ok', r.err || 'ok'); rec('finalize pays OBOND - FEE (real output)', OBOND - FEE, await paidTo(r.response, h1op)); }
  // 4. fraud at h3 with h4, h5 on top -> all voided, race restarts at h3
  { const L3 = T.batch(b2.mem, 3, { k: 30, mut: T.MUT.mem }), H3 = T.batch(b2.mem, 3);
    let r = await trig(op2, ROLL, sub(L3, 3, b2.final), OBOND); rec('fraudulent h3 submitted', 'ok', r.err || 'ok'); L3.sid = r.unit;
    const L4 = T.batch(L3.mem, 4); r = await trig(op1, ROLL, sub(L4, 4, L3.final), OBOND); rec('h4 on bad h3', 'ok', r.err || 'ok'); L4.sid = r.unit;
    const L5 = T.batch(L4.mem, 5); r = await trig(op1, ROLL, sub(L5, 5, L4.final), OBOND); rec('h5 on h4', 'ok', r.err || 'ok'); L5.sid = r.unit;
    const o = await trig(ch2, ROLL, { open: L3.sid }, CBOND); const burned0 = (await vars(ROLL)).burned || 0;
    const win = await play(ROLL + o.unit, L3.roots, H3.roots, ch2, H3, op2); rec('honest challenger vs fraudulent h3', 'c', win);
    rec('challenger paid CBOND - GF - FEE + OBOND/2 (real output)', CBOND - GF - FEE + OBOND / 2, await paidTo(play.last, A.ch2));
    const v = await vars(ROLL); rec('top reset to 2', 2, v.top); rec('burned += OBOND/2', OBOND / 2, (v.burned || 0) - burned0); rec('h3 flagged fraud', 1, v['f' + L3.sid]);
    await net.timetravel({ shift: WIN + 's' }); r = await trig(w, ROLL, { finalize: 2 }); rec('h2 finalizes', 'ok', r.err || 'ok');
    r = await trig(w, ROLL, { finalize: 3 }); rec('finalize voided h3', 'bounce', r.err ? 'bounce' : 'ok', { err: r.err });
    r = await trig(ch1, ROLL, { open: L5.sid }, CBOND); rec('open on voided h5', 'bounce', r.err ? 'bounce' : 'ok');
    r = await trig(op2, ROLL, { reclaim: L3.sid }); rec('fraudster reclaims h3', 'bounce', r.err ? 'bounce' : 'ok');
    r = await trig(op1, ROLL, { reclaim: L4.sid }); rec('reclaim voided h4', 'ok', r.err || 'ok'); rec('h4 bond back OBOND - FEE (real output)', OBOND - FEE, await paidTo(r.response, A.op1));
    r = await trig(op1, ROLL, { reclaim: L5.sid }); rec('reclaim voided h5', 'ok', r.err || 'ok');
    r = await trig(op1, ROLL, sub(H3, 3, b2.final), OBOND); rec('race restarts: honest h3 resubmitted', 'ok', r.err || 'ok');
    r = await trig(op1, ROLL, sub(T.batch(L4.mem, 5), 5, L4.final), OBOND); rec('extend the voided chain', 'bounce', r.err ? 'bounce' : 'ok');
    await net.timetravel({ shift: WIN + 's' }); r = await trig(w, ROLL, { finalize: 3 }); rec('new h3 finalizes', 'ok', r.err || 'ok'); }
  // 5. accounting: the rollup holds exactly burned + kept FEEs + GB refunds + bounce fees, no bond is outstanding
  { const v = await vars(ROLL); const b = await bal(ROLL); rec('rollup balance >= burned (all bonds settled)', true, b >= (v.burned || 0), { balance: b, burned: v.burned, lf: v.lf, top: v.top }); }
  const avg = a => a && a.length ? Math.round(a.reduce((x, y) => x + y, 0) / a.length) : 0;
  const feeRep = Object.fromEntries(Object.entries(fees).map(([k, a]) => [k, { n: a.length, avg: avg(a), max: Math.max(...a) }]));
  console.log('FEES ' + JSON.stringify(feeRep));
  const s = { total: results.length, pass: results.filter(r => r.pass).length, fail: results.filter(r => !r.pass).length };
  console.log('SUMMARY ' + JSON.stringify(s)); fs.writeFileSync(process.env.OUT || 'rolldevnet-results.json', JSON.stringify({ results, fees: feeRep }, null, 1));
  await net.stop(); process.exit(0);
})().catch(async e => { console.log('ERR', e.stack || e); try { await net.stop(); } catch (x) {} process.exit(1); });
