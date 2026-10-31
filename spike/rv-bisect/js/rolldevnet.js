// Real devnet run (aa-testkit: genesis + witness + hub, real units, real bounces, real secondary triggers, real payments)
// of the rollup prototype: rv_step + rv_game (referee, rv_game_ref.aa) + rv_rollup.
// usage (on the box): AATK=/data/hark/wt-all/vendor/aa-testkit OCORE=$AATK/node_modules/ocore node rolldevnet.js
// Every trigger sets max_aa_responses to the real length of its response chain (MAXR below); NOMAXR=1 sends the
// triggers without it (ocore then prepays tps fee for 1 + 10 units per trigger) to measure the difference.
'use strict';
const path = require('path'); const fs = require('fs');
const AATK = process.env.AATK || '/data/hark/wt-all/vendor/aa-testkit';
process.env.NODE_PATH = [path.join(AATK, 'node_modules'), process.env.NODE_PATH].filter(Boolean).join(path.delimiter); require('module').Module._initPaths();
process.env.OCORE = process.env.OCORE || path.join(AATK, 'node_modules', 'ocore');
const { Testkit } = require(path.join(AATK, 'main.js'));
const { Network } = Testkit({ TESTDATA_DIR: process.env.TESTDATA || path.join(__dirname, '..', 'devnet-testdata-roll'), NETWORK_PORT: +(process.env.PORT || 16641) });
const ref = require('./ref.js'); const T = require('./rolltrace.js'); const M = require('./mkrollup.js'); // (re)generates rv_game_ref.aa / rv_seg_ref.aa / rv_rollup.aa
const WP = require('./mkwitproof.js'); const K = require('./witkit.js'); // loop round 3: rv_witbind.aa / rv_witproof.aa
const OBOND = 200000, CBOND = 120000, GF = 10000, GB = 1000, FEE = 2000, WIN = 86400, RK = 10000;
// max_aa_responses per trigger = number of AAs that respond in its chain (one lower bounces 'max_aa_responses N exceeded'):
// rollup submit / finalize / reclaim, referee mids / pick / direct open, rv_step: 1 (refunds and payouts go to plain
// addresses); rollup open: 2 (rollup -> referee); referee resolve: 2 (referee -> rollup callback); fwd test AA: 2 (fwd -> rollup)
const NOMAXR = !!process.env.NOMAXR;
const cmdOf = data => ['submit', 'open', 'finalize', 'reclaim', 'mids', 'pick', 'resolve'].find(k => data && data[k] !== undefined) || (data && data.to ? 'fwd' : 'step');
const MAXR = { submit: 1, finalize: 1, reclaim: 1, mids: 1, pick: 1, step: 1, open: 2, resolve: 2, fwd: 2 };
const results = []; const rec = (name, expected, actual, extra) => { const pass = JSON.stringify(expected) === JSON.stringify(actual); results.push({ name, expected, actual, pass, ...(extra || {}) }); console.log(pass ? 'PASS' : 'FAIL', '|', name, '| expected', JSON.stringify(expected), '| actual', JSON.stringify(actual), extra ? JSON.stringify(extra) : ''); };
let net; const fees = {}; const units = {}; let ROLLA, GAMEA;
const withTimeout = (p, ms) => Promise.race([p, new Promise(r => setTimeout(() => r({ timeout: true }), ms))]);
async function unitFee(u) { const info = await net.wallet.op1.getUnitInfo({ unit: u }); const o = info.unitObj || {}; unitFee.extra = (o.tps_fee || 0) + (o.oversize_fee || 0); return (o.headers_commission || 0) + (o.payload_commission || 0); }
// one AA trigger (payment + data), with max_aa_responses unless NOMAXR
let objectHash;
async function send(wallet, to, data, amount, maxr) {
  objectHash = objectHash || require(path.join(process.env.OCORE, 'object_hash.js'));
  let cmd = cmdOf(data); if (cmd === 'open' && to === GAMEA) cmd = 'ropen';
  const opts = { to_address: to, amount, messages: [{ app: 'data', payload_location: 'inline', payload_hash: objectHash.getBase64Hash(data), payload: data }] };
  if (!NOMAXR) opts.max_aa_responses = maxr || (cmd === 'ropen' ? 1 : MAXR[cmd]);
  const r = await wallet.sendMulti(opts); if (r.unit) (units[cmd] = units[cmd] || []).push(r.unit); return r;
}
async function trig(wallet, to, data, amount = 10000, tag, maxr) {
  const r = await send(wallet, to, data, amount, maxr);
  if (r.error) return { err: 'compose: ' + String(r.error).slice(0, 120) };
  await net.witnessUntilStable(r.unit);
  if (tag) { (fees[tag] = fees[tag] || []).push(await unitFee(r.unit)); (fees[tag + '+tps'] = fees[tag + '+tps'] || []).push(unitFee.extra); }
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
    .with.agent({ seg: path.join(__dirname, '../aa/rv_seg_ref.aa') })
    .with.agent({ roll: path.join(__dirname, '../aa/rv_rollup.aa') }).with.agent({ fwd: path.join(__dirname, '../aa/fwd_test.aa') })
    .with.agent({ wbind: path.join(__dirname, '../aa/rv_witbind.aa') }).with.agent({ wproof: path.join(__dirname, '../aa/rv_witproof.aa') })
    .with.wallet({ op1: 1e12 }).with.wallet({ op2: 1e10 }).with.wallet({ ch1: 1e10 }).with.wallet({ ch2: 1e10 }).with.wallet({ ch3: 1e10 }).with.wallet({ w: 1e10 }).run();
  const { op1, op2, ch1, ch2, ch3, w } = net.wallet; const STEP = net.agent.step, GAME = net.agent.game, ROLL = net.agent.roll, FWD = net.agent.fwd, SEG = net.agent.seg, WBIND = net.agent.wbind, WPROOF = net.agent.wproof; ROLLA = ROLL; GAMEA = GAME;
  const A = { op1: await op1.getAddress(), op2: await op2.getAddress(), ch1: await ch1.getAddress(), ch2: await ch2.getAddress(), ch3: await ch3.getAddress(), w: await w.getAddress() };
  console.log('MODE', NOMAXR ? 'no max_aa_responses' : 'max_aa_responses set', JSON.stringify({ STEP, GAME, ROLL }));
  rec('deployed rv_step == address baked into the referee', STEP, M.stepAddr); rec('deployed referee == address baked into rv_rollup', GAME, M.gameAddr); rec('deployed rollup == computed address', ROLL, M.addr);
  rec('loop 3: deployed seg referee == address baked into rv_rollup', SEG, M.segAddr); rec('loop 3: deployed witbind / witproof == computed', [WBIND, WPROOF], [WP.bind.addr, WP.proof.addr]);
  const vars = async aa => { const v = await op1.readAAStateVars(aa); return v.vars || v; };
  const pts = (lo, hi) => { const cnt = Math.min(16, hi - lo) - 1; return { cnt, pt: j => j == 0 ? lo : j == cnt + 1 ? hi : lo + Math.floor(j * (hi - lo) / (cnt + 1)) }; };
  const sub = (tr, h, prev, o = {}) => ({ submit: h, s0: tr.s0, steps: tr.steps, final: tr.final, inp: tr.inpRoot, fpc: tr.fpc, fregs: tr.fregs, fmem: tr.fmem, prev, units: tr.units || Math.min(8, tr.steps), ...o });
  // play a rollup game on chain; returns the winner and the rollup's secondary response to the result
  async function play(gid, def, chv, chw, honest, opw, stopAt) {
    for (let it = 0; it < 40; it++) {
      const g = String((await vars(GAME))['g_' + gid] || '').split(':'); if (g[0] === 'done') return g[1];
      const lo = +g[3], hi = +g[4], turn = g[7]; const { cnt, pt } = pts(lo, hi); if (turn === stopAt) return 'stopped';
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
  { const ra = await send(op1, ROLL, sub(b1, 1, 'genesis'), OBOND); const rb = await send(op2, ROLL, sub(x1, 1, 'genesis'), OBOND);
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
  let H3;
  // 4. fraud at h3 with h4, h5 on top -> all voided, race restarts at h3
  { const L3 = T.batch(b2.mem, 3, { k: 30, mut: T.MUT.mem }); H3 = T.batch(b2.mem, 3);
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
  // ===== 6. attack pass 2 (timeouts, parallel games on one height, late callbacks on voided heights)
  const gstate = async ref => String((await vars(ROLL))['G' + ref] || '').split(':')[2];
  const rollRes = async r => (r && r.response) ? await secondary(r.response, ROLL) : null;
  const KEEP = M.ref.keep; // bytes the referee keeps from a move trigger (undefined = keeps it all)
  const H4 = T.batch(H3.mem, 4), H5 = T.batch(H4.mem, 5);
  // 6a. operator runs out of time on its first move -> challenger wins (even against an honest root), slash exact
  { let r = await trig(op1, ROLL, sub(H4, 4, H3.final), OBOND, 'submit'); rec('6a honest h4 by op1', 'ok', r.err || 'ok'); const sid = r.unit;
    const o = await trig(ch1, ROLL, { open: sid }, CBOND, 'open'); rec('6a ch1 opens on h4', 'ok', o.err || 'ok'); const gid = ROLL + o.unit;
    r = await trig(w, GAME, { resolve: gid }); rec('6a resolve before the move deadline', 'bounce', r.err ? 'bounce' : 'ok', { err: r.err });
    await net.timetravel({ shift: '3601s' });
    const { cnt, pt } = pts(0, H4.steps); r = await trig(op1, GAME, { mids: gid, roots: Array.from({ length: cnt }, (_, i) => H4.roots[pt(i + 1)]) });
    rec('6a operator mids after its deadline', 'bounce', r.err ? 'bounce' : 'ok', { err: r.err });
    const burned0 = (await vars(ROLL)).burned || 0;
    r = await trig(w, GAME, { resolve: gid }, 10000, 'resolve'); rec('6a resolve after the deadline', 'ok', r.err || 'ok'); const cb = await rollRes(r);
    rec('6a rollup game marked c (operator timed out)', 'c', await gstate(o.unit));
    rec('6a challenger paid CBOND - GF - FEE + OBOND/2 (real output)', CBOND - GF - FEE + OBOND / 2, await paidTo(cb, A.ch1));
    rec('6a operator paid nothing', 0, await paidTo(cb, A.op1));
    const v = await vars(ROLL); rec('6a burned += OBOND/2', OBOND / 2, (v.burned || 0) - burned0); rec('6a h4 flagged fraud', 1, v['f' + sid]); rec('6a top back to 3', 3, v.top);
    rec('6a open games on h4 back to 0', 0, v['n' + sid] || 0);
    r = await trig(op1, ROLL, { reclaim: sid }); rec('6a timed-out operator reclaims h4', 'bounce', r.err ? 'bounce' : 'ok', { err: r.err }); }
  // 6b. challenger runs out of time on a pick -> operator wins the challenger's bond
  { let r = await trig(op1, ROLL, sub(H4, 4, H3.final), OBOND, 'submit'); rec('6b h4 resubmitted by op1', 'ok', r.err || 'ok'); const sid = r.unit;
    const o = await trig(ch2, ROLL, { open: sid }, CBOND, 'open'); rec('6b ch2 opens on h4', 'ok', o.err || 'ok'); const gid = ROLL + o.unit;
    const gb0 = await bal(GAME); const opb0 = await bal(A.op1);
    const s = await play(gid, H4.roots, T.batch(H3.mem, 4, { k: 11, mut: T.MUT.reg }).roots, ch2, H4, op1, 'c'); rec('6b operator answered, challenger to move', 'stopped', s);
    const gdelta = (await bal(GAME)) - gb0, odelta = (await bal(A.op1)) - opb0; console.log('MEASURE one operator mids sent with 10000 bytes: referee balance delta', gdelta, 'operator balance delta', odelta);
    if (KEEP !== undefined) { rec('6b referee nets (0, KEEP] from a move (KEEP minus its refund-unit fee)', true, gdelta > 0 && gdelta <= KEEP, { gdelta });
      rec('6b operator move costs KEEP + its unit fee (< KEEP + 3000), not 10000 + fee', true, -odelta > KEEP && -odelta < KEEP + 3000, { odelta }); }
    await net.timetravel({ shift: '3601s' });
    r = await trig(ch2, GAME, { pick: gid, j: 0 }); rec('6b challenger pick after its deadline', 'bounce', r.err ? 'bounce' : 'ok', { err: r.err });
    r = await trig(w, GAME, { resolve: gid }, 10000, 'resolve'); rec('6b resolve after the deadline', 'ok', r.err || 'ok'); const cb = await rollRes(r);
    rec('6b rollup game marked d', 'd', await gstate(o.unit)); rec('6b operator paid CBOND - GF - FEE (real output)', CBOND - GF - FEE, await paidTo(cb, A.op1));
    rec('6b challenger paid nothing', 0, await paidTo(cb, A.ch2));
    const v = await vars(ROLL); rec('6b h4 live, not fraud', [4, undefined], [v.top, v['f' + sid]]); H4.sid = sid; }
  // 6c. two games on one honest height at once: finalize waits for BOTH
  { let r = await trig(op1, ROLL, sub(H5, 5, H4.final), OBOND, 'submit'); rec('6c honest h5 by op1', 'ok', r.err || 'ok'); const sid = r.unit;
    await net.timetravel({ shift: (WIN - 1800) + 's' });
    const oA = await trig(ch1, ROLL, { open: sid }, CBOND, 'open'), oB = await trig(ch2, ROLL, { open: sid }, CBOND, 'open');
    rec('6c two griefers open on h5', 'ok+ok', (oA.err || 'ok') + '+' + (oB.err || 'ok')); rec('6c open-games counter = 2', 2, (await vars(ROLL))['n' + sid]);
    await net.timetravel({ shift: '1900s' });
    r = await trig(w, ROLL, { finalize: 4 }); rec('6c finalize h4', 'ok', r.err || 'ok');
    r = await trig(w, ROLL, { finalize: 5 }); rec('6c finalize h5 with 2 games open', 'bounce', r.err ? 'bounce' : 'ok', { err: r.err });
    let win = await play(ROLL + oA.unit, H5.roots, T.batch(H4.mem, 5, { k: 11, mut: T.MUT.reg }).roots, ch1, H5, op1); rec('6c game A -> d', 'd', win);
    rec('6c A pays the operator CBOND - GF - FEE', CBOND - GF - FEE, await paidTo(play.last, A.op1)); rec('6c open-games counter = 1', 1, (await vars(ROLL))['n' + sid]);
    r = await trig(w, ROLL, { finalize: 5 }); rec('6c finalize h5 with game B still open', 'bounce', r.err ? 'bounce' : 'ok', { err: r.err });
    win = await play(ROLL + oB.unit, H5.roots, T.batch(H4.mem, 5, { k: 40, mut: T.MUT.pc }).roots, ch2, H5, op1); rec('6c game B -> d', 'd', win);
    rec('6c B pays the operator CBOND - GF - FEE', CBOND - GF - FEE, await paidTo(play.last, A.op1)); rec('6c open-games counter = 0', 0, (await vars(ROLL))['n' + sid] || 0);
    r = await trig(w, ROLL, { finalize: 5 }); rec('6c finalize h5 after both games', 'ok', r.err || 'ok'); rec('6c finalize pays OBOND - FEE', OBOND - FEE, await paidTo(r.response, A.op1));
    rec('6c lf = 5', 5, (await vars(ROLL)).lf); }
  // 6d. two challengers on one fraudulent height h6 (h7 on top, with a griefer game on it);
  //     first fraud win voids h6..h7, honest h6 is resubmitted, then the late callbacks arrive on the voided heights
  { const L6 = T.batch(H5.mem, 6, { k: 30, mut: T.MUT.mem }), X6 = T.batch(H5.mem, 6), L7 = T.batch(L6.mem, 7);
    let r = await trig(op2, ROLL, sub(L6, 6, H5.final), OBOND); rec('6d fraudulent h6 by op2', 'ok', r.err || 'ok'); const s6 = r.unit;
    r = await trig(op1, ROLL, sub(L7, 7, L6.final), OBOND); rec('6d h7 by op1 on bad h6', 'ok', r.err || 'ok'); const s7 = r.unit;
    const oA = await trig(ch1, ROLL, { open: s6 }, CBOND), oB = await trig(ch2, ROLL, { open: s6 }, CBOND), oC = await trig(ch3, ROLL, { open: s7 }, CBOND);
    rec('6d ch1 + ch2 open on h6, ch3 (griefer) on h7', 'ok+ok+ok', [oA, oB, oC].map(x => x.err || 'ok').join('+')); rec('6d open-games counter on h6 = 2', 2, (await vars(ROLL))['n' + s6]);
    const burned0 = (await vars(ROLL)).burned || 0;
    let win = await play(ROLL + oA.unit, L6.roots, X6.roots, ch1, X6, op2); rec('6d game A (ch1) -> c', 'c', win);
    rec('6d first fraud win pays CBOND - GF - FEE + OBOND/2', CBOND - GF - FEE + OBOND / 2, await paidTo(play.last, A.ch1));
    let v = await vars(ROLL); rec('6d top = 5 (h6, h7 voided)', 5, v.top); rec('6d burned += OBOND/2', OBOND / 2, (v.burned || 0) - burned0); rec('6d h6 still has 1 open game', 1, v['n' + s6]);
    r = await trig(op1, ROLL, { reclaim: s7 }); rec('6d reclaim voided h7 while its game is open', 'bounce', r.err ? 'bounce' : 'ok', { err: r.err });
    r = await trig(ch3, ROLL, { open: s6 }, CBOND); rec('6d new open on voided h6', 'bounce', r.err ? 'bounce' : 'ok', { err: r.err });
    r = await trig(op1, ROLL, sub(X6, 6, H5.final), OBOND); rec('6d honest h6 resubmitted while old games run', 'ok', r.err || 'ok'); const n6 = r.unit;
    win = await play(ROLL + oB.unit, L6.roots, X6.roots, ch2, X6, op2); rec('6d late game B (ch2) on voided h6 -> c', 'c', win);
    rec('6d second win gets only CBOND - GF - FEE (no second slash)', CBOND - GF - FEE, await paidTo(play.last, A.ch2));
    v = await vars(ROLL); rec('6d late c-callback does not void the new h6', [6, n6], [v.top, v.h6]); rec('6d burned unchanged by the second win', OBOND / 2, (v.burned || 0) - burned0);
    rec('6d h6 games counter = 0', 0, v['n' + s6] || 0);
    win = await play(ROLL + oC.unit, L7.roots, T.batch(L6.mem, 7, { k: 11, mut: T.MUT.reg }).roots, ch3, L7, op1); rec('6d late griefer game on voided h7 -> d', 'd', win);
    rec('6d late d-callback pays op1 CBOND - GF - FEE', CBOND - GF - FEE, await paidTo(play.last, A.op1));
    v = await vars(ROLL); rec('6d top still 6 after the late d-callback', 6, v.top);
    r = await trig(op1, ROLL, { reclaim: s7 }); rec('6d reclaim voided h7 after its game', 'ok', r.err || 'ok'); rec('6d h7 bond back OBOND - FEE', OBOND - FEE, await paidTo(r.response, A.op1));
    r = await trig(op2, ROLL, { reclaim: s6 }); rec('6d fraudster reclaims old h6', 'bounce', r.err ? 'bounce' : 'ok');
    await net.timetravel({ shift: WIN + 's' }); r = await trig(w, ROLL, { finalize: 6 }); rec('6d new h6 finalizes', 'ok', r.err || 'ok'); rec('6d lf = 6', 6, (await vars(ROLL)).lf); }
  // ===== 7. overpayment refunds (2026-10-31) on the real chain
  { const H6 = T.batch(H5.mem, 6), H7 = T.batch(H6.mem, 7), H8 = T.batch(H7.mem, 8); // new h6 (finalized in 6d) == honest batch 6
    globalThis.__H8 = H8; // section 8 continues on h8
    let r = await trig(op1, ROLL, sub(H7, 7, H6.final), OBOND + 50000, 'submit'); rec('7 submit h7 with OBOND + 50000', 'ok', r.err || 'ok'); const s7 = r.unit;
    rec('7 submit refund = 50000 - FEE (real output)', 50000 - FEE, await paidTo(r.response, A.op1));
    await net.timetravel({ shift: (WIN - 1800) + 's' });
    const o = await trig(ch1, ROLL, { open: s7 }, CBOND + 30000, 'open'); rec('7 open h7 with CBOND + 30000', 'ok', o.err || 'ok');
    rec('7 open refund = 30000 in full (real output)', 30000, await paidTo(o.response, A.ch1)); rec('7 the same response unit pays GF to the referee', GF, await paidTo(o.response, GAME));
    rec('7 referee received the open (no refund back to the rollup)', true, !!(await vars(GAME))['g_' + ROLL + o.unit]);
    await net.timetravel({ shift: '1900s' }); const gid = ROLL + o.unit;
    const s = await play(gid, H7.roots, T.batch(H6.mem, 7, { k: 11, mut: T.MUT.reg }).roots, ch1, H7, op1, 'c'); rec('7 operator answered the overpaid game, challenger to move', 'stopped', s);
    await net.timetravel({ shift: '3601s' });
    r = await trig(w, GAME, { resolve: gid }, RK + 25000, 'resolve'); rec('7 resolve with RK + 25000', 'ok', r.err || 'ok');
    rec('7 resolve refund = 25000 (real output, same unit as the callback)', 25000, await paidTo(r.response, A.w)); rec('7 callback payment GB to the rollup', GB, await paidTo(r.response, ROLL));
    const cb = await rollRes(r); rec('7 operator paid CBOND - GF - FEE = 108000', CBOND - GF - FEE, await paidTo(cb, A.op1));
    r = await trig(w, ROLL, { finalize: 7 }); rec('7 finalize h7', 'ok', r.err || 'ok'); rec('7 finalize pays OBOND - FEE', OBOND - FEE, await paidTo(r.response, A.op1));
    r = await trig(op2, ROLL, sub(H8, 8, H7.final), OBOND + FEE, 'submit'); rec('7 submit h8 with OBOND + FEE (kept, no refund unit)', ['ok', 0], [r.err || 'ok', await paidTo(r.response, A.op2)]);
    r = await trig(ch2, GAME, { open: ref.H('direct' + Date.now()), s0: H8.s0, sN: H8.final, n: 1, d: A.op2, c: A.ch2 }, GF + 5000); rec('7 direct referee open with GF + 5000 refunds 5000', ['ok', 5000], [r.err || 'ok', await paidTo(r.response, A.ch2)]); }

  // ===== 8. loop round 3: layer-1 game (rv_seg_ref) and witness proofs (rv_witbind / rv_witproof) on the real chain
  // max_aa_responses: uopen 2 (rollup -> seg); seg mids / pick 1, pick that hands off 2 (seg -> game); layer-2 resolve
  // 3 (game -> seg -> rollup); seg resolve on a timeout 2 (seg -> rollup); bind / prove 1
  const H64 = x => require('crypto').createHash('sha256').update(x).digest('base64');
  async function playSeg(sgid, defT, chT, honest, opw, chw) {
    const bnd = k => Math.floor(k * defT.steps / defT.units);
    for (let it = 0; it < 20; it++) {
      const g = String((await vars(SEG))['g_' + sgid] || '').split(':'); if (g[0] === 'done') return { w: g[1] };
      const lo = +g[3], hi = +g[4], slo = +g[5], shi = +g[6], turn = g[9]; const { cnt, pt } = pts(lo, hi);
      if (turn === 'd') { const st = Array.from({ length: cnt }, (_, i) => bnd(pt(i + 1))); const r = await trig(opw, SEG, { mids: sgid, steps: st, roots: st.map(x => defT.roots[x]) }, 10000, 'smids', 1); if (r.err) return { w: 'smids ' + r.err }; }
      else if (turn === 'c') { const v = await vars(SEG); const m = String(v['m_' + sgid]).split(','), n = String(v['n_' + sgid]).split(',').map(Number);
        const rootAt = i => i == 0 ? g[7] : i == cnt + 1 ? g[8] : m[i - 1], stepAt = i => i == 0 ? slo : i == cnt + 1 ? shi : n[i - 1];
        let j = 0; while (j < cnt && rootAt(j + 1) === chT.roots[stepAt(j + 1)]) j++;
        const one = pt(j + 1) - pt(j) === 1; const r = await trig(chw, SEG, { pick: sgid, j }, 10000, one ? 'spick-handoff' : 'spick', one ? 2 : 1); if (r.err) return { w: 'spick ' + r.err }; }
      else { // layer 2 on [slo, shi]
        const gid2 = SEG + H64(sgid); const sl = a => a.slice(slo, shi + 1);
        for (let k = 0; k < 40; k++) { const q = String((await vars(GAME))['g_' + gid2] || '').split(':'); if (q[0] === 'done') break;
          const lo2 = +q[3], hi2 = +q[4], t2 = q[7]; const p2 = pts(lo2, hi2);
          if (t2 === 'd') { const r = await trig(opw, GAME, { mids: gid2, roots: Array.from({ length: p2.cnt }, (_, i) => sl(defT.roots)[p2.pt(i + 1)]) }, 10000, 'mids'); if (r.err) return { w: 'l2 mids ' + r.err }; }
          else if (t2 === 'c') { const m = String((await vars(GAME))['m_' + gid2]).split(','); const at = i => i == 0 ? q[5] : i == p2.cnt + 1 ? q[6] : m[i - 1];
            let j = 0; while (j < p2.cnt && at(j + 1) === sl(chT.roots)[p2.pt(j + 1)]) j++; const r = await trig(chw, GAME, { pick: gid2, j }, 10000, 'pick'); if (r.err) return { w: 'l2 pick ' + r.err }; }
          else { const a = slo + lo2; if (honest.roots[a] === q[5] && !(await vars(STEP))['s_' + q[5]]) { const s = await trig(w, STEP, honest.wits[a], 10000, 'step'); if (s.err) return { w: 'step ' + s.err }; }
            const r = await trig(w, GAME, { resolve: gid2 }, 10000, 'resolve3', 3); if (r.err) return { w: 'l2 resolve ' + r.err };
            const segResp = await secondary(r.response, SEG); const rollResp = await secondary(segResp, ROLL); return { w: (String((await vars(SEG))['g_' + sgid]).split(':')[1]), roll: rollResp, unit: [lo, hi, slo, shi] }; } }
        return { w: 'l2 unfinished' }; }
    }
    return { w: 'unfinished' };
  }
  { const v0 = await vars(ROLL); rec('8 state before: lf = 7, top = 8', [7, 8], [v0.lf, v0.top]);
    const H8 = globalThis.__H8;
    const H9 = Object.assign(T.batch(H8.mem, 9, { extra: 300 }), { units: 24 });
    let r = await trig(op1, ROLL, sub(H9, 9, H8.final), OBOND, 'submit'); rec('8a honest h9 with units = 24', 'ok', r.err || 'ok'); const s9 = r.unit;
    rec('8a units stored', 24, (await vars(ROLL))['u' + s9]);
    await net.timetravel({ shift: (WIN - 1800) + 's' });
    r = await trig(ch3, ROLL, { uopen: s9 }, CBOND, 'uopen', 2); rec('8a uopen with CBOND only', 'bounce', r.err ? 'bounce' : 'ok');
    const o = await trig(ch3, ROLL, { uopen: s9 }, CBOND + GF, 'uopen', 2); rec('8a griefer uopen h9 (CBOND + GF)', 'ok', o.err || 'ok');
    rec('8a the rollup response paid 2 GF to the seg referee', 2 * GF, await paidTo(o.response, SEG));
    await net.timetravel({ shift: '1900s' });
    const sgid = ROLL + o.unit; const op0 = await bal(A.op1);
    const g = await playSeg(sgid, H9, Object.assign(T.batch(H8.mem, 9, { extra: 300, k: 150, mut: T.MUT.reg }), { units: 24 }), H9, op1, ch3);
    rec('8a griefer vs honest operator via layer 1 + layer 2 (real chain)', 'd', g.w, { unit: g.unit });
    rec('8a operator paid CBOND - GF - FEE (rollup response to the seg callback)', CBOND - GF - FEE, await paidTo(g.roll, A.op1));
    rec('8a no game open on h9', 0, (await vars(ROLL))['n' + s9] || 0);
    r = await trig(w, ROLL, { finalize: 8 }); rec('8a finalize h8', 'ok', r.err || 'ok');
    r = await trig(w, ROLL, { finalize: 9 }); rec('8a finalize h9 after its layer-1 game', 'ok', r.err || 'ok');
    // 8b fraud at h10 caught through layer 1
    const L10 = Object.assign(T.batch(H9.mem, 10, { k: 25, mut: T.MUT.mem }), { units: 5 }), X10 = T.batch(H9.mem, 10);
    r = await trig(op2, ROLL, sub(L10, 10, H9.final), OBOND, 'submit'); rec('8b fraudulent h10 (units 5)', 'ok', r.err || 'ok'); const s10 = r.unit;
    const o2 = await trig(ch1, ROLL, { uopen: s10 }, CBOND + GF, 'uopen', 2); rec('8b honest challenger uopen h10', 'ok', o2.err || 'ok');
    const g2 = await playSeg(ROLL + o2.unit, L10, X10, X10, op2, ch1);
    rec('8b fraud proven through layer 1', 'c', g2.w, { unit: g2.unit });
    rec('8b challenger paid CBOND - GF - FEE + OBOND/2', CBOND - GF - FEE + OBOND / 2, await paidTo(g2.roll, A.ch1));
    rec('8b h10 voided (top = 9), fraud flag', [9, 1], [(await vars(ROLL)).top, (await vars(ROLL))['f' + s10]]);
    { const sb = await bal(SEG); rec('8 seg referee solvent: per game it keeps GF, plus MK - refund-unit fee per mids / pick (as rv_game_ref), minus its response-unit fees (2 games, 4 moves)', true, sb > 0 && sb <= 2 * GF + 4 * 2000, { balance: sb }); }
    // 8c witness proofs: h10 whose final memory holds a real MNWIT1 root (engine-diff proofdump of adv5) at the guest's OUT slots
    const P = JSON.parse(fs.readFileSync(path.join(__dirname, 'testdata/proofs/adv5.json'), 'utf8')); const mem = K.memWithRoot(P.root);
    const N10 = T.batch(H9.mem, 10); const final = ref.H(N10.fpc + ':' + N10.fregs + ':' + mem.root() + ':' + N10.inpRoot + ':' + N10.steps);
    r = await trig(op1, ROLL, sub(N10, 10, H9.final, { fmem: mem.root(), final }), OBOND, 'submit'); rec('8c h10 with the witness memory image', 'ok', r.err || 'ok');
    r = await trig(w, WBIND, K.bindData(mem, 10), 10000, 'bind', 1); rec('8c bind before finalize', 'bounce', r.err ? 'bounce' : 'ok', { err: r.err });
    await net.timetravel({ shift: WIN + 's' }); r = await trig(w, ROLL, { finalize: 10 }); rec('8c finalize h10', 'ok', r.err || 'ok');
    const bad = K.bindData(mem, 10); bad.words = bad.words.map((x, k) => k === 0 ? (x ^ 1) >>> 0 : x);
    r = await trig(w, WBIND, bad, 10000, undefined, 1); rec('8c bind with a flipped word bit', 'bounce', r.err ? 'bounce' : 'ok');
    r = await trig(w, WBIND, K.bindData(mem, 10), 10000, 'bind', 1); rec('8c bind h10', 'ok', r.err || 'ok'); rec('8c W10 = the root', P.root, (await vars(WBIND)).W10);
    const kidJs = l => { const p = l.split(':'); const f = l.startsWith('pos:') ? 3 : 2; return p.length <= f ? l : p.slice(0, f).join(':'); };
    let okm = 0; for (const m of P.members) { const q = await trig(w, WPROOF, { prove: 10, leaf: m.leaf, sib: m.sib }, 10000, 'prove', 1); if (!q.err && (await vars(WPROOF))['L10:' + kidJs(m.leaf)] === m.leaf) okm++; else console.log('prove fail', q.err); }
    rec('8c memberships proven against finalized h10', P.members.length, okm);
    r = await trig(w, WPROOF, { prove: 10, leaf: P.absent.term, sib: P.absent.sib, key: P.absent.key }, 10000, 'prove', 1); rec('8c absence proven', ['ok', 1], [r.err || 'ok', (await vars(WPROOF))['A10:' + P.absent.key]]);
    r = await trig(w, WPROOF, { prove: 10, leaf: P.members[0].leaf + '1', sib: P.members[0].sib }, 10000, undefined, 1); rec('8c tampered leaf', 'bounce', r.err ? 'bounce' : 'ok');
    r = await trig(w, WPROOF, { prove: 9, leaf: P.members[0].leaf, sib: P.members[0].sib }, 10000, undefined, 1); rec('8c proof against unbound h9', 'bounce', r.err ? 'bounce' : 'ok'); }
  // 5. accounting: the rollup holds exactly burned + kept FEEs + GB refunds + bounce fees, no bond is outstanding
  { const v = await vars(ROLL); const b = await bal(ROLL); rec('rollup balance >= burned (all bonds settled)', true, b >= (v.burned || 0), { balance: b, burned: v.burned, lf: v.lf, top: v.top }); }
  const avg = a => a && a.length ? Math.round(a.reduce((x, y) => x + y, 0) / a.length) : 0;
  const feeRep = Object.fromEntries(Object.entries(fees).map(([k, a]) => [k, { n: a.length, avg: avg(a), max: Math.max(...a) }]));
  console.log('FEES ' + JSON.stringify(feeRep));
  // tps fee per trigger type, read back from the unit (paid at composition); actual settled values: tpscmp.js on the sqlite
  const tps = {}; for (const [k, us] of Object.entries(units)) { const a = []; for (const u of us) { const i = await op1.getUnitInfo({ unit: u }); const o = i.unitObj || {}; a.push({ u, tps: o.tps_fee || 0, mar: o.max_aa_responses }); } tps[k] = a; }
  const tpsRep = Object.fromEntries(Object.entries(tps).map(([k, a]) => { const v = a.map(x => x.tps).sort((x, y) => x - y); return [k, { n: v.length, avg: avg(v), median: v[v.length >> 1], max: v[v.length - 1], max_aa_responses: [...new Set(a.map(x => x.mar))] }]; }));
  console.log('TPS ' + JSON.stringify(tpsRep));
  const s = { total: results.length, pass: results.filter(r => r.pass).length, fail: results.filter(r => !r.pass).length };
  console.log('SUMMARY ' + JSON.stringify(s)); fs.writeFileSync(process.env.OUT || 'rolldevnet-results.json', JSON.stringify({ mode: NOMAXR ? 'nomaxr' : 'maxr', results, fees: feeRep, tps: tpsRep, units }, null, 1));
  await net.stop(); process.exit(0);
})().catch(async e => { console.log('ERR', e.stack || e); try { await net.stop(); } catch (x) {} process.exit(1); });
