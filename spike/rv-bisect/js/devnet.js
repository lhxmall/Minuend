// Real devnet (aa-testkit: genesis + witness + hub, real units, real bounces, real payments) run of the spike AAs.
// usage (on the box): AATK=/data/hark/wt-all/vendor/aa-testkit OCORE=$AATK/node_modules/ocore node devnet.js
'use strict';
const path = require('path'); const fs = require('fs');
const AATK = process.env.AATK || '/data/hark/wt-all/vendor/aa-testkit';
process.env.NODE_PATH = [path.join(AATK, 'node_modules'), process.env.NODE_PATH].filter(Boolean).join(path.delimiter); require('module').Module._initPaths();
process.env.OCORE = process.env.OCORE || path.join(AATK, 'node_modules', 'ocore');
const { Testkit } = require(path.join(AATK, 'main.js'));
const { Network } = Testkit({ TESTDATA_DIR: process.env.TESTDATA || path.join(__dirname, '..', 'devnet-testdata'), NETWORK_PORT: +(process.env.PORT || 16631) });
const ref = require('./ref.js'); const T = require('./trace.js'); require('./mkgame.js'); // regenerates aa/rv_game.aa with the real rv_step address
const G = require('./mkgame.js');
const BOND = 100000, FEE = 2000;
const results = []; const rec = (name, expected, actual, extra) => { const pass = expected === actual; results.push({ name, expected, actual, pass, ...(extra || {}) }); console.log(pass ? 'PASS' : 'FAIL', '|', name, '| expected', expected, '| actual', actual, extra ? JSON.stringify(extra) : ''); };
let net;
async function trig(wallet, to, data, amount = 10000) {
  const r = await wallet.triggerAaWithData({ toAddress: to, amount, data });
  if (r.error) return { err: 'compose: ' + String(r.error).slice(0, 120) };
  await net.witnessUntilStable(r.unit);
  const { response } = await net.getAaResponseToUnit(r.unit);
  if (response.bounced) { const e = response.response && response.response.error; return { err: (typeof e === 'string' ? e : JSON.stringify(e || 'bounced')).slice(0, 160), unit: r.unit }; }
  return { unit: r.unit, response };
}
// amount the AA's response unit paid to `addr` (0 if no response unit)
async function paidTo(resp, addr) { const u = resp && resp.response_unit; if (!u) return 0; const info = await net.wallet.op.getUnitInfo({ unit: u });
  let sum = 0; for (const m of (info.unitObj && info.unitObj.messages) || []) if (m.app === 'payment' && !m.payload.asset) for (const o of m.payload.outputs) if (o.address === addr) sum += o.amount; return sum;
}
const bal = async (w, a) => { const b = await w.getBalanceOf(a); return b && b.base ? (b.base.stable || 0) + (b.base.pending || 0) : 0; };

(async () => {
  net = await Network.create().with.agent({ step: path.join(__dirname, '../aa/rv_step.aa') }).with.agent({ game: path.join(__dirname, '../aa/rv_game.aa') })
    .with.wallet({ op: 1e12 }).with.wallet({ ch: 1e10 }).with.wallet({ ch2: 1e10 }).with.wallet({ ch3: 1e10 }).run();
  const { op, ch, ch2, ch3 } = net.wallet; const STEP = net.agent.step, GAME = net.agent.game;
  const A = { op: await op.getAddress(), ch: await ch.getAddress(), ch2: await ch2.getAddress(), ch3: await ch3.getAddress() };
  rec('deployed rv_step address == $STEP baked into rv_game', STEP, G.stepAddr);
  const vars = async aa => { const v = await op.readAAStateVars(aa); return v.vars || v; };
  const N = 6, n = T.honestLen(N), H = T.run(N, n);
  const pts = (lo, hi) => { const cnt = Math.min(16, hi - lo) - 1; return { cnt, pt: j => j == 0 ? lo : j == cnt + 1 ? hi : lo + Math.floor(j * (hi - lo) / (cnt + 1)) }; };
  async function play(gid, def, chv, chw, opts = {}) {
    for (let it = 0; it < 60; it++) {
      const g = String((await vars(GAME))['g_' + gid] || '').split(':'); if (g[0] === 'done') return g[1];
      const lo = +g[3], hi = +g[4], turn = g[7]; const { cnt, pt } = pts(lo, hi);
      if (turn === 'd') {
        if (opts.defSilent) { await net.timetravel({ shift: '3601s' }); const r = await trig(ch3, GAME, { resolve: gid }); if (r.err) return 'resolve ' + r.err; play.last = r.response; continue; }
        const r = await trig(op, GAME, { mids: gid, roots: Array.from({ length: cnt }, (_, i) => def[pt(i + 1)]) }); if (r.err) return 'mids ' + r.err;
      } else if (turn === 'c') {
        const m = String((await vars(GAME))['m_' + gid]).split(','); const rootAt = i => i == 0 ? g[5] : i == cnt + 1 ? g[6] : m[i - 1];
        let j = 0; while (j < cnt && rootAt(j + 1) === chv[pt(j + 1)]) j++;
        const r = await trig(chw, GAME, { pick: gid, j }); if (r.err) return 'pick ' + r.err;
      } else {
        if (H.roots[lo] === g[5] && !(await vars(STEP))['s_' + g[5]]) { const s = await trig(ch3, STEP, H.wits[lo]); if (s.err) return 'step ' + s.err; }
        const r = await trig(ch3, GAME, { resolve: gid }); if (r.err) return 'resolve ' + r.err; play.last = r.response;
      }
    }
    return 'unfinished';
  }
  const claim = async (roots) => { const r = await trig(op, GAME, { claim: 1, s0: roots[0], sN: roots[n], n }, BOND); if (r.err) throw Error('claim ' + r.err); return r.unit; };
  const open = async (w, cid) => { const r = await trig(w, GAME, { open: cid }, BOND); if (r.err) throw Error('open ' + r.err); return r.unit; };

  // 1. lying operator vs honest challenger, real rv_step memo
  { const L = T.run(N, n, 40, T.MUT.reg); const b0 = await bal(op, A.ch); const cid = await claim(L.roots); const gid = await open(ch, cid);
    const w = await play(gid, L.roots, H.roots, ch);
    rec('lying operator (register lie at step 40) vs honest challenger', 'c', w);
    rec('resolve pays challenger own bond + half claim bond - FEE (real payment output)', BOND + BOND / 2 - FEE, await paidTo(play.last, A.ch));
    const vs = await vars(GAME); rec('claim flagged fraudulent', 1, vs['f_' + cid]);
    await net.timetravel({ shift: '86401s' }); const f = await trig(op, GAME, { finalize: cid }); rec('finalize fraudulent claim', 'bounce', f.err ? 'bounce' : 'accepted'); }
  // 2. honest operator vs two griefers, then finalize
  { const L = T.run(N, n, 20, T.MUT.mem); const a0 = await bal(op, GAME); const cid = await claim(H.roots); const g1 = await open(ch2, cid); const g2 = await open(ch3, cid);
    const w1 = await play(g1, H.roots, L.roots, ch2); const p1 = await paidTo(play.last, A.op); const w2 = await play(g2, H.roots, L.roots, ch3);
    rec('defender win pays the griefer\'s stake - FEE to operator (real payment output)', BOND - FEE, p1);
    rec('griefer 1 vs honest operator', 'd', w1); rec('griefer 2 vs honest operator', 'd', w2);
    await net.timetravel({ shift: '86401s' }); const f = await trig(ch, GAME, { finalize: cid }); rec('finalize griefed honest claim', 'accepted', f.err ? 'bounce:' + f.err : 'accepted');
    rec('finalize returns claim bond - FEE to operator (real payment output)', BOND - FEE, await paidTo(f.response, A.op));
    const a1 = await bal(op, GAME); rec('game AA did not lose funds on the griefed claim (pays out <= takes in)', 'yes', a1 >= a0 ? 'yes' : 'no', { aaBefore: a0, aaAfter: a1 }); }
  // 3. defender silent -> challenger wins on timeout
  { const L = T.run(N, n, 40, T.MUT.pc); const cid = await claim(L.roots); const gid = await open(ch, cid); const w = await play(gid, L.roots, H.roots, ch, { defSilent: true });
    rec('defender silent past deadline', 'c', w); }
  // 4. separator injection and malformed claims bounce on the real chain
  { const bad = '::1:' + A.op + ':10:open'; const r = await trig(op, GAME, { claim: 1, s0: bad, sN: H.roots[n], n }, BOND); rec('claim with s0 "::1:ADDR:10:open" (record forging)', 'bounce', r.err ? 'bounce' : 'accepted');
    const r2 = await trig(op, GAME, { claim: 1, s0: H.roots[0], sN: H.roots[n], n: 0 }, BOND); rec('claim n=0', 'bounce', r2.err ? 'bounce' : 'accepted');
    const r3 = await trig(ch, GAME, { open: 'nonexistent' }, BOND); rec('open unknown claim', 'bounce', r3.err ? 'bounce' : 'accepted'); }
  // 5. rv_step on the real chain: honest store step, then forged / malformed calls must not change the memo
  { const d = H.wits.find(x => x.w !== undefined && ((x.w >>> 0) & 127) === 35); const st = d.step + 1; const want = H.roots[st];
    const r = await trig(ch, STEP, d); rec('honest store step accepted on chain', 'ok', r.err ? 'bounce:' + r.err : 'ok');
    const pre = H.roots[d.step]; const memo0 = (await vars(STEP))['s_' + pre]; rec('memo = reference post root', want, memo0);
    const attacks = [['stale nroot', { ...d, nroot: d.mem }], ['wrong sibling', { ...d, msib: d.msib.map((x, i) => i === 5 ? ref.H('e') : x) }], ['mw+1', { ...d, mw: d.mw + 1 }],
      ['regs[3] = "5" (string)', { ...d, regs: d.regs.map((x, i) => i === 3 ? '5' : x) }], ['regs[3] = -0', { ...d, regs: d.regs.map((x, i) => i === 3 ? -0 : x) }], ['regs[3] = 2^32', { ...d, regs: d.regs.map((x, i) => i === 3 ? 2 ** 32 : x) }],
      ['mem 4096 chars', { ...d, mem: 'x'.repeat(4096) }], ['regs length 33', { ...d, regs: [...d.regs, 0] }], ['step 1.5', { ...d, step: 1.5 }], ['pc "4096"(string of digits)', { ...d, pc: String(d.pc) }]];
    for (const [nm, data] of attacks) { const x = await trig(ch, STEP, data); const memo = (await vars(STEP))['s_' + pre];
      rec('rv_step on chain: ' + nm, 'harmless', memo === want ? 'harmless' : 'MEMO CHANGED', { outcome: x.err ? 'bounce: ' + x.err : 'accepted' }); } }
  const s = { total: results.length, pass: results.filter(r => r.pass).length, fail: results.filter(r => !r.pass).length };
  console.log('SUMMARY ' + JSON.stringify(s)); fs.writeFileSync(process.env.OUT || 'devnet-results.json', JSON.stringify(results, null, 1));
  await net.stop(); process.exit(0);
})().catch(async e => { console.log('ERR', e.stack || e); try { await net.stop(); } catch (x) {} process.exit(1); });
