// Simulated Obyte chain for the rollup prototype, on the REAL ocore formula evaluator (oc.js).
// - every AA's init+state runs through ocore formula/index.evaluate with shared state vars;
// - the messages of each .aa template are mirrored here from the same $st locals (devnet.js checks them on a real chain);
// - payments move balances; a payment+data to another AA is a secondary trigger; any bounce in the chain reverts
//   the whole primary trigger (ocore >= aa2 behaviour) and refunds the sender minus the bounce fee;
// - an AA that would pay more than it holds bounces (ocore: not enough funds).
'use strict';
const { run, val } = require('./oc.js'); const fs = require('fs'); const crypto = require('crypto');
const isDec = v => v && typeof v === 'object' && typeof v.toNumber === 'function' && 'd' in v && 'e' in v;
const M = require('./mkrollup.js');
const ROLL = M.addr, GAME = M.gameAddr, STEP = M.stepAddr;
const STEPF = fs.readFileSync(__dirname + '/../aa/rv_step.oscript', 'utf8') + "\nvar['s_' || $pre] = $post;";
const plain = v => { if (v === undefined || v === null) return v; if (isDec(v)) return v.toNumber();
  if (Array.isArray(v)) return v.map(plain); if (typeof v === 'object') { if (v.obj !== undefined && Object.keys(v).length <= 2) return plain(v.obj); const o = {}; for (const k in v) o[k] = plain(v[k]); return o; } return v; };
const cloneSV = sv => { const o = {}; for (const a in sv) { o[a] = {}; for (const k in sv[a]) o[a][k] = { ...sv[a][k] }; } return o; };
const rnd = () => crypto.randomBytes(32).toString('base64');
const errMsg = e => e && String((e.formattedError || e).message || e.bounce_message || JSON.stringify(e)).slice(0, 140);
const AAS = {
  [ROLL]: { f: M.body + '\n' + M.state, out: (st, L, from) => { const o = [];
      if (st.call) o.push({ to: GAME, amt: +L('GF'), data: st.call });
      if (+st.rf > 0) o.push({ to: from, amt: +st.rf }); // overpayment refund (submit: - OBOND - FEE, open: - CBOND)
      if (st.pay && +st.amt > 0) o.push({ to: st.pay, amt: +st.amt }); return o; } },
  [GAME]: { f: M.ref.body + '\n' + M.ref.state, out: (st, L, from) => [...(st.cb ? [{ to: st.to, amt: +L('GB'), data: st.cb }] : []), ...(+st.rf > 0 ? [{ to: from, amt: +st.rf }] : [])] }, // rf: move refund (trigger - MK), open refund (trigger - GF), resolve refund (trigger - RK)
  [STEP]: { f: STEPF, out: () => [] },
};
// an AA that bounces every trigger (used as a hostile operator / challenger that refuses payouts)
const OCP = process.env.OCORE || '/workspace/projects/4ecc28f7-451e-450a-b62c-b8b357f0cc38/wt-aa/vendor/aa-testkit/node_modules/ocore';
const BOUNCER = require(OCP + '/object_hash.js').getChash160(['autonomous agent', { init: "{ bounce('no payouts please'); }" }]);
AAS[BOUNCER] = { f: "bounce('no payouts please');", out: () => [] };
const conn = { query: (sql, params, cb) => cb(AAS[params[0]] ? [{ 1: 1 }] : []) }; // is_aa() looks up aa_addresses
const BOUNCE_FEE = 10000;
class Chain {
  constructor() { this.sv = {}; this.ts = 1e9; this.bal = {}; this.log = []; this.burnedOut = 0; }
  b(a) { return this.bal[a] || 0; }
  // primary trigger from a user address
  async send(from, to, amount, data, unit) {
    const hasNull = o => o === null || (typeof o === 'object' && Object.values(o).some(hasNull));
    if (data && hasNull(JSON.parse(JSON.stringify(data)))) return { err: 'unsendable: a unit cannot carry null / NaN / Infinity' };
    unit = unit || rnd(); const snapSV = cloneSV(this.sv), snapBal = { ...this.bal };
    this.bal[from] = this.b(from) - amount;
    const r = await this._trig(from, to, amount, data, unit, 0);
    if (r.err) { this.sv = snapSV; this.bal = snapBal; this.bal[from] = this.b(from) - Math.min(amount, BOUNCE_FEE); this.bal[to] = this.b(to) + Math.min(amount, BOUNCE_FEE); return { err: r.err, unit }; }
    return { unit, pays: r.pays, st: r.st };
  }
  async _trig(from, to, amount, data, unit, depth) {
    this.bal[to] = this.b(to) + amount;
    const aa = AAS[to]; if (!aa) return { pays: [] };
    if (depth > 9) return { err: 'too many responses' };
    const r = await run(aa.f, { data: JSON.parse(JSON.stringify(data || {})), address: from, ts: this.ts, stateVars: this.sv, unit, aa: to, outputs: { base: amount }, conn });
    if (r.err) return { err: errMsg(r.err) };
    const st = plain(val(r.locals, 'st')) || {}; const L = k => plain(val(r.locals, k));
    const outs = aa.out(st, L, from); const pays = [];
    const runit = rnd();
    for (const o of outs) { if (this.b(to) < o.amt) return { err: 'not enough funds in ' + to.slice(0, 6) + ': has ' + this.b(to) + ' pays ' + o.amt };
      this.bal[to] -= o.amt; pays.push({ from: to, to: o.to, amt: o.amt });
      if (AAS[o.to]) { const s = await this._trig(to, o.to, o.amt, o.data, runit, depth + 1); if (s.err) return { err: 'secondary ' + o.to.slice(0, 6) + ' bounced: ' + s.err }; pays.push(...s.pays); }
      else this.bal[o.to] = this.b(o.to) + o.amt; }
    return { pays, st };
  }
  v(aa, k) { const x = this.sv[aa] && this.sv[aa][k]; return x ? (typeof x.value === 'object' ? x.value.toNumber() : x.value) : undefined; }
  r(k) { return this.v(ROLL, k); }
}
module.exports = { Chain, ROLL, GAME, STEP, M, rnd, BOUNCER };
