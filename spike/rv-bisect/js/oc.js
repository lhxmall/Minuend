// Real-ocore harness (vendored ocore 0.4.8 == byteball/ocore master constants/evaluation as of 2026-10-27).
// - validate(aaSource) -> {complexity, count_ops} via aa_validation.validateAADefinition (same as val.sh)
// - evalInit(formula, data, vars) -> {locals, err} via formula/index.evaluate with all upgrades active
'use strict';
const _si = global.setImmediate;
const Mod = require('module'); const orig = Mod._load;
Mod._load = function (req) {
  if (/(^|\/)(db|sqlite_pool|mysql_pool|kvstore)(\.js)?$/.test(req) || req === 'sqlite3') return new Proxy(function () {}, { get: (t, k) => k === 'then' ? undefined : (() => new Promise(() => {})), apply: () => new Promise(() => {}) });
  return orig.apply(this, arguments);
};
const OC = process.env.OCORE || '/workspace/projects/4ecc28f7-451e-450a-b62c-b8b357f0cc38/wt-aa/vendor/aa-testkit/node_modules/ocore';
process.env.devnet = '1';
const constants = require(OC + '/constants.js');
constants.aa2UpgradeMci=0; constants.aa3UpgradeMci=0; constants.v4UpgradeMci=0;
const efPath = require.resolve(OC + '/formula/error/errorFormatter.js'); const em = new Mod(efPath); em.filename = efPath; em.loaded = true;
em.exports = d => ({ message: (d.error && (d.error.bounce_message || d.error.message)) || String(d.error) }); require.cache[efPath] = em;
const fp = require(OC + '/formula/index');
require(OC + '/storage.js').readAAStateVar = (a, n, cb) => cb(undefined);
const parseOjson = require(OC + '/formula/parse_ojson').parse;
let aav; const AAV = () => aav || (aav = require(OC + '/aa_validation.js'));

function validate(src) {
  return new Promise(res => parseOjson(src, (err, def) => {
    if (err) return res({ err: 'parse: ' + err });
    AAV().validateAADefinition(def, (aa, name, cb) => cb(null), 1e9, (err, r) => res(err ? { err } : r));
  }));
}
function evalInit(formula, data, extra = {}) {
  return new Promise(res => {
    const locals = {};
    const at = [];
    fp.evaluate({ conn: null, formula, bStatementsOnly: true, bStateVarAssignmentAllowed: true, stateVars: {},
      trigger: { address: 'CHALLENGERADDRESSXXXXXXXXXXXXXXX', data, outputs: { base: 20000 } },
      objValidationState: { last_ball_mci: 1e9, last_ball_timestamp: 1e9 }, address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU', locals, ...extra },
    at, '', (e, r) => res({ err: e, locals }));
  });
}
const val = (locals, k) => { const x = locals[k]; if (x === undefined) return undefined; if (x && x.obj !== undefined) return x.obj; return (typeof x === 'object' && x.toString) ? x.toString() : x; };
// full-flow runner: shared stateVars across calls; returns {err, locals, stateVars}
function run(formula, { data, address = 'USERADDRESSXXXXXXXXXXXXXXXXXXXXX', unit, ts = 1e9, stateVars = {}, outputs = { base: 20000 }, aa = 'GAMEAAXXXXXXXXXXXXXXXXXXXXXXXXXX', responseVars = {}, conn = null }) {
  return new Promise(res => {
    const locals = {};
    fp.evaluate({ conn, formula, bStatementsOnly: true, bStateVarAssignmentAllowed: true, stateVars, responseVars,
      trigger: { address, data, outputs, unit: unit || require('crypto').randomBytes(32).toString('base64') },
      objValidationState: { last_ball_mci: 1e9, last_ball_timestamp: ts }, address: aa, locals },
    [], '', (e) => res({ err: e && ((e.formattedError || e).message || e), locals, stateVars, responseVars }));
  });
}
module.exports = { validate, evalInit, val, run, constants };
