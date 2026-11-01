// Validates each .aa with ocore's OWN deploy-time validator
// (aa_validation.validateAADefinition) and reports the AA-wide complexity
// and op count exactly as a deployment would compute them (exit 1 if the
// definition is invalid — including complexity > MAX_COMPLEXITY or ops >
// MAX_OPS — exit 2 if it is within OPS_HEADROOM ops of the cap).
//
// Round 9 (R9-L3): the previous version re-walked only the `if` / `init` /
// `state` formulas and missed the `{…}` formulas inside messages, so it
// under-counted ops by up to 35; it now runs the real validator, so the
// numbers below ARE the deploy numbers.
// Usage: node tools/check_aa_complexity.js agents/*.aa
const fs = require('fs');
const path = require('path');

// aa_validation pulls in ocore's db layer; nothing here touches a db, so the
// db modules are stubbed before ocore is loaded.
const Module = require('module');
const origLoad = Module._load;
Module._load = function (req, parent, isMain) {
	if (/(^|\/)(db|sqlite_pool|mysql_pool)(\.js)?$/.test(req) || req === 'sqlite3')
		return new Proxy(function () {}, { get: (t, k) => (k === 'then' ? undefined : () => {}), apply: () => ({}) });
	return origLoad.apply(this, arguments);
};
process.env.devnet = process.env.devnet || '1';

const ocoreRoot = path.join(__dirname, '..', '..', 'vendor', 'aa-testkit', 'node_modules', 'ocore');
const parseOjson = require(path.join(ocoreRoot, 'formula', 'parse_ojson')).parse;
const constants = require(path.join(ocoreRoot, 'constants.js'));
const aaValidation = require(path.join(ocoreRoot, 'aa_validation.js'));

// Ops the gate keeps free under MAX_OPS (a near-full AA warns, never fails).
const OPS_HEADROOM = 0;
const FILLER = 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU';
const SUBSTITUTIONS = {
	PERP_ASSET_ID_HERE: 'n9y3VghJdrwhU4nWem6P78yNc2NVFywqMdFcaXGBTeE=',
	ROLLUP_AA_HERE: FILLER,
	VAULT_BASE_HERE: FILLER,
};

function check(f) {
	return new Promise((resolve) => {
		let src = fs.readFileSync(f, 'utf8');
		for (const [k, v] of Object.entries(SUBSTITUTIONS)) src = src.split(k).join(v);
		src = src.replace(/DISPUTE_[A-Z]+_AA_HERE|VAULT_AA_HERE/g, FILLER);
		parseOjson(src, (err, def) => {
			if (err) {
				console.error(`${f}: parse error: ${err}`);
				process.exit(1);
			}
			aaValidation.validateAADefinition(def, (aa, name, cb) => cb(null), 1e9, (verr, res) => {
				if (verr) {
					console.error(`${f}: INVALID: ${verr}`);
					process.exit(1);
				}
				const cx = res.complexity;
				const ops = res.count_ops;
				console.log(
					`${f}: complexity ${cx}/${constants.MAX_COMPLEXITY}, ops ${ops}/${constants.MAX_OPS} ` +
						`(headroom ${constants.MAX_OPS - ops} ops, ${constants.MAX_COMPLEXITY - cx} complexity)`
				);
				if (constants.MAX_OPS - ops < OPS_HEADROOM) {
					console.error(`${f}: ops ${ops} leaves < ${OPS_HEADROOM} ops of headroom`);
					process.exit(2);
				}
				resolve();
			});
		});
	});
}

(async () => {
	for (const f of process.argv.slice(2)) await check(f);
	process.exit(0);
})();
