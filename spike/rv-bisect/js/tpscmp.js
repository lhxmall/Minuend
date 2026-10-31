// tps fee + response count per trigger type of one rolldevnet.js run (docs/rv-dispute-design.md 6.5)
// usage: node tpscmp.js <copy of a node's byteball.sqlite> <rolldevnet OUT json>
// needs the sqlite3 module: NODE_PATH=$AATK/node_modules or SQLITE3=<path to sqlite3 module>
// tps_fee = prepaid by the client at composition; actual_tps_fee = settled once stable (the excess stays as the
// address's tps-fee credit); count_aa_responses = AAs that actually responded; max_aa_responses = cap set by the client.
const sqlite3 = require(process.env.SQLITE3 || 'sqlite3');
const db = new sqlite3.Database(process.argv[2], sqlite3.OPEN_READONLY);
const run = require(require('path').resolve(process.argv[3]));
const q = (s, p = []) => new Promise((r, j) => db.all(s, p, (e, x) => e ? j(e) : r(x)));
const avg = a => a.length ? Math.round(a.reduce((x, y) => x + y, 0) / a.length) : 0;
const med = a => { const v = [...a].sort((x, y) => x - y); return v.length ? v[v.length >> 1] : 0; };
(async () => {
	const out = { mode: run.mode, byCmd: {}, total: {}, overCap: 0, underused: 0 };
	let allPaid = [], allActual = [];
	for (const [cmd, us] of Object.entries(run.units || {})) {
		const rows = await q(`SELECT unit, tps_fee, actual_tps_fee, max_aa_responses mar, count_aa_responses car, count_primary_aa_triggers trg
			FROM units WHERE unit IN (${us.map(() => '?').join(',')})`, us);
		const paid = rows.map(r => r.tps_fee || 0), act = rows.map(r => r.actual_tps_fee || 0);
		allPaid = allPaid.concat(paid); allActual = allActual.concat(act);
		const resp = {}; for (const r of rows) { const k = 'max ' + r.mar + ' / got ' + r.car; resp[k] = (resp[k] || 0) + 1;
			if (r.mar != null && r.car > r.mar) out.overCap++; if (r.mar != null && r.car != null && r.car < r.mar) out.underused++; }
		out.byCmd[cmd] = { n: rows.length, paid_avg: avg(paid), paid_median: med(paid), paid_max: Math.max(...paid), actual_avg: avg(act), actual_median: med(act), actual_max: Math.max(...act), responses: resp };
	}
	out.total = { n: allPaid.length, paid_sum: allPaid.reduce((x, y) => x + y, 0), actual_sum: allActual.reduce((x, y) => x + y, 0), paid_median: med(allPaid), actual_median: med(allActual) };
	console.log(JSON.stringify(out, null, 1));
	db.close();
})();
