// tps-fee diagnosis for an aa-testkit devnet run (see docs/rv-dispute-design.md 6.4)
// usage: node tpsdiag.js <copy of a node's byteball.sqlite> [threshold=5000]
// needs the sqlite3 module: NODE_PATH=$AATK/node_modules or SQLITE3=<path to sqlite3 module>
const sqlite3 = require(process.env.SQLITE3 || 'sqlite3');
const db = new sqlite3.Database(process.argv[2], sqlite3.OPEN_READONLY);
const TH = +(process.argv[3] || 5000);
const q = (s, p = []) => new Promise((r, j) => db.all(s, p, (e, x) => e ? j(e) : r(x)));
(async () => {
	// units whose prepaid tps_fee is large; el = unit timestamp - last ball timestamp (ocore uses 1 s when it is 0)
	const big = await q(`SELECT u.unit, u.main_chain_index mci, u.tps_fee, u.actual_tps_fee, u.count_primary_aa_triggers trg,
		u.max_aa_responses mar, u.headers_commission + u.payload_commission sz, u.timestamp - l.timestamp el,
		(SELECT address FROM unit_authors a WHERE a.unit = u.unit LIMIT 1) author
		FROM units u JOIN units l ON l.unit = u.last_ball_unit WHERE u.tps_fee > ? ORDER BY u.rowid`, [TH]);
	console.log('large prepaid tps_fee (' + big.length + '):');
	for (const b of big) console.log(' ', JSON.stringify(b));
	const hist = await q(`SELECT u.timestamp - l.timestamp el, count(*) n FROM units u JOIN units l ON l.unit = u.last_ball_unit
		WHERE u.is_aa_response IS NULL GROUP BY el ORDER BY el`);
	console.log('elapsed (s) histogram of non-AA units:', JSON.stringify(hist));
	const tot = await q(`SELECT count(*) n, sum(tps_fee) paid, sum(actual_tps_fee) actual FROM units WHERE is_aa_response IS NULL AND tps_fee IS NOT NULL`);
	console.log('totals:', JSON.stringify(tot[0]));
	// last tps_fees_balance per author of a large unit: the prepayment stays as credit for later units
	for (const a of [...new Set(big.map(b => b.author))]) {
		const [row] = await q('SELECT tps_fees_balance, mci FROM tps_fees_balances WHERE address = ? ORDER BY rowid DESC LIMIT 1', [a]);
		const us = await q(`SELECT u.tps_fee FROM unit_authors a JOIN units u USING(unit) WHERE a.address = ? ORDER BY u.rowid`, [a]);
		console.log(' ', a, 'units', us.length, 'paid', us.map(x => x.tps_fee).join(','), 'balance', JSON.stringify(row));
	}
	db.close();
})();
