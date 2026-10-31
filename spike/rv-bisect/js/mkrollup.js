// builds aa/rv_rollup.aa with the referee address and a genesis memory root baked in
// GENMEM env (default: the memory root of the rolltrace.js test program image)
const fs=require('fs'); const R=require('./mkref.js'); const SR=require('./mksegref.js');
let genMem = process.env.GENMEM;
if (!genMem) genMem = require('./rolltrace.js').genesis().root();
// loop round 4: GOV env = governance address allowed to schedule upgrades (default: a fixed test address)
const govAddr = process.env.GOV || 'GOVXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
const body=fs.readFileSync(__dirname+'/../aa/rv_rollup.oscript','utf8').split('RV_GOV_ADDRESS').join(govAddr).split('RV_GAME_AA_ADDRESS').join(R.addr).split('RV_SEG_AA_ADDRESS').join(SR.addr).split('GENESIS_MEM_ROOT').join(genMem);
const state=`
	if ($d.submit) {
		var['top'] = $st.h;
		var['h' || $st.h] = $st.sid;
		var['s' || $st.sid] = $st.rec;
		var['m' || $st.sid] = $d.fmem;
		var['u' || $st.sid] = $d.units;
		response['sid'] = $st.sid;
	}
	else if ($d.open OR $d.uopen) {
		var['G' || trigger.unit] = $st.g;
		var['n' || $st.sid] += 1;
		response['game'] = $st.to || trigger.unit;
	}
	else if ($d.finalize) {
		var['lf'] = $d.finalize;
		var['r' || $st.sid] = 'F';
	}
	else if ($d.reclaim) var['r' || $st.sid] = 'R';
	else if ($d.upgrade) {
		if ($st.clr) var['U' || $st.clr] = false;   // loop round 5 (R5-M1)
		var['U' || $st.up] = $d.mem;
		var['uh'] = $st.up;
		var['top'] = $st.up - 1;
		response['upgrade'] = $st.up;
	}
	else if ($st.xb) {
		var['x' || $st.xb] = $st.v;
		response['xbind'] = $st.v;
	}
	else {
		var['G' || $ref] = $st.sid || ':' || $g[1] || ':' || $d.w;
		var['n' || $st.sid] -= 1;
		if ($st.fraud) var['f' || $st.sid] = 1;
		if ($st.first) var['burned'] += $OBOND - $OBOND / 2;
		if ($st.void) var['top'] = $st.h - 1;
		response['result'] = $d.w;
	}
`;
const esc=s=>s.replace(/\\/g,'\\\\').replace(/`/g,'\\`');
const aa=`["autonomous agent", {
 bounce_fees: {base: 10000},
 init: \`{
${esc(body)}
}\`,
 messages: [
  {if: \`{$st.call}\`, app: 'payment', payload: {asset: 'base', outputs: [{address: \`{$st.to}\`, amount: \`{$st.gf}\`}]}},
  {if: \`{$st.call}\`, app: 'data', payload: \`{$st.call}\`},
  {if: \`{$st.rf}\`, app: 'payment', payload: {asset: 'base', outputs: [{address: \`{trigger.address}\`, amount: \`{$st.rf}\`}]}},
  {if: \`{$st.pay}\`, app: 'payment', payload: {asset: 'base', outputs: [{address: \`{$st.pay}\`, amount: \`{$st.amt}\`}]}},
  {app: 'state', state: \`{${esc(state)}}\`}
 ]
}]`;
fs.writeFileSync(__dirname+'/../aa/rv_rollup.aa', aa);
module.exports={body, state, govAddr, gameAddr: R.addr, stepAddr: R.stepAddr, genMem, addr: R.chashOf(aa), ref: R, seg: SR, segAddr: SR.addr};
