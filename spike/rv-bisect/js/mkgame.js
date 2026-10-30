const fs=require('fs');
// the game reads the one-step memo from the rv_step AA: substitute its real address (chash160 of rv_step.aa)
const OC = process.env.OCORE || '/workspace/projects/4ecc28f7-451e-450a-b62c-b8b357f0cc38/wt-aa/vendor/aa-testkit/node_modules/ocore';
let stepAddr; require(OC + '/formula/parse_ojson').parse(fs.readFileSync(__dirname+'/../aa/rv_step.aa','utf8'), (e, d) => { if (e) throw Error(e); stepAddr = require(OC + '/object_hash.js').getChash160(d); });
const body=fs.readFileSync(__dirname+'/../aa/rv_game.oscript','utf8').split('RV_STEP_AA_ADDRESS').join(stepAddr);
const state=`
	var[$st.k] = $st.v;
	if ($st.m) var['m_' || $gid] = $st.m;
	if ($d.open) var['n_' || $st.cid] += 1;
	if ($d.resolve) {
		var['m_' || $gid] = false;
		if ($st.fraud) var['f_' || $st.cid] = 1;
		else var['n_' || $st.cid] -= 1;
	}
	response['game'] = $st.v;
`;
const esc=s=>s.replace(/\\/g,'\\\\').replace(/`/g,'\\`');
const aa=`["autonomous agent", {
 bounce_fees: {base: 10000},
 init: \`{
${esc(body)}
}\`,
 messages: [
  {if: \`{$st.pay}\`, app: 'payment', payload: {asset: 'base', outputs: [{address: \`{$st.pay}\`, amount: \`{$st.amt}\`}]}},
  {app: 'state', state: \`{${esc(state)}}\`}
 ]
}]`;
fs.writeFileSync(__dirname+'/../aa/rv_game.aa', aa);
module.exports={body, state, stepAddr};
