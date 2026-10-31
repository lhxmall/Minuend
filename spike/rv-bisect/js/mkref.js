// builds aa/rv_game_ref.aa (referee mode) with the real rv_step address baked in
const fs=require('fs');
const OC = process.env.OCORE || '/workspace/projects/4ecc28f7-451e-450a-b62c-b8b357f0cc38/wt-aa/vendor/aa-testkit/node_modules/ocore';
const chashOf = src => { let a; require(OC + '/formula/parse_ojson').parse(src, (e, d) => { if (e) throw Error(e); a = require(OC + '/object_hash.js').getChash160(['autonomous agent', d[1]]); }); return a; };
const stepAddr = chashOf(fs.readFileSync(__dirname+'/../aa/rv_step.aa','utf8'));
const body=fs.readFileSync(__dirname+'/../aa/rv_game_ref.oscript','utf8').split('RV_STEP_AA_ADDRESS').join(stepAddr);
const state=`
	var[$st.k] = $st.v;
	if ($st.m) var['m_' || $gid] = $st.m;
	if ($d.resolve) var['m_' || $gid] = false;
	response['game'] = $st.v;
`;
const esc=s=>s.replace(/\\/g,'\\\\').replace(/`/g,'\\`');
const aa=`["autonomous agent", {
 bounce_fees: {base: 10000},
 init: \`{
${esc(body)}
}\`,
 messages: [
  {if: \`{$st.cb}\`, app: 'payment', payload: {asset: 'base', outputs: [{address: \`{$st.to}\`, amount: \`{$GB}\`}]}},
  {if: \`{$st.cb}\`, app: 'data', payload: \`{$st.cb}\`},
  {if: \`{$st.rf}\`, app: 'payment', payload: {asset: 'base', outputs: [{address: \`{trigger.address}\`, amount: \`{$st.rf}\`}]}},
  {app: 'state', state: \`{${esc(state)}}\`}
 ]
}]`;
fs.writeFileSync(__dirname+'/../aa/rv_game_ref.aa', aa);
const addr = chashOf(aa);
module.exports={body, state, stepAddr, addr, chashOf, keep: 2000};
