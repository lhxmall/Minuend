// builds aa/rv_seg_ref.aa (layer-1 referee, loop round 3) with the real rv_game_ref address baked in
const fs = require('fs'); const R = require('./mkref.js');
const body = fs.readFileSync(__dirname + '/../aa/rv_seg_ref.oscript', 'utf8').split('RV_GAME_AA_ADDRESS').join(R.addr);
const state = `
	var[$st.k] = $st.v;
	if ($st.m) { var['m_' || $gid] = $st.m; var['n_' || $gid] = $st.ms; }
	if ($st.call) var['x_' || $st.call.open] = $st.xg;
	if ($st.cb) { var['m_' || $gid] = false; var['n_' || $gid] = false; }
	response['game'] = $st.v;
`;
const esc = s => s.replace(/\\/g, '\\\\').replace(/`/g, '\\`');
const aa = `["autonomous agent", {
 bounce_fees: {base: 10000},
 init: \`{
${esc(body)}
}\`,
 messages: [
  {if: \`{$st.call}\`, app: 'payment', payload: {asset: 'base', outputs: [{address: \`{$GAME}\`, amount: \`{$GF}\`}]}},
  {if: \`{$st.call}\`, app: 'data', payload: \`{$st.call}\`},
  {if: \`{$st.cb}\`, app: 'payment', payload: {asset: 'base', outputs: [{address: \`{$st.to}\`, amount: \`{$GB}\`}]}},
  {if: \`{$st.cb}\`, app: 'data', payload: \`{$st.cb}\`},
  {if: \`{$st.rf}\`, app: 'payment', payload: {asset: 'base', outputs: [{address: \`{trigger.address}\`, amount: \`{$st.rf}\`}]}},
  {app: 'state', state: \`{${esc(state)}}\`}
 ]
}]`;
fs.writeFileSync(__dirname + '/../aa/rv_seg_ref.aa', aa);
module.exports = { body, state, addr: R.chashOf(aa), gameAddr: R.addr };
