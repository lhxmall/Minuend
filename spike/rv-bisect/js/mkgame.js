const fs=require('fs');
const body=fs.readFileSync(__dirname+'/../aa/rv_game.oscript','utf8');
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
  {if: \`{$st.pay}\`, app: 'payment', payload: {asset: 'base', outputs: [{address: \`{$st.pay}\`, amount: \`{$d.finalize ? $BOND : 2 * $BOND - 2000}\`}]}},
  {app: 'state', state: \`{${esc(state)}}\`}
 ]
}]`;
fs.writeFileSync(__dirname+'/../aa/rv_game.aa', aa);
module.exports={body, state};
