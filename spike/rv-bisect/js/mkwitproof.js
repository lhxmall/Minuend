// builds aa/rv_witbind.aa (rv_rollup address baked in) and aa/rv_witproof.aa (rv_witbind address baked in), loop round 3
const fs = require('fs'); const M = require('./mkrollup.js');
const esc = s => s.replace(/\\/g, '\\\\').replace(/`/g, '\\`');
const state = `
	var[$st.k] = $st.v;
	response['proven'] = $st.k;
`;
const mk = (name, body) => { const aa = `["autonomous agent", {
 bounce_fees: {base: 10000},
 init: \`{
${esc(body)}
}\`,
 messages: [
  {app: 'state', state: \`{${esc(state)}}\`}
 ]
}]`; fs.writeFileSync(__dirname + '/../aa/' + name + '.aa', aa); return { body, state, addr: M.ref.chashOf(aa) }; };
const bind = mk('rv_witbind', fs.readFileSync(__dirname + '/../aa/rv_witbind.oscript', 'utf8').split('RV_ROLLUP_AA_ADDRESS').join(M.addr));
const proof = mk('rv_witproof', fs.readFileSync(__dirname + '/../aa/rv_witproof.oscript', 'utf8').split('RV_WITBIND_AA_ADDRESS').join(bind.addr));
module.exports = { bind, proof, rollAddr: M.addr };
