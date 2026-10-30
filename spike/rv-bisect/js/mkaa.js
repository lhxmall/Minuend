// wrap an .oscript init body into an AA definition (ojson) that memoizes var['s_'||$pre] = $post
const fs=require('fs');
function aa(body, extraState=''){ const esc=body.replace(/\\/g,'\\\\').replace(/`/g,'\\`');
 return `["autonomous agent", {\n bounce_fees: {base: 10000},\n init: \`{\n${esc}\n}\`,\n messages: [{app: 'state', state: \`{ var['s_' || $pre] = $post; response['post'] = $post; ${extraState} }\`}]\n}]`; }
module.exports={aa};
if (require.main===module){ fs.writeFileSync(process.argv[3], aa(fs.readFileSync(process.argv[2],'utf8'))); }
