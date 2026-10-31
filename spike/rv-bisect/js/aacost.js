// static ocore cost of every rollup AA (complexity / ops; limits 100 / 2000)
const { validate } = require('./oc.js'); const fs = require('fs');
require('./mkwitproof.js');
(async () => { const out = {};
  for (const f of ['rv_step', 'rv_game_ref', 'rv_seg_ref', 'rv_rollup', 'rv_witbind', 'rv_witproof']) { const r = await validate(fs.readFileSync(__dirname + '/../aa/' + f + '.aa', 'utf8'));
    out[f] = r.err ? String(r.err).slice(0, 200) : { complexity: r.complexity, ops: r.count_ops }; }
  console.log('AACOST ' + JSON.stringify(out)); process.exit(0); })();
