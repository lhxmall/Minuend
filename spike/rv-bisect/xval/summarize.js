// Merge the summary lines of several xfuzz / xtests logs.   usage: node summarize.js log1 log2 ...
'use strict';
const fs = require('fs'); const T = {}; const add = (o, k, v) => { o[k] = (o[k] || 0) + v; };
const fails = [];
for (const f of process.argv.slice(2)) for (const line of fs.readFileSync(f, 'utf8').split('\n')) {
  if (!line.startsWith('{')) continue; let j; try { j = JSON.parse(line); } catch (e) { continue; }
  if (j.bad) fails.push({ f, ...j });
  const s = j.summary; if (!s) continue;
  for (const [k, v] of Object.entries(s)) {
    if (typeof v === 'number' && !['shard', 'shards'].includes(k)) add(T, k, v);
    else if (v && typeof v === 'object') { T[k] = T[k] || {}; for (const [a, b] of Object.entries(v)) add(T[k], a, b); }
  }
}
if (T.mn) T.mnemonicsCovered = Object.keys(T.mn).length;
console.log(JSON.stringify({ total: T, failures: fails.slice(0, 20), nFailures: fails.length }, null, 1));
