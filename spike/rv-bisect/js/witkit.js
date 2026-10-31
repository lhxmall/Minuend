// loop round 3: helpers for rv_witbind / rv_witproof tests. The guest (feature prod) writes the MNWIT1 segment end root
// at OUT[0x1FFE8..8] (8 little-endian u32 words = the 32 root bytes) and the status at OUT[0x1FFF9].
'use strict';
const ref = require('./ref.js');
const OUTW = 0x03F00000 / 4 + 0x1FFE8, STW = 0x03F00000 / 4 + 0x1FFF9;
const rootWords = b64 => { const b = Buffer.from(b64, 'base64'); return Array.from({ length: 8 }, (_, k) => b.readUInt32LE(4 * k)); };
const wordsRoot = ws => { const b = Buffer.alloc(32); ws.forEach((w, k) => b.writeUInt32LE(w >>> 0, 4 * k)); return b.toString('base64'); };
// a memory image with the root (and status) at the guest's OUT slots, plus some unrelated words
function memWithRoot(b64, status = 0, extra = {}) { const m = new ref.Mem(); rootWords(b64).forEach((w, k) => m.set(OUTW + k, w)); if (status) m.set(STW, status);
  for (const i in extra) m.set(+i, extra[i]); m.root(); return m; }
const bindData = (m, h) => ({ bind: h, words: Array.from({ length: 8 }, (_, k) => m.get(OUTW + k)), wsib: Array.from({ length: 8 }, (_, k) => m.proof(OUTW + k)), ssib: m.proof(STW) });
module.exports = { OUTW, STW, rootWords, wordsRoot, memWithRoot, bindData };
