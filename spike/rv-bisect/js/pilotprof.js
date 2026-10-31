// Flat self-step profile of the mnpilot guest by ELF symbol (FUNC entries of .symtab).
// usage: node pilotprof.js <elf> <batch.bin> [top]
const ref = require('./ref.js'); const fs = require('fs'); const { FastMem, load } = require('./elfrun.js');
function syms(path) {
  const b = fs.readFileSync(path); const shoff = b.readUInt32LE(32), shes = b.readUInt16LE(46), shn = b.readUInt16LE(48);
  const sh = i => { const o = shoff + i * shes; return { type: b.readUInt32LE(o + 4), off: b.readUInt32LE(o + 16), size: b.readUInt32LE(o + 20), link: b.readUInt32LE(o + 24) }; };
  const out = [];
  for (let i = 0; i < shn; i++) { const s = sh(i); if (s.type !== 2) continue; const str = sh(s.link);
    for (let o = s.off; o < s.off + s.size; o += 16) { const nm = b.readUInt32LE(o), val = b.readUInt32LE(o + 4), sz = b.readUInt32LE(o + 8), info = b[o + 12];
      if ((info & 15) !== 2 || !sz) continue; let e = str.off + nm; while (b[e]) e++; out.push({ name: b.toString('latin1', str.off + nm, e), lo: val, hi: val + sz }); } }
  return out.sort((x, y) => x.lo - y.lo);
}
const [elf, batch, top] = process.argv.slice(2); const S = syms(elf);
const find = pc => { let l = 0, h = S.length - 1; while (l <= h) { const m = (l + h) >> 1; if (pc < S[m].lo) h = m - 1; else if (pc >= S[m].hi) l = m + 1; else return m; } return -1; };
const b = fs.readFileSync(batch); const inp = new FastMem(); for (let i = 0; i < b.length / 4; i++) inp.set(i, b.readUInt32LE(4 * i));
const mem = new FastMem(); const st = { pc: load(elf, mem), regs: Array(32).fill(0), step: 0, inp }; const cnt = new Map(); const calls = new Map();
while (st.pc !== ref.HALT && st.pc !== ref.TRAP) { const k = find(st.pc); cnt.set(k, (cnt.get(k) || 0) + 1); if (k >= 0 && st.pc === S[k].lo) calls.set(k, (calls.get(k) || 0) + 1); ref.step(st, mem); }
const rows = [...cnt].sort((a, b) => b[1] - a[1]).slice(0, +(top || 25));
console.log(`total ${st.step} steps, ${S.length} symbols`);
for (const [k, c] of rows) console.log(String(c).padStart(11), (100 * c / st.step).toFixed(1).padStart(5) + '%', String(calls.get(k) || 0).padStart(8) + ' calls', k < 0 ? '?' : S[k].name.slice(0, 140));
