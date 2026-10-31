// loop round 10: static opcode scan of a guest ELF against the rv_step / ref.js instruction set.
// Every 32-bit word of every executable section is classified as ref.js `step` would decode it; words that would
// trap (outside RV32IM-as-modelled, e.g. fence / csr / misencoded funct fields) are listed with their address and
// whether a direct branch / jal in the scanned code targets them or they follow a non-terminal instruction
// (= reachable by fall-through). usage: node opscan.js <elf> [<elf> ...]
'use strict';
const fs = require('fs');
function sections(b) {
  if (b.readUInt32BE(0) !== 0x7f454c46 || b[4] !== 1) throw new Error('not ELF32');
  const shoff = b.readUInt32LE(32), shentsize = b.readUInt16LE(46), shnum = b.readUInt16LE(48), shstrndx = b.readUInt16LE(50);
  const sh = i => { const o = shoff + i * shentsize; return { name: b.readUInt32LE(o), type: b.readUInt32LE(o + 4), flags: b.readUInt32LE(o + 8), addr: b.readUInt32LE(o + 12), off: b.readUInt32LE(o + 16), size: b.readUInt32LE(o + 20) }; };
  const str = sh(shstrndx); const nm = o => { let e = str.off + o; while (b[e]) e++; return b.toString('latin1', str.off + o, e); };
  return Array.from({ length: shnum }, (_, i) => sh(i)).map(s => ({ ...s, name: nm(s.name) }));
}
const sx = (v, n) => (v << (32 - n)) >> (32 - n);
function cls(w) {
  const op = w & 127, f3 = (w >>> 12) & 7, f7 = w >>> 25;
  if (op === 0x33 && f7 === 1) return 'mul';
  if (op === 0x33) return (f7 === 0 || (f7 === 0x20 && (f3 === 0 || f3 === 5))) ? 'alu' : null;
  if (op === 0x13) { if (f3 === 1 && f7 !== 0) return null; if (f3 === 5 && !(f7 === 0 || f7 === 0x20)) return null; return 'alu'; }
  if (op === 0x37 || op === 0x17 || op === 0x6f) return 'ctl';
  if (op === 0x67) return f3 ? null : 'jalr';
  if (op === 0x63) return (f3 === 2 || f3 === 3) ? null : 'br';
  if (op === 0x03) return [1, 2, 4, 0, 1, 2, 0, 0][f3] ? 'ld' : null;
  if (op === 0x23) return f3 <= 2 ? 'st' : null;
  if (op === 0x73) return w === 0x73 ? 'ecall' : null;
  return null;
}
for (const f of process.argv.slice(2)) {
  const b = fs.readFileSync(f); const ex = sections(b).filter(s => s.flags & 4 && s.type === 1);
  const words = new Map(); for (const s of ex) for (let k = 0; k + 4 <= s.size; k += 4) words.set(s.addr + k, b.readUInt32LE(s.off + k));
  const targets = new Set(); const kinds = {};
  for (const [a, w] of words) { const c = cls(w); kinds[c || 'TRAP'] = (kinds[c || 'TRAP'] || 0) + 1;
    if (c === 'ctl' && (w & 127) === 0x6f) targets.add((a + sx(((w >>> 31) << 20) | (((w >>> 12) & 255) << 12) | (((w >>> 20) & 1) << 11) | (((w >>> 21) & 1023) << 1), 21)) >>> 0);
    if (c === 'br') targets.add((a + sx(((w >>> 31) << 12) | (((w >>> 7) & 1) << 11) | (((w >>> 25) & 63) << 5) | (((w >>> 8) & 15) << 1), 13)) >>> 0); }
  const bad = [];
  for (const [a, w] of words) { if (cls(w)) continue; const p = words.get(a - 4); const pc = p === undefined ? null : cls(p);
    const fall = pc && !(pc === 'jalr' || (pc === 'ctl' && (p & 127) === 0x6f) || pc === 'ecall'); // ecall a7=93 halts; others continue (input read)
    bad.push({ addr: '0x' + a.toString(16), word: '0x' + (w >>> 0).toString(16).padStart(8, '0'), target: targets.has(a), fallthrough: !!fall }); }
  const live = bad.filter(x => x.target || x.fallthrough);
  console.log(JSON.stringify({ elf: f, text_words: words.size, sections: ex.map(s => s.name), kinds, trap_words: bad.length, reachable_trap_words: live.length, reachable: live.slice(0, 20), unreached_sample: bad.filter(x => !(x.target || x.fallthrough)).slice(0, 5) }));
}
