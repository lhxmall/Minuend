// Reference rv32im single-step semantics + sparse word-Merkle memory (Obyte merkle hashing).
// This is the "off-chain" model the Oscript one-step AAs must match bit-for-bit.
'use strict';
const crypto = require('crypto');
const H = s => crypto.createHash('sha256').update(s, 'utf8').digest('base64');
const D = +(process.env.MEM_DEPTH || 24);            // memory = 2^D words (D=24 -> 64 MiB)
const Z = [H('0')]; for (let i = 0; i < 64; i++) Z.push(H(Z[i] + Z[i]));
const TRAP = 1, HALT = 2;                             // pc sentinels (pc % 4 != 0 => no-op steps)
const M32 = 2 ** 32;

class Mem {
  constructor() { this.w = new Map(); this.nodes = null; }
  get(i) { return this.w.get(i) || 0; }
  set(i, v) { if (v) this.w.set(i, v >>> 0); else this.w.delete(i);
    if (!this.nodes) return;                       // incremental path update once built
    const L = this.nodes; let k = i; if (v) L[0].set(k, H(String(v >>> 0))); else L[0].delete(k);
    for (let l = 0; l < D; l++) { const p = Math.floor(k / 2); const a = L[l].get(2 * p) || Z[l], b = L[l].get(2 * p + 1) || Z[l];
      const h = H(a + b); if (h === Z[l + 1]) L[l + 1].delete(p); else L[l + 1].set(p, h); k = p; } }
  build() { // levels: Map index->hash for non-zero subtrees
    const L = [new Map()]; for (const [i, v] of this.w) L[0].set(i, H(String(v)));
    for (let l = 0; l < D; l++) { const n = new Map();
      for (const i of L[l].keys()) { const p = Math.floor(i / 2); if (n.has(p)) continue;
        const a = L[l].get(2 * p) || Z[l], b = L[l].get(2 * p + 1) || Z[l]; n.set(p, H(a + b)); }
      L.push(n); }
    this.nodes = L; }
  root() { if (!this.nodes) this.build(); return this.nodes[D].get(0) || Z[D]; }
  proof(i) { if (!this.nodes) this.build(); const s = []; let k = i;
    for (let l = 0; l < D; l++) { s.push(this.nodes[l].get(k ^ 1) || Z[l]); k = Math.floor(k / 2); } return s; }
}
const sx = (v, bits) => (v & (1 << (bits - 1))) ? v - 2 ** bits : v;   // sign-extend
const s32 = v => v | 0, u32 = v => v >>> 0;

function stateRoot(st, mem) { return H(st.pc + ':' + st.regs.join(',') + ':' + mem.root() + ':' + (st.inp ? st.inp.root() : Z[D]) + ':' + st.step); }

// one step; returns {kind, w, addr?} witness info and mutates st/mem
function step(st, mem) {
  const wit = { pc: st.pc, regs: st.regs.join(','), mem_root: mem.root(), step: st.step };
  const R = st.regs; const done = () => { st.step++; R[0] = 0; return wit; };
  if (st.pc % 4 !== 0) { wit.kind = 'noop'; return done(); }
  if (st.pc >= 4 * 2 ** D) { st.pc = TRAP; wit.kind = 'trap'; return done(); }
  const wi = st.pc / 4; const w = mem.get(wi); wit.w = w; wit.wsib = mem.proof(wi);
  const op = w & 127, rd = (w >>> 7) & 31, f3 = (w >>> 12) & 7, rs1 = (w >>> 15) & 31, rs2 = (w >>> 20) & 31, f7 = w >>> 25;
  const a = R[rs1], b = R[rs2]; let npc = u32(st.pc + 4); const wr = v => { if (rd) R[rd] = u32(v); };
  const immI = sx(w >>> 20, 12), immS = sx(((w >>> 25) << 5) | ((w >>> 7) & 31), 12);
  const immB = sx(((w >>> 31) << 12) | (((w >>> 7) & 1) << 11) | (((w >>> 25) & 63) << 5) | (((w >>> 8) & 15) << 1), 13);
  const immU = (w >>> 12) * 4096, immJ = sx(((w >>> 31) << 20) | (((w >>> 12) & 255) << 12) | (((w >>> 20) & 1) << 11) | (((w >>> 21) & 1023) << 1), 21);
  const trap = () => { st.pc = TRAP; wit.kind = wit.kind || 'trap'; return done(); };
  const jumpTo = t => { t = u32(t); if (t % 4) return false; npc = t; return true; };
  if (op === 0x33 && f7 === 1) { wit.kind = 'mul'; // M extension
    const A = BigInt(a), B = BigInt(b), As = BigInt(s32(a)), Bs = BigInt(s32(b)); let r;
    switch (f3) { case 0: r = A * B; break; case 1: r = (As * Bs) >> 32n; break; case 2: r = (As * B) >> 32n; break; case 3: r = (A * B) >> 32n; break;
      case 4: r = b === 0 ? -1n : (s32(a) === -M32 / 2 && s32(b) === -1) ? As : As / Bs; break;
      case 5: r = b === 0 ? 0xffffffffn : A / B; break;
      case 6: r = b === 0 ? As : (s32(a) === -M32 / 2 && s32(b) === -1) ? 0n : As % Bs; break;
      case 7: r = b === 0 ? A : A % B; break; }
    wr(Number(BigInt.asUintN(32, r)));
  } else if (op === 0x33 || op === 0x13) { wit.kind = 'alu';
    const imm = op === 0x13; const B2 = imm ? u32(immI) : b; const sh = B2 & 31; const alt = imm ? (f3 === 5 && (w >>> 30) & 1) : (f7 === 0x20);
    if (!imm && !(f7 === 0 || (f7 === 0x20 && (f3 === 0 || f3 === 5)))) return trap();
    if (imm && f3 === 1 && f7 !== 0) return trap();
    if (imm && f3 === 5 && !(f7 === 0 || f7 === 0x20)) return trap();
    switch (f3) { case 0: wr(alt && !imm ? a - B2 : a + B2); break; case 1: wr(a << sh); break;
      case 2: wr(s32(a) < s32(B2) ? 1 : 0); break; case 3: wr(a < B2 ? 1 : 0); break; case 4: wr(a ^ B2); break;
      case 5: wr(alt ? s32(a) >> sh : a >>> sh); break; case 6: wr(a | B2); break; case 7: wr(a & B2); break; }
  } else if (op === 0x37) { wit.kind = 'ctl'; wr(immU); }
  else if (op === 0x17) { wit.kind = 'ctl'; wr(st.pc + immU); }
  else if (op === 0x6f) { wit.kind = 'ctl'; const ret = st.pc + 4; if (!jumpTo(st.pc + immJ)) return trap(); wr(ret); }
  else if (op === 0x67) { wit.kind = 'ctl'; if (f3) return trap(); const ret = st.pc + 4; if (!jumpTo((a + immI) & ~1)) return trap(); wr(ret); }
  else if (op === 0x63) { wit.kind = 'ctl'; let c;
    switch (f3) { case 0: c = a === b; break; case 1: c = a !== b; break; case 4: c = s32(a) < s32(b); break; case 5: c = s32(a) >= s32(b); break;
      case 6: c = a < b; break; case 7: c = a >= b; break; default: return trap(); }
    if (c && !jumpTo(st.pc + immB)) return trap(); }
  else if (op === 0x03 || op === 0x23) { wit.kind = 'mem'; const isS = op === 0x23; const ea = u32(a + (isS ? immS : immI));
    const size = [1, 2, 4, 0, 1, 2, 0, 0][f3]; if (!size || (isS && f3 > 2)) return trap(); if (ea % size) return trap();
    const wa = Math.floor(ea / 4); if (wa >= 2 ** D) return trap(); const off = ea % 4; const old = mem.get(wa); wit.mword = old; wit.msib = mem.proof(wa);
    if (isS) { const mask = size === 4 ? M32 - 1 : (2 ** (8 * size) - 1) * 2 ** (8 * off); const v = (b % 2 ** (8 * size)) * 2 ** (8 * off);
      mem.set(wa, u32(old - ((old & mask) >>> 0) + v)); // (old & mask) only on the size bytes
    } else { let v = Math.floor(old / 2 ** (8 * off)) % 2 ** (8 * size); if (f3 < 3 && size < 4) v = sx(v, 8 * size); wr(v); } }
  else if (op === 0x73) { wit.kind = 'sys'; // ecall: a7=93 exit -> HALT ; anything else -> trap (input read omitted in spike)
    if (w === 0x00000073 && R[17] === 93) { st.pc = HALT; return done(); }
    if (w === 0x00000073 && R[17] === 63 && R[10] < 2 ** D) { const inp = st.inp || new Mem(); wit.iw = inp.get(R[10]); wit.isib = inp.proof(R[10]); R[10] = wit.iw; }
    else return trap(); }
  else return trap();
  st.pc = npc; return done();
}
module.exports = { H, D, Z, Mem, step, stateRoot, TRAP, HALT };
