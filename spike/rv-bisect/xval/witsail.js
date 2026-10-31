// MNWIT1 variant of pilotsail.js: also compares the witness words (OUT+0x1FFFB..0x1FFFF: node hashes,
// leaf updates, leaves, scratch_ok, unit count) and every per-unit root (OUT+0x20000, 8 words/unit).
// Spot-check of the mnpilot guest against sail-riscv: the `embed` build reads the batch from a
// data ELF at 0x0300_0000; sail runs to the final `li a7,93` in _start (--stop-at-pc) and dumps
// memory; the JS model runs the same two ELFs. Compared: instruction count, result words OUT[0..13+nev]
// and the hash vs the expected (real engine) hash.
// usage: node pilotsail.js <rvengine-embed.elf> <batch.bin> <workdir> [expected_hash]
const fs = require('fs'), path = require('path'), cp = require('child_process');
const ref = require('../js/ref.js'); const { FastMem, load } = require('../js/elfrun.js');
const SAIL = process.env.SAIL || '/data/hark/spike-rv/xval/sail-riscv-0.16/build/c_emulator/sail_riscv_sim';
const CFG = process.env.SAILCFG || path.join(__dirname, 'rv32im-strict.json');
const [elf, batch, wd, expect] = process.argv.slice(2); fs.mkdirSync(wd, { recursive: true });
// data ELF (one PT_LOAD at 0x03000000, no entry use)
const data = fs.readFileSync(batch); const ehs = 52, phs = 32, off = ehs + phs;
const eh = Buffer.alloc(ehs); eh.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1, 0]); eh.writeUInt16LE(2, 16); eh.writeUInt16LE(243, 18); eh.writeUInt32LE(1, 20);
eh.writeUInt32LE(0x03000000, 24); eh.writeUInt32LE(ehs, 28); eh.writeUInt16LE(ehs, 40); eh.writeUInt16LE(phs, 42); eh.writeUInt16LE(1, 44); eh.writeUInt16LE(40, 46);
const ph = Buffer.alloc(phs); ph.writeUInt32LE(1, 0); ph.writeUInt32LE(off, 4); ph.writeUInt32LE(0x03000000, 8); ph.writeUInt32LE(0x03000000, 12);
ph.writeUInt32LE(data.length, 16); ph.writeUInt32LE(data.length, 20); ph.writeUInt32LE(6, 24); ph.writeUInt32LE(4, 28);
const dataElf = path.join(wd, 'input.elf'); fs.writeFileSync(dataElf, Buffer.concat([eh, ph, data]));
// JS model
const mem = new FastMem(); const entry = load(elf, mem); load(dataElf, mem);
let stopPc = -1; for (let a = entry; a < entry + 64; a += 4) if (mem.get(a / 4) === 0x00000073) { stopPc = a - 4; break; }  // li a7,93 before the ecall
const st = { pc: entry, regs: Array(32).fill(0), step: 0, inp: new FastMem() }; const t0 = Date.now();
while (st.pc !== stopPc && st.pc !== ref.HALT && st.pc !== ref.TRAP) ref.step(st, mem);
const jsSteps = st.step, jsMs = Date.now() - t0;
const OUT = 0x03F00000 / 4; const nev = mem.get(OUT + 8); const units = mem.get(OUT + 0x1FFFF) >>> 0;
const idx = []; for (let k = 0; k < 13 + nev; k++) idx.push(k); for (let k = 0x1FFF8; k < 0x20000 + 8 * units; k++) idx.push(k); // loop1: +status/peak/ev-overflow words
const jsOut = idx.map(k => mem.get(OUT + k) >>> 0);
// sail
const pre = path.join(wd, 'mem'); const t1 = Date.now();
const r = cp.spawnSync(SAIL, ['--config', CFG, '--inst-limit', String(jsSteps + 1000), '--stop-at-pc', '0x' + stopPc.toString(16), '--dump-memory', pre, '--show-times', elf, dataElf],
  { encoding: 'utf8', maxBuffer: 1 << 26 });
const sailMs = Date.now() - t1; const log = (r.stdout || '') + (r.stderr || '');
const dumps = fs.readdirSync(wd).filter(f => f.startsWith('mem')); let sailOut = null;
for (const f of dumps) { const b = fs.readFileSync(path.join(wd, f)); const m = /0x([0-9a-f]+)/i.exec(f);   // region dump, name carries base
  const base = m ? parseInt(m[1], 16) : 0; if (base <= 0x03F00000 && base + b.length > 0x03F00000 + 4 * (0x20000 + 8 * units)) {
    sailOut = idx.map(k => b.readUInt32LE(0x03F00000 - base + 4 * k)); } }
const insn = /(\d+)\s+instructions?/i.exec(log) || /instructions?[^\d]*(\d+)/i.exec(log);
const hash = jsOut.slice(0, 8).map(v => [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, v >>> 24].map(x => x.toString(16).padStart(2, '0')).join('')).join('');
const finalRoot = units ? jsOut.slice(jsOut.length - 8).map(v => [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, v >>> 24].map(x => x.toString(16).padStart(2, '0')).join('')).join('') : null;
console.log(JSON.stringify({ units, final_root: finalRoot, scratch_ok: jsOut[13 + nev + 6], status: jsOut[13 + nev + 1], heap_peak_live: jsOut[13 + nev + 2], heap: jsOut[12], js_steps_to_stop: jsSteps, sail_insns: insn ? +insn[1] : null, out_words: jsOut.length,
  out_match: sailOut ? JSON.stringify(sailOut) === JSON.stringify(jsOut) : null, hash, hash_vs_expected: expect ? hash === expect : null,
  dumps, sail_exit: r.status, js_ms: jsMs, sail_ms: sailMs, sail_log_tail: log.split('\n').slice(-8).join(' | ') }));
