// loop round 16 (step 4): guest-level MNWIT-S migration of a FULL-SIZE session, natively in sail-riscv (the JS
// model is too slow for a session at the caps). The `embed,prod,stateless` image (built with MNPILOT_IMPORT_DIGEST =
// the export digest) reads [SL_MIG_MAGIC, snapshot words] from a data ELF at 0x0300_0000; sail runs to the final
// `li a7,93` and dumps memory. Reported: sail instruction count (= rv32 steps), status, the migration root vs the
// host root (engine-diff slmigcap root.txt), SNAP_KIND / SNAP_N, heap high-water (OUT[12]) and peak live heap.
// usage: node migsail.js <rvengine-embed-mig.elf> <dir with mig.bin, root.txt> <workdir> [inst-limit]
const fs = require('fs'), path = require('path'), cp = require('child_process');
const { FastMem, load } = require('../js/elfrun.js');
const SAIL = process.env.SAIL || '/data/hark/spike-rv/xval/sail-riscv-0.16/build/c_emulator/sail_riscv_sim';
const CFG = process.env.SAILCFG || path.join(__dirname, 'rv32im-strict.json');
const [elf, dir, wd, lim] = process.argv.slice(2); fs.mkdirSync(wd, { recursive: true });
const data = fs.readFileSync(path.join(dir, 'mig.bin')); const ehs = 52, phs = 32, off = ehs + phs;
if (data.length > 0x00F00000) throw new Error('input above the embed region');
const eh = Buffer.alloc(ehs); eh.set([0x7f, 0x45, 0x4c, 0x46, 1, 1, 1, 0]); eh.writeUInt16LE(2, 16); eh.writeUInt16LE(243, 18); eh.writeUInt32LE(1, 20);
eh.writeUInt32LE(0x03000000, 24); eh.writeUInt32LE(ehs, 28); eh.writeUInt16LE(ehs, 40); eh.writeUInt16LE(phs, 42); eh.writeUInt16LE(1, 44); eh.writeUInt16LE(40, 46);
const ph = Buffer.alloc(phs); ph.writeUInt32LE(1, 0); ph.writeUInt32LE(off, 4); ph.writeUInt32LE(0x03000000, 8); ph.writeUInt32LE(0x03000000, 12);
ph.writeUInt32LE(data.length, 16); ph.writeUInt32LE(data.length, 20); ph.writeUInt32LE(6, 24); ph.writeUInt32LE(4, 28);
const dataElf = path.join(wd, 'input.elf'); fs.writeFileSync(dataElf, Buffer.concat([eh, ph, data]));
const mem = new FastMem(); const entry = load(elf, mem);
let stopPc = -1; for (let a = entry; a < entry + 64; a += 4) if (mem.get(a / 4) === 0x00000073) { stopPc = a - 4; break; }
const pre = path.join(wd, 'mem'); for (const f of fs.readdirSync(wd)) if (f.startsWith('mem')) fs.unlinkSync(path.join(wd, f));
const t1 = Date.now();
const r = cp.spawnSync(SAIL, ['--config', CFG, '--inst-limit', String(lim || 40000000000), '--stop-at-pc', '0x' + stopPc.toString(16), '--dump-memory', pre, '--show-times', elf, dataElf],
  { encoding: 'utf8', maxBuffer: 1 << 26 });
const sailMs = Date.now() - t1; const log = (r.stdout || '') + (r.stderr || '');
const OUTB = 0x03F00000; const want = [0, 8, 12, 0x1FFD6, 0x1FFD7, 0x1FFD8, 0x1FFE8, 0x1FFF0, 0x20000 - 6, 0x20000 - 7];
let words = null;
for (const f of fs.readdirSync(wd).filter(f => f.startsWith('mem'))) {
  const b = fs.readFileSync(path.join(wd, f)); const m = /0x([0-9a-f]+)/i.exec(f); const base = m ? parseInt(m[1], 16) : 0;
  if (base <= OUTB && base + b.length >= OUTB + 4 * 0x20000) { words = k => b.readUInt32LE(OUTB - base + 4 * k); }
}
const hx = k => { let s = ''; for (let i = 0; i < 8; i++) { const v = words(k + i) >>> 0; s += [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, v >>> 24].map(x => x.toString(16).padStart(2, '0')).join(''); } return s; };
const insn = /(\d+)\s+instructions?/i.exec(log) || /instructions?[^\d]*(\d+)/i.exec(log);
const hostRoot = fs.existsSync(path.join(dir, 'root.txt')) ? fs.readFileSync(path.join(dir, 'root.txt'), 'utf8').trim() : null;
const o = words ? { status: words(0x20000 - 7) >>> 0, root: hx(0), seg_start: hx(0x1FFF0), seg_end: hx(0x1FFE8), snap_kind: words(0x1FFD6) >>> 0, snap_n: words(0x1FFD7) >>> 0,
  heap_highwater: words(12) >>> 0, heap_peak_live: words(0x20000 - 6) >>> 0 } : null;
console.log(JSON.stringify({ ok: !!o && o.status === 0 && o.root === hostRoot && o.seg_start === hostRoot && o.seg_end === hostRoot && o.snap_kind === 3, ...o, host_root: hostRoot,
  input_words: data.length / 4, sail_insns: insn ? +insn[1] : null, sail_exit: r.status, sail_ms: sailMs, sail_log_tail: log.split('\n').slice(-6).join(' | ') }));
