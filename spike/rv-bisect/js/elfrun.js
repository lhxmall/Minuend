// Load an rv32 ELF into the reference emulator (fast mode: no Merkle) and count executed instructions.
const ref=require('./ref.js'); const fs=require('fs');
class FastMem { constructor(){ this.w=new Map(); } get(i){ return this.w.get(i)||0; } set(i,v){ this.w.set(i, v>>>0); } root(){ return ''; } proof(){ return null; } }
function load(path, mem){ const b=fs.readFileSync(path); const e=b.readUInt32LE(24), phoff=b.readUInt32LE(28), phn=b.readUInt16LE(44), phs=b.readUInt16LE(42);
  for(let i=0;i<phn;i++){ const o=phoff+i*phs; if(b.readUInt32LE(o)!==1) continue; const off=b.readUInt32LE(o+4), va=b.readUInt32LE(o+8), fsz=b.readUInt32LE(o+16);
    for(let k=0;k<fsz;k+=4){ const v = (b[off+k]|0) | ((b[off+k+1]|0)<<8) | ((b[off+k+2]|0)<<16) | ((b[off+k+3]|0)<<24); if(v) mem.set((va+k)/4, v>>>0); } }
  return e; }
function runElf(path, input, maxSteps=5e8, D){ const mem=new FastMem(); const entry=load(path, mem);
  const inp=new FastMem(); input.forEach((v,i)=>inp.set(i,v));
  const st={pc:entry, regs:Array(32).fill(0), step:0, inp}; const kinds={}; const pages=new Set();
  const t0=Date.now();
  while(st.pc!==ref.HALT && st.pc!==ref.TRAP && st.step<maxSteps){ const w=ref.step(st, mem); if(process.env.KINDS) kinds[w.kind]=(kinds[w.kind]||0)+1; }
  return {steps: st.step, pc: st.pc, a0: st.regs[10], ms: Date.now()-t0, kinds, words: mem.w.size};
}
module.exports={runElf, FastMem, load};
if(require.main===module){ const r=runElf(process.argv[2], process.argv.slice(3).map(Number)); console.log(JSON.stringify(r)); }
