// Run riscv-tests ELFs (rv32ui / rv32um, built with work/rvt/kit) on the Merkle reference emulator and check
// EVERY step with the Oscript one-step AA on the real ocore evaluator (pre root and post root must both match).
// usage: node rvtests.js a.elf b.elf ...   -> one JSON line per test
const ref=require('./ref.js'); const {load}=require('./elfrun.js'); const {evalInit,val}=require('./oc.js'); const fs=require('fs');
const body=fs.readFileSync(__dirname+'/../aa/rv_step.oscript','utf8');
(async()=>{ for (const f of process.argv.slice(2)) {
 const mem=new ref.Mem(); const entry=load(f, mem); mem.root();
 const st={pc:entry, regs:Array(32).fill(0), step:0, inp:new ref.Mem()}; st.inp.root();
 let checked=0, bad=0, first=null; const t0=Date.now(); const MAX=+(process.env.MAX||200000);
 while(st.pc!==ref.HALT && st.pc!==ref.TRAP && st.step<MAX){
  const preRoot=ref.stateRoot(st,mem); const pre={pc:st.pc, regs:[...st.regs], step:st.step};
  const wit=ref.step(st, mem);
  const data={pc:pre.pc, regs:pre.regs, mem:wit.mem_root, inp:st.inp.root(), step:pre.step, w:wit.w, wsib:wit.wsib};
  if(wit.msib){ data.mw=wit.mword; data.msib=wit.msib; data.nroot=mem.root(); } if(wit.isib){ data.iw=wit.iw; data.isib=wit.isib; }
  const r=await evalInit(body,data); checked++;
  if(r.err || val(r.locals,'pre')!==preRoot || val(r.locals,'post')!==ref.stateRoot(st,mem)){ bad++; if(!first) first={step:pre.step, pc:pre.pc, w:(wit.w>>>0).toString(16), err:r.err&&String((r.err.formattedError||r.err).message||r.err).slice(0,120)}; }
 }
 // one more absorbing step after HALT/TRAP must be a no-op that only bumps step
 const preRoot=ref.stateRoot(st,mem); const r=await evalInit(body,{pc:st.pc, regs:[...st.regs], mem:mem.root(), inp:st.inp.root(), step:st.step});
 st.step++; const absorbOk=!r.err && val(r.locals,'pre')===preRoot && val(r.locals,'post')===ref.stateRoot(st,mem);
 const name=f.split('/').pop().replace('.elf','');
 console.log(JSON.stringify({test:name, end: st.pc===ref.HALT?'HALT':st.pc===ref.TRAP?'TRAP':'MAX', a0:st.regs[10], pass: st.pc===ref.HALT && st.regs[10]===0, failedCase: st.regs[10]>>>1, steps:st.step-1, checked, bad, absorbOk, first, ms:Date.now()-t0}));
 } process.exit(0); })();
