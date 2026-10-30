// Run the compiled guest on the Merkle-tracking reference emulator and check sampled steps with the Oscript one-step AA.
const ref=require('./ref.js'); const {load}=require('./elfrun.js'); const {evalInit,val}=require('./oc.js'); const fs=require('fs');
const body=fs.readFileSync(__dirname+'/../aa/rv_step.oscript','utf8');
(async()=>{ const mem=new ref.Mem(); const entry=load(process.argv[2], mem); mem.root();
 const st={pc:entry, regs:Array(32).fill(0), step:0, inp:new ref.Mem()}; process.argv.slice(3).map(Number).forEach((v,i)=>st.inp.set(i,v)); st.inp.root();
 const every=+(process.env.EVERY||50); let checked=0, bad=0, kinds={}; const t0=Date.now();
 const MAX=+(process.env.MAX||1e12); while(st.pc!==ref.HALT && st.pc!==ref.TRAP && st.step<MAX){
  const pre={pc:st.pc, regs:[...st.regs], step:st.step}; const sample = st.step % every === 0;
  const wit=ref.step(st, mem);
  if(sample){ const data={pc:pre.pc, regs:pre.regs, mem:wit.mem_root, inp:st.inp.root(), step:pre.step, w:wit.w, wsib:wit.wsib};
   if(wit.msib){ data.mw=wit.mword; data.msib=wit.msib; data.nroot=mem.root(); } if(wit.isib){ data.iw=wit.iw; data.isib=wit.isib; }
   const r=await evalInit(body,data); checked++; kinds[wit.kind]=(kinds[wit.kind]||0)+1;
   if(r.err || val(r.locals,'post')!==ref.stateRoot(st,mem)){ bad++; if(bad<5) console.log('BAD', pre.step, wit.kind, r.err&&(r.err.formattedError||r.err).message); } }
 }
 console.log('steps',st.step,'a0',st.regs[10],'checked',checked,'bad',bad,JSON.stringify(kinds),'ms',Date.now()-t0, 'words', mem.w.size); process.exit(0); })();
