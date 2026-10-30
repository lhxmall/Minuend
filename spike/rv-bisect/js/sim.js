// End-to-end bisection game simulation on the real ocore evaluator: rv_game + rv_step formulas, shared state vars.
const {run,val}=require('./oc.js'); const ref=require('./ref.js'); const fs=require('fs');
const G=require('./mkgame.js'); const GAME=G.body+'\n'+G.state;
const STEPF=fs.readFileSync(__dirname+'/../aa/rv_step.oscript','utf8')+"\nvar['s_' || $pre] = $post;";
const STEP='MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU', GA='GAMEAAXXXXXXXXXXXXXXXXXXXXXXXXXX', OP='OPERATORXXXXXXXXXXXXXXXXXXXXXXXX', CH='CHALLENGERXXXXXXXXXXXXXXXXXXXXXX';
const I=(op,rd,f3,rs1,imm)=>(((imm&0xfff)<<20)|(rs1<<15)|(f3<<12)|(rd<<7)|op)>>>0;
const R=(op,rd,f3,rs1,rs2,f7)=>((f7<<25)|(rs2<<20)|(rs1<<15)|(f3<<12)|(rd<<7)|op)>>>0;
const S=(f3,rs1,rs2,imm)=>((((imm>>5)&127)<<25)|(rs2<<20)|(rs1<<15)|(f3<<12)|((imm&31)<<7)|35)>>>0;
const B=(f3,rs1,rs2,imm)=>((((imm>>12)&1)<<31)|(((imm>>5)&63)<<25)|(rs2<<20)|(rs1<<15)|(f3<<12)|(((imm>>1)&15)<<8)|(((imm>>11)&1)<<7)|99)>>>0;
function program(N){ return [ I(19,1,0,0,0), I(19,2,0,0,N), ((0x40000>>>12)<<12|(4<<7)|55)>>>0, // lui x4,0x40 (data at 0x40000)
  I(19,11,0,0,0),
  /*loop*/ R(51,1,0,1,2,0), R(51,3,0,1,2,1), S(2,4,3,0), I(3,5,2,4,0), R(51,6,4,5,3,0) /*xor*/, I(19,10,0,11,0), 0x73|0 /*placeholder*/, R(51,7,0,7,10,0), I(19,11,0,11,1),
  I(19,4,0,4,4), I(19,2,0,2,-1), B(1,2,0,-44), I(19,17,0,0,93), 0x73 ]; }
function trace(N, lieAt){ // returns roots[0..n] and snapshots for witness generation
  const mem=new ref.Mem(); const p=program(N); p[10]=0x73; // ecall read: a7 must be 63 -> set x17=63 at start
  p.splice(0,0,I(19,17,0,0,63)); p[p.length-2]=I(19,17,0,0,93);
  p.forEach((w,i)=>mem.set(i,w));
  const st={pc:0, regs:Array(32).fill(0), step:0, inp:new ref.Mem()}; for(let i=0;i<64;i++) st.inp.set(i, (i*2654435761)>>>0);
  const roots=[ref.stateRoot(st,mem)], snaps=[]; 
  while(st.pc!==ref.HALT && st.step<100000){ snaps.push({st:{pc:st.pc,regs:[...st.regs],step:st.step}, wit:null}); const wit=ref.step(st,mem); snaps[snaps.length-1].wit=wit; roots.push(ref.stateRoot(st,mem)); }
  const lie=roots.map((r,i)=> (lieAt!=null && i>=lieAt) ? ref.H('lie'+i) : r);
  return {roots, lie, snaps, inpRoot: st.inp.root(), n: roots.length-1, halted: st.pc===ref.HALT, mem};
}
(async()=>{
 const N=+(process.env.N||40); const sv={}; let ts=1e9; let rounds=0;
 const call=async(f,data,from,aa=GA,out)=>{ const r=await run(f,{data,address:from,ts,stateVars:sv,aa, unit: require('crypto').randomBytes(32).toString('base64'), outputs: out||{base:200000}}); if(r.err) throw Error('bounce: '+r.err+' '+JSON.stringify(data).slice(0,120)); return r; };
 for (const scen of ['operator lies', 'honest operator, griefing challenger', 'liar times out']) {
  const lieAt = scen==='operator lies' ? +(process.env.LIE||137) : scen==='liar times out' ? 50 : null;
  const T=trace(N, lieAt); const claimRoots = lieAt!=null ? T.lie : T.roots;
  const chRoots = scen.startsWith('honest') ? T.roots.map((r,i)=>i>=200?ref.H('grief'+i):r) : T.roots; // challenger's view
  const claimUnit='CLAIM'+Math.random();
  let r=await run(GAME,{data:{claim:1,s0:claimRoots[0],sN:claimRoots[T.n],n:T.n},address:OP,ts,stateVars:sv,unit:claimUnit,aa:GA,outputs:{base:100000}}); if(r.err) throw Error(r.err);
  const gid='GAME'+Math.random();
  r=await run(GAME,{data:{open:claimUnit},address:CH,ts,stateVars:sv,unit:gid,aa:GA,outputs:{base:100000}}); if(r.err) throw Error(r.err);
  let moves=2, g;
  const gs=()=>String(sv[GA]['g_'+gid].value).split(':');
  for(;;){ g=gs(); const lo=+g[3], hi=+g[4], turn=g[7];
   if(turn==='s'||g[0]==='done') break;
   const cnt=Math.min(16,hi-lo)-1; const pt=j=> j==0?lo: j==cnt+1?hi: lo+Math.floor(j*(hi-lo)/(cnt+1));
   if(scen==='liar times out' && rounds>=0 && moves>=4){ ts+=3601; break; }
   ts+=120; await call(GAME,{mids:gid, roots:Array.from({length:cnt},(_,i)=>claimRoots[pt(i+1)])},OP); moves++;
   // challenger: first segment whose right end it disagrees with
   let j=0; while(j<cnt && chRoots[pt(j+1)]===claimRoots[pt(j+1)]) j++;
   ts+=120; await call(GAME,{pick:gid, j},CH); moves++; rounds++;
  }
  g=gs();
  if(g[7]==='s'){ const lo=+g[3]; const sn=T.snaps[lo]; // anyone runs the one step from the agreed pre-state
    // witness from honest snapshot at step lo (pre-state agreed by both, equals honest root)
    if (sn && ref.stateRoot.length) {}
    const w=sn.wit; const data={pc:sn.st.pc, regs:sn.st.regs, mem:w.mem_root, inp:T.inpRoot, step:sn.st.step, w:w.w, wsib:w.wsib};
    if(w.msib){ data.mw=w.mword; data.msib=w.msib; // post-store root from the honest trace
      data.nroot = await (async()=>{ // recompute: replay to lo+1 cheaply = re-run trace prefix
        const m=new ref.Mem(); const t2=trace(N,null); return null; })(); }
    if(w.msib && (w.kind==='mem') && ((w.w&127)===35)) { const t3=replayTo(N, lo+1); data.nroot=t3; }
    if(w.isib){ data.iw=w.iw; data.isib=w.isib; }
    ts+=120; const sr=await call(STEPF,data,CH,STEP); moves++;
    console.log('   one-step at', lo, 'kind', w.kind, 'pre ok', val(sr.locals,'pre')===g[5], 'post', val(sr.locals,'post')===T.roots[lo+1] ? 'matches honest' : 'DIFF');
  }
  ts+=60; const rr=await call(GAME,{resolve:gid},CH); moves++;
  g=String(sv[GA]['g_'+gid].value);
  console.log(scen.padEnd(38),'n',T.n,'halted',T.halted,'rounds',rounds,'moves',moves,'=>',g, 'fraud flag', sv[GA]['f_'+claimUnit]?String(sv[GA]['f_'+claimUnit].value):'none');
  rounds=0;
 }
 process.exit(0);
})().catch(e=>{console.log('ERR',e.message);process.exit(1)});
// rebuild memory root after step k (for store witness): replay honest trace
function replayTo(N,k){ const mem=new ref.Mem(); const p=program(N); p[10]=0x73; p.splice(0,0,I(19,17,0,0,63)); p[p.length-2]=I(19,17,0,0,93); p.forEach((w,i)=>mem.set(i,w));
  const st={pc:0, regs:Array(32).fill(0), step:0, inp:new ref.Mem()}; for(let i=0;i<64;i++) st.inp.set(i,(i*2654435761)>>>0);
  while(st.step<k) ref.step(st,mem); return mem.root(); }
