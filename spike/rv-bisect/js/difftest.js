// Differential test: Oscript rv_step (real ocore evaluator) vs JS reference ref.js
const {evalInit,val}=require('./oc.js'); const ref=require('./ref.js'); const fs=require('fs');
const body=fs.readFileSync(__dirname+'/../aa/rv_step.oscript','utf8');
let seed=+(process.env.SEED||1); const rnd=()=>{seed=(seed*1103515245+12345)%2147483648; return seed/2147483648;};
const ri=n=>Math.floor(rnd()*n); const pick=a=>a[ri(a.length)];
const r32=()=>pick([0,1,2,0x7fffffff,0x80000000,0xffffffff,0xfffffffe,ri(2**32),ri(2**32),ri(65536),ri(2**32)]);
const R=(op,rd,f3,rs1,rs2,f7)=>((f7<<25)|(rs2<<20)|(rs1<<15)|(f3<<12)|(rd<<7)|op)>>>0;
const I=(op,rd,f3,rs1,imm)=>(((imm&0xfff)<<20)|(rs1<<15)|(f3<<12)|(rd<<7)|op)>>>0;
const S=(op,f3,rs1,rs2,imm)=>((((imm>>5)&127)<<25)|(rs2<<20)|(rs1<<15)|(f3<<12)|((imm&31)<<7)|op)>>>0;
const B=(f3,rs1,rs2,imm)=>((((imm>>12)&1)<<31)|(((imm>>5)&63)<<25)|(rs2<<20)|(rs1<<15)|(f3<<12)|(((imm>>1)&15)<<8)|(((imm>>11)&1)<<7)|99)>>>0;
const J=(rd,imm)=>((((imm>>20)&1)<<31)|(((imm>>1)&1023)<<21)|(((imm>>11)&1)<<20)|(((imm>>12)&255)<<12)|(rd<<7)|111)>>>0;
const reg=()=>ri(32), simm=n=>ri(2**n)-2**(n-1);
function gen(){ const k=ri(14);
 switch(k){ case 0: return R(51,reg(),ri(8),reg(),reg(),1);
  case 1: case 2: { const f3=ri(8); return R(51,reg(),f3,reg(),reg(),(f3==0||f3==5)&&ri(2)?32:0); }
  case 3: { const f3=ri(8); let imm=simm(12); if(f3==1) imm=ri(32); if(f3==5) imm=ri(32)|(ri(2)?0x400:0); return I(19,reg(),f3,reg(),imm); }
  case 4: return ((ri(2**20)<<12)|(reg()<<7)|pick([55,23]))>>>0;
  case 5: return J(reg(), simm(20)*2);
  case 6: return I(103,reg(),0,reg(),simm(12));
  case 7: case 8: return B(pick([0,1,4,5,6,7]),reg(),reg(),simm(12)*2);
  case 9: case 10: return I(3,reg(),pick([0,1,2,4,5]),reg(),simm(12));
  case 11: return S(35,ri(3),reg(),reg(),simm(12));
  case 12: return pick([0x73, ri(2**32), R(51,reg(),ri(8),reg(),reg(),ri(128))]);
  default: return R(51,reg(),ri(8),reg(),reg(),pick([0,1,32]));
 }}
(async()=>{ const N=+(process.env.N||200); let bad=0, kinds={};
 for(let t=0;t<N;t++){
  const mem=new ref.Mem(); const st={pc: 4*ri(2**20), regs: Array.from({length:32},(_, i)=>i?r32():0), step: ri(1000)};
  const w=gen(); mem.set(st.pc/4, w);
  // make loads/stores mostly in range & aligned: point rs1 at a data region
  const op=w&127; if(op==3||op==35){ const rs1=(w>>>15)&31; if(rs1 && ri(4)) { st.regs[rs1]= 4*(2**20+ri(2**20)) + pick([0,0,1,2,3]); } if(rs1==17) st.regs[17]=st.regs[17]; }
  if (w===0x73 && ri(2)) st.regs[17]=93;
  for(let j=0;j<4;j++) mem.set(2**20+ri(2**21), r32());
  if(op==3||op==35){ const rs1=(w>>>15)&31; const imm= op==35 ? (((w>>>25)<<5)|((w>>>7)&31)) : (w>>>20); const sim=imm>=2048?imm-4096:imm; const ea=(st.regs[rs1]+sim)>>>0; if(ea<2**26) mem.set(Math.floor(ea/4), r32()); }
  st.inp=new ref.Mem(); for(let j=0;j<3;j++) st.inp.set(ri(16), r32()); if (w===0x73 && ri(2)) { st.regs[17]=63; st.regs[10]=pick([ri(16),ri(16),2**24,ri(2**32)]); }
  const pre={pc:st.pc, regs:[...st.regs], mem:mem.root(), step:st.step};
  if(process.env.V) console.log('pre',t); const wit=ref.step(st, mem); if(process.env.V) console.log('stepped'); const want=ref.stateRoot(st, mem);
  const data={pc:pre.pc, regs:pre.regs, mem:pre.mem, inp:st.inp.root(), step:pre.step, w:wit.w, wsib:wit.wsib}; if(wit.isib){data.iw=wit.iw; data.isib=wit.isib;}
  if(wit.msib){ data.mw=wit.mword; data.msib=wit.msib; data.nroot=mem.root(); }
  if(process.env.V) console.log('case',t,w.toString(16), JSON.stringify(data).length, wit.kind, st.regs[(w>>>15)&31]); if(process.env.DUMP==t) fs.writeFileSync('case.json', JSON.stringify(data)); if(process.env.NOEVAL) continue; const r=await evalInit(body, data); const got=val(r.locals,'post');
  kinds[wit.kind]=(kinds[wit.kind]||0)+1;
  if(r.err || got!==want){ bad++; if(bad<=8) console.log('MISMATCH', t, wit.kind, w.toString(16), 'err', r.err&&String((r.err.formattedError||r.err).message).slice(0,200), 'pc', st.pc, 'rd', (w>>>7)&31, 'ref rd val', st.regs[(w>>>7)&31]); }
 }
 console.log('cases',N,'mismatches',bad, JSON.stringify(kinds)); process.exit(0); })();
