// Honest + mutated execution traces with full one-step witnesses (for the adversarial game tests).
const ref=require('./ref.js');
const I=(op,rd,f3,rs1,imm)=>(((imm&0xfff)<<20)|(rs1<<15)|(f3<<12)|(rd<<7)|op)>>>0;
const R=(op,rd,f3,rs1,rs2,f7)=>((f7<<25)|(rs2<<20)|(rs1<<15)|(f3<<12)|(rd<<7)|op)>>>0;
const S=(f3,rs1,rs2,imm)=>((((imm>>5)&127)<<25)|(rs2<<20)|(rs1<<15)|(f3<<12)|((imm&31)<<7)|35)>>>0;
const B=(f3,rs1,rs2,imm)=>((((imm>>12)&1)<<31)|(((imm>>5)&63)<<25)|(rs2<<20)|(rs1<<15)|(f3<<12)|(((imm>>1)&15)<<8)|(((imm>>11)&1)<<7)|99)>>>0;
// loop N times: x1+=x2; x3=x1*x2; sw; lw; xor; read input word i (ecall 63); acc; ... then exit (ecall 93)
function program(N){ return [ I(19,1,0,0,0), I(19,2,0,0,N), ((0x40000>>>12)<<12|(4<<7)|55)>>>0, I(19,11,0,0,0),
  /*loop*/ R(51,1,0,1,2,0), R(51,3,0,1,2,1), S(2,4,3,0), I(3,5,2,4,0), R(51,6,4,5,3,0), I(19,10,0,11,0), I(19,17,0,0,63), 0x73,
  R(51,7,0,7,10,0), I(19,11,0,11,1), I(19,4,0,4,4), I(19,2,0,2,-1), B(1,2,0,-48), I(19,17,0,0,93), 0x73 ]; }
function init(N){ const mem=new ref.Mem(); program(N).forEach((w,i)=>mem.set(i,w));
  const st={pc:0, regs:Array(32).fill(0), step:0, inp:new ref.Mem()}; for(let i=0;i<64;i++) st.inp.set(i,(i*2654435761)>>>0); mem.root(); st.inp.root(); return {st,mem}; }
// run n steps; mutate(st,mem) is applied right after step k-1->k (so root k is the first wrong one)
function run(N, n, k, mutate){ const {st,mem}=init(N); const roots=[ref.stateRoot(st,mem)], wits=[];
  for(let i=0;i<n;i++){ const pre={pc:st.pc, regs:[...st.regs], step:st.step, mem:mem.root(), inp:st.inp.root()};
    const w=ref.step(st,mem); const d={pc:pre.pc, regs:pre.regs, mem:pre.mem, inp:pre.inp, step:pre.step};
    if(w.wsib){ d.w=w.w; d.wsib=w.wsib; } if(w.msib){ d.mw=w.mword; d.msib=w.msib; if(((w.w>>>0)&127)===35) d.nroot=mem.root(); }
    if(w.isib){ d.iw=w.iw; d.isib=w.isib; } wits.push(d);
    if(k!=null && i+1===k) mutate(st,mem);
    roots.push(ref.stateRoot(st,mem)); }
  return {roots, wits, halted: st.pc===ref.HALT}; }
function honestLen(N){ const {st,mem}=init(N); while(st.pc!==ref.HALT) ref.step(st,mem); return st.step; }
const MUT={
  reg:(st)=>{ st.regs[20]=(st.regs[20]^1)>>>0; },
  pc:(st)=>{ st.pc=(st.pc+4)>>>0; },
  mem:(st,mem)=>{ mem.set(0x20000, 12345); },
  step:(st)=>{ st.step+=1; },
  inp:(st)=>{ st.inp.set(0, 777); },
};
module.exports={run, honestLen, MUT, program};
