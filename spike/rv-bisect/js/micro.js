const {validate, evalInit, val}=require('./oc.js');
const wrap=f=>`{messages:[{init:"{${f.replace(/"/g,'\\"')}}", app:'state', state:"{var['x']=1;}"}]}`;
(async()=>{
 const cases={
  empty:'$a=1;',
  add:'$a=trigger.data.x+1;',
  add10:'$a=trigger.data.x+1+2+3+4+5+6+7+8+9+10;',
  arr8:'$a=[1,2,3,4,5,6,7,8];',
  substr:'$a=substring(trigger.data.s, 3, 1);',
  floormod:'$a=floor(trigger.data.x/128)%32;',
  pow:'$a=2^trigger.data.x;',
  sha:'$a=sha256(trigger.data.s);',
  split:'$a=split(trigger.data.s, "-");',
  func1:'$f=($x)=>$x+1; $a=$f(1);',
  func2:'$f=($x)=>$x+1; $a=$f(1)+$f(2);',
  red8:'$a=reduce([1,2,3,4,5,6,7,8], 8, ($acc,$x)=>$acc+$x, 0);',
  ifelse:'if (trigger.data.x==1) $a=1; else $a=2;',
  mrk:'$a=is_valid_merkle_proof(trigger.data.s, {root:trigger.data.s, siblings:[], index:0});',
 };
 for (const [k,f] of Object.entries(cases)){ const r=await validate(wrap(f)); console.log(k.padEnd(10), r.err||(`cx ${r.complexity} ops ${r.count_ops}`)); }
 // semantics
 let r=await evalInit('$R=split(trigger.data.s, ","); $t=typeof($R[1]); $b=$R[1]+1; $j=join($R,","); $R2=$R; $c=floor(4294967295*65535/65536); $d=4294967295/3; $e=4294967296*4294967295;', {s:'00,7,4294967295'});
 console.log(r.err&&r.err.message, ['t','b','j','c','d','e'].map(k=>k+'='+val(r.locals,k)).join(' '));
 r=await evalInit('$R=split(trigger.data.s, ","); $R[1]=55; $j=join($R,",");', {s:'0,7,9'}); console.log(r.err&&r.err.message, val(r.locals,'j'));
 r=await evalInit('$x=12345678901234; $y=$x*1000; $z=$y%7; $w=12345678901234567;', {}); console.log(['x','y','z','w'].map(k=>k+'='+val(r.locals,k)).join(' '));
})();
