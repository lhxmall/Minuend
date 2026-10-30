const {validate}=require('./oc.js'); const fs=require('fs');
(async()=>{ for(const f of process.argv.slice(2)){ const r=await validate(fs.readFileSync(f,'utf8')); console.log(f.split('/').pop(),'=>',r.err||`complexity ${r.complexity} ops ${r.count_ops}`);} process.exit(0)})();
