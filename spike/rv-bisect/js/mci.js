const WS=require('ws'); const w=new WS('wss://obyte.org/bb');
w.on('open',()=>{ w.send(JSON.stringify(['request',{command:'get_last_mci',tag:'a'}])); w.send(JSON.stringify(['request',{command:'heartbeat',tag:'b'}]));});
w.on('message',m=>{ const s=m.toString(); if(s.includes('"a"')||s.includes('last_mci')){console.log(s.slice(0,300)); process.exit(0);} });
setTimeout(()=>{console.log('timeout');process.exit(1)},20000);
