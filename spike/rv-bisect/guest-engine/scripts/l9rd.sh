#!/bin/bash
# loop round 9: rolldevnet on the round-9 AAs (roll9 = repo js+aa @ f48109e: rv_rollup cancel, R9-H1) (per-height ts; RV_MINGAP=1 is set by rolldevnet.js itself)
L=/data/hark/logs/rv
# aa-testkit hubs bind a fixed port (3005): wait for the round-8 devnet to finish
while ! grep -q RDDONE $L/l8-rolldevnet.log 2>/dev/null; do sleep 30; done
cd /data/hark/spike-rv/roll9/js && export AATK=/data/hark/wt-all/vendor/aa-testkit OCORE=/data/hark/wt-all/vendor/aa-testkit/node_modules/ocore
rm -rf /data/hark/spike-rv/roll9/devnet-testdata; TESTDATA=/data/hark/spike-rv/roll9/devnet-testdata PORT=16771 OUT=$L/l9-rolldevnet.json timeout 9000 node rolldevnet.js > $L/l9-rolldevnet.log 2>&1
echo "RDDONE exit $?" >> $L/l9-rolldevnet.log
