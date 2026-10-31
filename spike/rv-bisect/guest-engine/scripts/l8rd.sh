#!/bin/bash
# loop round 8: rolldevnet on the round-8 AAs (roll8 = repo js+aa @ 95f79e9 + govd8; AA unchanged since round 7) (per-height ts; RV_MINGAP=1 is set by rolldevnet.js itself)
L=/data/hark/logs/rv
# aa-testkit hubs bind a fixed port (3005): wait for the round-7 devnet to finish
while ! grep -q RDDONE $L/l7-rolldevnet.log 2>/dev/null; do sleep 30; done
cd /data/hark/spike-rv/roll8/js && export AATK=/data/hark/wt-all/vendor/aa-testkit OCORE=/data/hark/wt-all/vendor/aa-testkit/node_modules/ocore
rm -rf /data/hark/spike-rv/roll8/devnet-testdata; TESTDATA=/data/hark/spike-rv/roll8/devnet-testdata PORT=16771 OUT=$L/l8-rolldevnet.json timeout 9000 node rolldevnet.js > $L/l8-rolldevnet.log 2>&1
echo "RDDONE exit $?" >> $L/l8-rolldevnet.log
