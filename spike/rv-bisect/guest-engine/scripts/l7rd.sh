#!/bin/bash
# loop round 7: rolldevnet on the round-7 AAs (per-height ts; RV_MINGAP=1 is set by rolldevnet.js itself)
L=/data/hark/logs/rv
# aa-testkit hubs bind a fixed port (3005): wait for the round-4 devnet re-run to finish
while ! grep -q RDDONE $L/l4-rolldevnet2.log 2>/dev/null; do sleep 30; done
cd /data/hark/spike-rv/roll7/js && export AATK=/data/hark/wt-all/vendor/aa-testkit OCORE=/data/hark/wt-all/vendor/aa-testkit/node_modules/ocore
rm -rf /data/hark/spike-rv/roll7/devnet-testdata; TESTDATA=/data/hark/spike-rv/roll7/devnet-testdata PORT=16771 OUT=$L/l7-rolldevnet.json timeout 9000 node rolldevnet.js > $L/l7-rolldevnet.log 2>&1
echo "RDDONE exit $?" >> $L/l7-rolldevnet.log
