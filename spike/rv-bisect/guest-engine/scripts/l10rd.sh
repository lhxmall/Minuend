#!/bin/bash
# loop round 10 (R9-T1): rolldevnet on roll10 (= roll9 AAs + rolldevnet section 9: rollup-2 with $GOV = a devnet wallet).
# usage: l10rd.sh [only9]  -> only9: section 9 only (l10-rolldevnet9.log), else the full run (l10-rolldevnet.log).
# aa-testkit hubs bind the fixed port 3005: one devnet at a time.
L=/data/hark/logs/rv; S=${1:+9}
for f in $L/l9-rolldevnet.log $L/l8-rolldevnet.log; do grep -q RDDONE $f || exit 1; done
cd /data/hark/spike-rv/roll10/js && export AATK=/data/hark/wt-all/vendor/aa-testkit OCORE=/data/hark/wt-all/vendor/aa-testkit/node_modules/ocore
rm -rf /data/hark/spike-rv/roll10/devnet-testdata; [ -n "$1" ] && export ONLY9=1
TESTDATA=/data/hark/spike-rv/roll10/devnet-testdata PORT=16771 OUT=$L/l10-rolldevnet$S.json timeout 9000 node rolldevnet.js > $L/l10-rolldevnet$S.log 2>&1
echo "RDDONE exit $?" >> $L/l10-rolldevnet$S.log
