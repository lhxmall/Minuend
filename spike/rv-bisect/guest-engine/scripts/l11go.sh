#!/bin/bash
# loop round 11 on the box (setsid, nice 5): R10-H1 cap mutation (loop11-mut.sh on /data/hark/spike-rv/loop11, target
# target-l11-mut), then rolldevnet on /data/hark/spike-rv/loop11/js (round-11 AAs) once the round-10 devnet is done
# (aa-testkit hubs bind the fixed port 3005: one devnet at a time): ONLY10 section first, then the full run.
# Logs l11-mut.log (MUTDONE), l11-rolldevnet10.log, l11-rolldevnet.log (RDDONE).
. /data/hark/spike-rv/env.sh
L=/data/hark/logs/rv; S=/data/hark/spike-rv
$S/loop11/guest-engine/scripts/loop11-mut.sh
until grep -q RDDONE $L/l10-rolldevnet.log 2>/dev/null; do sleep 60; done
cd $S/loop11/js && export AATK=/data/hark/wt-all/vendor/aa-testkit OCORE=/data/hark/wt-all/vendor/aa-testkit/node_modules/ocore
rm -rf $S/loop11/devnet-testdata; ONLY10=1 TESTDATA=$S/loop11/devnet-testdata PORT=16771 OUT=$L/l11-rolldevnet10.json timeout 3000 node rolldevnet.js > $L/l11-rolldevnet10.log 2>&1
echo "RDDONE exit $?" >> $L/l11-rolldevnet10.log
rm -rf $S/loop11/devnet-testdata; TESTDATA=$S/loop11/devnet-testdata PORT=16771 OUT=$L/l11-rolldevnet.json timeout 9000 node rolldevnet.js > $L/l11-rolldevnet.log 2>&1
echo "RDDONE exit $?" >> $L/l11-rolldevnet.log
