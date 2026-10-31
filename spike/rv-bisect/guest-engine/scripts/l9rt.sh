#!/bin/bash
# loop round 9: rolltest + aacost on the round-8 AAs (roll8) and the round-9 AAs (roll9), sim chain on the box's ocore
L=/data/hark/logs/rv; export AATK=/data/hark/wt-all/vendor/aa-testkit OCORE=/data/hark/wt-all/vendor/aa-testkit/node_modules/ocore
for r in 8 9; do (cd /data/hark/spike-rv/roll$r/js && OUT=$L/l$r-rolltest.json timeout 2400 node rolltest.js > $L/l$r-rolltest.log 2>&1; node aacost.js > $L/l$r-aacost.log 2>&1); done
echo RTDONE >> $L/l9-rolltest.log
