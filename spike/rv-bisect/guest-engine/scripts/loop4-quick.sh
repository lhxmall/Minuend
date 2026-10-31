#!/bin/bash
# loop4 quick regression on a build tag: quick.sh <tag>
. /data/hark/spike-rv/env.sh
P=/data/hark/target-l4$1-host/release/engine-diff; L=/data/hark/logs/rv/l4$1-quick.log; W=/data/hark/spike-rv/loop4
mkdir -p $W/scen-q
{ $P fuzz 100 300; $P witfuzz 50 300 50; $P advfuzz 50 300; $P segfuzz 50 300; $P scen $W/engine-diff/scenarios/upstream.scn $W/scen-q | tail -1; $P liqfuzz 100 300; $P snaptest 100 300; } > $L 2>&1
echo QUICKDONE >> $L
