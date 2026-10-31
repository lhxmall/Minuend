#!/bin/bash
# loop4 post-suite: segbig substitute (advmax, 25k units) + liqedge on the suite build; waits for the main mutation run,
# then re-runs its survivors with the liqedge check (loop4-mut2.sh)
. /data/hark/spike-rv/env.sh
W=/data/hark/spike-rv/loop4; L=/data/hark/logs/rv; B=/data/hark/target-l4c-host/release/engine-diff
{ $B segrun $W/poc/advmax.bin 16384; $B segrun $W/poc/advmax.bin 5000 "" 2; $B segrun $W/poc/advmax.bin 1000; } > $L/l4-segbig-adv.log 2>&1
/data/hark/target-l4e-host/release/engine-diff liqedge > $L/l4-liqedge.log 2>&1
while ! grep -q '^DONE' $L/l4-mut.log; do sleep 30; done
S=$(grep -a '^mut' $L/l4-mut.log | grep -a -- '-> no$' | sed 's/^mut \([0-9]*\).*/\1/' | tr '\n' ' ')
echo "survivors: $S" > $L/l4-mut2.head
cd $W && MUTS="$S" LOG=$L/l4-mut2.log ./loop4-mut2.sh > $L/l4-mut2.out 2>&1
echo POSTDONE >> $L/l4-mut2.head
