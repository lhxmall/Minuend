#!/bin/bash
# loop round 10 (R10-H1): whole-state heap at the caps (mktcap n m r orders wd), after l10m2.sh (same binary)
L=/data/hark/logs/rv; B=/data/hark/target-l10m-host/release/engine-diff; O=$L/l10-mktcap3.log
while ! grep -q MKDONE $L/l10-mktcap2.log 2>/dev/null; do sleep 20; done
. /data/hark/spike-rv/env.sh
cd /data/hark/spike-rv/loop10m/engine-diff && touch src/*.rs && CARGO_TARGET_DIR=/data/hark/target-l10m-host cargo build --release 2>&1 | grep -E '^(warning|error)|-->|Finished' > $O
for a in "256 0 0 64 64" "256 16 256 64 64" "256 32 256 64 64" "256 64 256 64 64" "256 128 256 64 64" "256 256 256 64 64"; do echo "mktcap $a $(timeout 6000 $B mktcap $a)" >> $O; done
echo MKDONE >> $O
