#!/bin/bash
# loop round 10 (R10-H1): mktcap v2 (non-netting positions: every account holds a position in every market), after l10m.sh
. /data/hark/spike-rv/env.sh
L=/data/hark/logs/rv; P=/data/hark/target-l10m-host; O=$L/l10-mktcap2.log
while ! grep -q MKDONE $L/l10-mktcap.log 2>/dev/null; do sleep 20; done
cd /data/hark/spike-rv/loop10m/engine-diff && touch src/*.rs && CARGO_TARGET_DIR=$P cargo build --release 2>&1 | grep -E '^(warning|error)|-->|Finished' > $O
B=$P/release/engine-diff
for a in "16 16 0" "64 64 0" "128 128 0" "256 64 0" "256 128 0" "256 256 0" "256 256 256"; do echo "mktcap $a $(timeout 5000 $B mktcap $a)" >> $O; done
echo MKDONE >> $O
