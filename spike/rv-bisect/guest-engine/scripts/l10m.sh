#!/bin/bash
# loop round 10 (R10-H1 measurement): default host build of loop10m (+ mktcap), then mktcap runs
. /data/hark/spike-rv/env.sh
L=/data/hark/logs/rv; P=/data/hark/target-l10m-host; O=$L/l10-mktcap.log
[ -d $P ] || cp -a /data/hark/target-l9w-hostdef $P
cd /data/hark/spike-rv/loop10m/engine-diff && touch src/*.rs && CARGO_TARGET_DIR=$P cargo build --release 2>&1 | grep -E '^(warning|error)|-->|Finished' > $O
B=$P/release/engine-diff
for a in "16 16 16" "64 64 0" "64 64 64" "128 128 0" "128 128 128" "256 256 0" "256 256 256"; do echo "mktcap $a $(timeout 3000 $B mktcap $a)" >> $O; done
echo MKDONE >> $O
