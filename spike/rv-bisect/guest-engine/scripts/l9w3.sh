#!/bin/bash
# loop round 9: rebuild the govwit host after the synced test command (tar kept older mtimes: cargo saw it fresh)
. /data/hark/spike-rv/env.sh
L=/data/hark/logs/rv; W=/data/hark/spike-rv/loop9w; O=$L/l9w-3.log
while ! grep -q W2DONE $L/l9w-2.log 2>/dev/null; do sleep 15; done
touch $W/engine-diff/src/*.rs
(cd $W/engine-diff && CARGO_TARGET_DIR=/data/hark/target-l9w-host cargo build --release --features govwit 2>&1 | grep -E '^(warning|error)|-->|Finished') > $O 2>&1
{ echo govwit; /data/hark/target-l9w-host/release/engine-diff govwit; echo W3DONE; } >> $O 2>&1
