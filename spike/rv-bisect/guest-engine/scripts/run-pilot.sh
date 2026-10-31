#!/bin/bash
# Final pilot run: rebuild host + guest + embed, 3-way diff bench, fuzz, sail spot-check, mutants.
. /data/hark/spike-rv/env.sh
P=/data/hark/spike-rv/pilot; L=/data/hark/logs/rv
set -x
(cd $P/engine-diff && CARGO_TARGET_DIR=/data/hark/target-pilot-host cargo build --release -q) 2> $L/pilot2-build.log
(cd $P/guest-engine && CARGO_TARGET_DIR=/data/hark/target-pilot cargo build --release -q --target riscv32im-unknown-none-elf) 2>> $L/pilot2-build.log
(cd $P/guest-engine && CARGO_TARGET_DIR=/data/hark/target-pilot-embed cargo build --release -q --features embed --target riscv32im-unknown-none-elf) 2>> $L/pilot2-build.log
B=/data/hark/target-pilot-host/release/engine-diff; E=/data/hark/target-pilot/riscv32im-unknown-none-elf/release/rvengine
EE=/data/hark/target-pilot-embed/riscv32im-unknown-none-elf/release/rvengine
sha1sum $B $E $EE > $L/pilot2-bins.txt
rm -rf $P/batches2; mkdir -p $P/batches2
$B fuzz 300 300 > $L/pilot2-fuzz.log 2>&1
cd $P/js
CFG='[{"name":"depth200","makers":10,"levels":50,"per":2},{"name":"depth800","makers":16,"levels":200,"per":2},{"name":"stress200","makers":10,"levels":50,"per":2,"stress":true}]'
node pilotbench.js $B $E $P/batches2 "$CFG" > $L/pilot2-bench.jsonl 2> $L/pilot2-bench.err
for f in depth200-n10 depth200-n1000 depth800-n10 depth800-n1000 stress200-n1000; do echo "$f $($B witstat $P/batches2/$f.bin)"; done > $L/pilot2-witstat.log
cd $P/xval
R=$($B real $P/batches2/depth200-n10.bin | node -e 'console.log(JSON.parse(require("fs").readFileSync(0)).hash)')
node pilotsail.js $EE $P/batches2/depth200-n10.bin $P/sail/d200n10 $R > $L/pilot2-sail.log 2>&1
rm -f $P/sail/d200n10/mem.*.bin
cd $P && ./pilot-mut.sh
cp $L/pilot-mut.log $L/pilot2-mut.log
echo ALLDONE >> $L/pilot2-bench.err
