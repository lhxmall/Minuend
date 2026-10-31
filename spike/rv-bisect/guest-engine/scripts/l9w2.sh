#!/bin/bash
# loop round 9 (R7-L3 WIP): govwit leaf-flip test, default build unchanged, govwit guest image + govgen batches through the JS guest
. /data/hark/spike-rv/env.sh
L=/data/hark/logs/rv; W=/data/hark/spike-rv/loop9w; O=$L/l9w-2.log; G=riscv32im-unknown-none-elf
while ! grep -q QDONE $L/l9w-q.log 2>/dev/null; do sleep 20; done
f(){ grep -E '^(warning|error)|-->|Finished'; }
B=/data/hark/target-l9w-host/release/engine-diff
(cd $W/engine-diff && CARGO_TARGET_DIR=/data/hark/target-l9w-host cargo build --release --features govwit 2>&1 | f) > $O 2>&1
{ echo govwit; $B govwit; } >> $O 2>&1
[ -d /data/hark/target-l9w-g ] || cp -a /data/hark/target-l8-g /data/hark/target-l9w-g
(cd $W/guest-engine && CARGO_TARGET_DIR=/data/hark/target-l9w-g cargo build --release --features govwit --target $G 2>&1 | f) >> $O 2>&1
E=/data/hark/target-l9w-g/$G/release/rvengine
mkdir -p $W/govg; rm -f $W/govg/*.bin; for s in 21 22 23; do $B govgen $s 300 $W/govg/gov$s.bin > /dev/null; done
(cd $W/js && node witscen.js $B $E $W/govg > $L/l9w-govguest.log 2>&1)
# default build of the same sources (govwit off): unchanged behaviour
[ -d /data/hark/target-l9w-hostdef ] || cp -a /data/hark/target-l8-host /data/hark/target-l9w-hostdef
(cd $W/engine-diff && CARGO_TARGET_DIR=/data/hark/target-l9w-hostdef cargo build --release 2>&1 | f) >> $O 2>&1
D=/data/hark/target-l9w-hostdef/release/engine-diff
{ echo default-govwit; $D govwit; echo default-govedge; $D govedge; echo default-govfuzz; $D govfuzz 30 300 | tail -1 | cut -c1-200; echo W2DONE; } >> $O 2>&1
