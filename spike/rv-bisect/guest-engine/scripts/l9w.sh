#!/bin/bash
# loop round 9 (R7-L3 WIP, feature govwit): build host with govwit + default, quick differential checks
. /data/hark/spike-rv/env.sh
L=/data/hark/logs/rv; W=/data/hark/spike-rv/loop9w; O=$L/l9w-q.log; B=/data/hark/target-l9w-host/release/engine-diff
f(){ grep -E '^(warning|error)|-->|Finished'; }
(cd $W/engine-diff && CARGO_TARGET_DIR=/data/hark/target-l9w-host cargo build --release --features govwit 2>&1 | f) > $O 2>&1
{ echo govedge; $B govedge; echo govfuzz; $B govfuzz 60 300 | tail -1 | cut -c1-400; echo xfuzz; $B xfuzz 60 300 | tail -1 | cut -c1-400;
  echo snaptest; $B snaptest 30 200 | tail -1; echo witfuzz; $B witfuzz 30 300 20 | tail -1 | cut -c1-300; echo segfuzz; $B segfuzz 30 300 | tail -1 | cut -c1-300;
  echo hbind; $B hbind 30 300 | tail -1; echo proofs; $B proofs 10 25 | tail -1 | cut -c1-300; echo capcheck; $B capcheck 10 100 8 | tail -1;
  echo liqfuzz; $B liqfuzz 30 300 | tail -1 | cut -c1-300; echo orafuzz; $B orafuzz 30 300 | tail -1 | cut -c1-300; echo fuzz; $B fuzz 50 300 | tail -1 | cut -c1-300;
  echo scen; $B scen $W/engine-diff/scenarios/upstream.scn | tail -1 | cut -c1-200; echo QDONE; } >> $O 2>&1
