#!/bin/bash
# loop round 8: rebuild host after the cap:perp_slash_new check, govedge + govfuzz, then round-7 mutant 4 (Slash dropped
# from the shared ledger cap) against the new govedge
. /data/hark/spike-rv/env.sh
L=/data/hark/logs/rv; W=/data/hark/spike-rv/loop8; B=/data/hark/target-l8-host/release/engine-diff
(cd $W/engine-diff && CARGO_TARGET_DIR=/data/hark/target-l8-host cargo build --release 2>&1 | grep -E '^(warning|error)|-->|Finished') > $L/l8-e.log 2>&1
{ echo govedge; $B govedge; echo govfuzz; $B govfuzz 30 300 | tail -1 | cut -c1-200; } >> $L/l8-e.log 2>&1
M=$W/mut-l7m4; rm -rf $M; mkdir -p $M; cp -r $W/guest-engine $W/engine-diff $M/; ln -s $W/engine-src $M/engine-src
python3 - $M/guest-engine/src/lib.rs <<'PY'
import sys
p=sys.argv[1]; s=open(p).read()
a="BatchOp::GovDeposit { .. } | BatchOp::GovWithdraw { .. } | BatchOp::Slash { .. } => {"
assert s.count(a)==1; open(p,'w').write(s.replace(a,"BatchOp::GovDeposit { .. } | BatchOp::GovWithdraw { .. } => {"))
PY
(cd $M/engine-diff && CARGO_TARGET_DIR=/data/hark/target-l8-mut cargo build --release -q 2>/dev/null) && echo "l7 mut 4 vs round-8 govedge: $(/data/hark/target-l8-mut/release/engine-diff govedge)" >> $L/l8-e.log
rm -rf $M
echo EDONE >> $L/l8-e.log
