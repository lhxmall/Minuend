#!/bin/bash
# loop round 10 (R10-H1 fix: MAX_STATE_MARKETS 32, MAX_STATE_ORACLES 32): host default + govwit builds, guest default + prod builds of loop10h,
# then the tests the cap touches: govedge (cap:markets), govcap, govfuzz / xfuzz, capcheck, snaptest, liqedge, govwit leaf-flip;
# govgen batches through the JS guest (default image); prodheight on the prod image.
. /data/hark/spike-rv/env.sh
L=/data/hark/logs/rv; O=$L/l10h.log; W=/data/hark/spike-rv/loop10h; G=riscv32im-unknown-none-elf; P=/data/hark/target-l10h
f(){ grep -E '^(warning|error)|-->|Finished'; }
for p in "l10m-host l10h-host" "l10g-host l10h-hostgw" "l10g-g l10h-g" "l10g-gprod l10h-gprod"; do set -- $p; [ -d /data/hark/target-$2 ] || cp -a /data/hark/target-$1 /data/hark/target-$2; done
cd $W && find guest-engine engine-diff -name '*.rs' -exec touch {} +
{ (cd $W/engine-diff && CARGO_TARGET_DIR=$P-host cargo build --release 2>&1 | f)
  (cd $W/engine-diff && CARGO_TARGET_DIR=$P-hostgw cargo build --release --features govwit 2>&1 | f)
  (cd $W/guest-engine && CARGO_TARGET_DIR=$P-g cargo build --release --target $G 2>&1 | f)
  (cd $W/guest-engine && CARGO_TARGET_DIR=$P-gprod cargo build --release --features prod --target $G 2>&1 | f)
  sha1sum $P-host/release/engine-diff $P-hostgw/release/engine-diff $P-g/$G/release/rvengine $P-gprod/$G/release/rvengine; echo BUILT; } > $O 2>&1
B=$P-host/release/engine-diff; BW=$P-hostgw/release/engine-diff
for b in $B $BW; do echo "== $b"; $b govedge; $b govcap; $b govfuzz 100 300 | tail -1 | cut -c1-300; $b xfuzz 100 300 | tail -1 | cut -c1-300; done >> $O 2>&1
{ echo govwit; $BW govwit; $B capcheck 20 200 8; $B snaptest 60 300 | tail -1 | cut -c1-300; $B liqedge | cut -c1-300; } >> $O 2>&1
mkdir -p $W/govg && rm -f $W/govg/*.bin; for s in 31 32 33; do $B govgen $s 300 $W/govg/gov$s.bin > /dev/null; done
(cd $W/js && node witscen.js $B $P-g/$G/release/rvengine $W/govg > $L/l10h-govguest.log 2>&1; tail -n 2 $L/l10h-govguest.log >> $O)
(cd $W/js && node prodheight.js $P-gprod/$G/release/rvengine $P-g/$G/release/rvengine > $L/l10h-prodheight.log 2>&1; tail -n 1 $L/l10h-prodheight.log >> $O)
echo "mktcap 256 32 32 64 64 $($B mktcap 256 32 32 64 64)" >> $O   # whole state at the round-10 caps (engine-direct, caps not applied: 32 markets x 32 oracles)
echo HDONE >> $O
