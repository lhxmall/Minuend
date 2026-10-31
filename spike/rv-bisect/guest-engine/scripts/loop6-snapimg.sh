#!/bin/bash
# loop6: snapshot dirs + upgrade images (compiled-in import digest "<hex>:<words>") + snapguest (default and prod images)
# usage: loop6-snapimg.sh <build tag>   (needs build.sh <tag> first)
. /data/hark/spike-rv/env.sh
T=${1:-b}; W=/data/hark/spike-rv/loop6; L=/data/hark/logs/rv; G=riscv32im-unknown-none-elf; P=/data/hark/target-l6$T
B=$P-host/release/engine-diff
cd $W && mkdir -p poc && rm -rf snap-liq7 snap-liq7b snap-gen snap-genb
dw(){ sed 's/.*"snapshot_words":\([0-9]*\),"digest":"\([0-9a-f]*\)".*/\2:\1/'; }
$B liqgen 7 60 poc/liq7.bin > /dev/null
D=$($B snapdir poc/liq7.bin 60 2 snap-liq7 | dw)
$B snapdir poc/liq7.bin 60 3 snap-liq7b > /dev/null
$B genbig 9 300 poc/gen9.bin > /dev/null
# loop round 5 (R4-M4): the prod image binds heights -> its fixture's export digest is built with "bind"
DG=$($B snapdir poc/gen9.bin 70 2 snap-gen bind | dw)
$B snapdir poc/gen9.bin 70 3 snap-genb bind > /dev/null
echo "expect $D $DG" > $L/l6$T-snapimg.log
cd $W/guest-engine
MNPILOT_IMPORT_DIGEST=$D CARGO_TARGET_DIR=$P-gimp cargo build --release --target $G 2>&1 | grep -E '^(warning|error)|Finished' >> $L/l6$T-snapimg.log
MNPILOT_IMPORT_DIGEST=$DG CARGO_TARGET_DIR=$P-gimpprod cargo build --release --features prod --target $G 2>&1 | grep -E '^(warning|error)|Finished' >> $L/l6$T-snapimg.log
cd $W/js
IMPORT_ELF=$P-gimp/$G/release/rvengine OTHER_SNAP=$W/snap-liq7b/snap.bin node snapguest.js $P-g/$G/release/rvengine $W/snap-liq7 > $L/l6$T-snapguest.log 2>&1
PROD=1 IMPORT_ELF=$P-gimpprod/$G/release/rvengine OTHER_SNAP=$W/snap-genb/snap.bin node snapguest.js $P-gprod/$G/release/rvengine $W/snap-gen > $L/l6$T-snapguest-prod.log 2>&1
tail -1 $L/l6$T-snapguest.log >> $L/l6$T-snapimg.log; tail -1 $L/l6$T-snapguest-prod.log >> $L/l6$T-snapimg.log
echo SNAPIMGDONE >> $L/l6$T-snapimg.log
