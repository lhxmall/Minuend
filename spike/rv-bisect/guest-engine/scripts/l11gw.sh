#!/bin/bash
# loop round 11 step 2: govwit as the DEFAULT feature (work/govwit-default.patch applied in /data/hark/spike-rv/loop11gw;
# loop11 sources otherwise). Builds the default (no --features) host / guest / prod targets, checks that the default
# binaries behave as the round-10 govwit build, and reruns the tests the commitment touches:
# govedge / govfuzz / xfuzz / witfuzz / segfuzz / proofs / govwit leaf-flip, govgen 41..43 through the JS guest,
# prodheight, snapguest (default + prod upgrade images). Log l11gw.log, GWDONE at the end.
. /data/hark/spike-rv/env.sh
L=/data/hark/logs/rv; O=$L/l11gw.log; W=/data/hark/spike-rv/loop11gw; G=riscv32im-unknown-none-elf; P=/data/hark/target-l11gw
f(){ grep -E '^(warning|error)|-->|Finished'; }
for p in "l10h-hostgw l11gw-host" "l10h-g l11gw-g" "l10h-gprod l11gw-gprod"; do set -- $p; [ -d /data/hark/target-$2 ] || cp -a /data/hark/target-$1 /data/hark/target-$2; done
cd $W && find guest-engine engine-diff -name '*.rs' -exec touch {} + && touch guest-engine/Cargo.toml engine-diff/Cargo.toml
{ grep -n 'default = \["govwit"\]' guest-engine/Cargo.toml engine-diff/Cargo.toml
  (cd $W/engine-diff && CARGO_TARGET_DIR=$P-host cargo build --release 2>&1 | f)
  (cd $W/guest-engine && CARGO_TARGET_DIR=$P-g cargo build --release --target $G 2>&1 | f)
  (cd $W/guest-engine && CARGO_TARGET_DIR=$P-gprod cargo build --release --features prod --target $G 2>&1 | f)
  sha1sum $P-host/release/engine-diff $P-g/$G/release/rvengine $P-gprod/$G/release/rvengine; echo BUILT; } > $O 2>&1
B=$P-host/release/engine-diff
{ echo "govedge $($B govedge | tail -1 | cut -c1-200)"; echo "govwit $($B govwit | tail -1 | cut -c1-200)"
  echo "govfuzz $($B govfuzz 100 300 | tail -1 | cut -c1-200)"; echo "xfuzz $($B xfuzz 100 300 | tail -1 | cut -c1-200)"
  echo "witfuzz $($B witfuzz 100 300 100 | tail -1 | cut -c1-200)"; echo "segfuzz $($B segfuzz 100 300 | tail -1 | cut -c1-200)"
  echo "proofs $($B proofs 30 25 | tail -1 | cut -c1-300)"; } >> $O 2>&1
mkdir -p $W/govg && rm -f $W/govg/*.bin; for s in 41 42 43; do $B govgen $s 300 $W/govg/gov$s.bin > /dev/null; done
(cd $W/js && node witscen.js $B $P-g/$G/release/rvengine $W/govg > $L/l11gw-govguest.log 2>&1; tail -n 2 $L/l11gw-govguest.log >> $O)
(cd $W/js && node prodheight.js $P-gprod/$G/release/rvengine $P-g/$G/release/rvengine > $L/l11gw-prodheight.log 2>&1; tail -n 1 $L/l11gw-prodheight.log >> $O)
# snapguest: upgrade images built without --features (govwit by default)
cd $W && mkdir -p poc && rm -rf snap-liq7 snap-liq7b snap-gen snap-genb
dw(){ sed 's/.*"snapshot_words":\([0-9]*\),"digest":"\([0-9a-f]*\)".*/\2:\1/'; }
$B liqgen 7 60 poc/liq7.bin > /dev/null; D=$($B snapdir poc/liq7.bin 60 2 snap-liq7 | dw); $B snapdir poc/liq7.bin 60 3 snap-liq7b > /dev/null
$B genbig 9 300 poc/gen9.bin > /dev/null; DG=$($B snapdir poc/gen9.bin 70 2 snap-gen bind | dw); $B snapdir poc/gen9.bin 70 3 snap-genb bind > /dev/null
echo "snap expect $D $DG" >> $O
for p in "l10gw-gimp l11gw-gimp" "l10gw-gimpprod l11gw-gimpprod" "l10g-gimp l11gw-gimp" "l10g-gimpprod l11gw-gimpprod"; do set -- $p; [ -d /data/hark/target-$2 ] || { [ -d /data/hark/target-$1 ] && cp -a /data/hark/target-$1 /data/hark/target-$2; }; done
(cd $W/guest-engine && MNPILOT_IMPORT_DIGEST=$D CARGO_TARGET_DIR=$P-gimp cargo build --release --target $G 2>&1 | f
 MNPILOT_IMPORT_DIGEST=$DG CARGO_TARGET_DIR=$P-gimpprod cargo build --release --features prod --target $G 2>&1 | f) >> $O
(cd $W/js && IMPORT_ELF=$P-gimp/$G/release/rvengine OTHER_SNAP=$W/snap-liq7b/snap.bin node snapguest.js $P-g/$G/release/rvengine $W/snap-liq7 > $L/l11gw-snapguest.log 2>&1
 PROD=1 IMPORT_ELF=$P-gimpprod/$G/release/rvengine OTHER_SNAP=$W/snap-genb/snap.bin node snapguest.js $P-gprod/$G/release/rvengine $W/snap-gen > $L/l11gw-snapguest-prod.log 2>&1)
tail -1 $L/l11gw-snapguest.log >> $O; tail -1 $L/l11gw-snapguest-prod.log >> $O
echo GWDONE >> $O
