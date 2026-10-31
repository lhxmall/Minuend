#!/bin/bash
# loop round 3 full suite (VM). Logs /data/hark/logs/rv/l3-*. Binaries from build.sh d (target-l3d-*).
. /data/hark/spike-rv/env.sh
W=/data/hark/spike-rv/loop3; L=/data/hark/logs/rv; G=riscv32im-unknown-none-elf; P=/data/hark/target-l3d
B=$P-host/release/engine-diff; B8=$P-host-d8/release/engine-diff
E=$P-g/$G/release/rvengine; E8=$P-g-d8/$G/release/rvengine; EE=$P-gembed/$G/release/rvengine; EP=$P-gprod/$G/release/rvengine
sha1sum $B $B8 $E $E8 $EE $EP > $L/l3-bins.txt
mkdir -p $W/poc/robust $W/poc/robust-limit $W/poc/guest $W/scen-l3 $W/extra $W/d8 $W/proofs $W/sail
rm -f $W/poc/robust/*.bin
$B robust $W/poc/robust > /dev/null && mv -f $W/poc/robust/limit_max_accounts_units.bin $W/poc/robust-limit/
cp $W/poc/robust-limit/limit_max_accounts_units.bin $W/poc/robust/
{ $B selftest $W/poc/robust; $B depthsel; $B8 depthsel; } > $L/l3-selftest.log 2>&1
rm -f $W/poc/robust/limit_max_accounts_units.bin
# batches + host heap simulation (S1b changed the level representation: re-measure)
$B crowd 256 64 $W/poc/crowdmax.bin > /dev/null; $B crowd 30 60 $W/poc/crowd1800.bin > /dev/null; $B crowd 8 20 $W/poc/crowd168.bin > /dev/null
$B gen 3 12 50 2 14000 $W/poc/genmax.bin stress > /dev/null; $B advgen 7 16000 $W/poc/advmax.bin > /dev/null
$B frag $W/poc/frag.bin > /dev/null; $B frag $W/poc/frag16.bin 16 6000 > /dev/null; $B grind 1 12 any $W/poc/grind1any.bin > /dev/null
for f in crowd168 crowd1800 crowdmax genmax advmax frag frag16 crowdcmax crowdc4k; do echo "$f $($B heapsim $W/poc/$f.bin)"; done > $L/l3-heapsim.log 2>&1
echo "limit $($B heapsim $W/poc/robust-limit/limit_max_accounts_units.bin)" >> $L/l3-heapsim.log
# long guest jobs first (JS model): limit batch; crowd1800 / frag16 / grind1any; segments (default + prod image); big3k segments
(cd $W/js && node robust.js $B $E $W/poc/robust-limit > $L/l3-robust-limit.log 2>&1) & PL=$!
cp $W/poc/crowd1800.bin $W/poc/frag16.bin $W/poc/grind1any.bin $W/poc/guest/
(cd $W/js && node robust.js $B $E $W/poc/guest > $L/l3-guest-poc.log 2>&1) & PG=$!
# native diff suite
($B fuzz 300 300 > $L/l3-fuzz.log 2>&1; $B segfuzz 300 300 > $L/l3-segfuzz.log 2>&1) & P1=$!
($B witfuzz 300 300 300 > $L/l3-witfuzz.log 2>&1) & P2=$!
($B advfuzz 300 300 > $L/l3-advfuzz.log 2>&1; $B proofs 300 25 > $L/l3-proofs.log 2>&1; $B scen $W/engine-diff/scenarios/upstream.scn $W/scen-l3 > $L/l3-scen.log 2>&1)
wait $P1 $P2
# segments bigger than one guest run (host): 20 000-unit upstream batch, S = 16 384 and S = 5 000 with a refused header
{ $B genbig 41 20000 $W/poc/big20k.bin; $B segrun $W/poc/big20k.bin 16384; $B segrun $W/poc/big20k.bin 5000 "" 2; } > $L/l3-segbig.log 2>&1
rm -rf $W/seg-small $W/seg-big3k; $B genbig 7 300 $W/poc/big300.bin > /dev/null; $B genbig 5 3000 $W/poc/big3k.bin > /dev/null
{ $B segrun $W/poc/big300.bin 90 $W/seg-small 2; $B segrun $W/poc/big3k.bin 700 $W/seg-big3k; } > $L/l3-segrun.log 2>&1
# depth rule (MAX_WIT_DEPTH = 8 build)
rm -f $W/d8/*.bin; $B8 depth8 20 $W/d8 > $L/l3-depth8.log 2>&1
# prod image: flags must be 0 (fl9 = advgen seed 9 has the market-2 flag)
$B advgen 9 50 $W/poc/fl9.bin > /dev/null
(cd $W/js && { echo "default $(node witrun.js $E $W/poc/fl9.bin | head -c 160)"; echo "prod $(node witrun.js $EP $W/poc/fl9.bin | head -c 160)"; } > $L/l3-prodflags.log 2>&1)
(cd $W/js && node segguest.js $E $W/seg-small > $L/l3-segguest-small.log 2>&1; node segguest.js $EP $W/seg-small > $L/l3-segguest-small-prod.log 2>&1) & G4=$!
(cd $W/js && node segguest.js $E $W/seg-big3k > $L/l3-segguest-big3k.log 2>&1) & G5=$!
(cd $W/js && node robust.js $B8 $E8 $W/d8 > $L/l3-depth8-guest.log 2>&1) & G0=$!
$B gen 11 10 50 2 100 $W/extra/depth200-n100.bin > /dev/null; $B gen 12 10 50 2 300 $W/extra/stress200-n300.bin stress > /dev/null
for s in 21 22 23; do $B advgen $s 300 $W/extra/adv$s.bin > /dev/null; done
cp $W/poc/crowd168.bin $W/poc/crowdc256.bin $W/extra/
(cd $W/js && node witscen.js $B $E $W/scen-l3 > $L/l3-scen-guest.log 2>&1) & G1=$!
(cd $W/js && node witscen.js $B $E $W/extra > $L/l3-extra-guest.log 2>&1) & G2=$!
(cd $W/js && node robust.js $B $E $W/poc/robust > $L/l3-robust.log 2>&1) & G3=$!
wait $G0 $G1 $G2 $G3
# end to end: real prod guest memory -> rv_witbind / rv_witproof (sim chain on real ocore)
$B gen 13 10 50 2 300 $W/poc/e2e.bin > /dev/null; $B proofdump $W/poc/e2e.bin > $W/proofs/e2e.json
(cd /data/hark/spike-rv/roll3/js && OCORE=/data/hark/wt-all/vendor/aa-testkit/node_modules/ocore node witproofe2e.js $EP $W/poc/e2e.bin $W/proofs/e2e.json > $L/l3-witproof-e2e.log 2>&1)
# sail spot-check (embed build)
: > $L/l3-sail.log
for f in $W/scen-l3/bnd_fee_guard_equity_clause.bin $W/poc/crowd168.bin $W/poc/robust/insurance_author.bin $W/poc/robust/ops_over_limit.bin $W/extra/adv21.bin $W/poc/crowdc256.bin; do
  n=$(basename $f .bin)
  R=$($B portout $f | node -e 'console.log(JSON.parse(require("fs").readFileSync(0)).hash)')
  echo "$n expected_hash $R" >> $L/l3-sail.log
  (cd $W/xval && node witsail.js $EE $f $W/sail/l3-$n $R) >> $L/l3-sail.log 2>&1
  rm -f $W/sail/l3-$n/mem.*.bin
done
echo SAILDONE >> $L/l3-sail.log
echo SUITE_MAIN_DONE >> $L/l3-bins.txt
wait $PL $PG $G4 $G5
echo SUITEDONE >> $L/l3-bins.txt
