#!/bin/bash
# loop round 4 full suite (VM). Logs /data/hark/logs/rv/l7-*. Binaries from loop7-build.sh <tag> (target-l7<tag>-*), tag = $1 (default c).
# = loop3-suite.sh + liqfuzz / snaptest / capcheck / statecap, liquidation batches through the JS guest, snapshot +
# upgrade images through the guest (loop7-snapimg.sh), prod SetHeight (prodheight.js), rolltest + rolldevnet on the round-4 AAs.
. /data/hark/spike-rv/env.sh
T=${1:-c}; W=/data/hark/spike-rv/loop7; L=/data/hark/logs/rv; G=riscv32im-unknown-none-elf; P=/data/hark/target-l7$T
B=$P-host/release/engine-diff; B8=$P-host-d8/release/engine-diff
E=$P-g/$G/release/rvengine; E8=$P-g-d8/$G/release/rvengine; EE=$P-gembed/$G/release/rvengine; EP=$P-gprod/$G/release/rvengine
sha1sum $B $B8 $E $E8 $EE $EP > $L/l7-bins.txt
mkdir -p $W/poc/robust $W/poc/robust-limit $W/poc/guest $W/scen-l4 $W/extra $W/d8 $W/proofs $W/sail
rm -f $W/poc/robust/*.bin
$B robust $W/poc/robust > /dev/null && mv -f $W/poc/robust/limit_max_accounts_units.bin $W/poc/robust-limit/
cp $W/poc/robust-limit/limit_max_accounts_units.bin $W/poc/robust/
{ $B selftest $W/poc/robust; $B depthsel; $B8 depthsel; } > $L/l7-selftest.log 2>&1
rm -f $W/poc/robust/limit_max_accounts_units.bin
# batches + host heap simulation (S1b changed the level representation: re-measure)
$B crowd 256 64 $W/poc/crowdmax.bin > /dev/null; $B crowd 30 60 $W/poc/crowd1800.bin > /dev/null; $B crowd 8 20 $W/poc/crowd168.bin > /dev/null
$B gen 3 12 50 2 14000 $W/poc/genmax.bin stress > /dev/null; $B advgen 7 16000 $W/poc/advmax.bin > /dev/null
$B frag $W/poc/frag.bin > /dev/null; $B frag $W/poc/frag16.bin 16 6000 > /dev/null; $B grind 1 12 any $W/poc/grind1any.bin > /dev/null
for f in crowd168 crowd1800 crowdmax genmax advmax frag frag16 ; do echo "$f $($B heapsim $W/poc/$f.bin)"; done > $L/l7-heapsim.log 2>&1
echo "limit $($B heapsim $W/poc/robust-limit/limit_max_accounts_units.bin)" >> $L/l7-heapsim.log
# long guest jobs first (JS model): limit batch; crowd1800 / frag16 / grind1any; segments (default + prod image); big3k segments
(cd $W/js && node robust.js $B $E $W/poc/robust-limit > $L/l7-robust-limit.log 2>&1) & PL=$!
cp $W/poc/crowd1800.bin $W/poc/frag16.bin $W/poc/grind1any.bin $W/poc/guest/
(cd $W/js && node robust.js $B $E $W/poc/guest > $L/l7-guest-poc.log 2>&1) & PG=$!
# native diff suite
($B fuzz 300 300 > $L/l7-fuzz.log 2>&1; $B segfuzz 300 300 > $L/l7-segfuzz.log 2>&1) & P1=$!
($B witfuzz 300 300 300 > $L/l7-witfuzz.log 2>&1) & P2=$!
($B advfuzz 300 300 > $L/l7-advfuzz.log 2>&1; $B proofs 300 25 > $L/l7-proofs.log 2>&1; $B scen $W/engine-diff/scenarios/upstream.scn $W/scen-l4 > $L/l7-scen.log 2>&1)
wait $P1 $P2
# loop round 4: liquidation / ADL / withdraw / oracle ports, snapshot, account cap, heap bound
{ $B liqfuzz 300 300; $B snaptest 300 300; $B capcheck 50 200 8; $B capcheck 20 300 64; $B snapcap; $B liqedge; } > $L/l7-liq-snap-cap.log 2>&1
{ $B orafuzz 300 300; $B hbind 300 300; } > $L/l7-ora-hbind.log 2>&1
# loop round 6: governance + commit-reveal port, review caps
{ $B govedge; $B govfuzz 300 300 | tail -1; $B govcap; } > $L/l7-gov.log 2>&1
{ $B statecap 64 8 8; $B statecap 128 42 64; $B statecap 256 42 64; } > $L/l7-statecap.log 2>&1
mkdir -p $W/liqg; rm -f $W/liqg/*.bin; for s in 1 2 3 4 5 6; do $B liqgen $s 300 $W/liqg/liq$s.bin > /dev/null; done
for s in 1 2 3; do $B liqgen $s 300 $W/liqg/liq${s}v2.bin v2 > /dev/null; done; for s in 1 2 3 4; do $B oragen $s 300 $W/liqg/ora$s.bin > /dev/null; done; for s in 1 2 3 4 5 6; do $B govgen $s 300 $W/liqg/gov$s.bin > /dev/null; done
(cd $W/js && node witscen.js $B $E $W/liqg > $L/l7-liq-guest.log 2>&1) & G6=$!
(cd $W && ./snapimg.sh $T > /dev/null 2>&1; cd js && node prodheight.js $EP $E > $L/l7-prodheight.log 2>&1) & G7=$!
# segments bigger than one guest run (host): 20 000-unit upstream batch, S = 16 384 and S = 5 000 with a refused header
{ $B genbig 41 20000 $W/poc/big20k.bin; $B segrun $W/poc/big20k.bin 16384; $B segrun $W/poc/big20k.bin 5000 $W/seg-big20k 2; rm -rf $W/seg-big20k; } > $L/l7-segbig.log 2>&1
{ $B segrun $W/poc/advmax.bin 16384; $B segrun $W/poc/advmax.bin 5000 $W/seg-advmax 2; $B segrun $W/poc/advmax.bin 1000; rm -rf $W/seg-advmax; } > $L/l7-segbig-adv.log 2>&1
rm -rf $W/seg-small $W/seg-big3k; $B genbig 7 300 $W/poc/big300.bin > /dev/null; $B genbig 5 3000 $W/poc/big3k.bin > /dev/null
{ $B segrun $W/poc/big300.bin 90 $W/seg-small 2; $B segrun $W/poc/big3k.bin 700 $W/seg-big3k; } > $L/l7-segrun.log 2>&1
# depth rule (MAX_WIT_DEPTH = 8 build)
rm -f $W/d8/*.bin; $B8 depth8 20 $W/d8 > $L/l7-depth8.log 2>&1
# prod image: flags must be 0 (fl9 = advgen seed 9 has the market-2 flag)
$B advgen 9 50 $W/poc/fl9.bin > /dev/null
(cd $W/js && { echo "default $(node witrun.js $E $W/poc/fl9.bin | head -c 160)"; echo "prod $(node witrun.js $EP $W/poc/fl9.bin | head -c 160)"; } > $L/l7-prodflags.log 2>&1)
(cd $W/js && node segguest.js $E $W/seg-small > $L/l7-segguest-small.log 2>&1; PROD=1 node segguest.js $EP $W/seg-small > $L/l7-segguest-small-prod.log 2>&1) & G4=$!
(cd $W/js && node segguest.js $E $W/seg-big3k > $L/l7-segguest-big3k.log 2>&1) & G5=$!
(cd $W/js && node robust.js $B8 $E8 $W/d8 > $L/l7-depth8-guest.log 2>&1) & G0=$!
$B gen 11 10 50 2 100 $W/extra/depth200-n100.bin > /dev/null; $B gen 12 10 50 2 300 $W/extra/stress200-n300.bin stress > /dev/null
for s in 21 22 23; do $B advgen $s 300 $W/extra/adv$s.bin > /dev/null; done
cp $W/poc/crowd168.bin /data/hark/spike-rv/loop3/poc/crowdc256.bin $W/extra/; cp /data/hark/spike-rv/loop3/poc/crowdc256.bin $W/poc/
(cd $W/js && node witscen.js $B $E $W/scen-l4 > $L/l7-scen-guest.log 2>&1) & G1=$!
(cd $W/js && node witscen.js $B $E $W/extra > $L/l7-extra-guest.log 2>&1) & G2=$!
(cd $W/js && node robust.js $B $E $W/poc/robust > $L/l7-robust.log 2>&1) & G3=$!
wait $G0 $G1 $G2 $G3 $G6 $G7
# end to end: real prod guest memory -> rv_witbind / rv_witproof (sim chain on real ocore)
$B gen 13 10 50 2 300 $W/poc/e2e.bin > /dev/null; $B proofdump $W/poc/e2e.bin > $W/proofs/e2e.json
(cd /data/hark/spike-rv/roll7/js && OCORE=/data/hark/wt-all/vendor/aa-testkit/node_modules/ocore node witproofe2e.js $EP $W/poc/e2e.bin $W/proofs/e2e.json > $L/l7-witproof-e2e.log 2>&1)
# sail spot-check (embed build)
: > $L/l7-sail.log
for f in $W/scen-l4/bnd_fee_guard_equity_clause.bin $W/poc/crowd168.bin $W/poc/robust/insurance_author.bin $W/poc/robust/ops_over_limit.bin $W/extra/adv21.bin $W/poc/crowdc256.bin; do
  n=$(basename $f .bin)
  R=$($B portout $f | node -e 'console.log(JSON.parse(require("fs").readFileSync(0)).hash)')
  echo "$n expected_hash $R" >> $L/l7-sail.log
  (cd $W/xval && node witsail.js $EE $f $W/sail/l7-$n $R) >> $L/l7-sail.log 2>&1
  rm -f $W/sail/l7-$n/mem.*.bin
done
echo SAILDONE >> $L/l7-sail.log
echo SUITE_MAIN_DONE >> $L/l7-bins.txt
# rollup AAs (round 7: per-height timestamp in s0) on the sim chain and on a devnet (RV_MINGAP=1 there)
(cd /data/hark/spike-rv/roll7/js && export AATK=/data/hark/wt-all/vendor/aa-testkit OCORE=/data/hark/wt-all/vendor/aa-testkit/node_modules/ocore &&
  OUT=$L/l7-rolltest.json timeout 2400 node rolltest.js > $L/l7-rolltest.log 2>&1; node aacost.js > $L/l7-aacost.log 2>&1)
# rolldevnet (RV_MINGAP=1, devnet clock) runs separately: l7rd.sh -> l7-rolldevnet.log
wait $PL $PG $G4 $G5
echo SUITEDONE >> $L/l7-bins.txt
