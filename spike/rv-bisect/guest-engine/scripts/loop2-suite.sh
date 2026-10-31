#!/bin/bash
# loop round 2 full suite (VM). Logs /data/hark/logs/rv/l2-*. Binaries from build.sh (target-l2-*).
. /data/hark/spike-rv/env.sh
W=/data/hark/spike-rv/loop2; L=/data/hark/logs/rv; G=riscv32im-unknown-none-elf
B=/data/hark/target-l2-host/release/engine-diff
B8=/data/hark/target-l2-host-d8/release/engine-diff
E=/data/hark/target-l2-g/$G/release/rvengine
E8=/data/hark/target-l2-g-d8/$G/release/rvengine
EE=/data/hark/target-l2-gembed/$G/release/rvengine
sha1sum $B $B8 $E $E8 $EE > $L/l2-bins.txt
mkdir -p $W/poc/robust $W/poc/robust-limit $W/poc/guest $W/scen-l2 $W/extra $W/d8 $W/proofs $W/sail
rm -f $W/poc/robust/*.bin
$B robust $W/poc/robust > /dev/null && mv -f $W/poc/robust/limit_max_accounts_units.bin $W/poc/robust-limit/
cp $W/poc/robust-limit/limit_max_accounts_units.bin $W/poc/robust/
{ $B selftest $W/poc/robust; $B depthsel; $B8 depthsel; } > $L/l2-selftest.log
rm -f $W/poc/robust/limit_max_accounts_units.bin
# batches
$B crowd 256 64 $W/poc/crowdmax.bin > /dev/null; $B crowd 30 60 $W/poc/crowd1800.bin > /dev/null; $B crowd 8 20 $W/poc/crowd168.bin > /dev/null
$B gen 3 12 50 2 14000 $W/poc/genmax.bin stress > /dev/null; $B advgen 7 16000 $W/poc/advmax.bin > /dev/null
$B frag $W/poc/frag.bin > /dev/null; $B frag $W/poc/frag16.bin 16 6000 > /dev/null
for f in crowd168 crowd1800 crowdmax genmax advmax frag frag16; do echo "$f $($B heapsim $W/poc/$f.bin)"; done > $L/l2-heapsim.log
echo "limit $($B heapsim $W/poc/robust-limit/limit_max_accounts_units.bin)" >> $L/l2-heapsim.log
# W2 grinding (account key pairs) + proofs for the Oscript verifier
: > $L/l2-grind.log
for s in 1 2 3; do for m in target any; do
  $B grind $s 12 $m $W/poc/grind$s$m.bin >> $L/l2-grind.log
  $B proofdump $W/poc/grind$s$m.bin > $W/proofs/grind$s$m.json
done; done
$B gen 3 12 50 2 1000 $W/poc/g1000.bin stress > /dev/null; $B proofdump $W/poc/g1000.bin > $W/proofs/g1000.json
for s in 5 6 7; do $B advgen $s 400 $W/poc/adv$s.bin > /dev/null; $B proofdump $W/poc/adv$s.bin > $W/proofs/adv$s.json; done
# (the Oscript verifier js/smtverify.js runs where ocore 0.4.8 is vendored -- the sandbox -- on these proofs)
# long guest jobs in parallel: limit batch; crowd1800 / frag16 / grind through the guest
(cd $W/js && node robust.js $B $E $W/poc/robust-limit > $L/l2-robust-limit.log 2>&1) & PL=$!
cp $W/poc/crowd1800.bin $W/poc/frag16.bin $W/poc/grind1any.bin $W/poc/guest/
(cd $W/js && node robust.js $B $E $W/poc/guest > $L/l2-guest-poc.log 2>&1) & PG=$!
# native diff suite (parallel)
($B fuzz 300 300 > $L/l2-fuzz.log 2>&1) & P1=$!
($B witfuzz 300 300 300 > $L/l2-witfuzz.log 2>&1) & P2=$!
($B advfuzz 300 300 > $L/l2-advfuzz.log 2>&1; $B proofs 300 25 > $L/l2-proofs.log 2>&1; $B scen $W/engine-diff/scenarios/upstream.scn $W/scen-l2 > $L/l2-scen.log 2>&1)
wait $P1 $P2
# depth rule (MAX_WIT_DEPTH = 8 build): host checks + guest(d8) vs host(d8)
rm -f $W/d8/*.bin; $B8 depth8 20 $W/d8 > $L/l2-depth8.log 2>&1
(cd $W/js && node robust.js $B8 $E8 $W/d8 > $L/l2-depth8-guest.log 2>&1) & G0=$!
# guest (JS model) diffs
$B gen 11 10 50 2 100 $W/extra/depth200-n100.bin > /dev/null; $B gen 12 10 50 2 300 $W/extra/stress200-n300.bin stress > /dev/null
for s in 21 22 23; do $B advgen $s 300 $W/extra/adv$s.bin > /dev/null; done
cp $W/poc/crowd168.bin $W/extra/
(cd $W/js && node witscen.js $B $E $W/scen-l2 > $L/l2-scen-guest.log 2>&1) & G1=$!
(cd $W/js && node witscen.js $B $E $W/extra > $L/l2-extra-guest.log 2>&1) & G2=$!
(cd $W/js && node robust.js $B $E $W/poc/robust > $L/l2-robust.log 2>&1) & G3=$!
wait $G0 $G1 $G2 $G3
# sail spot-check (embed build)
: > $L/l2-sail.log
for f in $W/scen-l2/bnd_fee_guard_equity_clause.bin $W/poc/crowd168.bin $W/poc/robust/insurance_author.bin $W/poc/robust/ops_over_limit.bin $W/extra/adv21.bin; do
  n=$(basename $f .bin)
  R=$($B portout $f | node -e 'console.log(JSON.parse(require("fs").readFileSync(0)).hash)')
  echo "$n expected_hash $R" >> $L/l2-sail.log
  (cd $W/xval && node witsail.js $EE $f $W/sail/l2-$n $R) >> $L/l2-sail.log 2>&1
  rm -f $W/sail/l2-$n/mem.*.bin
done
echo SAILDONE >> $L/l2-sail.log
echo SUITE_MAIN_DONE >> $L/l2-bins.txt
wait $PL $PG
echo SUITEDONE >> $L/l2-bins.txt
