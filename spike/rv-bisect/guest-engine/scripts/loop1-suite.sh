#!/bin/bash
# loop round 1 full suite (VM). Logs /data/hark/logs/rv/l1-*
. /data/hark/spike-rv/env.sh
W=/data/hark/spike-rv/loop1; L=/data/hark/logs/rv
B=/data/hark/target-l1-host/release/engine-diff
E=/data/hark/target-l1-g/riscv32im-unknown-none-elf/release/rvengine
EE=/data/hark/target-l1-gembed/riscv32im-unknown-none-elf/release/rvengine
(cd $W/engine-diff && CARGO_TARGET_DIR=/data/hark/target-l1-host cargo build --release 2>&1 | grep -E '^(warning|error)|-->|Finished') > $L/l1-build.log
(cd $W/guest-engine && CARGO_TARGET_DIR=/data/hark/target-l1-g cargo build --release --target riscv32im-unknown-none-elf 2>&1 | grep -E '^(warning|error)|-->|Finished') >> $L/l1-build.log
(cd $W/guest-engine && CARGO_TARGET_DIR=/data/hark/target-l1-gembed cargo build --release --features embed --target riscv32im-unknown-none-elf 2>&1 | grep -E '^(warning|error)|-->|Finished') >> $L/l1-build.log
sha1sum $B $E $EE > $L/l1-bins.txt
mkdir -p $W/poc/robust $W/poc/robust-limit $W/scen-l1 $W/extra
$B robust $W/poc/robust > /dev/null && mv -f $W/poc/robust/limit_max_accounts_units.bin $W/poc/robust-limit/
cp $W/poc/robust-limit/limit_max_accounts_units.bin $W/poc/robust/  # selftest/heapsim want it there too
$B selftest $W/poc/robust > $L/l1-selftest.log
rm -f $W/poc/robust/limit_max_accounts_units.bin
$B crowd 256 64 $W/poc/crowdmax.bin > /dev/null; $B crowd 30 60 $W/poc/crowd1800.bin > /dev/null; $B crowd 8 20 $W/poc/crowd168.bin > /dev/null
$B gen 3 12 50 2 14000 $W/poc/genmax.bin stress > /dev/null; $B advgen 7 16000 $W/poc/advmax.bin > /dev/null
for f in crowd168 crowd1800 crowdmax genmax advmax; do echo "$f $($B heapsim $W/poc/$f.bin)"; done > $L/l1-heapsim.log
echo "limit $($B heapsim $W/poc/robust-limit/limit_max_accounts_units.bin)" >> $L/l1-heapsim.log
# long guest job in parallel: the MAX_ACCOUNTS x MAX_UNITS limit batch through the guest
(cd $W/js && node robust.js $B $E $W/poc/robust-limit > $L/l1-robust-limit.log 2>&1) & PL=$!
# native diff suite (parallel)
($B fuzz 300 300 > $L/l1-fuzz.log 2>&1) & P1=$!
($B witfuzz 300 300 300 > $L/l1-witfuzz.log 2>&1) & P2=$!
($B advfuzz 300 300 > $L/l1-advfuzz.log 2>&1; $B proofs 300 25 > $L/l1-proofs.log 2>&1; $B scen $W/engine-diff/scenarios/upstream.scn $W/scen-l1 > $L/l1-scen.log 2>&1) 
wait $P1 $P2
# guest (JS model) diffs
$B gen 11 10 50 2 100 $W/extra/depth200-n100.bin > /dev/null; $B gen 12 10 50 2 300 $W/extra/stress200-n300.bin stress > /dev/null
for s in 21 22 23; do $B advgen $s 300 $W/extra/adv$s.bin > /dev/null; done
cp $W/poc/crowd168.bin $W/extra/
(cd $W/js && node witscen.js $B $E $W/scen-l1 > $L/l1-scen-guest.log 2>&1) & G1=$!
(cd $W/js && node witscen.js $B $E $W/extra > $L/l1-extra-guest.log 2>&1) & G2=$!
(cd $W/js && node robust.js $B $E $W/poc/robust > $L/l1-robust.log 2>&1) & G3=$!
wait $G1 $G2 $G3
# sail spot-check (embed build)
: > $L/l1-sail.log
for f in $W/scen-l1/bnd_fee_guard_equity_clause.bin $W/poc/crowd168.bin $W/poc/robust/insurance_author.bin $W/poc/robust/ops_over_limit.bin; do
  n=$(basename $f .bin)
  R=$($B portout $f | node -e 'console.log(JSON.parse(require("fs").readFileSync(0)).hash)')
  echo "$n expected_hash $R" >> $L/l1-sail.log
  (cd $W/xval && node witsail.js $EE $f $W/sail/l1-$n $R) >> $L/l1-sail.log 2>&1
  rm -f $W/sail/l1-$n/mem.*.bin
done
echo SAILDONE >> $L/l1-sail.log
# mutation test
cd $W && P=$W bash guest-engine/scripts/loop1-mut.sh
echo MUTDONE >> $L/l1-build.log
wait $PL
echo SUITEDONE >> $L/l1-build.log
