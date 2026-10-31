#!/bin/bash
# loop round 10 (step 2): which proof fixtures / MNWIT1 roots change when govwit becomes the default?
# proofdump on the same batches with the govwit host (target-l10g-host) and the default host of the same sources (target-l9w-hostdef)
. /data/hark/spike-rv/env.sh
L=/data/hark/logs/rv; D=$L/l10-fx; mkdir -p $D; O=$L/l10-fx.log; : > $O
G=/data/hark/target-l10g-host/release/engine-diff; F=/data/hark/target-l9w-hostdef/release/engine-diff
while ! grep -q BUILDDONE $L/l10g-build.log 2>/dev/null; do sleep 20; done
cd $D
for s in 5 6 7; do $G advgen $s 400 adv$s.bin > /dev/null; done
$G gen 3 12 50 2 1000 g1000.bin stress > /dev/null
for s in 21 22 23; do $G govgen $s 300 gov$s.bin > /dev/null; done
for s in 1 2; do $G liqgen $s 300 liq$s.bin > /dev/null; done
for b in adv5 adv6 adv7 g1000 gov21 gov22 gov23 liq1 liq2; do
  $G proofdump $b.bin > $b.govwit.json; $F proofdump $b.bin > $b.default.json
  rg=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$b.govwit.json')).root)"); rd=$(node -e "console.log(JSON.parse(require('fs').readFileSync('$b.default.json')).root)")
  echo "$b govwit $rg default $rd $([ "$rg" = "$rd" ] && echo SAME || echo CHANGED)" >> $O
done
echo FXDONE >> $O
