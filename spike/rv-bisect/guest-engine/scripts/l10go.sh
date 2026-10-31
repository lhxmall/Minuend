#!/bin/bash
# loop round 10 (R7-L3): full suite on the govwit build. Seeds target-l10g-* from l9w (incremental), builds, snapimg, suite.
L=/data/hark/logs/rv; H=/data/hark
for p in "l9w-host l10g-host" "l9w-g l10g-g"; do set -- $p; [ -d $H/target-$2 ] || cp -a $H/target-$1 $H/target-$2; done
cd /data/hark/spike-rv/loop10 && find guest-engine engine-diff -name '*.rs' -exec touch {} + && ./loop10-build.sh g
cp loop10-snapimg.sh snapimg.sh
./loop10-suite.sh g > $L/l10-suite.out 2>&1
