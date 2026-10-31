#!/bin/bash
# loop round 10 (R7-L3 govwit full suite): usage: loop10-build.sh <tag>  -> /data/hark/target-l10<tag>-{host,host-d8,g,g-d8,gembed,gprod}
. /data/hark/spike-rv/env.sh
T=$1; W=/data/hark/spike-rv/loop10; L=/data/hark/logs/rv; G=riscv32im-unknown-none-elf; P=/data/hark/target-l10$T
f(){ grep -E '^(warning|error)|-->|Finished'; }
( cd $W/engine-diff && CARGO_TARGET_DIR=$P-host cargo build --release --features govwit 2>&1 | f
  cd $W/engine-diff && CARGO_TARGET_DIR=$P-host-d8 cargo build --release --features depth8,govwit 2>&1 | f
  cd $W/guest-engine && CARGO_TARGET_DIR=$P-g cargo build --release --features govwit --target $G 2>&1 | f
  cd $W/guest-engine && CARGO_TARGET_DIR=$P-g-d8 cargo build --release --features depth8,govwit --target $G 2>&1 | f
  cd $W/guest-engine && CARGO_TARGET_DIR=$P-gembed cargo build --release --features embed,govwit --target $G 2>&1 | f
  cd $W/guest-engine && CARGO_TARGET_DIR=$P-gprod cargo build --release --features prod,govwit --target $G 2>&1 | f
  sha1sum $P-host/release/engine-diff $P-host-d8/release/engine-diff $P-g/$G/release/rvengine $P-g-d8/$G/release/rvengine $P-gembed/$G/release/rvengine $P-gprod/$G/release/rvengine
) > $L/l10$T-build.log 2>&1
echo BUILDDONE >> $L/l10$T-build.log
