#!/bin/bash
# usage: build.sh <tag>  -> /data/hark/target-l7<tag>-{host,host-d8,g,g-d8,gembed,gprod}
. /data/hark/spike-rv/env.sh
T=$1; W=/data/hark/spike-rv/loop7; L=/data/hark/logs/rv; G=riscv32im-unknown-none-elf; P=/data/hark/target-l7$T
f(){ grep -E '^(warning|error)|-->|Finished'; }
( cd $W/engine-diff && CARGO_TARGET_DIR=$P-host cargo build --release 2>&1 | f
  cd $W/engine-diff && CARGO_TARGET_DIR=$P-host-d8 cargo build --release --features depth8 2>&1 | f
  cd $W/guest-engine && CARGO_TARGET_DIR=$P-g cargo build --release --target $G 2>&1 | f
  cd $W/guest-engine && CARGO_TARGET_DIR=$P-g-d8 cargo build --release --features depth8 --target $G 2>&1 | f
  cd $W/guest-engine && CARGO_TARGET_DIR=$P-gembed cargo build --release --features embed --target $G 2>&1 | f
  cd $W/guest-engine && CARGO_TARGET_DIR=$P-gprod cargo build --release --features prod --target $G 2>&1 | f
  sha1sum $P-host/release/engine-diff $P-host-d8/release/engine-diff $P-g/$G/release/rvengine $P-g-d8/$G/release/rvengine $P-gembed/$G/release/rvengine $P-gprod/$G/release/rvengine
) > $L/l7$T-build.log 2>&1
echo BUILDDONE >> $L/l7$T-build.log
