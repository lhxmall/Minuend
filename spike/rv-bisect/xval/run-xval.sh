#!/bin/bash
# Full cross-validation run on the InstaBox VM (everything under /data/hark). Detach it:
#   setsid nohup ./run-xval.sh > /data/hark/logs/rv/xval-run.out 2>&1 < /dev/null &
# Env: SAIL (source-built sail_riscv_sim), SAILREL (release binary, for a build cross-check), OCORE, N (fuzz cases), LOG dir.
set -u
cd "$(dirname "$0")"; H=$PWD
X=/data/hark/spike-rv/xval
export SAIL=${SAIL:-$X/sail-riscv-0.16/build/c_emulator/sail_riscv_sim}
SAILREL=${SAILREL:-$X/sail-riscv-Linux-x86_64/bin/sail_riscv_sim}
export OCORE=${OCORE:-/data/hark/wt-all/vendor/aa-testkit/node_modules/ocore}
export XTMP=${XTMP:-$X/tmp}; export HOME=$H
LOG=${LOG:-/data/hark/logs/rv}; N=${N:-12000}; RVT=${RVT:-/data/hark/spike-rv/rvt/out}
mkdir -p $XTMP $LOG
echo "== sail: $($SAIL --version) $SAIL"; $SAIL --build-info 2>&1 | head -5
# 1. configs: regenerate from THIS binary's defaults and compare with the committed ones
$SAIL --rv32 --print-default-config > $XTMP/rv32-default.json
python3 mkconfig.py $XTMP/rv32-default.json $XTMP && for c in strict relaxed; do cmp -s $XTMP/rv32im-$c.json rv32im-$c.json && echo "config $c identical" || echo "config $c DIFFERS"; done
$SAIL --config rv32im-strict.json --print-isa-string
# 2. riscv-tests, strict config, every step: JS vs sail AND rv_step on ocore
SAILCFG=$H/rv32im-strict.json node xtests.js $RVT/*.elf > $LOG/xval-tests-strict.log 2>/dev/null; tail -1 $LOG/xval-tests-strict.log
# 3. riscv-tests, relaxed config (shows the deliberate trap choices)
SAILCFG=$H/rv32im-relaxed.json RVSTEP=0 node xtests.js $RVT/*.elf > $LOG/xval-tests-relaxed.log 2>/dev/null; tail -1 $LOG/xval-tests-relaxed.log
# 4. random fuzz, strict, 4 shards in parallel, rv_step on the fuzzed steps
for s in 0 1 2 3; do SAILCFG=$H/rv32im-strict.json N=$N SEED=1 SHARD=$s SHARDS=4 node xfuzz.js > $LOG/xval-fuzz-strict-$s.log 2>/dev/null & done; wait
for s in 0 1 2 3; do tail -1 $LOG/xval-fuzz-strict-$s.log; done
# 5. fuzz, relaxed config (no rv_step), smaller
for s in 0 1; do SAILCFG=$H/rv32im-relaxed.json RVSTEP=0 N=4000 SEED=2 SHARD=$s SHARDS=2 node xfuzz.js > $LOG/xval-fuzz-relaxed-$s.log 2>/dev/null & done; wait
for s in 0 1; do tail -1 $LOG/xval-fuzz-relaxed-$s.log; done
# 6. release binary vs source build: same riscv-tests + 2000 fuzz cases
SAIL=$SAILREL SAILCFG=$H/rv32im-strict.json RVSTEP=0 node xtests.js $RVT/*.elf > $LOG/xval-tests-release.log 2>/dev/null; tail -1 $LOG/xval-tests-release.log
SAIL=$SAILREL SAILCFG=$H/rv32im-strict.json RVSTEP=0 N=2000 SEED=3 node xfuzz.js > $LOG/xval-fuzz-release.log 2>/dev/null; tail -1 $LOG/xval-fuzz-release.log
# 7. harness self-test: injected model bugs must be caught by the sail comparison alone
SAILCFG=$H/rv32im-strict.json RVT=$RVT ./mutants.sh 3000 > $LOG/xval-mutants.log 2>&1; cat $LOG/xval-mutants.log
echo XVAL-DONE
