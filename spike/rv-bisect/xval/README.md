# xval — rv_step / js/ref.js vs sail-riscv (independent reference)

Overview and results: `../README.md` ("Cross-validation against sail-riscv") and `../docs/rv-dispute-design.md` §7.1 (zh).
Machine-readable results of the 2026-10-31 run: `results-2026-10-31.json`.

## Files
| file | what |
|---|---|
| `mkconfig.py` | derive `rv32im-strict.json` / `rv32im-relaxed.json` from `sail_riscv_sim --rv32 --print-default-config` |
| `rv32im-strict.json` | I + M (+ Zicsr) only; RAM `[0, 64 MiB)` = rv_step memory; nothing else mapped; misaligned ld/st -> exception; no Zifencei |
| `rv32im-relaxed.json` | strict + misaligned ld/st allowed + Zifencei (shows rv_step's deliberate TRAP choices) |
| `lib.js` | run sail + parse its `--trace-step` trace, minimal ELF32 writer, sail shadow state, per-step compare + spec classification, rv_step-on-ocore check |
| `xtests.js` | riscv-tests ELFs (built by `../rvtests/build.sh`): JS vs sail every step, rv_step every step (`RVSTEP=0` to skip) |
| `xfuzz.js` | random single steps (`N`, `SEED`, `SHARD`/`SHARDS`, `RVSTEP`, `KEEP=1` keeps failing ELFs) |
| `mutants.sh` | harness self-test: bugs injected into a copy of `js/ref.js` (`XREF=`), must be caught by the sail comparison alone |
| `summarize.js` | merge summary lines of several logs |
| `build-sail.sh` | builds m4 + sail-riscv 0.16 from source under /data/hark/spike-rv/xval (run detached) |
| `run-xval.sh` | the full run (configs check, riscv-tests strict + relaxed, fuzz strict 4 shards + relaxed, release-binary cross-check, mutants) |

## Build of the reference (VM, everything under /data/hark/spike-rv/xval, no sudo, ~13 min)
```sh
X=/data/hark/spike-rv/xval; cd $X
curl -sLO https://github.com/rems-project/sail/releases/download/0.20.3-binary/sail-Linux-x86_64.tar.gz      # Sail compiler
curl -sLO https://github.com/Kitware/CMake/releases/download/v3.31.6/cmake-3.31.6-linux-x86_64.tar.gz
curl -sL -o sail-riscv-src-0.16.tgz https://github.com/riscv/sail-riscv/archive/refs/tags/0.16.tar.gz
# + m4 1.4.19 from source into $X/tools (GMP's configure needs m4; the VM has none)
export PATH=$X/tools/bin:$X/cmake-3.31.6-linux-x86_64/bin:$X/sail/bin:$PATH
cd sail-riscv-0.16 && cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DDOWNLOAD_GMP=TRUE -DENABLE_RISCV_TESTS=FALSE && cmake --build build -j4
# -> build/c_emulator/sail_riscv_sim   (script: build-sail.sh, run from $X; log /data/hark/logs/rv/xval-build.log)
```

## Run
```sh
cd /data/hark/spike-rv/xval/tree/xval        # copy of spike/rv-bisect/{js,aa,xval}
setsid nohup ./run-xval.sh > /data/hark/logs/rv/xval-run.out 2>&1 < /dev/null &      # ~20 min
# single pieces (cwd must be this dir; it has the package.json ocore needs; HOME=$PWD):
SAIL=.../sail_riscv_sim SAILCFG=$PWD/rv32im-strict.json OCORE=/data/hark/wt-all/vendor/aa-testkit/node_modules/ocore \
  XTMP=/data/hark/spike-rv/xval/tmp HOME=$PWD node xtests.js /data/hark/spike-rv/rvt/out/*.elf
... N=12000 SEED=1 SHARD=0 SHARDS=4 node xfuzz.js
```

## How a step is compared
- sail runs the same ELF with `--inst-limit (steps+1) --trace-instr --trace-gpr --trace-mem --trace-exception --trace-step`;
  each blank-line block is one step (a fetch fault has no instruction line: its pc is the exception's tval).
- Shadow state = ELF image + sail's register / memory writes. After every step: pc (from the next step's record), all 32
  registers, and every memory word written by either side must equal the JS model's.
- One side traps: classified as `spec:*` when it is one of rv_step's documented choices (ecall a7=93 HALT / a7=63 input read,
  FENCE, FENCE.I, CSR, MRET/WFI/SRET, misaligned access) — otherwise `BUG:*`. Both trap: `agree-trap:<sail cause>`, and
  neither side may have changed a register or memory word (rv_step has a single TRAP sentinel, no mcause/mepc).
- rv_step on the real ocore evaluator: pre and post state roots of the same step must equal the JS model's.

## Self-test (2026-10-31, `RVSTEP=0`, fuzz 3000 cases seed 99 + all riscv-tests)
| injected bug | fuzz cases flagged | riscv-tests flagged |
|---|---|---|
| sltiu signed compare | 115 | 2 |
| lh zero-extends | 9 | 6 |
| remu by 0 returns 0 | 14 | 1 |
| div INT_MIN / -1 returns 0 | 8 | 1 |
| sra logical | 22 | 3 |
| sll via register with 6-bit count | 44 | **0** |
| jalr keeps bit 0 | 15 | **0** |
| sb byte mask wrong | 19 | 5 |
| bge unsigned | 18 | 1 |
| mulhsu operands swapped | 52 | 1 |
| auipc without pc | 44 | 15 |

All 11 caught; two only by the fuzz. (`& 63` instead of `& 31` on the shift count is an equivalent mutant in JS.)
