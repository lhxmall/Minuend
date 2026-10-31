# spike/rv-bisect — RISC-V bisection fraud proof on Obyte (feasibility spike)

Prototype only. Not wired into the rollup; not audited. Report (Chinese): `work/spike-rv-report.md` in the Hark project workspace.

## Files
- `aa/rv_step.oscript` — rv32im one-step oracle (Oscript init body). `aa/rv_step.aa` = deployable wrapper
  (memo `var['s_' || pre_root] = post_root`). Real ocore validation: **complexity 10 / 100, ops 1850 / 2000**.
- `aa/rv_game.oscript` + `js/mkgame.js` → `aa/rv_game.aa` — K-ary (K=16) bisection game: claim / open / mids / pick /
  resolve / finalize, bonds, per-move timeout, final decision from the rv_step memo. **complexity 15, ops 868**
  (after the adversarial fixes). `mkgame.js` bakes in the real rv_step address (chash160 of `aa/rv_step.aa`).
- `js/ref.js` — JS reference rv32im semantics + sparse word-Merkle memory (Obyte merkle hashing, depth D=24).
- `js/oc.js` — real-ocore harness (validateAADefinition + formula evaluate with shared state vars).
- `js/difftest.js` — random differential test Oscript vs reference (`SEED=.. N=..`).
- `js/sim.js` — end-to-end game on the ocore evaluator (lying operator / griefing challenger / timeout).
- `js/elfrun.js`, `js/realtrace.js` — run a compiled riscv32im ELF on the reference emulator; check sampled
  steps of the real trace against the Oscript one-step AA.
- `guest/` — no_std riscv32im guest (sha256 / ed25519-dalek verify_strict / BTreeMap order-book workload),
  built with rustc 1.99 `--target riscv32im-unknown-none-elf`.

## State commitment
`state_root = sha256(pc ':' join(regs, ',') ':' mem_root ':' inp_root ':' step)` (base64).
Memory = 2^D 32-bit words, Obyte merkle (`leaf = H(String(word))`, `node = H(left + right)`), zero subtrees
precomputed. Input (batch data) = separate read-only word tree `inp_root`, read with `ecall a7=63 (a0 = word index)`.
`ecall a7=93` → HALT (pc=2). Illegal / misaligned / out-of-range → TRAP (pc=1). pc ≡ 1,2 (mod 4) are absorbing no-op steps.

## Results (2026-10-30)
- difftest: 26 000+ random instructions, 0 mismatches; 3 injected bugs all detected.
- real compiled trace (sha256 guest, 16 186 steps): 2 313 sampled steps checked by the Oscript AA, 0 mismatches;
  ed25519 guest first 700 000 steps, 703 sampled, 0 mismatches. The guest's own results are correct
  (sha256 word matches Node, ed25519 verify_strict returns valid) → reference semantics agree with rustc/LLVM output.
- game sim (487-step trace): lie at step 137 → narrowed to step 136 in 3 rounds (10 moves), challenger wins;
  honest operator vs griefing challenger → defender wins; operator times out → challenger wins.
- instruction counts (riscv32im, opt-level 3): sha256(200 B) ≈ 16 k; ed25519 verify_strict ≈ 2.86 M;
  BTreeMap order insert ≈ 1 k each.

## Adversarial testing (2026-10-30, run on the InstaBox VM)
Loop: attack -> fix -> rerun the full suite, until one pass finds nothing new (3 passes).
- `js/rvtests.js` + `rvtests/` (cpp + rustc `global_asm!`, no gcc cross toolchain): official riscv-tests rv32ui (42) + rv32um (8),
  **every step** re-checked by the Oscript AA: 13 731 steps, 0 mismatches; 48/50 pass, `ma_data` / `fence_i` TRAP by design
  (misaligned access and fence.i are unsupported).
- `js/attack.js` (real ocore evaluator, 300 cases + random-adversary fuzz, `FUZZ=150 FUZZSEED=7`): lying operator /
  lying challenger at first / middle / last step in reg / pc / mem / step / input root, both sides lying, forged Merkle proofs,
  malformed inputs, instruction edge cases, protocol abuse, exact deadlines, concurrent challenges, bond accounting, ops.
- `js/devnet.js` (aa-testkit devnet, real units / bounces / payment outputs): 27 cases.
- Bugs found and fixed in `rv_game`: (A) payout `2*BOND` per game drained the AA (the claim bond was paid out once per game);
  (B) roots containing `:` / `,` corrupted the `:`-joined records (stuck game, or a forged claim finalized without a window);
  (C) a fraudster's sock-puppet challenger could win back the whole claim bond (now half is burned);
  (D) the hard-coded rv_step address was not the real one (every one-step dispute would time out in the liar's favour).
- Pass 3 (final): 300/300 evaluator, 2x150 fuzz games, devnet 27/27, riscv-tests unchanged.
- Open: the claim's `s0` must be bound by the rollup (prev finalized root + batch input root); the challenger must post the
  rv_step memo before the one-step deadline. (sail-riscv differential run: done 2026-10-31, see below.)

## Rollup prototype (2026-10-31)
Design doc (Chinese, beginner level, full flow + constants + costs + gaps): `docs/rv-dispute-design.md`.
- `aa/rv_rollup.oscript` + `js/mkrollup.js` -> `aa/rv_rollup.aa` (complexity 42, ops **750**, address
  `W4BAKM5O2QOOBYTUY3FPKAICE5SY35BP`): heights submitted in order (`h == top + 1`, one live submission per height = the race),
  operator bond OBOND 200000, `s0` computed by the AA (pc 0, regs 0, previous final memory root / GENMEM, this batch's input
  root, step 0), final root must be a halted/trapped state whose parts are given in clear; challengers open parallel games
  (**CBOND 120000**, decided 2026-10-31; GF 10000 forwarded to the referee); a lost game = fraud: first winner gets
  CBOND-GF-FEE+OBOND/2 = 208000, a griefer's bond pays the operator CBOND-GF-FEE = 108000; a live fraudulent h voids h..top
  (`top = h-1`) and the race restarts at h; finalize in order after WIN 86400 s with zero open games (198000 back); voided
  non-fraud submissions reclaim 198000 after their games end. MAXSTEPS stays 2^40.
- Overpayment refunds (2026-10-31): submit refunds `paid - OBOND - FEE` (its own response unit; <= FEE kept), open refunds
  `paid - CBOND` in full (extra output on the unit that pays GF), referee direct open refunds `paid - GF`, resolve keeps
  RK 10000 and refunds the rest, mids/pick keep MK 2000 (unchanged). finalize/reclaim triggers still keep their 10000.
- Burned half of a fraudulent operator's bond (OBOND/2 per fraud, `var['burned']`) stays **permanently locked** in the rollup
  AA: no command pays it out (true burn). Any exit (a treasury or a challenger reward pool) brings back either a trusted key or a
  way for the fraudster's own puppet challenger to recoup it (owner decision 2026-10-31).
- `aa/rv_game_ref.oscript` + `js/mkref.js` -> `aa/rv_game_ref.aa` (complexity 10, ops **848**, address
  `W7OQFFFU6446637YBHIA7B74L6X4ZO5B`): the same 16-ary bisection as `rv_game` in referee mode (no bonds; result called back to
  the opener `{res, w: 'd'|'c'}` with GB 1000); move timeout 3600 s; keeps MK 2000 of each mids/pick trigger and refunds the
  rest (attack pass 2). `rv_step` unchanged (ops **1850**, `7USF3LMWZF53XJGAM2SS2QIQSTHD3YNA`).
- Tests: `js/rolltest.js` (real ocore evaluator, multi-AA chain in `js/chain.js`) **209/209** (new group `overpay`, 33);
  `js/rolldevnet.js` (aa-testkit devnet) **119/119** with `max_aa_responses` set and again with `NOMAXR=1`, incl. operator /
  challenger timeouts, two games on one height, fraud voiding with late callbacks and reclaim, and (section 7) real refund
  outputs for overpaid submit / open / resolve / direct referee open. riscv-tests 48/50 (unchanged).
- `max_aa_responses` (test client): every trigger sets it to its real response-chain length — 1 for submit / finalize /
  reclaim / mids / pick / rv_step / direct referee open, 2 for rollup open (rollup -> referee) and resolve (referee -> rollup);
  verified against `count_aa_responses` in the node's sqlite, none exceeded. Devnet, 101 triggers: prepaid tps fee 48,545 with
  vs 7,255,120 without; **settled tps fee identical (25,328 vs 25,306)** because ocore settles on `1 + count_aa_responses`, not
  on the cap. So it cuts the prepayment (excess otherwise becomes non-withdrawable tps-fee credit), not the final cost
  (earlier "4-5x lower tps fee" claim corrected). Downside: a lower prepayment can fall under the parentable threshold
  (3 x current tps fee): the two simultaneous race submits were skipped as parents for 253 s on devnet. +24 bytes per unit.
  `js/tpscmp.js` reports prepaid / settled / response counts per trigger type.
- tps fee: the 1,205,193-byte tps fee seen without `max_aa_responses` is a devnet prepayment artifact (first AA trigger of each
  wallet, last ball with the same timestamp, x11 units); settled 224. `js/tpsdiag.js` reproduces the analysis.
- Known gaps: finalize/reclaim trigger bytes not refunded; each fraud voiding costs the fraudster only OBOND/2 (sock-puppet first
  challenger); DA unsolved; 2^40 step cap; operators/challengers cannot be AAs; challenger must be online; the Minuend engine is not yet ported to a no_std riscv32im guest.

## Cross-validation against sail-riscv (2026-10-31) — `xval/`
Independent reference: **sail-riscv 0.16** (the RISC-V International formal model; C++ emulator generated by Sail),
**built from source on the VM** under `/data/hark/spike-rv/xval/` (prebuilt Sail 0.20.3 compiler, CMake 3.31.6 binary
tarball, m4 1.4.19 from source for GMP's configure, GMP 6.3.0 fetched by sail-riscv's CMake; nothing system-wide; ~13 min).
Chosen over Spike/rvemu because it is the ISA's golden model and built in reasonable time. The official 0.16 release binary
was run as well as a build cross-check (identical results).
- `xval/mkconfig.py` derives two configs from `sail_riscv_sim --rv32 --print-default-config`:
  `rv32im-strict.json` = I + M (+ Zicsr, needed for machine-mode traps) only, RAM exactly `[0, 64 MiB)` like rv_step's
  2^24-word memory, nothing else mapped (CLINT / dtb moved out), misaligned load/store -> AlignmentException, no Zifencei;
  `rv32im-relaxed.json` = same with misaligned access allowed and Zifencei on (to expose rv_step's deliberate TRAP choices).
  The run regenerates both from the source-built binary and checks they are byte-identical to the committed ones.
- Comparison, **every executed step**: sail's trace (`--trace-instr --trace-gpr --trace-mem --trace-exception --trace-step`)
  is replayed into a shadow pc / 32 regs / memory, compared with the JS model (`js/ref.js`) after each step: pc, all 32
  registers, and every memory word written by either side (both start from the same ELF image). The rv_step AA on the real
  ocore evaluator is checked on the same steps (pre and post state roots == the JS model's), so rv_step == JS == sail.
  Where only one side traps, the step is classified: rv_step's documented choices (`ecall a7=93` HALT, `a7=63` input read,
  FENCE / FENCE.I / CSR / MRET / WFI / EBREAK / misaligned -> TRAP) are `spec:*`; anything else is a bug. rv_step has one TRAP
  sentinel (pc 1, no mcause/mepc), so for both-trap steps only "both trap, no register / memory change" is compared.
- `xval/xtests.js`: riscv-tests rv32ui + rv32um, strict config: **50 tests, 13 731 steps, all compared with sail and all
  re-checked by rv_step on ocore: 0 mismatches** (48 end in `ecall` HALT = spec; `ma_data` misaligned load and `fence_i` both
  trap in sail too). Relaxed config: 0 bugs, the two expected `spec` divergences (sail allows the misaligned load, executes
  fence.i as a nop).
- `xval/xfuzz.js`: random single steps. Each case is a tiny ELF (written by `lib.js`): a 62-instruction lui/addi preamble that
  loads a random/edge register file, the fuzzed instruction at a random pc (incl. the last memory word), a second random
  instruction, and planted data words around the effective address. All 53 classes: every rv32im instruction + fence / fence.i /
  ecall (a7 = 93 / 63 / other) / ebreak / CSR / mret-wfi-sret / illegal encodings / random words. Edge values: x0 destination
  (1 713), signed overflow (106), div by zero (264), INT_MIN / -1 (129), shift >= 32 via register (598), misaligned branch
  targets (675) and jumps (205), sign-extending loads (485), unaligned loads (514) / stores (341), end of memory (274),
  out-of-range (535) and wrapping (168) effective addresses.
  **Strict, seed 1, 4 shards: 12 000 cases, 20 850 fuzzed steps (20 906 rv_step evaluations), 764 850 steps compared in
  total: 0 mismatches.** Relaxed, seed 2: 4 000 cases, 6 943 fuzzed steps, 0 bugs (spec only). Release binary, seed 3:
  2 000 cases + riscv-tests, 0 bugs.
- Harness self-test (`xval/mutants.sh`): bugs injected into a copy of `js/ref.js`, with rv_step switched off (`RVSTEP=0`),
  must be caught by the sail comparison alone: sltiu signed, lh zero-extending, remu-by-0, div INT_MIN/-1, sra logical,
  sll via register with a 6-bit count, jalr not clearing bit 0, sb byte mask, bge unsigned, mulhsu operands swapped, auipc
  without pc — **all caught** (see `xval/README.md` for counts). (`& 63` instead of `& 31` on the shift count is an
  equivalent mutant in JS, whose shift operators already use 5 bits.)
- Result: **no oracle bug found; rv_step and js/ref.js unchanged** (ops 1850, address `7USF3LMWZF53XJGAM2SS2QIQSTHD3YNA`),
  so the rollup sim / devnet were not rerun. Logs on the VM: `/data/hark/logs/rv/xval-*.log`, `xval-*-summary.json`.
