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
  rv_step memo before the one-step deadline; no differential run against sail-riscv yet.

## Rollup prototype (2026-10-31)
Design doc (Chinese, beginner level, full flow + constants + costs + gaps): `docs/rv-dispute-design.md`.
- `aa/rv_rollup.oscript` + `js/mkrollup.js` -> `aa/rv_rollup.aa` (complexity 42, ops **729**): heights submitted in order
  (`h == top + 1`, one live submission per height = the race), operator bond OBOND 200000, `s0` computed by the AA
  (pc 0, regs 0, previous final memory root / GENMEM, this batch's input root, step 0), final root must be a halted/trapped
  state whose parts are given in clear; challengers open parallel games (CBOND 100000, GF 10000 forwarded to the referee);
  a lost game = fraud: first winner gets CBOND-GF-FEE+OBOND/2 = 188000, the other OBOND/2 is burned, a live fraudulent h
  voids h..top (`top = h-1`) and the race restarts at h; finalize in order after WIN 86400 s with zero open games
  (198000 back); voided non-fraud submissions reclaim 198000 after their games end.
- `aa/rv_game_ref.oscript` + `js/mkref.js` -> `aa/rv_game_ref.aa` (complexity 10, ops **840**): the same 16-ary bisection
  as `rv_game` in referee mode (no bonds; result called back to the opener `{res, w: 'd'|'c'}` with GB 1000); move timeout
  3600 s; keeps MK 2000 of each mids/pick trigger and refunds the rest (attack pass 2: without it an honest operator lost money
  on games deeper than ~1.7e7 steps). `rv_step` unchanged (ops **1850**).
- Tests: `js/rolltest.js` (real ocore evaluator, multi-AA chain in `js/chain.js`) **176/176**; `js/rolldevnet.js`
  (aa-testkit devnet) **104/104**, incl. operator / challenger timeouts, two games on one height, fraud voiding with late
  callbacks and reclaim. riscv-tests 48/50 (unchanged).
- Recommendation: CBOND 120000 (>= 2.2x the honest operator's worst-case cost at 2^40 steps), or keep 100000 and cap
  MAXSTEPS at 2^32.
- tps fee: the 1,205,193-byte tps fee seen on one pick in devnet runs 3/5 is a devnet artifact, not a cost that would build up
  on mainnet: the first AA trigger of each wallet prepays ocore's local tps estimate, and on devnet a unit's last ball usually
  has the same timestamp (elapsed 0 -> 1 s, 14 units/s, tps_interval 2, x11 units for an AA trigger without
  `max_aa_responses`). Settled actual fee 224; the rest stays as that address's tps-fee credit. Clients should still set
  `max_aa_responses` (1 for submit/mids/pick/finalize/reclaim, 2 for open/resolve) to cut mainnet tps fees ~4-5x.
  `js/tpsdiag.js` reproduces the analysis from a node's sqlite copy.
- Known gaps: overpayment not refunded; burned funds locked in the AA; each fraud voiding costs the fraudster only OBOND/2
  (sock-puppet first challenger); DA unsolved; 2^40 step cap; operators/challengers cannot be AAs; challenger must be online;
  no sail-riscv cross-check; the Minuend engine is not yet ported to a no_std riscv32im guest.
