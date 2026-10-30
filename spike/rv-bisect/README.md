# spike/rv-bisect — RISC-V bisection fraud proof on Obyte (feasibility spike)

Prototype only. Not wired into the rollup; not audited. Report (Chinese): `work/spike-rv-report.md` in the Hark project workspace.

## Files
- `aa/rv_step.oscript` — rv32im one-step oracle (Oscript init body). `aa/rv_step.aa` = deployable wrapper
  (memo `var['s_' || pre_root] = post_root`). Real ocore validation: **complexity 10 / 100, ops 1850 / 2000**.
- `aa/rv_game.oscript` + `js/mkgame.js` → `aa/rv_game.aa` — K-ary (K=16) bisection game: claim / open / mids / pick /
  resolve / finalize, bonds, per-move timeout, final decision from the rv_step memo. **complexity 14, ops 715**.
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
