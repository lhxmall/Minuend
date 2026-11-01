# rv loop round 22 — stateless global caps (`gcnt:0`), round-21 close-out (2026-11-01)

Branch `spike/rv-bisect`, parent 642ddf8 (round-21 head). Design: `docs/rv-stateless-guest.md` §2 (`gcnt:0`), §5
"Global caps (round 22)", §9 (export precondition), §11.8. Code: `guest-engine/src/stateless.rs` (`SlCaps` /
`SL_CAPS` / `SL_CAPS_PROD`, `gcnt_leaf` / `gcnt_of`, `AcctRec.f0`, loader section after the rank sub-trees,
`gcnt_delta` / `gcap_pre` / `gcap_ok`, end-root rewrite + catch-alls, builder `Need::Gcnt` + `t_gdrop`, migration
bound); `stateless/adl.rs` (test forgeries `t_adrop` 5 / 6); harness `engine-diff/src/sl.rs` (`slpoc22`, `sess_seg`
= the SESSION image on a synthetic pre-state, `seg_words2`). Box logs: `guest-engine/results-loop22/`. Notes:
work/rv-rollup-notes.md "Loop round 22". Pushes: Radicle first, then GitHub.

Status: **FINAL**

## Choice of the round-22 gap

Candidates (user list): stateless global account caps (R17-I3), stateless lineage export / migration path (R16-I2),
stale `cmt:` lazy deletion (R16-I1), DA / witness availability design in the AA. Picked the **global caps**: it is the
only one of the four where the two images could still produce different results for the same units (the session
refuses a first credit / listing / stake at its caps, the stateless image did not), it is a prerequisite of the export
path (an exported state must fit the session image: with `gcnt:0` that check is O(1)), and it is implementable and
testable within the round. Export itself, `cmt:` deletion and DA stay open (What remains).

## What was done

1. **Round-21 close-out**: mutant passes collected (Tests), the two non-equivalent survivors killed by new forgeries
   (`load-absent-check-off`: `t_adrop` 5 = a tree claimed absent while its `adlr:` leaf exists; `leftmost-skip-stub`:
   `t_adrop` 6 = the leftmost rank leaf sent as an opaque stub of its own hash with the second leaf's path expanded,
   used by P2 / P3b / P3c), plus `end-del-off` (an untested path: a rank sub-tree emptied in a segment) killed by
   `slpoc22` P0; equivalence notes in rv-loop-21 Tests; rv-loop-21 FINAL.
2. **Global caps (R16-I3 / R17-I3)**: aggregate leaf `gcnt:0` = (Account-map entries, PERP-ledger ids, markets, oracle
   bonds), always present, kept by delta over the records a segment loads; the session's `state_cap_ok` global rules
   on it for the op and a Reveal's inner op with the author (Deposit / Liquidate keeper; GovDeposit / GovWithdraw /
   Slash challenger; CreateMarket; Stake). Caps are consensus constants of the lineage (`SL_CAPS_PROD`); host tests
   set the session's values and compare against the SESSION image (`sess_seg`), not the cap-less `direct()` reference.
3. Adversarial review (below), PoCs `slpoc22` P0–P4, mutants `loop22-mut.py` (20 round-22 + 5 round-21 re-tests),
   full stateless regression, riscv32 stateless guest build, Radicle CI (`slpoc22` added to `.radicle/native.yaml`).

## Summary of findings

| id | sev | where | what | status |
|---|---|---|---|---|
| R22-M1 | M | global account cap (design) | upstream never removes an id from the Account map / PERP ledger, so ANY hard cap on them is a permanent lockout of new users (no first Deposit, no keeper's first credit, no first GovDeposit / Slash reward) once filled, and filling it costs one dust Deposit unit per slot (2^20 slots ≈ 2^20 L1 units). The session's `MAX_STATE_ACCOUNTS` = 256 has the same flaw (pilot memory bound, accepted earlier as a pilot limit) | **mitigated by decision**: the lineage keeps the counts but does not cap the Account map / PERP ledger (`SL_CAPS_PROD.accounts = u64::MAX`); listings (burned fee) 2^16 and oracle bonds (bonded PERP) 2^12 are capped. Production needs an eviction rule for empty ids (upstream) before any account cap |
| R22-I1 | I | R16-I3 / R17-I3 | the stateless image now applies the session's global caps on `gcnt:0`; with the session's values both images agree unit by unit at and one below the caps (slpoc22 P1: 7 refusals at the caps incl. the Liquidate keeper of R17-I3, root + events = session) | closes R16-I3 / R17-I3 (mechanism; values per R22-M1) |
| R22-I2 | I | commits | the session's `MAX_STATE_COMMITS` (1024) is not mirrored: commits expire lazily in the stateless image (R16-I1), so "live commits" is not an aggregate of touched records; the per-account `SL_MAX_ACMT` bound stays | documented; needs eager commit expiry (an `oexp`-style queue) or `cmt:` deletion (R16-I1) |
| R22-I3 | I | export (R16-I2) | export precondition is O(1) now (counts within the session's caps); with R22-M1 an export can become impossible once the lineage outgrows 256 ids — an export must be decided while the counts fit, or the session image's caps raised first | design note (§9) |
| R22-I4 | I | cost | one more leaf on segments that create or remove a membership / bond / market (or run a capped unit by a non-member); `gcap_ok` sums the deltas over the loaded records (O(loaded accounts) per capped non-member unit, ≤ 4096) | measured (Tests) |

Review notes (no finding):
- **Soundness of the delta.** `gcnt:0` is checked against MNWIT-S like every leaf (forged counts: P2 refused); a count
  change without the leaf loaded is `Need::Gcnt` at the end root (omission / adversarial operator: P2 refused); the
  delta's premise — every membership change belongs to a loaded record — holds by the existing guards (dirty accounts
  loaded; light record flags fixed; a listing proves its market id absent; ora guard (a): bonds of non-loaded `ostk:`
  never change) and is backed by end-root catch-alls (partial-state Account / PERP ids and markets without a record).
- **The rule needs the count even when nothing changes**: a capped unit by a non-member that then fails (Liquidate of a
  healthy target, GovWithdraw beyond the balance) changes no count; `gcap_pre` still requires `gcnt:0`, else the
  session's 19 would become the engine's error code (P4, mutant `gcap-pre-need-off`).
- **Reveal inner op**: the session runs `state_cap_ok` on the decoded inner op with the author, whether or not the
  inner op runs; the stateless image does the same (`gcap_pre` / `gcap_ok` on `inner`).
- **Order vs other refusals**: the commit bond (R7-M2), R7-M1, the oracle bounds and the global caps all refuse with
  code 19 in one predicate, as in the session. The W2 depth rule (code 18) runs before the caps in the session and after
  them in the stateless image; the two images evaluate depth on different trees (MNWIT1 vs MNWIT-S), so they cannot
  agree on a ground-deep key anyway (pre-existing, unchanged).
- **Height hook**: the oracle expiry releases bonds before the first unit; the delta sees them (`ostk:` loaded by the
  hook) and a Stake after the hook reads the reduced count, as the session.
- Migration: a snapshot beyond `SL_CAPS` is refused (`ST_SL_MIG_BOUNDS`); the migration root includes `gcnt:0` (pure
  function of the state).
- Oracle-bond cap 2^12: Sybil bonding to fill it locks 2^12 × `ORACLE_BOND_PERP` (refundable after unbonding) — the
  session's 32 is far cheaper to fill; acceptable bound, noted.

Totals: **C 0 · H 0 · M 1 (mitigated by decision) · L 0 · I 4**.

## Tests

Logs: `guest-engine/results-loop22/` (box /data/hark/logs/rv). Binaries (engine-diff, CARGO_TARGET_DIR
/data/hark/target-spike, profile l20, copied to loop22/bin; mutants: profile l22m): 8868800b (7c0993c), 9b25c0dc
(prod caps + catch-alls), ec234148 (t_adrop 6), 19d9730e (+ migration bound: **final guest code**, full regression),
a2f07f30 (+ slpoc22 P5 / slpoc21 P3d: test code only; final tests).

| what | result | log |
|---|---|---|
| slpoc22 (final) | P0 both rank sub-trees emptied: status 0 = direct, `adlr:` leaves deleted; **P1 at the caps: session 7 × code 19 (2nd first Deposit, Liquidate by a new keeper = R17-I3, 2nd new PERP id, GovWithdraw / Slash by a non-member, 2nd listing, 2nd new oracle) = stateless, root + events equal**, witness 7.4 KB; P1 one below the account cap: 3 × 19, equal; P2 forged `gcnt:0` (t_gdrop 1–4) / omitted / adversarial operator denying Gcnt: 6 / 6 refused, 0 wrong; P3 production caps: first credits equal to a session at cap 2^20, the 2nd listing / 2nd oracle run in the lineage (session constants refuse); P4 failing capped units at the cap (no count change): 19 × 2 = session, deny-Gcnt operator refused (13); P5 Reveal with a capped inner Deposit by the non-member author: 19 × 2 = session (below the cap: the engine's code 2), deny-Gcnt refused | l22-final.log, l22-reg.log |
| round-21 survivors re-tested | **end-del-off KILLED** (slpoc22 P0), **load-absent-check-off KILLED** (slpoc21 `t_adrop` 5; also in round-21 pass 2), **leftmost-skip-stub KILLED** (pass 3: slpoc21 P3d — `t_adrop` 6 / P3c alone could not reach it: removing the second leaf beside a single-leaf stub is refused by the collapse rule, so a whale + tie pair was needed); removed-count-off (liveness only) and insurance-in-tree (unreachable on supported paths) survive — rv-loop-21 notes | l22-mut.log, l22-mut2.log, l22-mut3.log, l21-mut2.log |
| gcnt guard mutants (loop22-mut.py, 18 round-22) | pass 1: 16 / 20 killed (incl. the 2 round-21 re-tests); pass 2: **gcnt-end-need-off KILLED** (slora 10 300 40: the hook's bond expiry rewrites `gcnt:0` without any capped unit), **gcap-inner-off KILLED** (slpoc22 P5); survivors `catchall-acct-off` / `catchall-mkt-off` = defence in depth (the premise of `gcnt_delta` already holds through the dirty-account / market guards and ora guard (a); the catch-alls are the explicit statement of it). **Round 22: 16 / 18 killed, 2 equivalent** | l22-mut.log, l22-mut2.log |
| regression (final guest code 19d9730e) | slpoc15 / slcaps / slpoc17 (6 / 6 ADL segments proven) ok; slmig 20×300 0 / 5 20 / 20; slfuzz gen 60 / 60, perp 40 / 40, wd 30 / 30, ora 30 / 30, liq 10 / 10 (0 unsupported, 717 liquidation units proven), gov 100 / 100; sladv perp 6 546 + gen 5 470 + liq 47 515 + gov 26 099 cases **0 unsound**; slpoc18 20000, slpoc20, slpoc21 30×300 (12, 2 000) ok; slmiggov 30 / 30; slora 40×300 h1, 30×400 h40, adv 15×600 h1 + 10×400 h60 (83 242 cases **0 unsound**; unsupported segments unchanged vs round 21: 1 087 / 864 / 811 / 299 = funding / peg); govfuzz 30 / 30, liqfuzz 20 / 20 real engine = port. Final tests (a2f07f30): CI set + slpoc21 P3d 8 / 8 + 3 / 3 honest proven, 16 + 6 forged refused | l22-reg.log, l22-gov.log, l22-final.log |
| cost vs round 21 (same commands) | witness bytes: gen +0.04 %, perp +0.5 %, wd +0.04 %, ora +0.05 %, liq +0.01 %, gov +0.5 %, orc +0.2 %; guest hashes (sl_hashes): +0.1 – 0.4 % | l22-reg.log, l22-gov.log, ../results-loop21/l21-regF.log, l21-govF.log |
| riscv32 stateless guest build | clean (release, `stateless`, riscv32im): b2 (gcnt + production caps) and b5 (final guest code) | l22-b2.log, l22-b5.log |
| Radicle native CI (incl. slpoc22) | 7c0993c, 85cf3a4, dbcdef4, bf3cd51 SUCCESS (the closing commit: see work notes) | /data/hark/radicle-ci/state/*/log.html |

## What remains

- Stateless lineage export (R16-I2): no MNWIT-S → snapshot run yet; precondition now O(1) (R22-I3).
- Stale `cmt:` deletion / eager commit expiry (R16-I1), which would also allow mirroring `MAX_STATE_COMMITS` (R22-I2).
- An eviction rule for empty ids (upstream) before any account cap (R22-M1).
- DA of the witness (AA design), funding / peg / ExtPrice, revealed Liquidate, the funding-rate market's liquidation
  (R20-I1 / R21-I4), upstream mirror of the leaf kinds.
