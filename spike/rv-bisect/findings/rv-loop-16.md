# rv loop round 16 — stateless PERP / listing / commit-reveal ops, MNWIT-S migration in the rollup, linked-FIFO levels, review (2026-11-01)

Branch `spike/rv-bisect`, parent 353908e. Commits: 47f2e67 (stateless GovDeposit / GovWithdraw / CreateMarket / Commit /
Reveal, leaves `perp:0` / `xsrc:` / `acmt:` (+ `gnon:` / `cmt:` records), R16-M1 fix, rv_rollup SNAP_KIND 3), 86fb224 (Reveal
inner-op load rule, operator Path-need fix, bulk MNWIT-S root, sladv `forge16:*`, `sldbg`), and — finished and committed
in round 17 — e06de09 (linked-FIFO price levels; the code was written in round 16 and left uncommitted at the round's end).
Design: `docs/rv-stateless-guest.md` (§2–6, §9, §11, new §12 written in round 17). Box logs:
`guest-engine/results-loop16/`. Notes: work/rv-rollup-notes.md "Loop round 16".

Status: **FINAL** (round-17 collection; the step-4 guest-level migration measurement is carried into round 17 step 3).

## What was done

1. **Stateless ops** (each differential vs the session port, `slfuzz … perp`, `sladv … perp`):
   * GovDeposit / GovWithdraw — `perp:0` (`:<perp_supply>:<perp_burned>:<next_market_id>`, always present) + the author's
     record; the session's per-account `state_cap_ok` rules (R7-M1 zero GovWithdraw) replayed.
   * CreateMarket — `perp:0` (next market id), `xsrc:<acct>` (external_sources membership), the new id proven absent.
   * Commit / Reveal — `acmt:<acct>` (the account's commit index, lazy expiry like `wdl:`, ≤ `SL_MAX_ACMT` 64 — a new
     stateless bound; R7-M2 commit bond), `cmt:` records by hash, `gnon:` watermarks. Reveal loads its inner op only when
     `reveal_begin` would consume the commit (exact replay of the inner-kind / signer / hash / parent / commit checks).
2. **R16-M1** (below) fixed: the stateless image writes its run counter to `OUT[SEG_N]`.
3. **rv_rollup accepts the MNWIT-S migration** (SNAP_KIND 3) on the export / migration digest binding (R15-I1 closed);
   rolltest group `r16mig`; AA mutants `js/aamut-l16.py` 8 / 8 killed.
4. **Migration root by bulk build** over the sorted leaves (one hash per node instead of incremental inserts) — the
   guest-side migration cost; `slmigcap` + `xval/migsail.js` measure a full-size migration under sail.
5. **Linked-FIFO levels** (committed in round 17, e06de09): `lvl:` holds only (head, tail), `olk:<order>` the FIFO links;
   a level is never loaded whole; R14-M1 (level cap) and the R15-M1 level bound are gone. sladv A17 `book:omit-head`.

## Summary of findings

| id | sev | where | what | status |
|---|---|---|---|---|
| R16-M1 | M | stateless guest image (`main.rs` sl_run / sl_migrate) | the stateless image never wrote the run counter `OUT[SEG_N]`; `rv_witbind` proves `OUT[SEG_N] == h` before binding `W<h>`, so **no stateless height could ever be bound** (every bind bounced) — the stateless chain was unusable by the AAs | **fixed** (47f2e67): both the migration and every unit run write `SL_RUNS`; `js/slmig.js` checks `OUT[SEG_N]` per height |
| R16-L1 | L | stateless Reveal guard | Reveal loaded / required its inner op even when the reveal would not consume the commit; a foreign-commit Stake reveal returned `ST_SL_UNSUPPORTED` although the session simply rejects it (liveness: an honest segment could not be proven) | **fixed** (86fb224): the inner op is read only when `reveal_begin` would consume the commit |
| R16-L2 | L | operator (`WitBuilder`) | a Path need on a key that exists as a verified leaf was not sent, so the need loop never converged (revealed Place re-using a live client_seq) — operator liveness, not soundness | **fixed** (86fb224); `sldbg` added to locate non-converging units |
| R16-I1 | I | lazy commit expiry | an expired commit's `cmt:` leaf is never deleted (the `acmt:` index drops it lazily, but the leaf itself stays — it may since have been re-created by another account, so it is neither read nor deleted): stale leaves accumulate in the tree | open (design §9 / §11): a lazy delete on the next touch of the hash (with the ttl check) is the fix; behaviour unaffected |
| R16-I2 | I | lineage | the stateless lineage has no export path (no MNWIT-S → session snapshot run): once migrated, the session image cannot be re-entered | open (design §9 / §11) |
| R16-I3 | I | stateless rules | the stateless image enforces no global caps (market / account / order / commit totals of the session): only per-object bounds | by design so far; needs a decision whether any session cap is consensus (then an aggregate leaf) — design §5 / §11.8 |

Totals: **C 0 · H 0 · M 1 (fixed) · L 2 (fixed) · I 3 (open)**.

Harness notes: an intermediate linked-FIFO build (`l16-f1.log`, sladv 6 × 200) reported 7 "unsound" cases that were all
"operator failed" (the honest operator's need loop did not converge — liveness of the harness, no wrong status-0
result); fixed before the final build (`l16-f3.log` 0, round-17 suite 0).

## Tests (box; `results-loop16/`)

| run | binary | result |
|---|---|---|
| `slfuzz 300 300 perp` / `60 1000 perp` | round-16 step 1 | 300 / 300 (2 632 segments, 102 698 units), 60 / 60 (1 566 / 66 865) — `l16-s1a.log` |
| `sladv 40 200 perp` / `sladv 20 200` | round-16 step 1 | 44 729 / 22 838 cases, 0 unsound — `l16-s1b.log` |
| `slfuzz` gen 200 × 300, 100 × 1000, wd 200 × 300, adv 200 × 200, ora 100 × 300; `slmig 40 300 0 / 900` | round-16 step 1 | all ok, slmig 40 / 40 each (429 expired sets with jumps) — `l16-s1c.log` |
| `slperpstat 30 300` | | op-kind mix of the perp workload (every new kind applied and rejected) — `l16-s1a.log` |
| rolltest (rv_rollup with SNAP_KIND 3) | roll16 | **489 / 489**; AACOST rv_rollup 1 711 ops / complexity 86 — `l16-roll.log` |
| `js/aamut-l16.py` | | 8 / 8 mutants killed — `l16-aamut.log` |
| linked-FIFO dev builds | loop16d | `l16-f1.log` (7 operator failures, see above), `l16-f2.log` (sldbg), `l16-f3.log` (slfuzz gen / wd / perp / adv ok, sladv 7 302 cases 0 unsound) |
| linked-FIFO final suite | target-l16d-host b6bedf37 (round 17) | see rv-loop-17 Tests (`results-loop17/l16-r17*.log`) |
| `slmigcap 64 16 8 64 8` | | 64 accounts × 16 markets × 8 oracles, 4 096 live orders, 1 024 positions: host migration root = reference, 214 461 snapshot words, 23 494 MNWIT-S leaves, host 0.10 s, heap peak 9.0 MB — `l16-cap*.log`; guest sail run: rv-loop-17 step 3 |

## What remains (carried into round 17)

Migration decode mode skipping the MNWIT1 witness tree (round-16 step 4 found the guest decode rebuilds it leaf by
leaf); stateless liquidation / ADL, oracle report / stake / slash / funding, proposals / vote / finalize (designs §12);
R16-I1..I3.
