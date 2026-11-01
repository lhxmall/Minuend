# rv loop round 18 — stateless governance (proposals / vote / finalize), review (2026-11-01)

Branch `spike/rv-bisect`, parent 5502b78 + round-17 collection 4a62fd5 / 5f2fcf6. Commits: 2b3d815 (stateless
governance + gov workload), fa479d1 (slpoc18, gov counters), + this round's closing commit(s) (see the branch log).
Design: `docs/rv-stateless-guest.md` §2 (leaf table), §4 (governance guards), §11, §12.1 (R18-I2 note), §12.3
(implemented form). Box logs: `guest-engine/results-loop18/`. Notes: work/rv-rollup-notes.md "Loop round 18".

Status: DRAFT (see "What remains").

## What was done

1. **Stateless governance** (`stateless.rs`, feature `govwit`, default): CreateProposal / Vote / FinalizeProposal run
   on a partial state with two new MNWIT-S leaf kinds, both pure functions of the session state:
   * `pglob:0` — next proposal id, number of non-zero PERP holders, the live set (≤ 64) with each proposal's exception
     count; loaded together with every live `prop:` record, so the partial proposals map is complete (cap 64,
     NoProposal, next id are exact).
   * `pexc:<acct>` — the live proposals for which the account's snapshot weight differs from its current balance, or
     that it voted on. The loader fills the partial `weight_snapshot` / `voted` of every live proposal for each account
     whose `pexc:` is loaded; the engine (`create_proposal` / `vote` / `finalize_proposal`) runs unchanged.
   * `prop:` leaves keep the MNWIT1 format; their |voted| / |snapshot| counts are carried explicitly
     (`wit::prop_leaf_n`): loaded count + delta; a proposal created in the segment records |snapshot| = holders now.
   * Guards: Create — creator record, `perp:0`, market present / absent, `pglob:`. Vote — voter record + `pexc:`,
     `pglob:` (also for a Reveal's inner Vote: the session's R6-H2 zero-voter rule runs on it whether or not it runs; the
     stateless image now evaluates R6-H2 from the proposal counts). Finalize — `pglob:`, the proposal's market, and the
     `pexc:` of every exception holder (`Need::PexcOf`; loaded holders = `n_exc` is the completeness proof). Post-unit:
     any PERP balance change needs `pglob:` and the account's `pexc:` (holder count, exception list rewrite).
   * SetSeq test fixture supported statelessly in non-prod builds (proposal deadlines are 20 000 applied units away);
     refused in `prod` exactly like the session.
2. **Harness**: `gov_batch` (real-engine MNP2 workload: gov deposits / withdrawals, proposals with valid / risky /
   delist params and unknown markets, votes by holders / zero-weight ids / repeat voters / unknown ids, SetSeq jumps,
   finalize early / late / unknown), mode `gov` in slfuzz / sladv / sldbg / sldiff, `gov_units_proven` counters,
   sladv `omit:pglob` (builder flag `t_omit_pglob`) / `omit:pexc` / `omit:pexc-of`, `extra:valid` adds every
   account's `pexc:`; `slpoc18`; `slmiggov` (migration of states with live proposals); `scripts/loop18-mut.py`.
3. **Not done this round**: oracle report / stake / slash / funding (§12.1) and the ADL rank index (§12.2). Review of
   §12.1 found that its lazy-unbonding rule cannot match a session-derived reference root (R18-I2).

## Summary of findings

| id | sev | where | what | status |
|---|---|---|---|---|
| R18-M1 | M | stateless Finalize | a proposal's removal drops its entry from every exception list, so Finalize must load every exception holder (voters + accounts whose balance changed since creation). Above SL_MAX_ACCOUNTS (4096) records the witness is refused (BADWIT): such a proposal can never be finalized statelessly, stays live, and keeps one of the 64 proposal slots; 64 of them block CreateProposal for good. Reachable by legitimate use (a popular vote with > 4096 voters) or by an attacker with > 4096 funded PERP ids (the stateless image has no global account cap, R16-I3). PoC `slpoc18` P3: 4000 voters -> finalize status 0 (witness 1.5 MB), 4097 -> BADWIT | **open** (design decision). Options: (a) lazy dead entries (ignored when read, pruned on touch) with the stateless lineage as its own reference (as R18-I2 (a)); (b) a chunked Finalize (consensus change: a finalize unit plus cleanup units, each bounded); (c) raise the per-segment account bound for Finalize only (witness size ~380 B / holder); **(d, recommended)** move each proposal's exceptions into a per-proposal sub-SMT whose root is a field of its `prop:` leaf: Finalize deletes the leaf and the whole sub-tree with it (O(1)), a Vote updates one sub-tree path, a balance change one path in each live proposal's sub-tree (<= 64) -- the reference stays a pure function of the session state |
| R18-I1 | I | MNWIT-S format | `pglob:0` is always present: every MNWIT-S root changes (also of states without governance), the migration root included | consensus-format change of the spike, documented (§2) |
| R18-I2 | I | design §12.1 (oracle) | lazy unbonding (an `orep:` entry carries its oracle's bond epoch / unlock height and stops counting by itself) cannot match a reference root computed from the session state: the session's `prune_oracle_unbonding` removes the oracle's reports from every market at the expiry height, the stateless leaf keeps them until touched | documented in §12.1 with options (stateless lineage as its own reference / eager expiry queue / upstream change: expiry removes only the bond) |
| R18-I3 | I | cost | every PERP balance change (GovDeposit / GovWithdraw / CreateMarket fee) now loads `pglob:` with every live `prop:` (≤ 64 records, ~150 B each) and the account's `pexc:` | accepted; gov workload max witness 31 KB |
| R18-I4 | I | test fixture | SetSeq runs in the stateless image in non-prod builds (glob: only) | test-only; prod refuses it like the session |

Review notes (no finding): population soundness (an entry-less pair is (balance, not voted) only against the complete
live set — a loaded `pexc:` without `pglob:` is BADWIT; entries must name live ids); forged counts (`prop:` / `pglob:`
leaves are hash-checked; a loaded voter count below the loaded voters is BADWIT); proposals created in the segment (the
engine's snapshot over the loaded balances is exact for every account whose `pexc:` is loaded; accounts without one
cannot change balance or vote, so they have no entry); the R6-H2 rule (inputs: author's membership from `pexc:`, counts
from `prop:` + deltas); a Finalize of a proposal created in the same segment (n_exc at load 0, every later holder is
loaded); extra valid records (more `pexc:` / `pglob:` change nothing: sladv `extra:valid` all correct).

Totals: **C 0 · H 0 · M 1 (open) · L 0 · I 4**.

## Tests

(filled below)
