# rv loop round 19 — R18-M1 fix (exception sub-trees), round 17/18 close-out, oracle review (2026-11-01)

Branch `spike/rv-bisect`, parent a749440 (round-18 head at the user stop 10:41; resumed 10:52). Commits: a7ea7e8 (round-18
draft edits), d1be889 (R18-M1 fix), 8822296 (rv-loop-18 FINAL, round-17 sail row), + this round's closing commit(s).
Design: `docs/rv-stateless-guest.md` §2, §4, §12.1 (round-19 review), §12.3. Box logs: `guest-engine/results-loop19/`.
Notes: work/rv-rollup-notes.md "Loop round 19". Pushes: Radicle first, then GitHub (user rule 10:56).

Status: DRAFT (see "What remains").

## What was done

1. **R18-M1 fixed** (d1be889): a live proposal's exception entries (account, snapshot weight, voted) — the pairs where
   the weight differs from the account's current PERP balance or the account voted — now live in a **per-proposal
   exception sub-tree** (compact SMT of the MNWIT-S form, leaves `pxe:<pid>:<acct>` -> `:<weight>:<voted>`), whose root
   is a field of `pglob:0` (digest over (id, xroot)). Round 18's per-account `pexc:` leaves and per-proposal exception
   counts are gone. Finalize drops the proposal's `pglob:` entry and with it the whole sub-tree: **no exception holder is
   loaded** (round 18: all of them, > 4096 unprovable). A Vote / balance change verifies the account's list against
   every live sub-tree (listed entry = member with recomputed leaf hash, every other pair proven absent) and rewrites
   one path per live proposal (≤ 64). The engine still runs unchanged on the populated partial proposals.
2. **R19-L1 fixed** (review of 1): node budget shared by the MNWIT-S tree and every sub-tree (`PTree::decode_lim`).
3. **Round-17 / 18 close-out**: rv-loop-18 FINAL (Tests, mutants), rv-loop-17 sail row; the 256-account cap fixture
   is not a session state (BAD_SNAP); the 64-account sail measurement rerun (decode mode vs round-16 baseline).
4. **Oracle / funding review** (design §12.1, round-19 bullets): R18-I2 resolved on paper by a bounded eager expiry queue
   (R19-I2); the funding transfer is O(holders) by construction (R19-I1). Not implemented this round.

## Summary of findings

| id | sev | where | what | status |
|---|---|---|---|---|
| R18-M1 | M | stateless Finalize (round 18) | Finalize had to load every exception holder; > 4096 holders -> the proposal could never be finalized and kept one of 64 slots | **fixed** (d1be889): exception sub-trees; slpoc18 P3 finalizes 4000 / 4097 / 20 000 voters with a 10.3–11.7 KB witness |
| R19-L1 | L | stateless loader (d1be889) | each exception sub-tree was decoded with its own SL_MAX_TREE_NODES budget and the running total was checked only after a decode: a witness could hold up to ~2x the node bound of round 18 (MNWIT-S tree + sub-trees) -> ~2x the guest heap for tree nodes (~172 B / node). Not a soundness issue (roots are checked; SL_MAX_WIT_BYTES still bounds the total); a heap / cost bound regression | **fixed** (this round): `PTree::decode_lim` with the remaining budget (MNWIT-S nodes + sub-tree nodes <= SL_MAX_TREE_NODES) |
| R19-I1 | I | design §12.1 (funding) | `transfer_funding` (≥ 2 reporters, once per market and height) is O(holders): Phase 2a/2b clamp and spend a budget in id order, so one account's result depends on every lower id; a stateless funding tick needs the complete holder set of the market (new `hset:<m>` leaf, maintained on every position open / close) and is bounded by SL_MAX_ACCOUNTS | documented (§12.1); options: holder-set leaf + per-market holder cap in both images, or upstream index-based funding |
| R19-I2 | I | design §12.1 (oracle expiry, resolves R18-I2) | one run = one height (+1 per run in `prod`) and unlock = height + 256, so the oracles expiring at run h are exactly the Unstake units of run h − 256 (≤ MAX_UNITS); an `oexp:<height>` queue leaf (function of `oracle_unbonding`) makes the set provable and the session-derived reference holds — no lazy entries needed. Worst case (Unstake units of one run) x SL_MAX_ORACLE_MKTS records in one run | documented; a per-segment Unstake cap (consensus, both images) would bound it |
| R19-I3 | I | test fixture (round 17) | `l17c256.sh` measured a 256-trader cap config: 256 traders + creator + oracles > MAX_STATE_ACCOUNTS (256), so the session decoder refuses the import (BAD_SNAP); the queued sail run measured a failing migration | fixture error; job stopped; the 64-account config is the cap measurement |

Review notes (no finding) on the sub-tree fix: listed entries must be strictly ascending live ids, members with their
recomputed leaf hash (a forged weight / vote or a non-exception pair listed is not a leaf); an unlisted pair must be
`Absent` (an unverified tag-2 leaf proves nothing: `Unknown` -> BADWIT; the builder sends tag-4 leaves for path ends);
sub-tree roots are bound by `pglob:0` (itself a checked MNWIT-S leaf); a list without `pglob:` is BADWIT; accounts
without a loaded list cannot change balance or vote (pre / post guards), so their (absent) entries are unchanged; a
proposal created in the segment starts with an empty sub-tree (its snapshot over the loaded balances is exact for every
loaded account, and only accounts with a loaded list can acquire an entry); a finalized proposal's sub-tree is simply not
written. sladv `forge19:pxe-drop` / `forge19:pxe-weight` (forged lists, also a fake entry for an entry-less account):
all refused.

Totals: **C 0 · H 0 · M 1 (R18-M1, fixed) · L 1 (fixed) · I 3**.

## Tests

(filled below)

## What remains

(filled below)
