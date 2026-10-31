# rv loop round 4 — liquidation / ADL / withdraw / oracle port, guarded state, session export / import, upgrade path (2026-10-31)

Target: `lhxmall/Minuend` branch `spike/rv-bisect` @ 4225a7f (loop round 3 result). Reference engine read only via
`git archive 20326c0` (engine-diff/engine-src); fix/47-all, main and PR #51 untouched. Commits: de583c8 (round-3 suite
results), 1d60b0c (port + guarded account map + snapshot, WIP), a0bdb3e (import lock, upgrade image, SetHeight hook,
account cap), 8d2140a (rv_rollup upgrade + xbind), and the results / findings commits after it.

Work items:

1. **Port** of the remaining hot engine paths: `Withdraw`, `Liquidate` (book IOC + ADL + funding-rate off-book close +
   residual haircut + keeper reward), `ReportPrice` (`apply_report`: median, ±10 % band, index band, TWAP,
   `transfer_funding`), `UpdateExternalPrice`, `settle_funding_peg` / `transfer_funding_rate`, the funding-rate mark
   block of `apply_fill_pair`. Batch kinds 6–10 (10 = `SetHeight`, the batch-commit hook), header fixtures bit 25
   (funding-rate market 3, account 0 = its external feed) and bit 26 (accounts 1..3 bonded oracles).
2. **R3-O1 by construction**: `ChainState.accounts: Accounts` (Deref to the map, no DerefMut; `get_mut` / `insert` /
   `remove` / `get_or_new` return or keep an `AcctMut` guard that re-indexes open interest, per-market holders and the
   MNWIT1 dirty set on drop). The holders index replaces the O(accounts) scans in `transfer_funding*`, ADL candidate
   selection and the funding journal.
3. **Session export / import** (`snapshot.rs`, R3-H2): canonical export (digest streamed, nothing stored), validated
   import (rebuilt tree + indexes), guest `EXPORT_MAGIC` / `SNAP_MAGIC` runs; then the **upgrade path**: an upgrade image
   carries the export it may import, the rollup switches images at a governance-chosen height and finalizes that height
   only on a proven export / import digest match.
4. **Long-run heap bound**: session account cap (`MAX_STATE_ACCOUNTS = 256`, code 19) with a measured per-account
   footprint; prod skips the O(state) from-scratch rebuild and state hash at segment end.
5. This review (below) and the round-4 suite / mutation test.

Severity as in rounds 1–3: **C** = honest party loses / wrong verdict on reachable input; **H** = guest ≠ host,
undefined guest outcome, or a protocol-reachable state loss / halt; **M** = design/spec gap with a concrete failure
mode or a defense-in-depth hole; **L** = minor / documentation; **I** = checked, no defect.

Totals: **C 1 · H 3 · M 6 · L 4 · I 5**. No real-engine ↔ port divergence (fuzz / advfuzz / witfuzz / scen / segfuzz /
liqfuzz all equal after the changes).

| id | sev | area | title | status |
|---|---|---|---|---|
| R4-S1 | C | guest / snapshot | the first import design accepted **any well-formed snapshot** on an image without a live session — the genesis image at height 1, or a dead image ("revive") — so an operator could start (or restart) the rollup from an arbitrary state, and the instruction game would confirm it (the guest really computes "import this") | fixed: an import is accepted only by an **upgrade image** built with `MNPILOT_IMPORT_DIGEST=<digest>:<words>` (compiled in → committed by the image's memory root = governance-chosen GENMEM); the words are hashed **before** decoding; ordinary images return ST_IMPORT_LOCKED (10); no in-place revive (a dead image stays dead, ST_DEAD 5). Defense in depth on layer 1: rv_rollup finalizes an upgrade height only on a proven export(h−1) == import(h) digest (R4-M1) |
| R4-S2 | H | guest / upgrade | an upgrade image whose first run is a **batch** (not the import) starts a fresh genesis session: the honest result of that height is "state wiped", so an operator could erase every balance at the upgrade height | fixed: ST_NEED_IMPORT (11) — an upgrade image without a session executes no unit (even if its digest string is malformed: such an image is a brick, never a genesis); rv_rollup additionally requires kind 2 (import) at the upgrade height |
| R4-H1 | H | guest / heap | the session lives in guest memory across heights and accounts are never deleted: the heap grows without bound until a run OOMs, the session dies (status 5 forever) and the rollup halts until an upgrade | mitigated (stopgap): `MAX_STATE_ACCOUNTS = 256` (deposit / liquidate by a new author at the cap → code 19); every other state is bounded per account or global, measured ≤ 80 KB per fully loaded account → ≤ 31 MB incl. fragmentation and per-run transient < the 50.2 MB heap. Not a production answer: 256 users is a liveness limit, and a rejected deposit needs a refund path in the bridge AA. Production needs a stateless guest (state as witness input) or much larger guest RAM |
| R4-H2 | H | guest / height | the engine height had no production source: `SetHeight` was a test fixture (any height ≥ current, refused as kind 0 in `prod`), so the prod engine stayed at height 0 forever (withdrawal ledger never pruned → the 64-pending limit locks withdrawals; feeds / TWAP never age) — and the fixture semantics would let an operator jump heights to age feeds and fire funding pegs at will | fixed: `SetHeight` = upstream's batch-commit hook (height + 1, `prune_withdrawals` with REPLAY_WINDOW 2048); `prod`: exactly current + 1 and only as the segment's first unit (one per rollup height, each costing a bond and a challenge window); test builds keep jumps for fixtures. Residual: R4-M4 |
| R4-M1 | M | rv_rollup | no upgrade path in the rollup and no check that an import imports the last finalized state | fixed: governance (`$GOV`) schedules `U<h>` = memory root of the upgrade image for lf < h ≤ top + 1 (live heights ≥ h are voided, bonds reclaimable); height h's s0 starts from U<h>; `xbind` proves a submission's OUT kind + digest words against its final memory (9 memory proofs); finalize of an upgrade height requires x(h−1) = 1:D and x(h) = 2:D. rv_rollup 63 / 1 449 (limits 100 / 2 000) |
| R4-M2 | M | port / liquidation | the liquidation order id is `liq_order_id(unit id)`, but the pilot batch carries no unit hash: the port uses unit id 0 and both harness sides mask the taker id of liquidation fills (LIQ_TAKER_EV) | open (documented): the id is not stored (IOC, never rests), so state / roots are unaffected; production: the unit input carries the unit id (a second 8-word slot per unit or a v2 stride-16 batch format) and the mask goes |
| R4-M3 | M | port coverage | not ported: oracle stake / unstake / slash, governance ops (listing, parameter changes), commit-reveal ordering | open: fixtures stand in (bit 25 funding market, bit 26 bonded oracles); these paths are not differential-tested in the guest |
| R4-M4 | M | height binding | the engine height is not bound to the rollup height: the operator decides whether a segment carries `SetHeight` (≤ 1 per rollup height), so the engine may lag the real batch count (feeds look fresher, pegs fire later) | open (documented): binding needs the AA to commit h into the input (e.g. s0 hashes h) and the guest to compare |
| R4-M5 | M | upgrade | governance is a trusted role: it can void live heights (to re-schedule a failed import) and its image choice decides the code; a dead image can only be recovered from its last **export** — heights between that export and the death are lost unless replayed | documented |
| R4-M6 | M | account cap | the cap is consensus-critical (part of the image) and a hard ceiling; an attacker can fill it with 256 dust deposits and lock everyone else out | documented with R4-H1 (stopgap only) |
| R4-L1 | L | snapshot | `run_import` hashes the snapshot words twice (once before decode, once in `SnapR`) | accepted: one SHA-256 pass over ≤ 13 k words is ~10^6 steps |
| R4-L2 | L | tests | round-3 mutants 15 / 18 / 20 (report band, liquidatable, ADL collateral) survived because those paths were not ported | ported in round 4; see the round-4 mutation table |
| R4-L3 | L | harness | `SetHeight`'s `prod` rule is not visible to the host differential harness (host builds are non-prod) | covered by `js/prodheight.js` on the prod image (6 / 6) |
| R4-L4 | L | Accounts guard | the derived index fields `Accounts::oi_long / holders / dirty` are `pub`: the type system stops in-place edits of positions, but not a direct write to an index | open (documented): no writer outside `state.rs` today (grep); make them private with read accessors when porting for real |
| R4-I1 | I | Accounts guard | can a path change positions without re-indexing? | no: `accounts` has no `DerefMut`; every mutable path goes through `AcctMut` (re-index on drop) or `insert` / `remove`; host runs assert `idx_ok` after every unit (first run found and fixed an insert-before-remove ordering bug in `insert`) |
| R4-I2 | I | account cap | can any unit other than deposit / liquidate create an account, or the insurance account push the count over? | no: the insurance account exists from genesis and is never removed; escrow / refund paths touch existing accounts; a failed unit's journal rollback deletes accounts it created; `capcheck` asserts accounts ≤ cap after every unit and that code 19 fires only for a new deposit / liquidate author at the cap |
| R4-I3 | I | snapshot | can a flipped / truncated snapshot be imported? | no: snaptest 300 × 300 — truncations and 8 random bit flips per batch all refused (flips that still decode as a valid snapshot of another state are refused by the digest) |
| R4-I4 | I | upgrade / AA | can the upgrade height finalize with a batch, an export, a mismatching import or swapped kinds? | no: rolltest `upgrade` (26 checks): kind 0 refused by xbind, mismatching digest / swapped kinds never finalize, re-scheduling voids and re-opens the height |
| R4-I5 | I | OI read path | does the funding open-interest read path now see coverage? | yes: the round-3 survivor "OI = 0" is killed by liqfuzz (29 / 30) |

---

## R4-S1 (C) — import on a session-less image

The first snapshot design (1d60b0c) made the IMPORT run legal whenever the image had no live session: a fresh image or
a DEAD one (whose allocator was reset — "revive"). The rollup's height-1 image is exactly such an image, and so is every
image after a trap. The instruction game only checks that the guest executed its program correctly; the program
accepted any canonically encoded snapshot. So an operator who submits, as height 1 (or as the first height after a
death), an import of a snapshot it made up — every balance its own — produces a final state that is the *correct*
result of that run: no challenger can win a game against it.

Fix (a0bdb3e): the import's expected digest and length are compiled into the image (`MNPILOT_IMPORT_DIGEST`), so the
image's memory root — chosen by governance as the new GENMEM — commits which state may be imported. An image without it
(the genesis image) refuses every import with ST_IMPORT_LOCKED; the words are hashed first and decoded only if the
digest matches, so a hostile snapshot never reaches the decoder's allocations; a dead image stays dead. `snaptest`:
"import without expected digest" and "another valid snapshot" checks, 300 / 300; `snapguest` G (genesis image refuses),
F (another valid snapshot refused), C (dead images stay dead).

## R4-S2 (H) — upgrade image runs a batch first

With the lock in place, an upgrade image still started a **genesis** session when its first run was an ordinary batch
(`run_segment` on `sess = None`). At the upgrade height the operator could therefore submit a batch instead of the import:
the honest result is the state of a brand-new chain, i.e. every balance wiped. Fix: `ST_NEED_IMPORT` — an image with an
import digest (even a malformed one) runs no unit until it imported. `snapguest` E: batch → status 11, no session,
no events, zero roots; the import afterwards succeeds and the same batch then matches the uninterrupted run.

## R4-H1 (H) — long-run heap bound

`engine-diff statecap n orders withdrawals` builds a session with n fully loaded accounts (deposit, positions in two
markets, resting orders incl. isolated ones, pending withdrawals, MNWIT1 tree committed) under the host heap simulation
(64-bit sizes, an upper bound of rv32). Results in `results-loop4/l4-statecap.log`. With the cap at 256 and the
round-2 fragmentation factor (×1.3) plus the measured per-run transient of the limit batch (4.4 MB), the worst case stays
below the 50.2 MB heap. `capcheck` (liqfuzz batches + cap + 8 / 64 extra depositors and new-keeper liquidations) checks
the rule itself.

## R4-H2 (H) — engine height

See the table. `js/prodheight.js` on the prod image: +1 as unit 0 accepted; a second SetHeight in the same segment,
a jump, the same height and going back all refused; the test image accepts jumps (fixtures).

## R4-M1 (M) — rv_rollup upgrade + export / import binding

```
upgrade {upgrade: h, mem}           from $GOV only; lf < h <= top + 1, h >= 2; U<h> = mem; top = h - 1
submit  h                           s0 = H(0 : Z32 : (U<h> or m(h-1) or GENMEM) : inp : 0)
xbind   {xbind: sid, words: [kind, d0..d7], wsib: [9 x 24 siblings]}
                                    memory proofs of OUT[0x1FFD6] (kind 1 = export, 2 = import; written only on
                                    status 0) and OUT[0x1FFD8..8] (digest) against m<sid>; x<sid> = kind:d0,..,d7
finalize h with U<h>                x(sid(h-1)) = 1:D and x(sid(h)) = 2:D
```

The xbind trigger (~9 KB) is read in place (`$d = {}` for it; R3-W2). rolltest `upgrade` 26 / 26; full rolltest
303 / 303 (277 old + 26).

---

## Fix status / tests

Commits on `spike/rv-bisect`: 1d60b0c, a0bdb3e (step 1), 8d2140a (rv_rollup upgrade / xbind), 43776ea, b21b27e, 4b039c2
(post scripts); results in `guest-engine/results-loop4/` (collected in loop round 7, commit after 76124b4).

### Round-4 suite (`scripts/loop4-suite.sh c`, InstaBox VM, build target-l4c-*, sha1 in `l4-bins.txt`)

| check | result |
|---|---|
| quick (l4c-quick: fuzz 100, witfuzz 50, advfuzz 50, segfuzz 50, scen, liqfuzz 100, snaptest 100) | all green |
| fuzz 300 × 300 / advfuzz 300 / witfuzz 300 | 300 / 300 · 300 / 300 · 300 / 300 |
| segfuzz 300 | 300 / 300 (12 621 segments) |
| proofs (host reference) | 177 087 membership, 61 540 absence ok, 0 / 829 291 forged |
| scen upstream.scn host / guest | 47 / 47 · 47 / 47 |
| selftest / depthsel (64, 8) | clean |
| depth8 host / guest | 20 / 20 · 20 / 20 |
| liqfuzz 300 (liquidate / ADL / withdraw / reports / ext prices / heights, real vs port) | 300 / 300 (332 441 units) |
| snaptest 300 (export / import / digest / flips / truncations) | 300 / 300, 2 400 flips never accepted with the same digest |
| capcheck 50 × cap 8, 20 × cap 64 | 50 / 50 · 20 / 20 (cap fired in every batch) |
| liqedge (deterministic boundary cases) | ok (7 / 7) |
| statecap 64 / 128 / 256 accounts (42 orders + 64 withdrawals each) | size-class high-water 0.76 / 6.70 / 12.22 MB (host 64-bit) < 50.2 MB |
| heapsim (crowd / gen / adv / frag / limit) | ≤ 19.2 MB (crowdmax) |
| liquidation batches through the JS guest (liqgen 1–6) | 6 / 6 (6 819 units, 1.74 G steps) |
| snapshot + upgrade images through the guest (snapimg: liq7, gen9 prod) | 9 / 9 · 9 / 9 |
| prodheight.js (prod SetHeight rule) | 6 / 6 |
| prodflags (prod image refuses header flags) | ok |
| segrun small / big3k, segbig-adv (16 384 / 5 000 / 1 000) | ok · ok · 1 / 4 / 17 segments ok (the 5 000 run without an out dir panicked: harness misuse, fixed in loop 5/6 suites) |
| segbig 20 000 units (segrun) | OOM-killed (R3-T1, harness only; segbig-adv covers the guest path) |
| segguest small default / big3k | 7 / 7 · 5 / 5 |
| segguest small PROD image | suite ran it without `PROD=1` → false 1 / 7 (R7-L5); re-run with `PROD=1` (`l4-segguest-small-prod2.log`): **7 / 7 match** (seg002 status 4 as in the manifest) |
| extra-guest / robust / robust-limit / guest-poc | 9 / 9 · 15 / 15 · 1 / 1 · 3 / 3 |
| witproof e2e (prod guest memory → rv_witbind / rv_witproof) | 8 / 8 |
| sail-riscv spot check (6 batches incl. adv21, crowdc256) | 6 / 6 out_match |
| rolltest (round-4 AAs, real ocore) | 303 / 303 |
| AA static cost (rv_rollup) | complexity 63, ops 1 449 |
| rolldevnet (devnet) | suite run: 92 PASS / 0 FAIL, then killed by its 2 400 s timeout at section 6d (load ~25); re-run with 9 000 s (`l4-rolldevnet2.log`): **149 / 149 PASS**, 0 FAIL |

### Round-4 mutation test (`scripts/loop4-mut.sh`, `results-loop4/l4-mut.log`; survivors re-run with liqedge: `l4-mut2.log`)

**41 / 61 killed** in the first pass. The 20 survivors were re-run with the deterministic liqedge cases
(`loop4-post.sh`, `l4-mut2.log`): MUT2SUMMARY. Survivors and their disposition (rounds 5–6):

| # | mutant | disposition |
|---|---|---|
| 4, 5, 10, 13 | pending `>`, min-withdraw `<=`, staleness `>=`, prune `>=` | killed by liqedge (mut2) |
| 6 | withdraw equity `<=` | killed in round 5 by liqedge `wd_equity` |
| 9 | ADL last share | **equivalent** (round 8, R8-T3): survived every round-5 check (`l5-mutff.log`; the round-5 "killed" entry was wrong); with one fill per liquidation `pos_deltas` has ≤ 1 entry, so `hole · delta / total = hole` |
| 11 | TWAP min samples | equivalent: `external_twap` unreachable (funding source BondedMedianTwap, governance switch unported in round 4) |
| 15, 17, 18 | capcheck fire rule, import trailing word, snapshot decoder cap | killed in round 5 (capcheck all-new-authors rule, snaptest trailing word, snapcap) |
| 21, 23, 24 | journal / book index / put_account variants | equivalent (round 5 analysis, R5-L6) |
| 27, 32 | segs counter, report band `<` | killed in round 5 (R5-L6: segfuzz segs check, liqedge) |
| 35 | liquidatable `<` | killed in round 6 (liqedge `liq_eq` / `liq_eq_plus1`) |
| 37 | ADL counterparty collateral `.max(0)` dropped | equivalent (round 6: `cp.collateral < 0` → `min(...) < 0` → `pay > 0` false either way) |
| 52 | smt_ref absence check without the prefix test | equivalent under honest roots (round 6) |
| 55, 56 | book rollback order / pushed count | argued equivalent under one-fill-per-unit (round 5, not proven) |
