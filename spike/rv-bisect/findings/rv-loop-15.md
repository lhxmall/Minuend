# rv loop round 15 — govwit default landed, stateless production items, adversarial review (2026-11-01)

Branch `spike/rv-bisect`, parent 6e150e4 (the brief named c5d1d9d as the pushed head; origin was 6e150e4). Design:
`docs/rv-stateless-guest.md` (§3, §4, §9, §11 updated). Code: `guest-engine/src/stateless.rs`, `guest-engine/src/main.rs`
(feature `stateless`), harness `engine-diff/src/sl.rs` (`slpoc15`, `slmig`, `slmigdump`, `slfuzz … wd`, `sladv … wd`),
`js/slmig.js`, mutants `guest-engine/scripts/loop15-mut.py`. Box logs: `guest-engine/results-loop15/`. Notes:
work/rv-rollup-notes.md "Loop round 15".

Status: **FINAL** for this round's scope (see "What remains").

## What was done

1. **govwit is the default feature** (consensus change: MNWIT1 roots of batches with governance state change, others
   identical) — round-10 govwit suite SUITEDONE all green, repo-default rebuild `l14-gw.log` green (rv-loop-10 "govwit
   default", design §7.3.4).
2. Round-14 collection (`results-loop14/`), rv-loop-14 Steps + FINAL.
3. Stateless production items (each differentially tested against the session port):
   * **R14-M2 light insurance record** — the fee leg of a Place reads only the insurance collateral; the witness now
     carries a light record (acct: leaf + apos: digest, no positions) for the insurance account only.
   * **`apos:` in digest form** `apos:<id>:<flags>:<npos>:<sha256(markets)>` (fixes R15-H1, enables the light record).
   * **Withdraw in stateless mode** — new leaf kind `wdl:<id>:<n>:<sha256(records)>` (the account's withdrawal records,
     ≤ 64), loader section `wdl`, pre-unit guard (author record + its withdrawal records + its order set and levels + the
     params of every book: the R2-E-3 resting-IM input), post-unit catch-all, end-root rewrite only when the live set changed.
   * **Height hook (lazy)** — a bound run (prod: run number = rollup height, carried `SL_RUNS`) moves the engine height
     before the units; withdrawal records expire on read (`height + REPLAY_WINDOW > height`) and a set is rewritten only
     when touched (witness-independent). Nothing else is pruned (commits / oracle unbonding have no reader in the
     stateless image's op set).
   * **MNWIT-S genesis by migration** — `stateless::migrate` / guest run `[SL_MIG_MAGIC, snapshot words]`: only a fresh
     lineage without a compiled genesis root, only the compiled-in export digest (`MNPILOT_IMPORT_DIGEST`, the R4-S1
     binding); MNWIT-S root over the decoded session state; per-object bounds check (R15-M1); sets `SL_ROOT` / `SL_RUNS`.
   * Not done this round (budget, correctness first): liquidation / ADL, oracle / funding, governance / commit-reveal in
     stateless mode, linked-FIFO levels (design §11).

## Summary of findings

| id | sev | where | what | status |
|---|---|---|---|---|
| R15-H1 | H | stateless `apos:` leaf (round-14 code) | the round-14 `apos:` leaf listed the account's position markets in decimal (`:<flags>:m1,m2,…`) inside the fixed 384-byte leaf buffer `wit::Buf`. An account with many positions in high market ids (64 × 10-digit ids → 775 bytes) makes `Buf::raw` index out of bounds: **panic** in the reference builder, the operator, and the guest's loader / end root (the riscv image traps). Markets are unbounded in the stateless image and the exposure cap allows 64 per account, so any account can be driven there; every segment touching it traps → the account's resting order at the top of a book halts the market (the R14-H1 class) | **fixed** (9c6ca07): fixed-length digest form `apos:<id>:<flags>:<npos>:<sha256(markets u32 LE)>` (139 bytes). PoC `slpoc15` P1 (64 positions in markets 4 000 000 000 + k): pre-fix mutant `R15-H1-preFix-decimal-apos` → the harness panics (empty output, `l15-mut.log`); fixed: place + taker fill + withdraw status 0, events and end root = direct reference |
| R15-M1 | M | migration | a session state can hold a price level with more than `SL_MAX_LEVEL_ORDERS` = 4 096 orders (256 accounts × 64 live orders at one price); after migration that level could never be loaded (the stateless image loads levels whole) → its market halts. Same for an account with > 64 markets of exposure (not reachable from the session: 16 markets) | **fixed**: `migrate` refuses such a snapshot (`ST_SL_MIG_BOUNDS` = 16; governance migrates at a height without it, or linked-FIFO levels lift the bound). `slpoc15` P5: 4 097 refused, 4 096 accepted (root = host root) |
| R14-M2 | M→L | insurance record | every Place loaded the full insurance record (all positions + their markets); > 64 positions → no witness | **fixed** (light record, insurance id only; a light record of any other account is refused). Premise corrected: in this engine version the insurance account never takes a position (never liquidated or liquidating, `engine.rs` 1324; never an ADL candidate or buyer of last resort, 1552 / 1580; cannot author), so the halt was reachable only from a migrated / genesis state; the light record also cuts the per-Place witness. `slpoc15` P2 (insurance with 100 positions): round-14 path BADWIT, light status 0 with the fee credited and the right root; light record of a user account BADWIT; forged count / digest BADWIT. sladv A14 `light:forged-digest`, `light:forged-collateral`, `light:user-account` all refused |
| R15-L1 | L | guest genesis sources | an image compiled with `MNPILOT_SL_GENESIS` could still accept a migration before its first stateless run (two genesis sources; whichever ran first won) | **fixed**: migration requires `SL_INIT == 0` and no compiled genesis root |
| R15-L2 | L | harness (found by the guest-level test) | `slmigdump` advanced the height twice per post-migration segment (4, 6, 8) while the image's `SL_RUNS` gives 4, 5, 6: the guest returned status 0 with a different end root (glob height) and then BADROOT — i.e. the height binding works; the fixture was wrong | fixed in the harness; `js/slmig.js` rerun green (see Tests) |
| R15-I1 | I | rollup integration | a migration run's SEG_START / SEG_END is an **MNWIT-S** root while the export run's SEG_END is an MNWIT1 root: rv_rollup's import rule `start_root(i) == end_root(e)` cannot hold across the format change | requirement for the integration: for SNAP_KIND 3 the rollup binds the snapshot digest (as for imports) and NOT the root chain; the MNWIT-S root is a disputable output of the migration run. Documented in design §9 / §11 |
| R15-I2 | I | migration scope | state the MNWIT-S leaf set does not commit (oracle report rings / TWAPs / unbonding, proposals' voter sets and weight snapshots, perp supply / burned, funding clocks) is not carried by a migration | documented (design §11): a production migration needs leaves for them before the stateless image supports the ops that read them; nothing in the current stateless op set reads them |
| R15-I3 | I | lazy expiry vs the session | the stateless chain's `wdl:` leaves may keep records older than the replay window until touched, so its MNWIT-S root is not the root of the session's (eagerly pruned) state; behaviour (events, every rule's outcome) is identical | by design; `slmig … 900` checks it against a lazy-commitment reference model (263 sets with expired records seen, all roots and events equal) |
| R15-I4 | I | light record reads | could a supported op read the insurance positions (absent from a light record)? | no: Deposit / Place / Cancel / Withdraw read only its collateral (fee leg); `need_acct` refuses a light record wherever an account's positions are read; the end root requires unchanged membership / no positions (`light-end-check-off` mutant survives = equivalent for the current op set, kept as defence for future ops) |

Totals: **C 0 · H 1 (fixed) · M 2 (fixed) · L 2 (fixed) · I 4**.

## Tests

_filled from the box runs (results-loop15/), see below_

## Mutants (`guest-engine/scripts/loop15-mut.py`)

_filled from l15-mut.log_

## What remains

Design §11: liquidation / ADL (per-market OI leaves, ordered ADL candidate index), oracle report / stake / slash and
funding in stateless mode, governance / commit-reveal (`weight_snapshot` O(holders)), CreateMarket, linked-FIFO levels
(drops whole-level loading, the level cap and R15-M1), lazy expiry for commits / oracle unbonding once those ops are
supported, rollup integration of the migration run (R15-I1) and DA of the witness, operator touched-set tracking,
upstream mirroring of the leaf kinds (`apos` digest form, `wdl`).
