# rv loop round 15 — govwit default landed, stateless production items, adversarial review (2026-11-01)

Branch `spike/rv-bisect`, parent 6e150e4 (the brief named c5d1d9d as the pushed head; origin was 6e150e4). Design:
`docs/rv-stateless-guest.md` (§3, §4, §9, §11 updated). Code: `guest-engine/src/stateless.rs`, `guest-engine/src/main.rs`
(feature `stateless`), harness `engine-diff/src/sl.rs` (`slpoc15`, `slmig`, `slmigdump`, `slfuzz … wd`, `sladv … wd`),
`js/slmig.js`, mutants `guest-engine/scripts/loop15-mut.py`. Box logs: `guest-engine/results-loop15/`. Notes:
work/rv-rollup-notes.md "Loop round 15".

Status: **FINAL** for this round's scope (all box rows collected) (see "What remains").

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
     The decoded session's MNWIT1 tree is freed before the MNWIT-S tree is built (peak memory); a guest-level migration
     of a session at the caps (256 accounts) was not measured (JS model too slow) — listed under "What remains".
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

## Tests (box, final binary f36c325d…, `results-loop15/l15b-final.log`; engine-diff `--features stateless`, govwit default)

| run | result |
|---|---|
| `slpoc15` | **all ok**: P1 R15-H1 (status 0, root + events = direct), P2 R14-M2 (light: status 0, fee credited; round-14 full path 12; light of a user account 12; forged digest 12), P3 withdraw paths, P4 lazy expiry (expired nonce re-used → applied, live duplicate → 6, untouched extra set unchanged), P5 R15-M1 (4 097 → 16, 4 096 → 0 with the host root), P6 20 / 20 single omissions refused, P7 R2-E-3 against pre-existing resting IM, P8a / P8b single omissions 0 wrong |
| `slcaps` | ok (round-14 caps unchanged) |
| `slmig 40 300 0` / `slmig 40 300 900` | **40 / 40** each: 40 migrations, 40 / 40 negative sets (tampered word / wrong digest → 7, non-fresh → 8, no compiled digest → 10), 184 stateless segments (8 442 units) chained on the migration root with the height hook; with height jumps 429 sets held expired records, every root = lazy-commitment reference, events = session |
| `slfuzz` gen 300 × 300 / 100 × 1000 / adv 300 × 200 / ora 200 × 300 | 300 / 300, 100 / 100, 300 / 300, 200 / 200 (0 bad segments; ora: 201 unsupported first segments as in round 14) |
| `slfuzz` **wd** 300 × 300 / 60 × 1500 | **300 / 300** (3 208 segments, 127 097 units), **60 / 60** (2 484 segments, 106 205 units; pending-cap reached) |
| `sladv 40 200` (gen) | 325 segments, **46 719** cases, 0 unsound (incl. A14 light:forged-digest / forged-collateral / user-account) |
| `sladv 30 200 wd` | 253 segments, **37 822** cases, 0 unsound (incl. A15 wdl:drop-record / claim-absent / add-record, omit:wdl, omit:light) |
| session suites (quick, same binary) | govedge 9 / 9, govwit 1 / 1, fuzz 40 / 40, witfuzz 40 / 40, liqfuzz 40 / 40, segfuzz 40 / 40, govfuzz 40 / 40; the session `prod` guest image is byte-identical to round 14 (`43f65cb4…`, `l15b-build.log`) |
| guest-level (riscv32im, JS model, `l15-mig.log`) | `js/slmig.js` on a `prod,stateless` image built with the export digest: migration run status 0, SEG roots = host MNWIT-S root (10.4 M steps, 1 876 snapshot words); 3 chained stateless runs at heights 4, 5, 6 (from `SL_RUNS`) status 0, events + roots = reference; second migration → 8, tampered snapshot on a fresh image → 7. First run caught the harness height bug R15-L2 |
| steps (`l15-steps.log`, gen 3 · 300 · 100) | 4 / 4 ok; stateless 100.4 M vs session 87.5 M steps (1.15 ×; round 14: 1.13 ×), peak heap 0.36 MB |

## Mutants (`guest-engine/scripts/loop15-mut.py`; killed = slpoc15 not ok, sladv unsound, slfuzz bad segment, or a panic)

| mutant | result |
|---|---|
| R15-H1-preFix-decimal-apos (round-14 decimal `apos:`) | **killed** — slpoc15 panics (PoC of R15-H1) |
| light-any-account (light record accepted for any id) | killed (slpoc15 P2) |
| light-apos-unchecked | killed (slpoc15) |
| light-apos-unchecked + update-unverified | killed (slpoc15) |
| light-acct-unchecked + update-unverified | killed (sladv wd, 26 unsound: `light:forged-collateral`) |
| light-end-check-off (end-root membership check of a light record) | survives — **equivalent** for the current op set (no supported op changes the insurance membership or gives it positions); kept as defence for future ops |
| wdl-pre-off (Withdraw without the author's `wdl` set) | survived pass 1 (the post catch-all caught every applied case); **killed** after P8a (dup-nonce dust withdraw: DuplicateNonce precedes Risk) — `l15-mut3.log` |
| wdl-pre + post-off | killed (sladv wd, 47) |
| wdl-unchecked + update-unverified | killed (sladv wd, 41) |
| wdl-expiry-filter-off | killed (slpoc15 P4) |
| wdl-rewrite-always (rewrite untouched sets) | killed (slpoc15 P4: untouched extra set with an expired record) |
| withdraw-aord-pre-off (R2-E-3 inputs not required) | survived pass 1; **killed** after P7 (pre-existing resting IM) — `l15-mut2.log` |

11 / 12 killed, 1 equivalent.

## What remains

Design §11: liquidation / ADL (per-market OI leaves, ordered ADL candidate index), oracle report / stake / slash and
funding in stateless mode, governance / commit-reveal (`weight_snapshot` O(holders)), CreateMarket, linked-FIFO levels
(drops whole-level loading, the level cap and R15-M1), lazy expiry for commits / oracle unbonding once those ops are
supported, rollup integration of the migration run (R15-I1) and DA of the witness, operator touched-set tracking,
upstream mirroring of the leaf kinds (`apos` digest form, `wdl`), guest-level migration cost / peak heap for a session
at the caps (needs a sail / native run, not the JS model).
