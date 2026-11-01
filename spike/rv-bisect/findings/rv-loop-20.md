# rv loop round 20 — stateless oracle (stake / unstake / report / slash, eager unbonding expiry), funding decision (2026-11-01)

Branch `spike/rv-bisect`, parent 5b85c5a (round-19 head). Design: `docs/rv-stateless-guest.md` §2 (leaves), §4 (guards),
§11, §12.1 "Round-20 implementation". Code: `guest-engine/src/stateless/ora.rs` (new), wiring in `stateless.rs`, the
funding flag in `state.rs`, the session rule in `lib.rs`; harness `engine-diff/src/sl.rs` (`slora`, `slpoc20`, `orc`
workload). Box logs: `guest-engine/results-loop20/`. Notes: work/rv-rollup-notes.md "Loop round 20". Pushes: Radicle first,
then GitHub.

Status: **FINAL** for the round-20 scope (oracle steps 1 and 3 implemented, step 2 = funding decided against with a
recommendation; stateless ADL not started — see "What remains").

## What was done

1. **Stateless oracle, step 1** (221003b, reworked d59780d): MNWIT-S leaves `ostk:` (bond / unlock), `orm:` (an oracle's
   markets), `orep:` (a market's reporters: report, `bonded` flag, history digest), `omk:` (oracle config, funding clock,
   TWAP rings), `oglob:0` (funding source, slash nonce, queue ends), `oexp:<u>` (expiry queue) — all pure functions of
   the session state, so the reference root stays `s_root(session state)`. Stake / Unstake / Report run unchanged on the
   partial state; the median, the mark band, the TWAP rings and `oracled` read only loaded records.
2. **Eager unbonding expiry (R19-I2)**: a run that moves the height walks the queue from `oglob:0`'s head, loads every
   group up to the new height with its oracles' `ostk:` and account records, runs the session's
   `prune_oracle_unbonding` on the partial state and applies the post-unit guards (bond returned to PERP → pglob /
   exception list; the released oracles' entries leave every report set; `oracled` flips → mkx:; queue unlinked).
3. **Slash, step 3** (f4f2e67): challenger record + `perp:0`, the target's bond, the market's TWAP / config, the target's
   history; the bond removal rewrites the target's entries in every market (post guard (b)), the unbonding leaves the
   queue. A revealed Slash is unsupported (its target guard runs on the op only, like a revealed Liquidate).
4. **Funding, step 2** (R19-I1 design "bounded holder list or rejected"): **rejected** — see R20-I1. A unit that reaches
   `transfer_funding` / `transfer_funding_rate` / `settle_funding_peg` sets `SL_FUNDING_REACHED` (state.rs) and the
   segment is UNSUPPORTED; a Report on a funding-rate market or under the AggregatedExternal source is unsupported.
5. Adversarial review of 1–3 (below), PoCs (`slpoc20` P1–P7), guard mutants (`loop20-mut.py`), full stateless
   regression, real-vs-port differentials (govfuzz / liqfuzz), riscv32 stateless guest build.

## Summary of findings

| id | sev | where | what | status |
|---|---|---|---|---|
| R20-M1 | M | stateless oracle, first form (221003b) | one `ohist:<m>:<acct>` leaf per (market, oracle): a bond change / expiry / slash had to load every history record of the oracle (guard (b)), and the hook loads every released oracle's: with no bound on the oracles released at one height, N × (markets per oracle) history records exceed the per-segment record limit (4 096) — e.g. 65 oracles × 64 markets unstaking at one height → at unlock height no witness exists for the hook, which runs before any unit and cannot be split by the operator: **the stateless chain halts** | **fixed** (d59780d): the history is a (length, digest) field of the oracle's `orep:<m>` entry; samples travel only for the Report author / Slash target; a released oracle's entries leave the loaded report sets without their samples. A bond change costs one record per MARKET |
| R20-M2 | M | eager expiry (R19-I2 design) | the oracles released at height h are the Unstake units of h − 256, bounded only by the batch table (4 096 authors): the hook's `ostk:` + account records (+ exception lists) exceed SL_MAX_ACCOUNTS → halt (same mechanism as R20-M1) | **fixed** (d59780d): `SL_MAX_UNSTAKES` oracles per expiry group; a further Unstake at that height is refused (code 19, inputs: `oglob:` + this height's group). slpoc20 P1 |
| R20-M3 | M | bounds of d59780d | SL_MAX_UNSTAKES × SL_MAX_ORACLE_MKTS = 64 × 64: released oracles covering > 256 distinct markets need > SL_MAX_MARKETS report-set records (and market records where `oracled` flips) → the hook has no witness → halt (cost: ≥ 257 listings + 5 bonds, returned at expiry) | **fixed** (777d820): 16 × 16 with a compile-time assert `SL_MAX_UNSTAKES × SL_MAX_ORACLE_MKTS ≤ SL_MAX_MARKETS`; 16 = the session's MAX_STATE_MARKETS, so no session state is excluded. slpoc20 P2 measures the worst case: 16 oracles × 16 distinct markets → 256 report-set + 256 market records, 125 KB, status 0 = session hook |
| R20-L1 | L | session vs stateless image (d59780d) | the session image allows up to MAX_STATE_ORACLES (32) unstakes at one height, the stateless image refused the 17th (after R20-M3): a session-reachable unit with different outcomes in the two images (the migration also refuses such a state) | **fixed** (5eb2796): `MAX_UNSTAKES_PER_HEIGHT` (16) is a rule of the session's `state_cap_ok` too (code 19); the stateless bound is the same constant. slpoc20 P7. govfuzz 30 / liqfuzz 20 (real engine vs port) unaffected |
| R20-I1 | I | funding (R19-I1 decision) | a holder-list leaf `hset:<m>` would make a funding tick provable but loads every holder each tick (~600 B per holder, every height with ≥ 2 reporters) and needs a per-market holder cap as a consensus rule of both images (> ~4 096 holders could never tick) — a squatting surface (dust positions fill the cap) | design **rejected**: funding transfers / the funding-rate peg stay UNSUPPORTED in the stateless image (a height with such a unit cannot be proven statelessly); production needs upstream index-based funding (cumulative per-market index, O(1) per tick, settled on touch) — design §12.1 round-20 bullet |
| R20-I2 | I | per-height work vs per-segment limits (generic) | the stateless guest proves one height per run with fixed record limits (256 markets, 4 096 accounts, 2^18 tree nodes); the operator can keep a height's UNITS within them by cutting batches, but nothing it can cut must exceed them: the hook (R20-M1..M3 bound it now) and a single unit. Checked for the oracle units: a Stake / Slash of an oracle with 16 markets ≤ 16 report-set + 16 market records; a Report ≤ one report set (64 entries) | documented; the pre-existing cases (Places in > 256 markets in ONE height are an operator choice, not a halt) unchanged |
| R20-I3 | I | stateless-only rules | SL_MAX_REPORTERS (64 per market) and SL_MAX_ORACLE_MKTS (16 per oracle) are stateless rules (code 19); the session cannot reach them (MAX_STATE_ORACLES 32, MAX_STATE_MARKETS 16); the migration refuses a state above them (ST_SL_MIG_BOUNDS, slpoc20 P5) | by design (like SL_MAX_POS) |

Review notes (no finding): every oracle record is checked against the tree (`ostk:` / `orm:` / `orep:` / `omk:` /
`oglob:` / `oexp:` leaves recomputed; history samples against their entry's digest; an `ohist` record needs its report
set loaded); a reporter whose `ostk:` is not loaded gets its bond PRESENCE from its entry's flag (consistent with a loaded
`ostk:`, else BADWIT; its value is read only by a slash of it / its expiry, which load its `ostk:`); the stand-in reporter
of an `oracled` market (round 14) is removed when the market's real report set is loaded and the two facts must agree;
the post guards compare against the load-time snapshots after EVERY unit and after the hook, so a transient change (bond
removed then re-staked in one segment) is still seen; `entries_now` decides membership only for loaded report sets,
every other membership cannot change (Report / Slash / bond changes load the sets, guard (c)); the queue's middle
insertion (unlock below the tail) is unsupported (never in a bound image: unlock = height + 256 is the maximum).

Totals: **C 0 · H 0 · M 3 (all fixed) · L 1 (fixed) · I 3**.

## Tests

Logs: `guest-engine/results-loop20/` (box /data/hark/logs/rv). Binaries (engine-diff, profile `l20`, shared
CARGO_TARGET_DIR /data/hark/target-spike): 65e247ae (221003b), 5522b875 / 64aecc5b (R20-M1/M2), 9429664c (Slash),
76818377 (R20-M3), d618f3ba (R20-L1, final code).

TESTS_TABLE

## What remains

- Funding transfers / the funding-rate peg / ExtPrice: unsupported (R20-I1: upstream index-based funding needed).
- Stateless ADL (§12.2 rank index; R17-H1 still UNSUPPORTED) — not started this round.
- Fuzz coverage of Slash is thin (a slashable streak needs 3 consecutive heights of deviant reports: 6 applied slashes
  proven across the `slora` runs); the directed `slpoc20` P6 covers the full path (queue unlink, `oracled` flip,
  challenger reward). A slash-heavy workload would raise it.
- Production items unchanged: DA, stateless export path (R16-I2), global caps (R16-I3 / R17-I3).
