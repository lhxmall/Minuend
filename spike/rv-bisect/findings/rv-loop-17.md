# rv loop round 17 — linked-FIFO levels committed, round-16 collection, migration decode mode, stateless liquidation, review (2026-11-01)

Branch `spike/rv-bisect`, parent 86fb224. Commits: e06de09 (linked-FIFO levels + design §2–6, 9, 11, 12), 3f093e0
(migration decode mode, findings/rv-loop-16.md), 5502b78 (stateless liquidation, R17-H1), 4a62fd5 (R17-L1 fix, sldiff, sladv wrong-root harness fix).
Design: `docs/rv-stateless-guest.md` (§4 Liquidate, §11, §12). Box logs: `guest-engine/results-loop17/`. Notes:
work/rv-rollup-notes.md "Loop round 17".

Status: **FINAL** (2026-11-01, collected by the second round-17 agent: R17-L1 fixed in 4a62fd5; sail measurement pending, see "What remains").

## What was done

1. **Linked-FIFO levels committed** after the full stateless suite on the round-16 dev build (b6bedf37): `lvl:` holds
   (head, tail), `olk:<order>` the FIFO links; level records carry any subset of a level's orders; R14-M1 / R15-M1 gone.
2. **Round-16 collection**: `findings/rv-loop-16.md` FINAL (R16-M1 M fixed, R16-L1 / L2 fixed, R16-I1..I3), notes
   "Loop round 16", logs `results-loop16/`.
3. **Migration decode mode** (`snapshot::decode_opts(r, build_wit = false)`): a migration no longer rebuilds the
   session's MNWIT1 witness tree (`Wit::from_state`, leaf by leaf) and reads / hashes the snapshot once (the decoder's
   SnapR hash; digest + full length checked after the decode). Guest measurement under sail: Tests.
4. **Stateless liquidation, book path** (`stateless.rs liq_pre`, `liq_first_maker`; engine flag `SL_ADL_REACHED`):
   keeper / target / market / insurance light / the target's orders loaded; the R7-H1 dust check's input proven
   (`first_maker_qty`: levels in price priority up to the first live maker of another account, start FIFO chain
   loaded up to it); the IOC walk checked like a Place's. Any unit that reaches the **ADL remainder** → UNSUPPORTED
   (the session ranks all opposite holders; design §12.2). Funding-rate markets and a revealed Liquidate → UNSUPPORTED.
   Harness: `slfuzz … liq` / `sladv … liq` (new workload `liq_sl_batch`: fill-driven marks, thin traders 5–9x,
   keepers, dust tops), `slpoc17` (ADL segments refused, also with every holder's record in the witness).
5. Oracle report / stake / slash / funding and proposals / vote / finalize stay unsupported; their designs are in §12
   (bonded-oracle epochs copied into per-market report sets; PERP balance checkpoints instead of weight_snapshot).

## Summary of findings

| id | sev | where | what | status |
|---|---|---|---|---|
| R17-H1 | H | stateless liquidation (this round's first draft, never committed) | the ADL remainder ranks every opposite holder of the market (`holders_of`, \|qty\| desc / id asc). In a partial state it ranks only the holders **the witness chose to load**: the operator steers the counterparty (load only the victim), or makes the ADL leg fail / find nobody (load none, or one whose fill errs) and the unit returns a status-0 result the session would not produce. The first draft refused only the outcome forms "Ok with no fill" and "an ADL fill (kind 2)"; an error raised inside the ADL leg (apply_fill_pair on the chosen candidate) still produced a status-0 rejection | **fixed before commit**: the engine sets `stateless::SL_ADL_REACHED` on entering the remainder; the stateless run clears it before every unit and refuses (UNSUPPORTED) any unit that set it, whatever its result; the outcome-form check stays as defence. PoC `slpoc17` (see Tests): every segment that reaches the ADL leg is refused with the honest witness and with a witness carrying every holder's record |
| R17-L1 | L | stateless event log (liquidation fills, MNP1) | the session's event writer masks the taker id of a liquidation / ADL fill (kind 2 / 3) in an MNP1 batch with `LIQ_TAKER_EV` (unit id 0 in MNP1); the stateless run wrote the real `liq_order_id(0)` -- the same status-0 unit produced a different event log in the two images (slfuzz liq: 3 / 20 batches "events differ", found with the new `sldiff` tool; end roots equal). Unreachable in `prod` (an MNP1 Liquidate is refused there; MNP2 writes the real id in both) | **fixed** (4a62fd5): the stateless writer applies the same mask; slfuzz liq 20/20 |
| R17-I1 | I | migration decode mode | the migration now decodes before it checks the digest (one hash pass instead of two): a non-matching input pays a full decode (bounded by `SNAP_LIMIT` words / `SNAP_MAX_ITEMS`, heap-bounded) before BAD_SNAP; a decode of untrusted words was previously never reached. It is never accepted (digest over exactly the words read + full-length check). Deterministic either way (a decode trap / OOM on garbage is a failed run like BAD_SNAP) | accepted trade-off, documented; revert to digest-first if guest cost of failing runs matters |
| R17-I2 | I | stateless W2 depth rule | the stateless image evaluates the W2 depth rule (keeper `acct:` key of a Liquidate, Place / Deposit keys) on the **MNWIT-S** tree, the session on the MNWIT1 tree: the same unit can be depth-refused in one image and not the other. Pre-existing since round 14 (the stateless image is its own consensus after the migration); unreachable without a 2^MAX_WIT_DEPTH prefix grind | documented; a production spec states the rule on the MNWIT-S tree |
| R17-I3 | I | R16-I3 applied to Liquidate | the session's global account cap for a keeper's first credit (`state_cap_ok` Deposit / Liquidate) is not enforced by the stateless image | as R16-I3 |

Linked-FIFO review (no finding): head selection (`sl_ok`), drained levels (`sl_drained`), the walk check on never-examined
better levels, end-root link rewrite (neighbours of removed orders, new head, appended tail must be loaded; an
unloaded order is live because no unit can remove it: Cancel needs it loaded, fills / STP take heads only), the
loader's link / seq consistency (FIFO = seq order: an order rests only in its placement unit, seqs grow with applied
units, rejected units roll back) — all hold; sladv `book:omit-head` / `drop-order-in-level` / `reorder-fifo` /
`omit-best-level` 0 wrong across 154 814 cases.

Totals: **C 0 · H 1 (fixed before commit) · M 0 · L 1 (fixed) · I 3**.

Harness note (not a finding): sladv 'wrong-root' counted 7 "unsound" in the liq workload -- the "wrong" witness is built
from the previous segment's pre-state, which equals this segment's pre-state when the previous segment changed nothing
(all its units refused / rejected); the witness is then honest and the acceptance correct. The harness now counts it as
a correct acceptance when the roots are equal and the result matches (4a62fd5).

## Tests

Logs: `guest-engine/results-loop17/` (box /data/hark/logs/rv). Binaries: target-l16d-host b6bedf37 (step 1),
target-l17-host 96d6f645 (step 3), target-l17m-host 24334b8e (step 4 commit 5502b78) / 1f24ac96 (+ sldiff) /
becc3ad4 (R17-L1 fix, 4a62fd5).

| what | result | log |
|---|---|---|
| step 1 suite (linked FIFO, b6bedf37) | slpoc15 / slcaps ok, slmig 40/40 x2, slfuzz gen 300/300, perp 300/300 + 60x1000 60/60, sladv gen 51 383 / perp 44 738 / wd 58 693 cases 0 unsound | l16-r17{a,b,c}.log |
| step 3 decode mode (96d6f645) | slpoc15 ok, slmig 40/40 (hstep 0) and 40/40 (hstep 900, 429 sets with expired records) | l17-mig.log |
| step 4 first liq runs (24334b8e / 1f24ac96) | slpoc17 10/10 ADL segments refused; slfuzz 20x300 liq **17/20 (3 bad: R17-L1)**; sladv 6x200 liq 59 716 cases, 7 "unsound" = harness wrong-root artifact | l17m-liq.log |
| step 4 regression (24334b8e) | slpoc15 / slcaps ok, slfuzz gen 100/100, perp 60/60, slpoc17 40/40 (10 ADL segments refused, also with every holder loaded) | l17m-reg.log |
| R17-H1 mutant (both ADL refusals off) | slpoc17 **not ok**: 4 wrong status-0 results (killed) | l17-mut.log |
| R17-L1 diagnosis | sldiff 8 300 liq: unit 19 Liquidate, stateless taker word liq_order_id(0) vs session LIQ_TAKER_EV | l17m-diff.log |
| after the fix (becc3ad4) | sldiff 8 liq: no differing segment; slpoc17 40/40; slfuzz 20x300 liq **20/20** (655 liq units proven, 205 ADL segments unsupported); sladv 6x200 liq 59 716 cases **0 unsound**; slpoc15 / slcaps ok; slfuzz gen 100/100, perp 60/60, wd 60/60; sladv 6x200 gen 5 247 cases 0 unsound | l17m-c2liq.log, l17m-c2reg.log |
| guest build (stateless, riscv32) | clean (l17m-gsl / l17m-b) | l17m-gsl.log |
| guest migration under sail, 64 accounts (decode mode, loop17) vs round-16 baseline (l16c2, loop16c) | **no result in round 17**: both sail runs were killed by the user stop at 02:41 UTC (decode mode after 1 h 47 m, baseline after 2 h 24 m, no partial count is printed); rerun in round 19 (l19-cap-dec / l19-cap-base, see rv-loop-19). The queued 256-account config is **not a valid session state**: 256 traders + creator + oracles exceed MAX_STATE_ACCOUNTS (256), so the host migration returns BAD_SNAP (status 7, the decoder's import cap) -- a fixture error, not a finding; stopped in round 19 | l17-cap.log, l16-cap2.log, l17-cap256.log |

## What remains

- Sail measurement of the decode mode: rerun in round 19 (64 accounts, both images; rv-loop-19). Host-side the decode
  mode is green (slmig, slpoc15) and `migrate_host_s` 0.103 s -> 0.093 s.
- ADL remainder (design §12.2), oracle / funding (§12.1): unsupported. Governance: round 18.

Status: **FINAL** (round-17 code and findings closed; the sail measurement is a pending data point, not a finding).
