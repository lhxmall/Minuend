# rv loop round 14 — stateless (witness-fed) guest: design, prototype, adversarial review (2026-11-01)

Branch `spike/rv-bisect`, parent 422e127. Design: `docs/rv-stateless-guest.md`. Prototype: `guest-engine/src/stateless.rs`
(feature `stateless`), harness `engine-diff/src/sl.rs`, `js/slsteps.js`, mutants `guest-engine/scripts/loop14-mut.py`.
Box logs: `guest-engine/results-loop14/`. Notes: work/rv-rollup-notes.md "Loop round 14".

## Summary

| id | sev | where | what | status |
|---|---|---|---|---|
| R14-C1 | C | stateless multiproof | a hash-only leaf `L(key, hash)` in the pruned tree carries an **unverified key**: the decoder checks only the first d bits (its path) and the root only its hash. An operator flips deep key bits of an existing leaf and "proves" it absent: the guest runs the batch as if the account did not exist and returns **status 0 with a wrong end root** — the instruction game cannot catch it (the run is a correct execution of the forged input) | **fixed** (c27b289): unverified leaves may be hashed, lifted and used for inclusion checks only (the record's recomputed leaf hash binds hex(key) → then marked verified); exclusion / split / update / delete through one → MISSING; verified leaves come as tag 4 (kid + rest, key and hash recomputed). PoC `sladv` case `forge:absent-via-leaf-key`: before the fix 15 / 15 status 0 with a wrong result (`results-loop14/l14-sladv-preC1.log`), after 273 / 273 refused |
| R14-H1 | H | stateless image rules | no global market cap any more → an account can hold positions in > `SL_MAX_POS` markets; its record (positions + apos) can then never be loaded, and one resting order of it at the top of a book halts that market (every taker needs the maker's record) | **fixed** (b1a4f3f): per-account exposure cap — a Place by an account with no position and no live order in the market is refused (code 19) when it already has 64 markets of exposure; inputs fully loaded, so the rule is witness-independent. `slcaps` unit 1 |
| R14-H2 | H | rollup integration | the stateless guest accepts any self-consistent witness and outputs its claimed root as the segment start root (sladv `wrong-root`: 94 / 285 runs status 0 with another start root; `forge:self-consistent` likewise). In the session image the chain is implied by the carried memory; for the stateless image **rv_rollup must bind start root(h) = end root(h-1)** and void a submission whose OUT status ≠ 0 without a game | **open — design requirement before the stateless image is used** (not exploitable today: the rollup runs the session image). Proposed rule in the design doc §9 (memory proofs of OUT[SEG_START] in m(h) and OUT[SEG_END] in m(h-1), as xbind does for kinds) |
| R14-M1 | M | order book | levels are loaded whole; a level with more than `SL_MAX_LEVEL_ORDERS` orders could never be loaded (liveness) and a big level makes every touch O(level) | **fixed (bounded)** (b1a4f3f): a GTC limit joining a level with 4 096 live orders is refused (19); the own-side level must be known (or proven empty by the trie) for every GTC limit, so the rule is witness-independent. `slcaps` unit 3. Production: linked-FIFO leaves (design §6) |
| R14-M2 | M | insurance record | every Place loads the insurance account with all its positions (fee / claw path needs only its collateral); with unbounded markets the insurance account can acquire > 64 positions through liquidations / ADL and then no Place can be proven | **open** (liquidation is not in the prototype's scope, so not reachable here): a light record (acct leaf + apos digest, positions untouched) for the fee leg; listed in design §11 |
| R14-M3 | M | cost bound | the first limits allowed 2^20 tree nodes and 4 096 × 4 096 orders per segment: a witness whose verification alone costs > 10^10 steps (an operator-chosen DoS on challengers / step bound) | **fixed** (b1a4f3f): tree nodes 2^18, orders 2^16 in total, witness 16 MiB; worst case ≈ 2^18 × 2 + 2^16 × ~4 compressions ≈ 0.8 M compressions ≈ 3 × 10^9 steps; honest segments use ~8 nodes per unit (§ measurements) |
| R14-L1 | L | prototype | PTree deletion returned "unchanged" for a child node that stayed the same node while a deeper deletion changed its hash → stale cached hash → wrong end root (first `slfuzz` run: 12 / 20 batches) | **fixed** in e10edba before the first commit of results (deletion reports `changed`) |
| R14-L2 | L | determinism | extra (valid) witness records can turn status 0 into MISSING (e.g. a level of a market whose params were not supplied), never change a status-0 result | accepted: a status-0 result is unique (`extra:valid` 325 / 325 identical); an operator who posts a MISSING run only invalidates its own height |
| R14-I1 | I | exclusion | can a key be proven absent while present? | no (after R14-C1): an exclusion path must end in E or a verified leaf with another key; `omit:*` / `flip:*` / `forge:*` never produce a wrong status-0 result (sladv 31 260 / 31 260 sound) |
| R14-I2 | I | order book | omitting the best level, hiding a level by claiming its trie node absent, dropping or reordering orders in a level | all refused (MISSING / BADWIT): `book:omit-best-level` 478 / 478, `book:hide-level-in-trie` 274 / 274, `book:drop-order-in-level` 274 / 274, `book:reorder-fifo` 173 / 173 |
| R14-I3 | I | duplicates / limits | the same account twice; counts above the limits | refused: `duplicate:account` 325 / 325, `limit:accounts` 325 / 325; duplicates of every record kind and an order in two levels / in a level and in `ordx` are refused by the loader |
| R14-I4 | I | oracle facts | the fill path's mark rule reads `last_index` and the bonded-reporter predicate, which MNWIT1 does not commit | committed in `mkx:`; `slfuzz ora` 200 / 200 (pre-states with bonded reports) |

## Tests (box, engine-diff --features stateless)

* `slfuzz 300 300` 300 / 300 (2 836 segments, 112 794 units), `slfuzz 100 1000` 100 / 100 (107 581 units),
  `slfuzz 300 200 adv` 300 / 300, `slfuzz 200 300 ora` 200 / 200 — every segment status 0, events equal to the session
  port, start / end roots = MNWIT-S roots of the session pre / post state (`results-loop14/l14-slfuzz.log`).
* `sladv 40 200`: 325 segments, 31 260 adversarial cases, 0 unsound (`results-loop14/l14-sladv.log`; case table there).
* `slcaps`: ok (units 19 / applied / 19 / applied / applied+1 fill; level of 4 096 orders loaded, 739 KB witness).
* Guard mutants (`loop14-mut.py`, `results-loop14/l14-mut.log`): see "Mutants".
* riscv32im: session vs stateless steps per segment (`results-loop14/l14-steps.log`): see "Steps".

## Mutants

_filled from l14-mut.log_

## Steps

_filled from l14-steps.log_

## R14-C1 (C) — exclusion through an unverified leaf key

Compact SMT proofs normally carry, for a hash-only sibling or terminal leaf, its key and its leaf hash. The leaf hash
`sha256("~L1:" || hex(key) || ":" || leaf)` binds the key, but the verifier cannot recompute it without the leaf
string, so the key is only as good as the path bits that led to it. The prototype's first decoder accepted
`L(key, hash)` and `get(key')` answered "absent" whenever `key' != key`. The PoC (`sladv`, A12): take an author X that
exists, build the records from a state without X (`acct/apos/cseq` claimed absent), and in the honest tree flip bit 255
of the keys of X's `acct:` / `apos:` / `cseq:` leaves. The root is unchanged (hashes unchanged); the loader accepts the
exclusion proofs; X's units run on a fresh account; the end root inserts a second `acct:` leaf for X next to the old one.
Status 0, wrong root, 15 / 15 segments. Fix: the three-valued leaf (unverified / verified), see the table; builder emits
tag 4 for leaves that end another key's path and for single-leaf siblings (which a deletion may lift into a later
split). After the fix the PoC is refused 273 / 273 and the 5 mutants of this class are killed (C1-unverified-absent).

## R14-H2 (H) — start-root binding is a rollup duty now

`run_stateless` checks the tree against the claimed root and outputs it; it cannot know the previous height's end root.
`sladv` `wrong-root` (witness of the previous segment's state) and `forge:self-consistent` (a forged state with its own
root) show status-0 runs whose start root differs from the chain. Required rule (not implemented — the AAs still run the
session image): finalize(h) or a void trigger checks OUT[SEG_START] of m(h) against OUT[SEG_END] of m(h-1) with memory
proofs (24 siblings each, like rv_witbind), and a submission whose OUT status ≠ 0 is voidable by one memory proof.

## What remains

See design §11: the remaining ops (withdraw, liquidation / ADL, oracles, funding, governance, commit-reveal, listing), the
height hook, the rollup integration (R14-H2, input layout, DA, MNWIT-S migration), linked-FIFO levels, the light insurance
record (R14-M2), operator touched-set tracking.
