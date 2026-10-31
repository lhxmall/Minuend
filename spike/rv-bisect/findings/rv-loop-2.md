# rv loop round 2 — attack → fix on the RISC-V guest engine + MNWIT1 (2026-10-31)

Target: `lhxmall/Minuend` branch `spike/rv-bisect` @ 65bee36 (loop round 1 result). Reference engine read only via
`git archive 20326c0` (engine-diff/engine-src); fix/47-all, main and PR #51 untouched. This round attacked the round-1
fixes (allocator, header limits, status words / event cap, insurance-author guard, proof verifier) and closed the open
items W2 (proof-depth grinding) and S1 (per-unit step bound). Fix commits: see "Fix status" at the end.

Severity as in round 1: **C** = honest party loses / wrong verdict on reachable input; **H** = guest ≠ host or undefined
guest outcome on protocol-reachable input; **M** = design/spec gap with a concrete failure mode or a defense-in-depth
hole; **L** = minor / documentation; **I** = checked, no defect (recorded because the task asked for it).

Totals: **C 0 · H 0 · M 5 · L 7 · I 4**. No real-engine ↔ port divergence (fuzz / advfuzz / witfuzz / scen all equal
after the port changes below).

| id | sev | area | title | status |
|---|---|---|---|---|
| W2 | M | MNWIT1 | proof depth grindable past any fixed AA verifier budget (round-1 open item) | fixed: consensus depth rule MAX_WIT_DEPTH = 64 (port + reference + spec), Oscript verifier measured (complexity 68 / 100, ops 1 369 / 2 000) |
| W2b | M | MNWIT1 | round-1 grinding model wrong: client_seq is forced to last+1 — the grindable input is the account key pair — and the targeted pre-plant on a victim's *predictable future* keys was missed | fixed (analysis, tool `grind`, D chosen against the targeted case) |
| W5 | M | MNWIT1 / AA | an Oscript verifier that derives kid with `split()` mis-derives the key of every leaf whose id has no a–f digit — incl. the genesis insurance account `acct:000…0` (ocore coerces numeric-looking parts to numbers) | fixed in the reference verifier (`index_of`/`substring`) + spec rule; found by running real proofs through ocore 0.4.8 |
| S1 | M | step bound | per-unit steps O(live orders) (5 full-book scans per place) + O(level) journal clone (W4) | fixed in the port, semantics-preserving: per-account order index + deque-op undo journal |
| S1b | M | step bound (full guest) | remaining O(level) in `cancel` (deque position scan + remove), O(accounts) funding OI; unbounded once the guest loads a pre-state | open: precise upstream requirements below |
| W6 | L | AA | Oscript static-cost pitfalls for the verifier: `^` costs +1 complexity per call, a ternary with two `sha256` costs 2 per level, object-literal lookup tables coerce `'0100'` → 100 | documented (design §7.5); reference verifier avoids all three |
| W4 | L | engine | undo journal clones the whole price level on first touch (round-1 W4) | fixed in the port (deque-op journal); upstream suggestion stands |
| A1 | L | allocator | free-list path ignored alignment > 64 (the carve path refused it) | fixed |
| A2 | L | allocator | heapsim's "64-bit sizes are an upper bound of rv32" is not true in general (classes that merge/split differently between 64 and 32 bit) | documented; guest-measured OUT[12] is the authority; bound = Σ per-class peaks |
| A4 | L | guest | `_start` does not zero `.bss`: allocator state (`FREE`, `HEAP`) relies on the loader | documented: the rollup's initial memory image must have `.bss` = 0 (JS model and sail do) |
| H1 | L | input | header word 3 is accepted with any bits (bit 24 = genesis market 2, bits 0–23 legacy skip): an operator-chosen flag that changes the starting state must not exist in a production guest | documented (pilot test fixture); production: flags must be 0 (else status 4) |
| D8 | L | MNWIT1 | the depth rule needs the tree: the `nowit` / `legacywit` bench builds do not enforce it | documented (bench-only builds) |
| A3 | I | allocator | fragmentation worst case vs 50.2 MB heap | measured: carved = Σ per-class peaks (+< 100 B pads); worst 20.2 MB (crowdmax, 64-bit) ; fragmentation stress `frag` 1.23× live |
| E1 | I | output | can the capped event log hide a divergence? | no (proof below) |
| I1 | I | input | insurance-author rejection vs real engine | consistent (op_signer = account; ids are pubkey hashes) |
| HV | I | input | header boundaries 4 096 / 16 384, zero counts | correct; explicit selftest cases added |

---

## W2 (M) — proof depth vs the AA verifier budget: depth rule

**Problem (round 1, open).** MNWIT1 proofs are binary paths over sha256 keys of grindable ids. ocore validates an AA's
cost **statically** (aa_validation.js / formula/validation.js, ocore 0.4.8 = `wt-aa/vendor/aa-testkit/node_modules/ocore`):
`MAX_COMPLEXITY = 100` and `MAX_OPS = 2000` summed over the whole AA definition, each `sha256` +1 complexity
regardless of input length (strings ≤ `MAX_AA_STRING_LENGTH` 4 096), loops only as `reduce/map/foreach/filter` with a
**constant** max count ≤ 100 whose body cost is multiplied by that count. So a verifier is a fixed unrolled depth D,
paid in full at deploy time; a leaf deeper than D is unprovable — forever.

**Options considered.** (a) salted key `sha256(salt‖kid)` with a per-batch salt: the tree must be rebuilt every batch
(O(state) guest steps per batch, breaks the incremental property) and an operator can grind the batch content that
fixes the salt; non-membership of a kid whose salt is unknown is undefined → rejected. (b) wider nodes (one sha256
covers 2 or 4 key bits; 4-ary measured below) — halves complexity, does not bound depth. (c) **depth rule** — chosen:
bounds depth, keeps the tree, cheap.

**Rule (consensus, MNWIT1).** Before a unit runs, every key it could create **for its own author** — `acct:{author}`
if the account does not exist (deposit/place), `ord:{order_id(author, market, client_seq)}` and `pos:{author}:{market}`
if the author has no position there (place) — must get proof depth ≤ `MAX_WIT_DEPTH` = 64 (depth of a new key =
1 + longest common prefix with an existing key, or the depth of the empty slot it fills). Otherwise the unit is rejected
(event code 18 `WIT_DEPTH_CODE`) without executing. Deterministic, a pure function of the pre-state; no rollback needed;
independent of whether the order later rests or fills. Side-effect insertions (a maker's first `pos:` leaf at a fill)
are not checked (rejecting the taker would let a ground maker wall the book).

**Why 64 (W2b).** Grinding the attacker's *own* key next to any of n existing keys (birthday) to depth > 64 costs
~2^64/n and only gets the attacker's unit rejected. What remains needs a **targeted** 64-bit prefix: (i) planting a leaf
next to a victim's *predictable future* key — the victim's next order id is `order_id(victim, m, last+1)` and its `pos:`
key is fixed — so the victim's next place in m is rejected (client_seq cannot skip) or (ii) a maker's unchecked
side-effect `pos:` lands deeper than 64. Both cost 2^64 key-pair generations (≈ 1.8·10^19). With D = 48 the same
attack would cost 2^48 (GPU-days) and permanently block a chosen account from a market — that is why D is 64 and not
lower.

**Grinding model (W2b).** The engine accepts only `client_seq == last + 1` (engine.rs `ok_seq`), so the round-1 claim
"order ids via client_seq" was wrong: the grindable input is the ed25519 key pair behind the account id. `engine-diff
grind` grinds account indices (4 080 key pairs, the harness signs index i with secret(i)): **2.8–3.2·10^5 tries/s on
the 4-vCPU box** (key generation bound); target mode (victim's ord key): 13 shared bits → victim depth 14; any mode:
21 bits → depth 22 (honest max 18, median 10, 421 leaves). Extrapolated CPU: 2^40 ≈ 40 days on 4 cores.

**Port.** `wit::MAX_WIT_DEPTH` (64; feature `depth8` → 8 for tests), `Smt::insert_depth`, `wit::{acct,pos,ord}_key`,
`mnpilot::wit_depth_ok` called in `run_batch_wit` before every op (Incremental mode), `smt_ref::MAX_DEPTH` = 64.

**Tests.** `engine-diff depthsel` (insert_depth at 0 / 1 / 63 / 64 / 65 bits, empty slot, deep split; in selftest);
`depth8` build: 20 batches with ground ord/acct/pos keys (184 units each, 64–79 rejected by the rule): every rule
decision equals an independent depth computation over the pre-state leaf strings (smt_ref keys), and
port(batch) == **real engine**(batch without the rule-rejected units) — state hash and every event — **20/20**;
guest(depth8 ELF) == host(depth8) on all 20: **20/20** (hash, events, every per-unit root; 15.0–15.6 M steps per batch).

**Oscript verifier (`js/smtverify.js`).** Membership and absence share one path: kt = sha256('~K1:'‖kid(t),'hex'),
h = sha256('~L1:'‖kt‖':'‖t), then one `reduce` over the siblings (deepest first) with exactly one sha256 per level
(left/right chosen by string concatenation), path bits pre-expanded from the hex key by a 64-char table. Validated
with ocore's own `validateAADefinition`:

| D (bits) | binary: complexity / ops | 4-ary (MNWIT2 proposal, levels = D/2): complexity / ops |
|---|---|---|
| 16 | 20 / 481 | 11 / 393 |
| 32 | 36 / 777 | 19 / 673 |
| 48 | 52 / 1 073 | 27 / 953 |
| **64** | **68 / 1 369** | **35 / 1 233** |
| 80 | 84 / 1 665 | 43 / 1 513 |
| 96 | 100 / 1 961 | 51 / 1 793 |

Binary at D = 64 leaves 32 complexity / 631 ops for the rest of the AA. Run on real-engine proofs (proofdump of grind /
gen / adv batches: depths 3–22 incl. the 22-deep ground leaf): 12 proof files (grind ×6, gen 1 000, adv ×3 incl. the insurance `acct:000…0` leaf): **36/36 members, 12/12 absences accepted; 156/156 forgeries rejected** (tampered text, dropped sibling, absence of a present key, swapped siblings, EMPTY/leaf terminal swap); synthetic full-depth proofs folded by an
independent node-crypto implementation at depths 0,1,7,8,31,32,33,63,64: 9/9 accepted, tampered sibling rejected,
depth 65 refused; ≤ 75 ms per verification in node. The 4-ary numbers are static only (no 4-ary tree implemented).

## W2b (M) — see W2.

## W5 (M) — Oscript `split()` breaks key derivation for all-decimal ids

Running the first real proofs through ocore, the insurance account's membership proof (`acct:` + 64 zeros, present
since genesis) failed: `split(leaf, ':')` returns numeric-looking parts as numbers, so `$p[0] || ':' || $p[1]` gives
`acct:0` and the derived key is wrong. Any id with no a–f hex digit (insurance, and ~10^-13 of random ids, more for
crafted ones) is affected; the effect is an unprovable leaf (liveness), not a forgery (the leaf hash binds the real key).
**Fix:** kid by `index_of` / `substring` only; spec rule "never parse leaf fields with split() in Oscript"; the
reference verifier test includes the insurance leaf (member) and absence terminals.

## S1 (M) — per-unit steps: index + deque-op journal (port)

`Engine::place` filtered every order of every book 5× per unit (live count, open qty, mode, exposure, resting IM) and
the book journal cloned the whole level on first touch. The port now keeps `OrderBook::by_acct` (account → its order
ids, maintained by the only two membership changes `oins` / `orem`, incl. rollback) and visits
`live_orders_of(account)` — the same orders in the same (OrderId) order as the filter, so results are identical; and the
journal records the level's front pops / back pushes and undoes them in reverse (identical id sequence). Equivalence:
fuzz 300/300, advfuzz 300/300 (92 300 units), witfuzz 300/300 (112 794 units), scen 47/47 — same event statistics as
round 1; every port run asserts `index_ok()` after every unit; 5 new mutants (index / journal) 8/9 killed (the survivor, "don't undo the resting push", is equivalent: a post-submit rollback needs a fill, a crossing order's rest level cannot pre-exist in an uncrossed book, and a level that did not exist is removed whole on rollback).
Measured (JS guest): crowd1800 (1 830 orders at one price) **833.2 M → 640.5 M steps (−23 %)**, still = real engine; rv32 heap 2.04 MB carved / 1.77 MB peak live.
Cost note: the depth pre-check adds ~2–4 sha256 key computations per place (+~16 k steps): small batches got slower
(scen 73.8 M → 82.1 M steps, adv21 10.0 M → 15.4 M); crowded books faster (above).

## S1b (M, open) — what still scales with the state

After S1 a place costs O(own orders × books + depth) except: (1) `OrderBook::cancel` — `dq.iter().position(id)` +
`VecDeque::remove` are O(orders at that price) (≈ 20–40 steps per element; at the pilot cap ≤ 16 384 → ≤ ~0.7 M steps,
with a loaded state ≤ accounts × 64); (2) `funding_open_interest` iterates all accounts (funding-rate markets only, not
in the pilot); (3) `state_hash` / final scratch rebuild are O(state) once per batch. Requirements for the full guest:
(1) replace the level `VecDeque<OrderId>` by an insertion-ordered map (e.g. `BTreeMap<u64 arrival, OrderId>` + id →
arrival) — **semantics-preserving** (same FIFO, same commitment bytes), no consensus change; (2) a running per-market
open-interest total maintained on position changes (semantics-preserving); (3) once the guest takes a pre-state, the
per-batch O(state) parts must be replaced by per-read-leaf proofs against the pre-root (MNWIT1 makes this possible).
With (1)+(2) the per-unit bound is O(log L + 64·books + 64 sha256 levels), independent of the state size.

## W6 (L) — Oscript cost pitfalls

`^` (pow) +1 complexity per evaluation (a per-level `2^(3 - d % 4)` made the binary verifier 2D + 5); a ternary with a
sha256 in each branch is charged both; `{'0':'0000', …}` lookup values become numbers (`'0100'` → 100). Design §7.5
lists them; the reference verifier is D + 4.

## A1 / A2 / A4 / A3 (allocator)

A1: `alloc` refuses `align > 64` before both paths (fixed). A2: heapsim maps 64-bit layouts; rv32 layouts are never
larger, but two requests sharing a 64-bit class can fall in different rv32 classes that peak at different times, so
Σ rv32 class peaks is not bounded by the 64-bit run in general — the guest's own OUT[12] (carved high-water) and
OUT[0x1FFFA] (peak live) are the authority (README corrected). A4: no `.bss` zeroing in `_start`; documented as an
input-image requirement. A3 (no defect): for a size-class allocator without coalescing, carved bytes = Σ over classes
of that class's peak live bytes + alignment pads; heapsim now prints `sum_class_peaks` and it equals the high-water to
< 100 B on every batch. Numbers (64-bit host sim, high-water / peak live / Σ class peaks): crowd1800 2.04 / 1.78 /
2.04 MB; crowdmax (16 384 orders at one price) 20.16 / 17.01 / 20.16 MB; limit batch 4.31 / 3.78 MB; genmax 1.15 MB;
`frag` (crowded level → cancel all → 3 968 distinct levels → cancel all → fills, 16 384 units) 4.08 / 3.33 MB
(1.23×); heap 50.2 MB. Guest (rv32) measured: {{GUEST_HEAP}}.

## H1 / D8 (L) — see table.

## E1 (I) — the capped event log cannot hide a divergence

(1) Unreachable: a unit emits ≤ 7 words (one `EV_APPLIED|n` word + 6 per fill, and `BookError::MultiFill` caps fills
at one per unit), and `13 + 7·MAX_UNITS ≤ 0x1FFF0` is const-asserted, so `n_ev ≤ EV_CAP` and OUT[0x1FFF8] = 0 within
the header limits (selftest/robust: all 15 cases + limit batch report 0). (2) Even past the cap the dispute game
bisects the full machine state (memory Merkle root per step), not the event log; OUT[8] (`n_ev`, still counted) and
the overflow flag are memory words, so two runs that differ anywhere differ in the asserted final state. (3) Fills
change accounts/positions, which are in the state hash and the per-unit MNWIT1 roots.

## I1 (I) — insurance author

minuend-dag `op_signer` returns the op's own `account` for Place/Cancel/Deposit and unit verification binds it to the
signing pubkey's hash, so the real engine never sees an all-zero author; the guest's BadAccount covers only inputs the
real engine cannot produce. No path in the pilot credits or trades the insurance account as a counterparty.

## HV (I) — header boundaries

`n_accounts = 4 096` and `n_ops = 16 384` accepted (status 0: limit batch, new `acc_at_limit`), 4 097 / 16 385
rejected (status 2 / 3), `n_ops = 0` (genesis root, empty log) and `n_accounts = 0` (every op BadAccount, new
`acc_zero_ops_zero`) — selftest asserts each; guest = host on all 15 robust cases.

---

## Fix status / tests

Commits on `spike/rv-bisect`: db1683c (code + tools), {{COMMITS}}.
Fixed: W2, W2b, W5, S1, W4 (port), A1; documented: W6, A2, A4, H1, D8. Open: S1b (upstream list above), AA-side
integration of the verifier into the 10 dispute AAs, layer-1 segmenting (round-1 G2).

| test | result |
|---|---|
{{TESTS}}
