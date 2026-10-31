# Stateless (witness-fed) dispute guest — design + prototype (loop round 14, R4-H1)

Branch `spike/rv-bisect` only (fix/47-all, main and PR #51 untouched). Prototype: `guest-engine/src/stateless.rs`
behind cargo feature `stateless` (+ `book.rs` peek log / level accessors, `main.rs` `sl_run`), harness
`engine-diff/src/sl.rs` (`slfuzz`, `sladv`, `slcaps`, `sldump`), `js/slsteps.js`. Review: `findings/rv-loop-14.md`.

## 1. Why

The session guest keeps the whole engine state in guest memory and the rollup carries the final memory of height
h-1 into s0 of h. Memory is bounded (50.2 MB heap), so the session needs global caps — `MAX_STATE_ACCOUNTS = 256`,
`MAX_STATE_MARKETS = 16`, `MAX_STATE_ORACLES = 32` (R4-H1 / R10-H1) — i.e. a 256-user exchange. A stateless guest
receives, per segment, only the state its units touch, with Merkle proofs against the segment's start root, and
returns the end root. Guest memory then scales with the segment's touched set, not with the exchange.

Goal of this round: design + a working prototype for the deposit / place / cancel / fill paths, differential-tested
against session mode, measured, and adversarially reviewed. Not a production image (§11).

## 2. The commitment: MNWIT-S = MNWIT1 + the state the session kept only in memory

MNWIT1 (design §7.3) commits `acct: pos: ord: band: meta:` (+ `prop: cmt: gnon:` with `govwit`). It is a sufficient
commitment for the AA verifiers, but NOT for re-executing units: the session also reads `seq`, `height`,
`seen_client_seq`, map membership (an id with only PERP / W), `MarketParams.spot_only / funding_rate / symbol`, the
oracle facts of the fill mark rule, and — the big one — the order book's *structure* (which price levels exist, their
FIFO order, an account's set of orders). MNWIT-S adds leaf kinds for exactly that, in the SAME tree (same key /
leaf / node hashing, same compact SMT; a kid is the identity prefix before the value part):

| leaf | value | why |
|---|---|---|
| `glob:0` | `:<seq>:<height>` | engine cursors |
| `cseq:<acct>` | `:<last client_seq>` (absent = 0) | client_seq gate |
| `apos:<acct>` | `:<flags>:<m>,<m>,…` flags bit0 Account entry, bit1 PERP entry, bit2 W entry | map membership + the markets with a position (which `pos:` leaves exist) |
| `mkx:<m>` | `:<spot>:<funding>:<symbol hex>:<last_index>:<oracled>` | MarketParams fields MNWIT1 omits; `last_index[m] != 0` and "a bonded reporter for m exists" (the fill path's mark rule, state.rs `apply_fill_pair`) |
| `lvl:<m>:<side>:<price>` | `:<n>:<sha256(live ids, FIFO)>` | one price level, its queue order |
| `bmp:<m>:<side>:<d>:<prefix>` | `:<256-bit map hex>` | price-level trie: fanout 256, depth 8 over `u = price ^ 2^63` (order-preserving); bit c of node (d, prefix) = some level has top d bytes = prefix and byte d = c. A node exists iff its map ≠ 0 |
| `aord:<acct>` | `:<n>:<sha256(entries sorted by id)>`, entry = (order id, market, side, price) | the account's live orders across markets (≤ 64) and where they rest |

`glob/cseq/apos/mkx/lvl/aord` are pure functions of the state; `bmp` too (the reference builder derives it from
the levels), but the guest maintains it by **delta** (sets / clears path bits of the levels a unit created or
emptied), so a node is updated without loading the other levels under it. Consensus change: every MNWIT root changes
(the AA verifiers keep working — they only prove `acct:` / `pos:` / `ord:` leaves — but W<h> roots are MNWIT-S roots).
The tree has ~2–3× the leaves of MNWIT1: one or two more levels of depth.

## 3. Input format

Guest input words (`main.rs sl_run`): `[0] SL_MAGIC "MNSW"`, `[1] B` batch words, `[2] W` witness bytes,
`[3 .. 3+B)` the MNP1/MNP2 batch (header flags must be 0: a stateless segment is always "resumed"), then the witness
bytes packed little-endian. Limits: B as the session's header limits, W ≤ `SL_MAX_WIT_BYTES` = 16 MiB.

Witness bytes (`stateless.rs load`):
```
"MNSW" u32 | claimed start root (32) | pruned tree (preorder) | records
tree tags: 0 E | 1 O(hash32) unexpanded subtree | 2 L(key32, leafhash32) hash-only leaf (key UNVERIFIED)
           | 3 N(left, right) | 4 L verified: kid u16+bytes, rest u16+bytes (key = key_of(kid), hash recomputed)
records:   glob: seq u64, height u64
           markets  u16 × { present u8, id u32, [MarketParams, mark i64, last_index i64, oracled u8] }
           accounts u16 × { present u8, id 32, [flags u8, collateral i128, perp u128, w i128, cseq u64,
                                              npos u8 × {m u32, qty i64, entry i64, iso u8, bucket i128}] }
           aord     u16 × { acct 32, n u16 × {order id 32, m u32, side u8, price i64} }   (n = 0: proven absent)
           bmp      u16 × { m u32, side u8, d u8, prefix u64, present u8, [map 32] }
           levels   u16 × { m u32, side u8, price i64, n u16 × {id, account, typ, tif, qty, remaining, seq, iso, margin_left} }
           ordx     u16 × { order id 32 }   (proven absent)
```
A record is never trusted: the guest re-formats the leaf strings from it, hashes them, and checks each against the
tree (inclusion: the leaf at the key's path has that hash; exclusion: the path ends in E or in a *verified* leaf with
another key). Absent markets / accounts prove all of their keys absent (`band/meta/mkx`, `acct/apos/cseq`). A level
record must hold every live order of the level (`n` and the FIFO digest of `lvl:`), each with its `ord:` leaf.
Rejected (ST_SL_BADWIT = 12): bad tags, depth > 256, non-canonical nodes (N(E,E), N(E,L), N(L,E)), a leaf whose key
is not on its path, root ≠ claimed root, any record that does not verify, duplicates (the same account / market /
level / bmp node / aord twice, an order in two levels or both in a level and in `ordx`), counts above the
per-segment limits (`SL_MAX_ACCOUNTS 4096`, `SL_MAX_MARKETS 256`, `SL_MAX_LEVELS 4096`, `SL_MAX_LEVEL_ORDERS 4096`,
`SL_MAX_ORDERS 65536` in total, `SL_MAX_BMP 16384`, `SL_MAX_TREE_NODES 2^18`, `SL_MAX_POS 64`), trailing bytes.

### 3.1 Proof verification cost

Per item, SHA-256 calls (a call ≈ 1–4 compressions, one compression ≈ 3.5 k rv32 steps in software):
* tree decode + root: one node hash (2 compressions) per expanded node, one leaf hash per verified (tag-4) leaf;
* per record: one key hash + one leaf hash per leaf it names (account: 3 + positions; market: 3; level: 1 + its
  orders + the FIFO digest ≈ n/2 compressions; bmp: 1; aord: 1 + digest);
* end root: one leaf hash per put, one node hash per node on the changed paths (cached nodes are reused).

Measured (host, `slfuzz`, §10): 4.9–6.0 verified leaves and 7.9–9.0 tree nodes per unit on the gen workloads; the
stateless run computes ~1.7× the hashes of the session's incremental MNWIT1 update for the same segment (it verifies
the leaves it reads, not only the ones it writes). riscv32im steps per segment: §10.

## 4. Execution on partial state — completeness guards

The loader builds an ordinary `ChainState` containing only the records, and the unchanged engine runs the units
(`dispatch`). Missing state must never be read as "absent". Two kinds of guard; a guard failure aborts the segment
with `ST_SL_MISSING = 13` and a `Need` (what to add):

**Pre-unit (reads, from the op alone):**
* Deposit: the author's account record (present or proven absent) and its position markets.
* Place: author record + its position markets; the order's market (present or absent); the insurance account; the
  author's `aord` and **every** order in it (each through its complete level) and those markets (live-order cap,
  resting IM, mode gate, QTY cap, spot-exposure rules read all own orders); every market that has a book in the
  partial state (`resting_open_im` walks all books); for a GTC limit, the own-side level at its price must be known or
  proven empty by the trie (input of the level-size rule, §5). A funding-rate market → `ST_SL_UNSUPPORTED` (its OI
  cap reads a global aggregate).
* Cancel: author record, its `aord`, and the target order id: its level, or an `ordx` exclusion proof.

**Post-unit (on the outcome, applied or rolled back — a rejection can depend on what the walk saw):**
* *Walk check* (§6): every non-empty level at or better than the last head the matching walk examined is known.
* *Dirty coverage*: every account / market the unit wrote (the journal's touched set, also for rolled-back units)
  is loaded — generic catch-all for makers, claws, fees, refunds.
* *Resting*: a new resting order's level is known or proven absent by the trie (then it becomes known, empty).
* *aord*: every account whose live-order set changed has its `aord` loaded (delta update).

Unsupported ops (withdraw, liquidate, oracle, governance, commit-reveal, fixtures, the height hook) →
`ST_SL_UNSUPPORTED = 14`.

**Determinism / soundness property** (what the tests check): if a run returns status 0, its events and end root
equal the session's for the same start state and batch, whatever *extra valid* records the witness carries. Extra
records can only turn status 0 into MISSING (e.g. a level in a market whose params were not supplied), never change a
status-0 result: every input of every rule is loaded completely (own orders, whole levels, trie prefix, accounts).

## 5. Rules of the stateless image (no global caps; per-object bounds that keep every record loadable)

* **Per-account exposure cap (R14-H1)**: a Place by an account with neither a position nor a live order in the
  market is refused (code 19) when the account already has `SL_MAX_POS = 64` markets of exposure. Without it an
  account could hold > 64 positions (markets are no longer capped), its record could never be loaded, and a resting
  order of it at the top of a book would halt that market.
* **Per-level size cap (R14-M1)**: a GTC limit joining a level that already has `SL_MAX_LEVEL_ORDERS = 4096` live
  orders is refused (19). Levels are loaded whole (§6), so an unbounded level would be unloadable.
* The live-order cap (64 per account, upstream) bounds `aord`.
Below the caps the session and the stateless image agree (differential tests); `slcaps` exercises both rules.

## 6. Order-book matching with partial state

A unit carries at most one fill (round 7), but the walk may pass the account's own cross makers (STP
cancel-maker-continue) and a resting-type taker peeks one more head (MultiFill / non-crossing stop). The guest must
know that no better level was left out.

**Levels** are loaded whole: all live orders, FIFO, checked against `lvl:` (count + ids digest). **Navigation** uses
the 256-ary trie over biased prices: 8 `bmp:` nodes per path. The book records each head the walk examines
(`OrderBook::peeks`, feature `stateless`; not state, never compared / cloned). After the unit the guest enumerates the
opposite side's trie *as of unit start* in price priority up to the last examined head F (the whole side if the walk
ran out): every set bit at or better than F must be a known level, every trie node on the way must be supplied.
Subtrees entirely worse than F are pruned, so the cost is (levels the walk passed) × ≤ 8 nodes. Then the trie is
updated by delta for every level that appeared / emptied (all 8 path nodes must be loaded).

Why per-level + trie rather than fixed price sectors: a sector leaf (all orders in a price range) makes a crowded
sector expensive for every trade near it and its boundaries are arbitrary; the trie gives O(8) nodes per level for
any price distribution, proves emptiness of a price (exclusion of a level) with its path, and needs no rebalancing.
Boundary attacks (§9 tests): omitting the best level, hiding a level by claiming its trie node absent, dropping /
reordering orders inside a level all fail (MISSING or BADWIT).

Production refinement (not prototyped): FIFO as a linked list (`ord` link leaves + head/tail in `lvl:`) instead of
whole levels — a fill touches the head only, a cancel its two neighbours, so a level's size stops mattering and the
level cap can go.

## 7. End root

After the last unit the guest re-derives every leaf of every loaded / created object (accounts incl. `cseq`,
`apos`, `pos` of current and start positions; present markets; every loaded or created order; known levels; dirty
trie nodes; dirty `aord`; `glob`) — puts first, then deletions — on the pruned tree, keeping it canonical:
* insertion into E → leaf; into a *verified* leaf with another key → split; into O → MISSING (path not expanded);
* deletion collapses a node left with one leaf child; a node left with a lone **O** sibling is ambiguous (an O may
  hide a single leaf, which canonical form would lift) → MISSING, so the operator expands siblings of deleted paths;
* **R14-C1**: a hash-only leaf (tag 2) carries an UNVERIFIED key (the path fixes only its first d bits, the root
  only its hash). It may be hashed, lifted by a collapse, and used for an inclusion check (the record's recomputed
  leaf hash binds hex(key), and then the leaf is marked verified), but never as an exclusion witness, a split point,
  an update or a deletion target → MISSING; verified leaves come as tag 4 (leaf string) or from an inclusion check.

## 8. What the operator supplies (and how it finds it)

The operator holds the full state (any replica). For a segment it builds the witness by iteration: start from a
guess (authors' accounts / `aord`, Place markets, Cancel targets, insurance), run the guest, add the reported `Need`,
repeat until status 0 (`engine-diff sl.rs operate`; 38 iterations per segment on average, §10). Builder rules
(`WitBuilder::build`): a need closes over what it implies (a level → its orders, its trie path and its market; an
order id → its level or an `ordx` proof); the pruned tree expands every needed key's path; a single-leaf subtree is
always a leaf, never an O; a leaf ending the path of *another* key, and every single-leaf sibling of a path, is sent
verified (tag 4: needed for exclusion / split / after a lift); other siblings with ≥ 2 leaves are expanded one level
(so a deletion can prove them internal) and O below that.

A production operator would compute the touched set directly while executing (the same reads the guards check)
instead of iterating; the guest's checks stay the same.

## 9. What a challenger checks — missing leaves are fraud

The guest's output is a deterministic function of (batch, witness). The operator claims, for height h, a final
memory whose OUT words say status 0, start root S and end root E.
* Omitted / forged / duplicate leaves: the guest's real output is MISSING / BADWIT (or a different E); the operator's
  claim of status 0 / E is false → a normal instruction-level dispute, which the challenger wins. "Exclusion proof
  mismatch" is exactly this: a key the operator claims absent but whose path shows a leaf with that key (or a
  verified leaf proves nothing / an unverified leaf is refused, R14-C1) makes the honest run report BADWIT.
* Wrong start root (R14-H2): `run_stateless` alone would accept any self-consistent witness and output its claimed
  root. Fixed in the image: the rollup builds s0(h) on the final memory of h-1, so the image keeps its last good end
  root in `.data` (`SL_ROOT`) and refuses a witness claiming another start root (`ST_SL_BADROOT = 15`); the first run
  starts from `MNPILOT_SL_GENESIS`, compiled in (the image memory root, chosen by governance, commits it; required in
  `prod`). A failed run (status ≠ 0) leaves the root unchanged and binds nothing (rv_witbind binds status-0 heights
  only), like a rejected header in the session image. No new AA rule is needed.
* Data availability: the challenger needs the witness (input tree of the height) to replay — the same DA assumption
  as the batch itself; the witness is part of the height's input.

## 10. Measurements (box, loop round 14; logs guest-engine/results-loop14/)

Differential (`engine-diff slfuzz`, stateless vs session, every segment status 0 with equal events, start root =
MNWIT-S root of the session pre-state, end root = MNWIT-S root of the session post-state):

| workload | batches | segments | units | witness / unit | max witness | verified leaves / unit | tree nodes / unit | hashes stateless / session |
|---|---|---|---|---|---|---|---|---|
| gen 300 orders | 300 / 300 | 2 836 | 112 794 | 683 B | 73 KB | 4.9 | 7.9 | 1.70 |
| gen 1000 orders | 100 / 100 | 2 079 | 107 581 | 871 B | 99 KB | 6.0 | 9.0 | 1.78 |
| adv (edge values) | 300 / 300 | 1 662 | 62 300 | 139 B | 15 KB | 1.7 | 1.6 | 3.4 |
| ora (oracled pre-state) | 200 / 200 | 1 655 (+201 unsupported first segments) | 75 765 | 627 B | 73 KB | 4.2 | 7.2 | 1.89 |

Adversarial (`sladv 40 200`, `l14-sladv.log`): 325 segments, 45 908 cases, 0 unsound.

riscv32im steps per segment (`js/slsteps.js`, JS reference model, `results-loop14/l14-steps.log`; session = `prod` image
carried from height to height, stateless = the bound image with its carried end root):

| config | units | session steps | stateless steps | ratio | steps / unit | peak heap stateless / session |
|---|---|---|---|---|---|---|
| gen 3 · 300 orders · 100 units / seg (4 seg) | 331 | 87.5 M | 98.9 M | 1.13 | 264 k → 299 k | 362 KB / 121 KB |
| adv 5 · 200 · 50 / seg (5 seg) | 204 | 10.9 M | 26.2 M | 2.40 | 54 k → 128 k | 95 KB / 28 KB |
| gen 8 · 300 · 300 / seg (2 seg) | 382 | 93.7 M | 87.8 M | 0.94 | 245 k → 230 k | 413 KB / 171 KB |

Fixed cost ≈ 2.3 – 2.5 M steps per segment (decode, start root, end root); per-unit cost ≤ the session's. Full segments
0.7 – 1.13 ×; tiny tail segments are dominated by the fixed part. Stateless peak heap does not grow with the exchange.

## 11. What remains (production)

1. Ops: withdraw (pending-withdrawal leaves `wd:` + the per-account pending count), liquidation / ADL (holders per
   market and OI are global aggregates → per-market `oi:` leaves maintained by delta; ADL candidate selection needs
   an ordered index like the price trie), oracle report / stake / slash (report history / TWAP leaves per (market,
   oracle); `oracled` maintenance when bonds change), funding (OI cap + peg), governance and commit-reveal (`govwit`
   leaves exist; `weight_snapshot` is O(holders) — needs a different snapshot design), CreateMarket.
2. The height hook (`commit_height`: withdrawals / unbonding / commits pruning) is O(state) → expiry-queue leaves
   keyed by height, or lazy pruning on touch.
3. Rollup integration: the MNWIT-S genesis root (`MNPILOT_SL_GENESIS`) from a one-off migration run over a session snapshot; DA of the witness.
4. Linked-FIFO levels (§6) to drop whole-level loading and the level cap; a light insurance record (R14-M2).
5. Operator: direct touched-set tracking instead of Need iteration; witness compression (shared path prefixes).
6. Per-unit roots: the stateless guest returns only the segment start / end roots (the AAs bind the end root).
7. Upstream: the leaf kinds and the guards must be mirrored by the real engine's witness code (consensus).
