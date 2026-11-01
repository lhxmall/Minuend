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
| `apos:<acct>` | `:<flags>:<npos>:<sha256(markets, u32 LE ascending)>` flags bit0 Account entry, bit1 PERP entry, bit2 W entry | map membership + the markets with a position (which `pos:` leaves exist). Round 15: digest form (the round-14 decimal list overflowed the 384-byte leaf buffer, R15-H1; the digest also lets the insurance account be loaded light, R14-M2) |
| `wdl:<acct>` | `:<n>:<sha256(records sorted by nonce: nonce u64, amount i128, pending u8, height u64)>` (absent = none; n ≤ 64) | round 15: the account's withdrawal records (Withdraw's nonce and pending-count rules); lazy expiry (§9) |
| `mkx:<m>` | `:<spot>:<funding>:<symbol hex>:<last_index>:<oracled>` | MarketParams fields MNWIT1 omits; `last_index[m] != 0` and "a bonded reporter for m exists" (the fill path's mark rule, state.rs `apply_fill_pair`) |
| `lvl:<m>:<side>:<price>` | `:<head id>:<tail id>` (round 16; rounds 14–15: `:<n>:<sha256(live ids, FIFO)>`) | one price level: its FIFO ends only |
| `olk:<order id>` | `:<prev id or ->:<next id or ->` | round 16 (linked-FIFO levels): a live order's neighbours in its level; the level's FIFO is the chain head → … → tail of these links, so a level is never loaded whole |
| `bmp:<m>:<side>:<d>:<prefix>` | `:<256-bit map hex>` | price-level trie: fanout 256, depth 8 over `u = price ^ 2^63` (order-preserving); bit c of node (d, prefix) = some level has top d bytes = prefix and byte d = c. A node exists iff its map ≠ 0 |
| `aord:<acct>` | `:<n>:<sha256(entries sorted by id)>`, entry = (order id, market, side, price) | the account's live orders across markets (≤ 64) and where they rest |
| `perp:0` | `:<perp_supply>:<perp_burned>:<next_market_id>` (always present) | round 16: PERP ledger aggregates + the market-id cursor (GovDeposit / GovWithdraw / CreateMarket) |
| `xsrc:<acct>` | `:1` (absent = not a source) | round 16: `external_sources` membership (a funding-market creator) |
| `acmt:<acct>` | `:<n>:<sha256((commit hash, ttl) sorted by hash)>` (absent = none; n ≤ `SL_MAX_ACMT` 64) | round 16: the account's commit index (R7-M2 commit bond, Commit's pending count); lazy expiry like `wdl:`; live entries are checked against their `cmt:` leaves (MNWIT1 `govwit` kind), `gnon:` read as in MNWIT1 |

| `pglob:0` | `:<next_proposal_id>:<non-zero PERP holders>:<n live>:<sha256((id u64, xroot 32 B) by id)>` (always present, `govwit`) | round 18: proposal cursor, the live set (≤ 64), the snapshot size a new proposal records; round 19: each live proposal's **exception sub-tree root** `xroot` (round 18: an exception count); loaded together with every live `prop:` and every live proposal's pruned sub-tree |
| `pxe:<pid>:<acct>` (leaf of proposal `pid`'s exception sub-tree, not of MNWIT-S) | `:<weight>:<voted 0/1>` | round 19 (R18-M1 fix; replaces round 18's per-account `pexc:<acct>` lists): the pair (account, live proposal) where the account's snapshot weight ≠ its current PERP balance, or it voted. Sub-tree = compact SMT of the MNWIT-S form over these leaves |
| `ostk:<acct>` | `:<bond or ->:<unlock height or ->` (absent = neither) | round 20 (oracle, §12.1): `oracle_bonds` / `oracle_unbonding` of one account |
| `orm:<acct>` | `:<n>:<sha256(markets u32 LE ascending)>` (n ≤ `SL_MAX_ORACLE_MKTS` 16) | round 20: the markets where the oracle has a report or a non-empty history (a bond change rewrites its entries there) |
| `orep:<m>` | `:<n>:<sha256(entries by oracle)>`, entry = (oracle, has report, price, bonded now, history length, sha256(history samples)) (n ≤ `SL_MAX_REPORTERS` 64) | round 20: the market's reporters — median / `oracled` input (`bonded` copied per entry); R20-M1: the slash-streak history is a digest in the entry, its samples are sent only where a unit reads / writes them |
| `omk:<m>` | `:<deviation,window,reward or ->:<funding_index_twap or ->:<last_funding_height or ->:<n>:<dg oracle TWAP ring>:<n>:<dg funding TWAP ring>` | round 20: the market's oracle config, funding clock and TWAP rings (absent = all default) |
| `oglob:0` | `:<funding source>:<slash nonce>:<queue head or ->:<queue tail or ->` (absent = all default) | round 20: global oracle facts + the expiry queue's ends |
| `oexp:<u>` | `:<prev u or ->:<next u or ->:<n>:<sha256(accounts)>` (n ≤ `SL_MAX_UNSTAKES` 16) | round 20 (R19-I2): the oracles whose unbonding ends at height u; a doubly linked list over the distinct unlock heights, ascending |
| `gcnt:0` | `:<accounts>:<PERP ids>:<markets>:<oracle bonds>` (always present) | round 22 (R16-I3 / R17-I3): the sizes of the session maps its global caps count (`accounts`, `perp_balances`, `markets`, `oracle_bonds`); kept by delta, read by the global caps (§5) |
| `adlr:<m>:<sign>` | `:<rank sub-tree root hex>` (absent = no holder of that sign; sign 0 long, 1 short) | round 21 (ADL, §12.2): the root of the market's **rank sub-tree** for one sign |
| rank leaf (of the `adlr:` sub-tree, not of MNWIT-S) | key = `BE(u64::MAX − |qty|)` (8 B) ‖ `AccountId[0..24]`, leaf = `sha256("~R1:" ‖ key ‖ AccountId)` | round 21: one leaf per non-insurance holder; the keys are raw (not hashed), so the compact SMT's bit order is the ADL order (|qty| descending, AccountId ascending) and its leftmost leaf is the pick |

`glob/cseq/apos/mkx/lvl/olk/aord/perp/xsrc/pglob` (with its `pxe` sub-trees), the oracle leaves and `adlr` (with its rank sub-tree) are pure functions of the state; `bmp` too (the reference builder derives it from
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
           accounts u16 × { kind u8 (0 absent, 1 full, 2 light), id 32,
                            full:  [flags u8, collateral i128, perp u128, w i128, cseq u64,
                                    npos u8 × {m u32, qty i64, entry i64, iso u8, bucket i128}]
                            light: [flags u8, collateral i128, perp u128, w i128, npos u32, markets digest 32]
                                   (round 15, R14-M2: INSURANCE_ACCOUNT only; acct: + apos: verified, no positions) }
           aord     u16 × { acct 32, n u16 × {order id 32, m u32, side u8, price i64} }   (n = 0: proven absent)
           bmp      u16 × { m u32, side u8, d u8, prefix u64, present u8, [map 32] }
           levels   u16 × { m u32, side u8, price i64, head 32, tail 32,
                            n u16 × {id, account, typ, tif, qty, remaining, seq, iso, margin_left, prev 32, next 32} }
                    (round 16: SOME orders of the level, strictly increasing seq; zero id = no neighbour)
           ordx     u16 × { order id 32 }   (proven absent)
           wdl      u16 × { acct 32, n u8 × {nonce u64, amount i128, pending u8, height u64} }   (n = 0: proven absent; round 15)
           perp     u8 (1: supply u128, burned u128, next_market u32)                            (round 16)
           gnon     u16 × { acct 32, nonce u64 }                     (0: proven absent; round 16)
           xsrc     u16 × { acct 32, present u8 }                    (round 16)
           acmt     u16 × { acct 32, n u8 × {hash 32, ttl u64, commit_unit 32, commit_height u64, revealed u8} }
           cmt      u16 × { hash 32, present u8, [CommitEntry] }     (round 16: a commit hash's record or its absence)
```
Migration run (round 15): `[0] SL_MIG_MAGIC "MNSM"`, then the session snapshot words (snapshot.rs encoding).
A record is never trusted: the guest re-formats the leaf strings from it, hashes them, and checks each against the
tree (inclusion: the leaf at the key's path has that hash; exclusion: the path ends in E or in a *verified* leaf with
another key). Absent markets / accounts prove all of their keys absent (`band/meta/mkx`, `acct/apos/cseq`). A level
record (round 16) is checked against `lvl:` (head, tail) and carries any subset of the level's live orders, each
verified by its `ord:` and `olk:` leaves; an order with no prev must be the head, no next the tail, and a link between
two loaded orders must agree with their seq order (FIFO = seq order within a level). Rounds 14–15 loaded every order.
Rejected (ST_SL_BADWIT = 12): bad tags, depth > 256, non-canonical nodes (N(E,E), N(E,L), N(L,E)), a leaf whose key
is not on its path, root ≠ claimed root, any record that does not verify, duplicates (the same account / market /
level / bmp node / aord twice, an order in two levels or both in a level and in `ordx`), counts above the
per-segment limits (`SL_MAX_ACCOUNTS 4096`, `SL_MAX_MARKETS 256`, `SL_MAX_LEVELS 4096`, `SL_MAX_LEVEL_ORDERS 4096` loaded per level record,
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
  author's `aord` and **every** order in it (round 16: each by id with its level's ends and links) and those markets (live-order cap,
  resting IM, mode gate, QTY cap, spot-exposure rules read all own orders); every market that has a book in the
  partial state (`resting_open_im` walks all books); for a GTC limit, the own-side level at its price must be known or
  proven empty by the trie (rounds 14–15 only: input of the level-size rule, gone in round 16). A funding-rate market →
  `ST_SL_UNSUPPORTED` (its OI cap reads a global aggregate).
* Cancel: author record, its `aord`, and the target order id: the order (round 16: with its links; its neighbours when
  their links change, end root) or an `ordx` exclusion proof.
* Place (round 15): the insurance account as a **light** record suffices (the fee leg reads / writes only its
  collateral); a full record is also accepted (same result). `need_acct` refuses a light record wherever an account's
  positions are read; the end root requires the light account's membership flags unchanged and no positions.
* Withdraw (round 15): author record + its position markets; its `wdl` set (present or proven absent); its `aord` and
  every order in it through its complete level; the params of every book in the partial state (`resting_open_im`, the
  R2-E-3 input); a funding-rate position → unsupported. Post-unit catch-all: a withdrawal record of an account whose set
  is not loaded → MISSING.

**Post-unit (on the outcome, applied or rolled back — a rejection can depend on what the walk saw):**
* *Walk check* (§6): every non-empty level at or better than the last head the matching walk examined is known.
* *Dirty coverage*: every account / market the unit wrote (the journal's touched set, also for rolled-back units)
  is loaded — generic catch-all for makers, claws, fees, refunds.
* *Resting*: a new resting order's level is known or proven absent by the trie (then it becomes known, empty).
* *aord*: every account whose live-order set changed has its `aord` loaded (delta update).

* Round 16: GovDeposit / GovWithdraw (author record + `perp:0`), CreateMarket (`perp:0`, `xsrc:` of the creator, the new
  market id proven absent), Commit (author record, `acmt:` + its live `cmt:` records, the commit hash's `cmt:`), Reveal
  (the `cmt:` record; the inner op is loaded only when the reveal would consume the commit, with the inner kind's own
  guards), `gnon:` for every governance-nonce op.

* Liquidate (round 17, book path): the keeper's record (its `acct:` key may be created by the reward: W2 depth key);
  the target's full record and its position markets (snapshot / isolated risk), the market (a funding-rate market →
  unsupported: off-book close + ADL over all holders), the insurance light record (fee leg), the target's `aord` and
  every order in it (the IOC's cancel-maker STP / refunds), and a proof of the R7-H1 dust check's input
  (`first_maker_qty`: every level in price priority up to the first one holding a live order of another account is
  known, its start FIFO chain loaded up to that order — `liq_first_maker`). The IOC walk is checked like a Place's
  (§6). **ADL remainder** (the book filled nothing; round 21, §12.2 round-21 implementation): the rank sub-tree of the
  candidates' sign (`adlr:<m>:<sign>`, as of unit start) must show its leftmost leaf (verified, tag 5) and that holder's
  full record must be loaded; the engine's pick among the loaded holders is then the session's (also checked on the
  kind-2 fill). Rounds 17–20: unsupported. A revealed Liquidate (Reveal inner op) → unsupported.
* Rank maintenance (round 21, every unit and the height hook): a dirty non-insurance account whose (sign, |qty|) changed in
  a market moves in the rank sub-trees (old key removed, new key inserted; `Need::Adl` / `AdlKey` / `AdlTop`).

* Governance (round 18, §12.3): CreateProposal (creator record, `perp:0`, the market present / absent, `pglob:` with
  every live `prop:`), Vote (voter record + its exception list, `pglob:`; also for a Reveal's inner Vote, whose R6-H2
  zero-voter rule the session evaluates whether or not it runs), FinalizeProposal (`pglob:` and the proposal's market;
  round 19: no exception holder -- the proposal's sub-tree leaves with its `pglob:` entry). An account's exception list
  is its `pxe:` entries across the live proposals' sub-trees: the witness sends the list and each live sub-tree pruned
  to the loaded accounts' keys; the loader checks every listed entry as a member (leaf hash recomputed) and every other
  (account, live proposal) pair as proven absent, then fills the partial proposals' `weight_snapshot` / `voted`
  (entry-less pair = weight = balance, not voted), so the engine runs unchanged; `prop:` counts are carried explicitly.
  Post-unit: a PERP balance change needs `pglob:` (holder count) and the account's exception list. SetSeq (test
  fixture) runs in non-prod builds.

* Oracle (round 20, §12.1 round-20 implementation): Stake / Unstake (the author's `ostk:`; an Unstake that starts an
  unbonding also `oglob:` and this height's expiry group when it exists), Report (`ostk:` of the author; for a bonded
  author, a present non-spot market and a valid price: `oglob:`, the market's `orep:` with the author's history samples,
  the author's `orm:`, `omk:`; a funding-rate market or the AggregatedExternal source → unsupported), Slash (challenger
  record, `perp:0`; the target's `ostk:`, the market, and for a bonded target `oglob:`, `omk:`, `orep:` + the target's
  history; a revealed Slash → unsupported). Post-unit (ora.rs `post`): a bond / unbonding changes only for a loaded
  `ostk:`; a bond that appeared / disappeared needs the oracle's `orm:` and every `orep:` in it (flags; R20-M1: one record
  per market); a report / history exists only inside loaded report sets; an entry that appeared / disappeared needs the
  oracle's `orm:`; market-level oracle state only for loaded `omk:`; a report set whose `oracled` fact flipped needs its
  market (mkx:); the expiry queue is updated (append at the tail, unlink emptied groups). A unit that reaches a funding
  transfer / the funding-rate peg (state.rs flag) → unsupported (R19-I1 / R20-I1).
* Height hook (round 20, R19-I2): a run that moves the height loads `oglob:0`, every expiry group up to the new height
  with each listed oracle's `ostk:` and account record, runs the session's `prune_oracle_unbonding` on the partial state
  (a released oracle's entries leave every report set, loaded samples or not), then the post-unit guards (dirty accounts,
  PERP balance → `pglob:` / exception list, oracle records, queue).

Unsupported ops (funding transfers / the funding-rate peg — incl. a funding-rate market's liquidation / ADL —, ExtPrice,
fixtures other than SetSeq; rounds 17–20 also the ADL remainder) →
`ST_SL_UNSUPPORTED = 14` (designs: §12).
Withdraw is supported since round 15; the height hook runs lazily (§9).

**Determinism / soundness property** (what the tests check): if a run returns status 0, its events and end root
equal the session's for the same start state and batch, whatever *extra valid* records the witness carries. Extra
records can only turn status 0 into MISSING (e.g. a level in a market whose params were not supplied), never change a
status-0 result: every input of every rule is loaded completely (own orders, whole levels, trie prefix, accounts).

## 5. Rules of the stateless image (no global caps; per-object bounds that keep every record loadable)

* **Per-account exposure cap (R14-H1)**: a Place by an account with neither a position nor a live order in the
  market is refused (code 19) when the account already has `SL_MAX_POS = 64` markets of exposure. Without it an
  account could hold > 64 positions (markets are no longer capped), its record could never be loaded, and a resting
  order of it at the top of a book would halt that market.
* ~~Per-level size cap (R14-M1)~~ — removed in round 16: linked-FIFO levels (§6) are never loaded whole, so a level
  of any size is loadable; the session and the stateless image agree on a Place joining a 4 096-order level (`slcaps`).
* The live-order cap (64 per account, upstream) bounds `aord`.
* **Per-account commit bound (round 16)**: a Commit by an account that already has `SL_MAX_ACMT = 64` live commits is
  refused (19) — keeps `acmt:` loadable (the session has only global commit caps).
Below the caps the session and the stateless image agree (differential tests); `slcaps` exercises the exposure rule
and the lifted level rule.

**Global caps (round 22, R16-I3 / R17-I3).** Rounds 14–21: no global caps (no aggregate leaf). Round 22 adds the
aggregate leaf `gcnt:0` = (Account-map entries, PERP-ledger ids, markets, oracle bonds) and the session's global rules
of `state_cap_ok` on it, for the op and a Reveal's inner op with the author, exactly as the session evaluates them:

| unit (author `a`) | refused (code 19) when |
|---|---|
| Deposit, Liquidate (keeper's first credit) | `a` has no Account entry and accounts ≥ `SL_CAPS.accounts` |
| GovDeposit, GovWithdraw, Slash (challenger) | `a` has no PERP entry and PERP ids ≥ `SL_CAPS.accounts` (the session's one `cap`) |
| CreateMarket | markets ≥ `SL_CAPS.markets` |
| Stake | `a` is not bonded and bonds ≥ `SL_CAPS.oracles` |

* **Delta, not a scan.** The counts move only with records the segment loads: the Account / PERP membership of every
  loaded account (its `apos:` flags at load vs the partial state; a dirty account is always loaded; a light record's
  flags never change), the loaded / proven-absent market records (a listing proves its id absent), the loaded `ostk:`
  records (bonds of other accounts never change: ora guard (a)). End root: any non-zero delta needs `gcnt:0` loaded
  (`Need::Gcnt`) and rewrites it; catch-alls refuse a partial-state account / market without its record. A capped unit
  by a non-member needs `gcnt:0` even when the unit then fails and changes no count (slpoc22 P4).
* **Values (consensus constants of the lineage, `SL_CAPS_PROD`).** Accounts / PERP ids: **uncapped** (R22-M1: ids are
  never removed upstream, so a hard cap is a permanent lockout of new users that costs one dust Deposit per slot —
  2^20 slots are cheap; the session's 256 has the same flaw as a pilot limit). Listings: 2^16 (each burns
  `CREATE_MARKET_FEE_PERP`). Oracle bonds: 2^12 (each locks `ORACLE_BOND_PERP`). With the session's values (host tests)
  the two images agree at the caps (slpoc22 P1). The counts stay useful uncapped: export precondition (§9, R16-I2) and
  storage metering.
* **Not mirrored:** the session's `MAX_STATE_COMMITS` (R22-I2): commits expire lazily in the stateless image (R16-I1),
  so the number of live commits is not an aggregate of touched records; the per-account `SL_MAX_ACMT` bound stays.
* Migration: a snapshot whose counts exceed `SL_CAPS` is refused (`ST_SL_MIG_BOUNDS`).

## 6. Order-book matching with partial state

A unit carries at most one fill (round 7), but the walk may pass the account's own cross makers (STP
cancel-maker-continue) and a resting-type taker peeks one more head (MultiFill / non-crossing stop). The guest must
know that no better level was left out.

**Levels** (round 16, linked FIFO): a level is its ends (`lvl:` head, tail) plus the orders a unit reaches, each with
its `olk:` links. The book (`OrderBook::sl`, feature `stateless`) holds the start links of the loaded orders and the
start ends of every known level; the walk may take an in-memory order as the level's head only if its whole start
predecessor chain is loaded and gone in this segment (`sl_ok`; an order created in the segment: the whole start chain
from the start tail); a level the walk empties in memory is really empty only if its start chain is loaded and gone
(`sl_drained`); otherwise the unit stops with `Need::Order(first missing)`. End root: new ends, and new links for every
loaded / created order whose neighbours changed; the neighbour of a removed order, a new head, and the tail a new order
is appended to must be loaded (an unloaded order is live: nothing in the segment could reach it). A fill reads the
head only, a cancel its two neighbours; the level size no longer matters. (Rounds 14–15 loaded levels whole against
`:<n>:<digest>`.) **Navigation** uses
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

Walk check with partial levels (round 16): a level strictly better than the frontier that the walk never examined
looked empty in memory, so its whole start chain must be loaded and gone. Adversarial cases `book:omit-head` (every
level record without its head) and `book:drop-order-in-level` (one middle order dropped) must end MISSING or the
reference result — never a different status-0 result.

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
* **Height hook (round 15, lazy).** The image carries its run count `SL_RUNS` (every run is a rollup height, also a
  refused one — like the session's RUNS); a `prod` run passes it as the height and the engine height moves to it before
  the units when greater (the session's `bind_height` + `commit_height`). Pruning is lazy: withdrawal records are read
  only if `height + REPLAY_WINDOW > height` and a `wdl:` set is rewritten only when the unit changed its live set (so an
  untouched extra record never changes the root). The stateless chain's root is therefore the root of the *lazily
  committed* state, not of the session's eagerly pruned one; behaviour is identical (`slmig … 900`, lazy reference
  model). Commits (round 16) use the same lazy rule: an `acmt:` entry is live while ttl ≥ height, an expired commit's
  `cmt:` record reads as absent, and the index is rewritten only when its live set changes. Known gap (R16-I1): an
  expired commit's `cmt:` leaf is never deleted (stale leaves accumulate; harmless for behaviour, costs tree size) — a
  lazy delete on the next touch of the hash is the fix. Oracle unbonding needs the same rule once supported (§12).
* **MNWIT-S genesis by migration (round 15).** Instead of (not in addition to — R15-L1) a compiled
  `MNPILOT_SL_GENESIS`, a fresh stateless image accepts one migration run `[SL_MIG_MAGIC, snapshot words]` whose digest /
  length equal the compiled-in `MNPILOT_IMPORT_DIGEST` (the export digest of the session image, chosen by governance —
  the R4-S1 binding). It decodes the snapshot, refuses a state that violates a per-object bound (an account with > 64
  markets of exposure or > 64 live commits: `ST_SL_MIG_BOUNDS` = 16, R15-M1; the round-15 level bound of 4 096 orders is
  lifted by linked-FIFO levels in round 16), computes the MNWIT-S root over the
  whole state and publishes it as SEG_START = SEG_END (SNAP_KIND 3); `SL_ROOT` / `SL_RUNS` (= export run + 1) start the
  lineage. Rollup integration (R15-I1): the export run's SEG_END is an MNWIT1 root, so for SNAP_KIND 3 the rollup binds the
  digest, not the root chain; the migration root is a disputable output like any other. State outside the MNWIT-S leaf
  set (oracle rings / TWAPs / unbonding, proposal voter sets / weight snapshots, perp supply, funding clocks) is not
  carried (R15-I2).
* **Lineage export (R16-I2).** The stateless lineage has no export path yet: a session image cannot be rebuilt from a
  stateless lineage (no MNWIT-S → snapshot run). Needed before the session image can be retired or re-entered.
  Round 22: the precondition is O(1) now — the lineage state fits the session image iff `gcnt:0` is within the
  session's caps (accounts / PERP ids ≤ `MAX_STATE_ACCOUNTS`, markets ≤ 16, bonds ≤ 32) and no commit index exceeds
  its bound; with uncapped accounts (R22-M1) an export can become impossible, i.e. an export must be a governance
  decision taken while the counts fit, or the session image's caps must be raised first.
* **Rollup (round 16).** rv_rollup accepts the migration (snapshot kind 3) on the export / migration digest binding
  (R15-I1 closed; rolltest group `r16mig`).

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

1. Ops: funding transfers / peg, ExtPrice — designs in §12 (funding: R20-I1). Done: the book-path ADL remainder (round 21,
   rank sub-trees, §12.2); oracle stake / unstake / report /
   slash + the eager unbonding expiry (round 20, §12.1); proposals / vote / finalize (round 18,
   §12.3); book-path liquidation (round 17);
   withdraw (round 15, `wdl:`); GovDeposit / GovWithdraw / CreateMarket / Commit / Reveal (round 16, `perp:0` / `xsrc:` /
   `acmt:`).
2. Height hook: lazy for withdrawals (round 15) and commits (round 16); stale `cmt:` leaves are never deleted (R16-I1);
   oracle unbonding needs the same rule (§12.1).
3. Rollup integration: SNAP_KIND 3 digest binding done (round 16); leaves for the state a migration drops (R15-I2:
   oracle rings / TWAPs / unbonding, proposals / voter sets / weight snapshots, funding clocks); export path of the
   stateless lineage (R16-I2); DA of the witness. Migration cost: the guest decode rebuilds the MNWIT1 witness tree of the
   snapshot before migrating (round-16 step 4) — round 17: `snapshot::decode_opts(.., build_wit = false)` skips it and
   the snapshot is hashed once (by the decoder; digest checked after the decode).
4. ~~Linked-FIFO levels~~ — done in round 16 (§6): the level cap R14-M1 and the migration bound R15-M1 are gone.
5. Operator: direct touched-set tracking instead of Need iteration; witness compression (shared path prefixes).
6. Per-unit roots: the stateless guest returns only the segment start / end roots (the AAs bind the end root).
7. Upstream: the leaf kinds and the guards must be mirrored by the real engine's witness code (consensus).
8. ~~No global caps in the stateless image (R16-I3)~~ — round 22 (§5): `gcnt:0` + the session's global rules with the
   lineage's own values (accounts uncapped, R22-M1); the session's commit cap is not mirrored (R22-I2).

## 12. Designs for the remaining ops (round 16)

Principle: every rule input is either a leaf of the touched objects or an aggregate leaf maintained by delta; nothing
iterates over all holders / all accounts. Each design states its leaves, the guards and what the operator supplies.

### 12.1 Oracle: per-market report sets with a bonded-oracle epoch

Session facts (state.rs `apply_report`, `stake / unstake / slash`, `prune_oracle_unbonding`): bonds are **global per
account** (`oracle_bonds`, `oracle_unbonding`), reports per (market, oracle) (`oracle_reports` + an 8-deep
`oracle_report_history` for slash streaks); the index is the median over reporters of m that hold a bond *now*; the
fill path's mark rule reads "some bonded reporter of m exists" (`oracled`). A bond change (stake, slash, unbonding
expiry) therefore changes the median input / `oracled` of every market the oracle ever reported in — a global effect,
and the expiry happens at a height with no op touching it.

| leaf | value |
|---|---|
| `ostk:<acct>` | `:<epoch>:<bond>:<unlock height or 0>` (absent = never bonded / slashed and cleaned) — `epoch` is a global counter value taken at each (re)bond |
| `orm:<acct>` | `:<n>:<sha256(markets ascending)>` — the markets the oracle has a report in (≤ `SL_MAX_ORACLE_MKTS`, stateless bound) |
| `orep:<m>` | `:<n>:<sha256(entries by oracle: oracle, price, epoch, unlock)>` — the report set of m (≤ `SL_MAX_REPORTERS`), each entry carrying a copy of its oracle's bond epoch / unlock height |
| `ohist:<m>:<acct>` | `:<n>:<sha256(≤ 8 samples)>` — the slash-streak ring |
| `oglob:0` | `:<next epoch>` |

* An entry counts (median, `oracled`) iff its `epoch` equals the oracle's current bond epoch and `unlock == 0 ||
  unlock > height` — evaluated from `orep:` alone, so **lazy unbonding** needs no op at the expiry height (the §9 rule).
  Report: author's `ostk:` (bonded), `orep:<m>`, `ohist:`, `orm:` (insert m); the median reads only `orep:<m>`.
* Stake / unstake / slash change `ostk:` and refresh the copied (epoch, unlock) in every `orep:` of the oracle's `orm:`
  list (≤ SL_MAX_ORACLE_MKTS records) — the bonded-oracle epoch makes a slashed-then-rebonded oracle's old entries
  count again exactly when the session would (same report kept, bond present again), via the refresh at re-bond.
* `mkx.oracled` becomes a derived value (any counting entry in `orep:<m>`), so the fill path loads `orep:<m>` instead of
  a flag that would go stale at an unbonding expiry.
* Funding (OI cap, peg): per-market `oi:<m>` = `:<long_qty>:<short_qty>` maintained by delta on every position change
  (the fill / liquidation already loads the market and both accounts); the funding-rate off-book liquidation keeps its
  own ADL order (below).

* **Round-18 review (R18-I2)**: as written, lazy unbonding cannot match a reference root computed from the session
  state: `prune_oracle_unbonding` (height hook) removes the expired oracle's bond AND its reports / histories from every
  market at the expiry height, so the session-derived `orep:<m>` no longer holds the entry while the stateless leaf still
  carries it (dead by its copied unlock height) until the market is next touched. Options: (a) the stateless lineage is
  its own consensus after the migration (R17-I2) and its reference is a stateless model with the lazy rule (the
  differential tests then compare events and the leaves the session can derive, not the whole root); (b) an eager hook
  that touches, at each height, the `orm:` markets of every oracle expiring there (bounded per oracle by
  SL_MAX_ORACLE_MKTS, unbounded in the number of oracles expiring at one height: needs an expiry queue leaf and a
  per-height processing bound); (c) a consensus change to upstream: expiry removes only the bond, reports of an unbonded
  oracle are ignored by the median (no report removal). The governance design (§12.3) avoided the problem only because
  Finalize is a unit that can load what it invalidates.

* **Round-19 review** (resolution of R18-I2 and the funding leg, rv-loop-19 R19-I1 / R19-I2):
  * Unbonding expiry is **eager and bounded** without a lazy rule: one guest run = one segment = one rollup height
    (lib.rs), the engine height is the run number (+1 per run in `prod`), and `apply_unstake` sets unlock = height +
    ORACLE_UNBOND_HEIGHTS (256). So the oracles expiring at run h are exactly those that unstaked in the single run
    h − 256: at most its Unstake units (≤ MAX_UNITS). A queue leaf `oexp:<unlock height>` = `:<n>:<sha256(accounts)>`
    (a pure function of `oracle_unbonding`) makes the set provable: the run at height h loads `oexp:<h>` (present or
    proven absent), and for each listed oracle its `ostk:`, `orm:` and every `orep:<m>` / `ohist:<m>:<acct>` of its
    `orm:` list (≤ SL_MAX_ORACLE_MKTS each), applies `prune_oracle_unbonding` on the partial state, and deletes
    `oexp:<h>`. The reference stays the session state, so §12.1's lazy entries (epoch / unlock copies) are not needed.
    Worst case per run: (Unstake units of run h − 256) × SL_MAX_ORACLE_MKTS records; a consensus bound on Unstake units
    per segment (session and stateless alike) would cap it. Non-`prod` height jumps load every `oexp:` in (glob, h].
  * The **funding transfer** (`transfer_funding`, every report tick with ≥ 2 reporters, once per market and height) is
    O(holders of the market): Phase 1 collects every holder's payment in id order, Phase 2a debits payers clamped at
    collateral into a budget, Phase 2b credits receivers in id order until the budget is spent -- the result for one
    account depends on every lower id's collateral. No partial evaluation is exact; a stateless Report that pays
    funding must load every holder of the market with a completeness proof (a per-market holder-set leaf
    `hset:<m>` = `:<n>:<sha256(ids)>`, maintained on every position open / close -- the same maintenance cost as
    §12.2's rank index) and is bounded by SL_MAX_ACCOUNTS: a market with more holders cannot take a funding tick
    statelessly. Alternatives: an upstream change to index-based (cumulative, settled on touch) funding, or a
    per-market holder cap enforced by both images.
  * Implementation order: (1) `ostk:` / `orep:` / `ohist:` / TWAP ring leaves + migration, Stake / Unstake / Report on
    markets where no funding tick is due (refuse the tick: UNSUPPORTED), `oexp:` expiry hook; (2) `hset:` + funding;
    (3) Slash (reads the market TWAP + the target's history; removes one report).

* **Round-20 implementation** (stateless/ora.rs; leaves §2; guards §4): steps (1) and (3) of the order above, step (2)
  decided against (R20-I1). Differences from the round-19 plan:
  * no `ohist:<m>:<acct>` leaf (R20-M1): with one leaf per (market, oracle) a bond change / expiry loads every history of
    the oracle; the history is a digest inside its `orep:` entry and the samples travel only for the Report author /
    Slash target. An expired oracle's entries leave the loaded report sets whether or not their samples were sent.
  * the queue is a doubly linked list of non-empty groups (`oexp:` prev / next, ends in `oglob:0`): Unstake appends at
    the tail (unlock = height + 256 is the maximum in a bound image; a smaller unlock → unsupported), a Slash / expiry
    unlinks an emptied group (its neighbours are loaded), the hook walks from the head.
  * bounds of one height's expiry (the hook runs before any unit and cannot be split by the operator): at most
    `SL_MAX_UNSTAKES` = `MAX_UNSTAKES_PER_HEIGHT` = 16 oracles per group (R20-M2; refusal code 19 in BOTH images,
    R20-L1) and `SL_MAX_ORACLE_MKTS` = 16 markets per oracle (R20-M3), so the hook's worst case (16 × 16 = 256 report-set
    + market records, slpoc20 P2: 125 KB) stays within `SL_MAX_MARKETS`; `SL_MAX_REPORTERS` = 64 per market. The session
    never reaches the last two (MAX_STATE_ORACLES 32, MAX_STATE_MARKETS 16); the migration refuses a state above any of
    them (ST_SL_MIG_BOUNDS).
  * `mkx:` keeps its `oracled` bit (a pure function: some entry has a report and `bonded`); a market whose report set is
    loaded has its real reporters instead of the stand-in one, the loader checks the two agree.
  * **Funding (R20-I1, the round-19 option "bounded holder list" rejected)**: a tick still needs every holder of the
    market (R19-I1). A `hset:<m>` holder list would be maintained on every position open / close (fills of both
    parties, liquidation, ADL, migration) and a tick would load all of them: a market above ~4 096 holders could never
    tick, so a per-market holder cap would have to become a consensus rule of both images — a new squatting surface (dust
    positions fill the cap and lock others out of the market) — and every tick (each height with ≥ 2 reporters) would
    cost a witness of ~600 B per holder. The stateless image therefore keeps funding transfers and the funding-rate peg
    UNSUPPORTED; production needs the upstream change to index-based funding (a per-market cumulative funding index
    updated O(1) per tick, each position settling `qty × (I_now − I_entry)` when touched), which also replaces the
    clamp-at-collateral budget of `transfer_funding` (Phase 2a / 2b) — a consensus decision upstream.

### 12.2 Liquidation / ADL: holder index by mark-independent rank

Session facts (engine.rs `liquidate_book_path`): liquidation reads the target's positions, the market, its book (§6
walk) and insurance — all loadable. The book-path ADL takes **one** counterparty per unit (round 7): the opposite-sign
holder first in the order **|qty| descending, AccountId ascending** — a mark-independent rank. (The funding-rate
off-book path ranks by unrealized funding cash at the close price — mark-dependent; it stays unsupported or needs a
consensus change to a mark-independent rank.)

| leaf | value |
|---|---|
| `adlq:<m>:<sign>:<d>:<prefix>` | 256-ary trie (like `bmp:`) over `u64::MAX − |qty|` of the holders of sign `sign` in m |
| `adlv:<m>:<sign>:<qty>` | `:<first acct>:<last acct>` — the holders with exactly this |qty|, a list sorted by AccountId |
| `alk:<m>:<acct>` | `:<prev acct or ->:<next acct or ->` — the holder's neighbours in its `adlv:` list |

* ADL pick: the best `adlq:` level (trie walk, 8 nodes, the same walk check as §6), its first account; that account's
  record. O(1) in the number of holders.
* Maintenance on every position change of a non-insurance account in m (fill, liquidation, ADL, migration): remove
  from the old (sign, |qty|) list (its two neighbours' links), insert into the new one — a sorted insert is verified
  with the two neighbours (`pred < acct < succ`, `pred.next == succ`; the operator supplies them), plus the `adlq:`
  path bits of a list that appeared / emptied. Same cost class as resting / cancelling an order.
* Differential test: session ADL counterparty == index head for every Liquidate in liqfuzz / sladv.
* Status (round 17): the book path is supported (§4); a unit that reaches the ADL remainder is unsupported until this
  index exists. Note the index must also be maintained by every op that changes a position (fills of Place, the
  liquidation itself), so it lands together with its maintenance in all supported ops, and in the migration.

**Round-21 implementation (rank sub-trees instead of `adlq:` trie + `adlv:` / `alk:` lists)** — `stateless/adl.rs`.
The trie + linked lists above need a sorted insert with two verified neighbours and a trie update per list; the round-19
machinery (a compact SMT per object whose root is a field of an MNWIT-S leaf, pruned multiproof, `PTree::set` /
`remove`) does the same job with one structure if the sub-tree's keys are the rank itself instead of a hash:

* `adlr:<m>:<sign>` holds the root of a compact SMT over the market's holders of that sign; key = `BE(u64::MAX − |qty|)`
  ‖ `AccountId[0..24]` (256 bits: the tree's depth limit), leaf hash = `sha256("~R1:" ‖ key ‖ AccountId)`. Bit order =
  rank order, so the leftmost leaf is the ADL counterparty. Insurance is never in a tree (never a candidate); the target
  is in the other sign's tree. A pure function of the session state: the reference root stays `s_root(state)`, the
  migration commits the trees with every other leaf.
* Witness: per needed tree (`Need::Adl(m, sign)`) the `adlr:` leaf (present / proven absent) and the sub-tree pruned to
  its leftmost path (`AdlTop(k)`: through the first k start keys — after k − 1 removals the leftmost remaining start key
  is among them) and the paths of the keys a unit removes / inserts (`AdlKey`). A verified rank leaf is a new tag 5
  (key + AccountId; key[8..] = id[..24] and the leaf hash recomputed), accepted only by `PTree::decode_raw` (tag 4 —
  hashed kid keys — is refused there, tag 5 everywhere else).
* ADL pick (run loop; engine flags `SL_ADL_REACHED` + `SL_ADL_SIDE`): the candidates' tree as of unit start (maintained
  through the previous units; this unit's maintenance runs after) must expose its leftmost leaf verified, and that
  holder's full record must be loaded (its tree entry is checked against the key). Every loaded holder is in the tree
  under its current key, so none ranks before the leftmost: the engine's pick among the loaded holders is the session's.
  An empty tree = no candidate anywhere. A kind-2 fill whose maker is not the leftmost holder → BADWIT (defence).
* Maintenance (after every unit and after the height hook): for each dirty non-insurance account, every market whose
  (sign, |qty|) changed against the account's current tree entry (initialised from its loaded record) — remove the old
  key (must be present with this account's leaf; unknown path → `AdlKey`), insert the new one (must be absent; unknown
  → `AdlKey`). End root: each loaded tree's root into its `adlr:` leaf (put; delete when it became empty).
* Cost: a unit that reaches the ADL reads one leftmost path (≤ depth of the sub-tree) and one account record; every
  position change costs a removal + an insertion path in the market's sub-trees (O(log holders), shared prefixes).
  `slpoc21` P1 (2 000 extra holders): the rank section of the witness 1.4 → 1.9 KB.
* Assumption (R21-I2): two holders of one market with the same |qty| never share a 24-byte AccountId prefix (ids are
  hashes of ed25519 keys); an insertion onto a present key is refused as UNSUPPORTED rather than mis-ranked.
* The funding-rate off-book path ranks by unrealized funding cash (mark-dependent) and stays unsupported (the whole
  liquidation of a funding-rate market is, `liq_pre`). A revealed Liquidate stays unsupported.

### 12.3 Governance (implemented, round 18; exception sub-trees round 19)

Session facts (engine.rs propose / vote / finalize): a proposal copies every non-zero PERP balance (`weight_snapshot`,
O(holders)) at creation; a vote weighs the voter's snapshotted balance and is recorded in `voted`; finalize compares the
tallies after the deadline and removes the proposal; the R6-H2 rule (state_cap_ok) bounds zero-weight voters by
|voted| < |snapshot| + MAX_ZERO_VOTERS; at most 64 live proposals.

The round-16 sketch (per-account `(seq, balance)` checkpoints) was dropped: the session state keeps no balance history,
so the reference MNWIT-S root (a function of the session state) could not contain it. Round 18 uses **exceptions**:

| leaf | value |
|---|---|
| `pglob:0` | `:<next id>:<non-zero holders>:<n live>:<sha256((id, xroot))>` — xroot = root of the proposal's exception sub-tree (round 19; round 18: n_exc) |
| `pxe:<pid>:<acct>` (sub-tree leaf) | `:<weight>:<voted>` for a live proposal where weight ≠ the account's current balance, or voted (round 18: per-account `pexc:<acct>` lists in MNWIT-S) |
| `prop:<id>` (MNWIT1 `govwit`) | unchanged; the stateless image writes its |voted| / |snapshot| counts from the loaded counts + deltas |

* Every (account, live proposal) pair without an entry has weight = the account's current balance and no vote; so a
  proposal is created in O(1) (no entry for anyone; |snapshot| = the holder count), a vote reads one record, and a
  balance change rewrites the account's own list (the old balance becomes an explicit entry for every live proposal).
* Finalize removes the proposal, so every entry for it disappears from the reference. Round 18 kept the entries in
  per-account `pexc:` leaves, so a Finalize had to load **all** n_exc holders (count-verified) and above SL_MAX_ACCOUNTS
  (4096) holders a proposal could never be finalized (R18-M1). **Round 19 fix**: each live proposal's entries form its
  own exception sub-tree whose root is a field of `pglob:`; a Finalize drops the `pglob:` entry and with it the whole
  sub-tree (O(1), no holder loaded: slpoc18 P3 finalizes 20 000 voters with an 11.7 KB witness). A Vote updates one
  sub-tree path; a balance change one path in each live proposal's sub-tree (≤ 64); a proposal created in the segment
  starts with an empty sub-tree (every exception it can get in the segment is a loaded account's). Still a pure
  function of the session state (s_root / migration unchanged in principle; the MNWIT-S root changes format).
* Witness (round 19): the `pglob:` section carries (id, xroot, `prop:` fields) per live proposal; after the exception
  lists (account, k, entries) come the live proposals' sub-trees in id order, each a pruned compact SMT (same preorder
  encoding as the MNWIT-S tree, ≤ SL_MAX_TREE_NODES nodes in total) whose root must equal its xroot.
* Tests: slfuzz / sladv `gov` (gov_batch on the real engine: deposits / withdrawals, proposals, votes, SetSeq jumps,
  finalize), slpoc18, slmiggov (migration of states with live proposals), loop18-mut.py / loop19-mut.py (guard mutants); sladv
  `forge19:pxe-drop` / `forge19:pxe-weight` (forged exception lists against the sub-trees, must be refused).
