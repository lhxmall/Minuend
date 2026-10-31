# guest-engine — Minuend matching engine pilot port (no_std riscv32im)

First bounded pass at running the **real** Minuend engine code inside the dispute VM. Source of truth:
`fix/47-all @ 20326c0` (read via `git show` / `git archive`; that branch, `main` and PR #51 are untouched).

## 1. Survey: what blocks a no_std riscv32im build (non-test code, fix/47-all @ 20326c0)

| crate | lines | HashMap/Set | OS std (fs/io/path/env/sync) | serde / bincode / json | String/format | i128/u128 |
|---|---|---|---|---|---|---|
| minuend-types | 803 | 3 (env_compat) | 3 (env_compat: `std::env`, `Mutex`, `OnceLock`) | serde derives; `hex` | 10 (env_compat) | 17 |
| minuend-book | 725 | 6 (`orders` map, journal seen-sets) | 0 | serde derives, thiserror | 0 | 1 |
| minuend-account | 530 | 0 | 0 | serde derives, thiserror | 0 | 20 |
| minuend-state | 2 774 | 16 | 12 (persist.rs, journal.rs) | **bincode** (persist.rs), base64, hex | 53 (wit leaves) | 45 |
| minuend-dag | 1 314 | 26 | 0 | serde_json, base64, hex, ed25519-dalek | 15 | 2 |
| minuend-exec | 2 903 | 4 | 6 (snapshot/WAL paths) | serde_json (1) | 2 | 44 |

Findings
- **No floating point anywhere** (0 uses of f32/f64).
- **i128/u128** are everywhere in money math. They compile fine for riscv32im (compiler-builtins), but are
  software ops: one `position_risk` call (3 notional + 2 bps, i.e. ~8 i128 divisions) costs **~12.5k steps**.
- **HashMap/HashSet → BTreeMap/BTreeSet** is safe for book/account/state as far as checked: every iteration over
  a hash container is order-independent (count / sum / any; `own_live_order_mode`'s `find` is order-independent
  because the mode gate forbids mixed modes per account+market; `leaves()` and `wit_leaves()` sort before hashing).
- **std-only pieces stay off-chain**: `persist.rs` (bincode snapshots), `journal.rs` (gov-nonce WAL file),
  `env_compat` (env vars + Mutex), exec's snapshot/WAL paths, gossip/settle/watch. None of them is on the
  `apply_one` path. **bincode** has no no_std mode → the state handed to a guest needs its own codec (or postcard).
- **serde / thiserror derives** are the only reason book/account are not no_std today; drop or gate them
  (`default-features = false`) — the pilot simply removes the derives.
- **dag**: ed25519 verification (2.86M steps/sig, earlier measurement) + serde_json unit text — keep out of the
  guest (layer-1 bisection over units + on-chain P-sig, as recommended in the report).
- **Biggest real blocker is not compilation but cost**: `apply_one` rebuilds the full witness tree after EVERY
  unit (`wit_root(state)` = Obyte merkle over all formatted `acct:/pos:/ord:/adr:/dep:/meta:` leaves, sorted).
  That is O(state) sha256 + string formatting per unit (see §4).

## 2. What was ported (2 700 lines, mostly verbatim)

| file | upstream source | changes |
|---|---|---|
| `src/book.rs` | `minuend-book/src/book.rs` (whole file) | `use` lines; `HashMap/HashSet` aliased to `BTreeMap/BTreeSet`; serde derive removed |
| `src/book_types.rs` | `minuend-book/src/lib.rs` (Order, Fill, MatchResult, BookError, SelfTrade) | serde/thiserror derives removed |
| `src/account.rs` | `minuend-account/src/lib.rs` (whole non-test file: apply_fill, snapshot, isolated_risk, spot requirements, vwap, realize) | `use` lines, derives |
| `src/types.rs` | `minuend-types/src/{lib,amount,ids,order}.rs` subset (constants, MarketParams, genesis_params, notional/bps math, order_id) | derives; `sha256` via sha2 0.10 no_std |
| `src/state.rs` | `minuend-state/src/lib.rs`: StateJournal, journal_account/market, submit_journaled, apply_fill_pair_journaled, rollback, book_mut, account_mut, **apply_fill_pair** (fee, claw, mark guard), market_params | ChainState reduced to the fields these paths touch; funding-rate mark/peg block stubbed (`PILOT:`; no funding market is listed) |
| `src/engine.rs` | `minuend-exec/src/lib.rs`: **`Engine::place`** (all gates: client_seq, MARK_CAP, live-order cap, QTY_CAP, overflow, tick, band, mode gate, reduce-only, open-qty IM incl. resting IM, isolated escrow, spot/funding branches), `cancel`, `resting_open_im`, `taker_fee_keeps_cash`, `funding_open_interest`, exposure helpers, `RejectReason`, `map_acct` | `deposit` simplified to the account effect (`credit` on a clone); anchor/address checks not ported |
| `src/lib.rs` | — | batch decoder, `run_batch` (one op = one unit; `seq` advances only on Applied, as `apply_one`), event log, pilot state hash |
| `src/main.rs` | — | riscv32im runtime: `_start`, bump allocator, input via `ecall a7=63`, results at `OUT=0x03F0_0000`, halt `a7=93`; feature `embed` reads the batch from memory for sail |

Pilot state hash = `sha256("MNPILOT1" || seq || Σ account_leaf(acct, perp, withdrawn) || Σ (market, sha256(book.commitment_bytes())) || marks || seen_client_seq)`
— `account_leaf` and `commitment_bytes` are the upstream encodings. Not ported: liquidation/ADL, withdraw,
oracle/report/TWAP/funding, governance, commit-reveal, DAG, witness trace (`wit_root`), persistence.

## 3. Differential test (host, `../engine-diff`)

`engine-diff` links the **real crates** (`../engine-src` = `git archive 20326c0`, fetched by `fetch-engine.sh`, not
committed) and drives the real `Engine::ingest` with ed25519-signed units in a linear DAG chain (deposits endorsed via
`deposits_allowed`, as the upstream tests' `allow_all`). The same batch runs through the port natively and through the
riscv32im ELF in the JS model (`js/pilotrun.js`). Compared: final state hash **and** the full event log (per unit:
Applied + fills [maker id, taker id, price, qty] or the reject reason).

Workloads (`engine-diff gen`): makers build a two-sided book around 100 000 USD (`levels` per side × `per_level`),
then N flow orders: 43 % passive limits, 20 % crossing limits sized to the first maker, 15 % market IOC, 12 % cancels
(incl. stale), 10 % oversized crossing (MultiFill / IOC). `stress` adds thin accounts (2k–20k USD), 15 % isolated
orders with escrow, and a cap spammer (64 live orders).

Results (2026-10-31, VM, logs `/data/hark/logs/rv/pilot2-*`):
- **`engine-diff fuzz 300 300`** (real vs port, native; 300 seeds, half `stress`, random depth 1–25 levels × 1–3,
  4–12 makers): **300/300 identical** (hash + event log). 65 183 applied units without fill, 31 502 with one fill,
  rejects: Risk 10 258, MultiFill 3 522, NotFound (stale cancel) 2 329.
- **3-way bench** (real engine ↔ port ↔ riscv32im guest in the JS model), 9 batches up to 1 832 units, depth 200/800,
  normal + stress: **9/9 identical** (and every setup-only batch too).
- **sail-riscv 0.16** spot-check (`xval/pilotsail.js`, `embed` build): batch `depth200 N=10` (236 units, real-engine hash
  `c9ce7980…81be`): sail ran to the final `li a7,93` in **16 196 951 instructions = the JS model's count exactly**; all 261
  result words (hash, counters, event log) in sail's memory dump equal the JS model's, and the hash equals the real
  engine's. (Smaller batch, 42 units: 957 185 = 957 185, identical too.)
- **Harness self-test** (mutants of the port, each must make `fuzz 100 300` disagree with the real engine):
  **7 of 13 killed** — taker fee 5→4 bps, `<=`→`<` in the crossing test, vwap rounding,
  resting-IM `max`→sum, isolated pro-rata escrow +1, cross IM gate without resting IM, live-order cap `>=`→`>` (needs
  1000-order batches: `fuzz 20 1000`, 8/20 disagree). Survivors: 2 equivalent within the pilot's scope (mark ±10 % band —
  unreachable while no oracle index exists, the mark stays frozen; `liquidatable` — not read on the place path) and 4
  boundary cases random batches rarely hit (isolated equity `<` vs `<=`, claw from a negative counterparty, isolated
  bucket release rounding, taker-fee guard's equity clause; release rounding was caught 1/100 with an earlier generator).
  Next: replay the upstream `#[test]` scenarios as batches to pin these boundaries. Results: `results-2026-10-31/`.
  **Update (§6):** with the upstream-scenario replay 10 of 13 are killed; the 3 survivors are equivalent.

## 4. Step counts (JS model; sail spot-check)

Steps per order = (steps(setup + N flow orders) − steps(setup only)) / N, so the one-off state build and the final
state hash cancel out. Every order is one unit (deposit/place/cancel incl. rejects). Batches: makers + 16 traders,
book around 100 000 USD; `depth200` = 50 levels × 2 orders per side, `depth800` = 200 × 2 per side.
Fees: operator pays R × 3372 (one move) + 11 467 (resolve); payout CBOND − GF − FEE = 108 000.

| book | N | applied/rej/fills | flow steps | **steps/order** | R flow | cost flow | full run (incl. setup) | R full | cost full | margin vs 108 000 (worst) |
|---|---|---|---|---|---|---|---|---|---|---|
| depth200 | 10 | 9/1/2 | 728,189 | **72,819** | 5 | 28,327 | 16,203,655 | 6 | 31,699 | +76,301 |
| depth200 | 100 | 92/8/47 | 8,505,091 | **85,051** | 6 | 31,699 | 23,980,557 | 7 | 35,071 | +72,929 |
| depth200 | 1000 | 948/52/414 | 93,819,765 | **93,820** | 7 | 35,071 | 109,295,231 | 7 | 35,071 | +72,929 |
| depth800 | 10 | 10/0/5 | 1,891,560 | **189,156** | 6 | 31,699 | 132,956,322 | 7 | 35,071 | +72,929 |
| depth800 | 100 | 96/4/35 | 20,411,491 | **204,115** | 7 | 35,071 | 151,476,253 | 7 | 35,071 | +72,929 |
| depth800 | 1000 | 964/36/415 | 196,017,586 | **196,018** | 7 | 35,071 | 327,082,348 | 8 | 38,443 | +69,557 |
| stress200 | 10 | 10/0/3 | 721,538 | **72,154** | 5 | 28,327 | 16,204,683 | 6 | 31,699 | +76,301 |
| stress200 | 100 | 78/22/32 | 7,508,714 | **75,087** | 6 | 31,699 | 22,991,859 | 7 | 35,071 | +72,929 |
| stress200 | 1000 | 740/260/320 | 88,192,765 | **88,193** | 7 | 35,071 | 103,675,910 | 7 | 35,071 | +72,929 |

(R = ceil(log16 steps). Setup ops: 68.5k steps each at depth 200, 157.5k at depth 800. Heap (bump, never frees):
3.1 MB after 1 226 units at depth 200, 4.2 MB after 1 832 at depth 800.)

**Cost model.** Per order ≈ **43k + 170 × L steps**, L = live resting orders (fit: 93.8k at L≈300, 196k at L≈900).
`Engine::place` is O(book): the live-order cap count, the QTY_CAP sum, `resting_open_im`, `has_*_exposure` and
`own_live_order_mode` each walk every order of every book (`live_orders()` + 32-byte account compares). Profile
(`js/pilotprof.js`, small batch): `resting_open_im` 18 %, sha256 16.8 % (order ids + final hash), inlined scans in
`run_batch`/`place` 12.8 %, `memcmp` 11.3 % (30k calls), `position_risk` 10 % (i128 division, ~12.5k steps/call).

**What the pilot does NOT include — the per-unit witness root** (now prototyped incrementally, §6). Upstream `apply_one` recomputes
`wit_root(state)` after every unit. `engine-diff witstat` sizes that tree on the real engine's final state:

| batch | live orders | leaves | bytes | sha256 blocks | ≈ steps @ 3.5k/block (sha only) |
|---|---|---|---|---|---|
| depth200 N=10 | 198 | 310 | 42 735 | 1 415 | 5.0M |
| depth200 N=1000 | 392 | 526 | 77 781 | 2 477 | 8.7M |
| depth800 N=10 | 800 | 940 | 146 869 | 4 529 | 15.9M |
| depth800 N=1000 | 1 002 | 1 166 | 183 691 | 5 641 | 19.7M |

That is ~5.7 blocks ≈ **20k steps per live order per unit**, before hex/decimal formatting and the sort — **100× the
matching cost**. A full port with the current commitment would spend >95 % of every unit's steps on `wit_root`.

**Extrapolated full port (estimate, not measured).**
- Layer 2 (one unit): exec 43k + 170·L, plus wit_root ≈ 20k·L (sha only; formatting likely +50–100 %), plus binding
  the loaded pre-state to the committed pre-root (another O(state) pass unless incremental). L = 200 → ~5–10M steps
  (R = 6, 31.7k bytes), L = 1 000 → ~20–40M (R = 7, 35.1k), L = 10 000 → ~0.2–0.4G (R = 8, 38.4k). All well under the
  108 000 payout; R ≤ 10 (45.2k) holds up to 2^40.
- Single-layer over a whole batch is out: BATCH_MAX_UNITS 200 000 × ≥5M steps ≈ 10^12 ≈ MAXSTEPS 2^40 — the
  two-layer game (bisect units first) is required, as recommended.
- Recommended engine change before a full port: an **incremental witness commitment** (fixed-depth sparse Merkle
  keyed by leaf id, update only touched leaves). Per unit that is ~5–10 touched leaves × (≈3 + 2·depth) blocks ≈
  0.2–0.5M steps, making layer-2 games ~0.3–0.6M steps (R = 5) independent of book size. O(book) scans in `place`
  (per-account live-order count / open qty / resting IM kept as running totals) would cut the 170·L term.
- Work left: port the other ops of `dispatch` (liquidate/ADL, withdraw, oracle/TWAP/funding, governance,
  commit-reveal, gov deposit/withdraw — ~4–5k lines, mostly mechanical as this pilot shows: book/account went in
  with `use`-line edits only), wit_leaves/obyte_merkle in no_std (alloc `format!`, hex/base64 no_std), a state codec
  replacing bincode + pre-state binding, a freeing deterministic allocator if units allocate a lot, and diff-testing
  against the upstream unit tests. Estimate: **3–4 weeks** for the guest (vs 4–6 in the report), plus the
  incremental-witness engine change (1–2 weeks, consensus change: ASSERTION_VERSION bump + AA redeploy).

## 5. Reproduce (InstaBox VM)
`scripts/run-pilot.sh` (builds host harness, guest, embed guest; fuzz; bench; witstat; sail; mutants) — logs in
`/data/hark/logs/rv/pilot2-*`. Pieces:
```sh
. /data/hark/spike-rv/env.sh                      # private rustup 1.99 + riscv32im target
(cd engine-diff && ./fetch-engine.sh && cargo build --release)
(cd guest-engine && cargo build --release --target riscv32im-unknown-none-elf)            # bin rvengine
(cd guest-engine && cargo build --release --features embed --target riscv32im-unknown-none-elf)
engine-diff gen 7 10 50 2 1000 b.bin [stress]; engine-diff real b.bin; engine-diff port b.bin; engine-diff fuzz 300 300
node js/pilotrun.js rvengine b.bin; node js/pilotbench.js <engine-diff> <rvengine> <outdir> [cfg]; node js/pilotprof.js rvengine b.bin
node xval/pilotsail.js <rvengine-embed> b.bin <workdir> <expected hash>
```

## 6. Incremental witness commitment — MNWIT1 (proposal, 2026-10-31)

**Consensus change for the real engine** (redefines `wit_root`; needs an `ASSERTION_VERSION` bump and a
redeploy of every AA that reads witness proofs). Implemented and measured here only — `fix/47-all`,
`main` and PR #51 are untouched. Full spec (Chinese): `docs/rv-dispute-design.md` §7.3.

**Spec.** Same leaf strings as `minuend_state::wit_leaves` (no `~:end` sentinel); a compact sparse
Merkle tree keyed by each leaf's identity prefix:
- `kid` = first 2 fields of the leaf (`acct:<hex>`, `ord:<hex id>`, `adr:<addr>`, `adrx:<hex>`, `dep:<b64>`,
  `obond:<hex>`, `band:<m>`, `meta:<m>`), first 3 for `pos:<hex>:<m>`;
- `key = sha256("~K1:" || kid)` (path = key bits, MSB first);
- `leaf = sha256("~L1:" || hex(key) || ":" || leaf_string)`; `node = sha256("~N1:" || b64(l) || b64(r))`;
- `EMPTY` = 32 zero bytes; a subtree with one leaf IS that leaf's hash (collapsed at the shallowest
  depth that separates it); root of the empty tree = `EMPTY`. `wit_root = b64(root)` (44 chars, same field type).
- Domain separation: `~K1:`/`~L1:`/`~N1:` prefixes vs legacy leaves (lowercase tags, `~:end`) and legacy
  nodes (base64 text). The shape is a pure function of the leaf set → root independent of insertion history.
- Genesis (`ChainState::new()`): `8q+ZwYDtXcypxizCpTw0YfUr/6XPNkvLSZYJVHlwirk=` (3 leaves).
- Proofs: membership = leaf string + siblings (fold with key bits); non-membership = siblings to a
  terminal that is `EMPTY` or a different leaf whose key shares the path prefix — replaces sorted-neighbour
  straddles, `wit_count`, `counts_root` and the sentinel.

**Dirty tracking.** `ChainState::wit_dirty` (accounts, (market, order id), markets) is filled by the
`StateJournal` (every account / market scalar / book order the place path records for rollback — noted on
success and on rollback), `account_mut`, cancel and deposit. After each unit (applied or rejected, as
upstream pushes one root per unit) `Wit::commit` regenerates the leaves of the dirty keys, skips unchanged
leaf hashes, deletes vanished leaves (closed `pos:`, filled/cancelled `ord:`) and rehashes only dirty paths.

**Code.** `src/wit.rs` (no_std: arena tree with free lists, leaf strings formatted into a stack buffer —
no heap per leaf; `legacy_root` = the current fix/47-all construction for comparison);
`run_batch_wit(rd, ev, unit_cb, WitMode)` in `src/lib.rs`; guest writes every unit's root at
`OUT+0x20000` words (8 per unit), unit counter at `OUT+0x1FFFF`, `scratch_ok` (final incremental root ==
root rebuilt from scratch in the guest) at `0x1FFFE`. Features: default = incremental, `nowit` = none
(the 2d01fe8 numbers), `legacywit` = legacy full rebuild for units ≥ header word 3. Host reference:
`../engine-diff/src/smt_ref.rs`, written independently (recursive from-scratch build over sorted keys,
keys parsed from the leaf TEXT the way an AA would) and fed with the REAL engine's `wit_leaves`
(filtered to the modelled tags acct/pos/ord/band/meta).

**Tests** (VM logs `/data/hark/logs/rv/wit-*`, copies in `results-2026-10-31/`):
- Regression `engine-diff fuzz 300 300` (real vs port after adding the dirty hooks): **300/300**, same event
  statistics as §3.
- **Property + diff test** `engine-diff witfuzz 300 300 300`: 300 random batches (half `stress`); for EVERY unit
  (1) real-engine state → `smt_ref` from scratch, (2) port incremental root, (3) port state → `smt_ref` from
  scratch: **300/300 batches, 112 794 units, all three equal**; guest-side `scratch_ok` = 1 everywhere.
  History independence (final leaf set inserted shuffled, with junk keys inserted/removed in between):
  **300/300**. Pure tree test (random set/remove incl. keys sharing 253-bit prefixes, root vs from-scratch
  after every op): **300/300 rounds, 34 894 ops**.
- **Host reference vs guest (JS model), per unit**: all 7 bench batches below `roots_equal` (2 066 units at depth
  2000), `scratch_ok` = 1, and the guest's event log + state hash = real engine (`match_real_guest`).
  `legacywit` guest roots = upstream `obyte_merkle::root` over the real leaves (`legacy_roots_equal`) — so the
  legacy cost column measures the real construction.
- **Upstream `#[test]` scenarios replayed as batches** (`engine-diff scen scenarios/upstream.scn`: 47 batches /
  355 units from minuend-book, -account, -state and -exec tests driven through deposit/place/cancel, plus 6
  boundary scenarios; header bit 24 lists a second market as the test fixtures do): real vs port (hash + events +
  per-unit roots) **47/47**; the same 47 through the riscv32im guest in the JS model (`js/witscen.js`) **47/47**.
- **sail-riscv 0.16** (`xval/witsail.js`, embed build; compares instruction count, events and every unit root):
  scenario `bnd_fee_guard_equity_clause` (2 markets, 9 units) **2 005 758 = 2 005 758** insns, 111 words equal;
  `depth200 N=10` (236 units) **52 812 940 = 52 812 940**, 2 154 words equal, final root = host reference
  `cca129b2…978c`, hash = real engine.
- **Mutation test** (`scripts/wit-mut.sh`: each mutant runs `fuzz 100 300` + `scen` + `witfuzz 30 300`):
  port mutants **10/13 killed** (was 7/13). The 4 former boundary survivors: isolated equity `<`→`<=` killed
  (scenario: margin == equity), bucket-release rounding killed (100 USD bucket closed in thirds), taker-fee
  guard equity clause killed (needs a 2nd market: isolated blow-through close leaves cross cash 10 020 USD but
  cross equity 20 USD vs a 40 USD fee; bracket scenarios at equity 0 and = fee), claw from a negative
  counterparty is **equivalent** (the mutant's negative `pay` is skipped by `if pay > 0` exactly like the
  original's 0). Other survivors as before: mark ±10 % band (mark frozen without an oracle index) and
  `liquidatable` (not read on the place path). Witness mutants **6/6 killed** (drop journal note on place
  success, drop `account_mut` hook, drop cancel hook, wrong `ord:` field, one-sided collapse, keep closed `pos:`
  leaves) — engine-only `fuzz` catches none of them; the per-unit root checks catch all.

**Steps per unit** (JS model; one unit = one op; flow units only — boundary step counts are read inside
one run when the guest bumps the unit counter, so setup and final hash cancel out). `inc` = with MNWIT1,
`nowit` = matching only, `wit` = inc − nowit, `legacy` = current per-unit full rebuild (measured for N=10).
R = ceil(log16 steps); operator cost = R × 3372 + 11 467 vs payout 108 000.
| book | N | leaves / avg depth / max depth | inc avg / median / max | nowit | **wit** | legacy wit | unit R (cost) | flow steps → R (cost) |
|---|---|---|---|---|---|---|---|---|
| depth200 | 10 | 231 / 9.06 / 14 | 250,424 / 189,354 / 652,484 | 72,006 | **178,418** | 6,042,590 | 5 (28,327) | 2,504,238 → 6 (31,699) |
| depth200 | 100 | 251 / 9.29 / 14 | 379,373 / 260,575 / 789,910 | 84,442 | **294,931** | — | 5 (28,327) | 37,937,253 → 7 (35,071) |
| depth200 | 1000 | 447 / 10.04 / 17 | 389,173 / 256,720 / 869,907 | 93,460 | **295,713** | — | 5 (28,327) | 389,173,266 → 8 (38,443) |
| depth800 | 10 | 843 / 11.02 / 18 | 542,721 / 745,842 / 909,385 | 184,140 | **358,581** | 22,304,829 | 5 (28,327) | 5,427,206 → 6 (31,699) |
| depth800 | 100 | 883 / 11.05 / 17 | 503,768 / 434,700 / 1,123,895 | 202,046 | **301,722** | — | 6 (31,699) | 50,376,827 → 7 (35,071) |
| depth800 | 1000 | 1069 / 11.26 / 17 | 535,650 / 461,846 / 1,176,458 | 195,633 | **340,017** | — | 6 (31,699) | 535,649,546 → 8 (38,443) |
| depth2000 | 10 | 2066 / 12.32 / 21 | 788,587 / 1,008,489 / 1,109,753 | 352,845 | **435,742** | 54,981,624 | 6 (31,699) | 7,885,869 → 6 (31,699) |
| depth2000 | 100 | 2121 / 12.34 / 21 | 701,285 / 593,600 / 1,232,993 | 354,200 | **347,085** | — | 6 (31,699) | 70,128,480 → 7 (35,071) |
| depth2000 | 1000 | 2311 / 12.47 / 21 | 697,316 / 622,891 / 1,401,744 | 334,655 | **362,661** | — | 6 (31,699) | 697,316,275 → 8 (38,443) |

(Source: VM logs `/data/hark/logs/rv/wit-bench-depth{200,800,2000,2000-n1000}.jsonl`, run 2026-10-31 at commit df02e33; the table was left as a placeholder when the previous run was cut off and was filled in loop round 1 from those logs. Every row: `match_real_guest`, `roots_equal`, `scratch_ok` = true.)
