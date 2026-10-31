# rv loop round 1 — attack → fix on the RISC-V guest engine + MNWIT1 (2026-10-31)

Target: `lhxmall/Minuend` branch `spike/rv-bisect` @ 8af2034 (guest-engine = no_std port of fix/47-all @ 20326c0,
MNWIT1 incremental witness). Reference engine read only via `git archive 20326c0` (engine-diff/engine-src);
fix/47-all, main and PR #51 untouched. Fix commits: see "Fix status" at the end.

Severity: **C** = an honest party loses / the dispute decides wrongly on reachable input; **H** = guest ≠ host or
undefined guest outcome on input the protocol can feed it; **M** = design/spec gap with a concrete failure mode or a
defense-in-depth hole; **L** = minor / documentation.

Totals: **C 1 · H 2 · M 5 · L 5**. No real-engine ↔ port divergence was found (D0).

| id | sev | area | title | status |
|---|---|---|---|---|
| G3 | C | guest robustness | bump allocator never frees → O(k²) heap at a crowded price level → guest aborts on batches the real engine accepts | fixed |
| G1 | H | guest robustness | batch header counts unchecked → wrap/trap/abort, guest ≠ host | fixed |
| G2 | H | guest robustness | output layout: per-unit roots past RAM end after 16 384 units, event log can overwrite counters/roots | fixed (limit + bound) |
| G4 | M | guest robustness | all-zero (INSURANCE_ACCOUNT) id accepted as op author | fixed |
| G5 | M | guest robustness | abort / out-of-memory outcome unspecified | fixed (status word + spec) |
| S1 | M | step count | per-unit cost O(live orders) unbounded without a unit cap; future pre-state guest needs a global bound | fixed for pilot (MAX_UNITS ⇒ L ≤ 16 384); spec for full guest |
| W1 | M | MNWIT1 | proof verifier rules underspecified (§7.3.3) | fixed (spec + reference verifier + test) |
| W2 | M | MNWIT1 | proof depth vs Oscript complexity (MAX_COMPLEXITY 100; grindable depth) | documented (AA side not in scope) |
| W3 | L | MNWIT1 | duplicate kid silently overwritten by incremental tree | fixed (scratch check counts leaves) |
| W4 | L | engine (both) | undo journal clones a whole price level per touch: O(level) CPU per unit in the real engine too | reported, not changed (verbatim port) |
| G6 | L | guest | `embed` build: stack shares 0x0300_0000.. with the input image | resolved by limits (input ≤ 640 KiB) |
| DOC1 | L | docs | README §6 / design §7.3 step tables left as `STEPS_PLACEHOLDER` / `STEPS_ROWS_ZH`, notes `FINALCOMMIT` | fixed |
| DOC2 | L | docs | batch header comment documents an `isolated<<3` flag the decoder ignores | fixed |

---

## G3 (C) — guest heap grows with total bytes ever allocated; a crowded price level kills the guest

**Where.** `guest-engine/src/main.rs` (2d01fe8..8af2034): `Bump` allocator, `dealloc` is a no-op, panics at
`HEAP >= 0x0300_0000` (≈ 48 MiB of heap). `book.rs::touch_level` (verbatim upstream #47 B4 undo journal) clones the
level's whole `VecDeque<OrderId>` on the first touch of every submit; `VecDeque` growth, `BTreeMap` node churn,
`Account` clones in `apply_fill_pair`, journal vectors and `WitDirty` sets are all leaked too.

**Attack.** k orders resting at one price (any accounts, 64 per account, MIN_OPEN_EQUITY 1 USD; an order of
0.0001 BTC needs ~1 USD of IM) → the j-th placement at that price clones j·32 bytes → Σ ≈ 16·k² bytes. No crossing,
no rejection needed; honest flow at a round price does the same.

**PoC.** `engine-diff crowd 30 60 crowd1800.bin` (30 deposits + 1 800 bids at 99 000 USD; real engine: 1 830 applied).
- host simulation of the old bump allocator (`engine-diff heapsim`, 64-bit sizes = upper bound): **57.5 MB > 50.2 MB**
  heap; `crowd 256 64` (16 384 units): **4.21 GB**.
- **old guest (8af2034 build `target-wit-g2`, JS model): exit a0 = 77 (abort) after 1 723 of 1 830 units,
  669 581 253 steps** — while the real engine and the port apply all 1 830 (`/data/hark/logs/rv/l1-poc-crowd.log`).
- consequence: the riscv32 guest aborts (exit 77) where the real engine produced a state; an honest operator's
  assertion of the real result cannot be defended by the guest → honest bond loss / wrong verdict.

**Fix.** Deterministic size-class free-list allocator (powers of two 16 B .. 32 MiB, LIFO free list per class, blocks
aligned to min(size, 64), carve from top, in-class realloc in place). Heap use now tracks live bytes per class.
Measured (host 64-bit upper bound): crowd1800 **1.9 MB** high-water, crowd 256×64 at MAX_UNITS **19.0 MB**, limit
batch (4 096 accounts × 16 384 units) 3.8 MB, gen 14 228 units 1.1 MB — all under the 50.2 MB heap with ≥ 2.6× margin
at the unit cap. Peak live bytes are written to OUT[0x1FFFA] and the carved high-water to OUT[12].

**Regression.** `engine-diff heapsim` (l1-heapsim.log), the crowd1800 guest run must halt with the host result
(l1-poc-crowd.log NEW section), `crowd168` through guest + sail (allocator free-list paths on a second RISC-V model).

## G1 (H) — header counts unchecked

**Where.** `run_batch_wit`: `n_acc = rd(1)`, `n_ops = rd(2)` used directly: `Vec::with_capacity(n_acc)`, index
`4 + a*8 + k` and `base + i*8 + k` in u32 (wraps), loop `0..n_ops`.

**Failure.** `n_ops = 2^32-1` on a short batch: the host port (`w.get(i).unwrap_or(0)`) runs 4·10^9 BadAccount units;
the guest writes unit roots at OUT+0x20000+8i and passes the 2^24-word RAM end at i = 16 384 → store **TRAP**
(rv_step), and input indices ≥ 2^24 also TRAP in the input ecall. `n_acc` ≥ ~1.5 M → `with_capacity` abort (exit 77),
larger values wrap the index arithmetic. Guest ≠ host, and the guest's outcome (trap / abort) is undefined in the
protocol. Step count before the trap ≈ 16 384 × (BadAccount unit) — no 2^40 blow-up, but no defined result either.

**PoC (old guest, `/data/hark/logs/rv/l1-poc-old-robust.log`).** `ops_over_limit` (header 16 385, 66 real ops,
rest truncated): **TRAP at unit 16 384** (store past RAM, 17.3 M steps; the old host code would have run all 16 385).
`acc_u32max`: **abort a0 = 77 after 136 steps** (`Vec::with_capacity`). `engine-diff robust <dir>` writes `ops_u32max`, `ops_over_limit` (16 385), `acc_u32max`, `acc_over_limit`
(4 097), `truncated_max_units`, `garbage_ops` …; `js/robust.js` runs each through the guest and `engine-diff portout`.

**Fix.** `check_header` before any op: bad magic → status 1, `n_accounts > MAX_ACCOUNTS (4 096)` → 2,
`n_ops > MAX_UNITS (16 384)` → 3; no op runs, hash = 0, status at OUT[0x1FFF9] (host: `Stats::status`). Within the
limits every index < 4 + 8·(4 096 + 16 384) < 2^24 (const-asserted): no wrap, no input trap; words past a truncated
batch read 0 (input-tree semantics, same on host) → kind 0 → BadAccount.
**Regression.** `engine-diff selftest` (explicit expectations, also kills shared-code mutants), `js/robust.js`
(14 cases incl. the MAX_ACCOUNTS×MAX_UNITS limit batch: guest halts normally and equals host).

## G2 (H) — output region collisions

Event log from OUT+13 unbounded; counters at OUT+0x1FFFB..0x1FFFF; roots from OUT+0x20000 (8 words/unit) up to the
RAM end = exactly 16 384 units. Upstream `BATCH_MAX_UNITS` = 200 000, so a legal upstream batch handed to the pilot
guest as one run traps at unit 16 384, and > ~18 700 units with fills (7 words each) overwrite the counter words and
the first roots (corrupted, ambiguous result). **Fix:** MAX_UNITS = 16 384 (G1), const-asserted
`13 + 7·MAX_UNITS ≤ 0x1FFF0` (a unit carries ≤ 1 fill), event writes bounded by `EV_CAP` with an overflow flag at
OUT[0x1FFF8] (never set within the limit). **Spec:** the layer-1 game must cut batches into segments of ≤ 16 384
units per guest run (docs §7.4).

## G4 (M) — INSURANCE_ACCOUNT as op author

The guest took account ids verbatim from the batch table; an all-zero id authors deposits/places as the insurance
fund. Upstream every op's account is its signer (`minuend_dag::op_signer`), an ed25519 pubkey hash, so the real
engine can never see that author; with signatures checked outside the guest (layer-1 / P-sig) a forged batch table
could otherwise trade the insurance fund inside the guest. **PoC:** `robust/insurance_author.bin` (account 0 replaced by the zero id): old guest
**53 applied** — the zero id's deposit and orders execute (first events `0x80000000`); new: those ops are
BadAccount (51 applied). **Fix:** `acct_of` filters `INSURANCE_ACCOUNT` → BadAccount; selftest asserts it.

## G5 (M) — abort semantics

Panic / OOM exited a0 = 77 leaving partial OUT words indistinguishable from a normal run. **Fix:** panic handler
writes `ST_ABORT = 0xFFFF0077` to OUT[0x1FFF9] before exiting; spec (§7.4): abort is a deterministic guest outcome;
the limits (MAX_UNITS, MAX_ACCOUNTS) plus the measured heap bound (≤ 19 MB of 48 MB at the cap) are what guarantee
that no batch the real engine accepts can abort the guest — the full guest must re-establish this bound for its
pre-state size (S1).

## S1 (M) — step bound

`Engine::place` scans every live order ~5× (43k + 170·L steps), and the journal clone adds O(level). Before G1 the
unit count was unbounded. With MAX_UNITS every live order was placed in this batch, so L ≤ 16 384: worst unit ≈
43k + 170·16 384 + 0.45 M (wit) ≈ 3.3 M steps, worst batch ≈ 16 384 × 3.3 M ≈ 5.4·10^10 < 2^40 (R ≤ 10, operator
cost ≤ 45 200 < 108 000). For the full guest with a loaded pre-state, L is bounded only by accounts × 64 → it needs a
global live-order cap or the running per-account totals (§7.2) to keep per-unit steps bounded; noted in §8.

## W1 (M) — proof verification rules underspecified

§7.3.3 described the fold but not: (a) the key must be DERIVED from the leaf text (kid = up to the 2nd ':' — 3rd for
`pos:` — or the whole string when there are fewer), never taken from the prover; (b) non-membership terminal leaf:
derived k' ≠ k AND k' shares the first d bits; (c) depth ≤ 256; (d) EMPTY = 32 zero bytes. Analysis: given the
~K1/~L1/~N1 domain separation and the key bound into the leaf hash, (a)+(k'≠k) are necessary; the prefix check is
redundant for an honestly built root (a forged terminal must equal the real subtree hash, i.e. a cross-domain
preimage) but cheap and kept. **Fix:** spec rewritten (§7.3.3), reference prover/verifier `smt_ref::{prove,
verify_member, verify_absent}`, `engine-diff proofs` (membership of every leaf, absence of random keys of every tag,
6 forgery families: absent-with-own-leaf, tampered text, truncated path, EMPTY at an occupied slot, fake member on an
absence path, swapped terminal) over real-engine per-unit leaf sets: 20 batches → 11 085 / 4 080 ok, **52 362
forgeries all rejected**, max depth 16 (300-batch run in l1-proofs.log). Mutants of the verifier rules are killed.

## W2 (M) — proof depth vs Oscript complexity

ocore `MAX_COMPLEXITY` = 100 and every `sha256` adds 1 (formula/validation.js); MNWIT1 nodes (`~N1:` prefix, key-bit
order) cannot use the constant-complexity `is_valid_merkle_proof`, so a verifier costs ≈ depth + 2 sha256 (+ anything
else the AA hashes). Honest depth ≈ log2(n) + 1–3 (21 at 2 311 leaves). Keys are hashes of grindable ids (order ids
via client_seq, account ids via pubkeys): ~2^b work puts a leaf b bits deeper on a victim's path; 2^48–2^50 sha256 (GPU
hours) → depth ≈ 60–70 for that victim. Above the AA's budget the victim's withdrawal / dispute proof is unverifiable
(DoS). Needed on the AA side (not in this spike): MAX_PROOF_DEPTH ≥ 96 with the rest of the AA's hashing budgeted, or
proof verification split over two triggers, or a wider node (16-ary halves depth). `sha256(x, 'hex')` IS supported by
ocore (evaluation.js: base64/hex/base32) — the open question in §7.3.3 is closed.

## W3 (L) — duplicate kid

`Smt::set` on an existing key overwrites; the from-scratch reference panics on duplicates. Kid uniqueness is an engine
invariant (e.g. `adrx:` relies on `check_aa_binding` 1:1). **Fix:** the guest's final from-scratch rebuild now also
checks `count == leaves put` (part of `scratch_ok`); spec says the real engine must assert it (debug) and the
from-scratch reference rejects duplicates. Not reachable with the pilot's leaf types (equivalent mutant).

## W4 (L) — level clone cost (real engine too)

The undo journal's first touch clones the whole level deque: O(level size) per unit for every node, not only the guest.
An attacker crowding one price makes every touch copy k·32 bytes (k ≤ accounts × 64). Not changed (the port must stay
verbatim); suggest journaling only the touched deque slots upstream.

## G6 (L) — embed stack/input overlap

`embed` (sail-only) maps the input at 0x0300_0000 and the stack grows down from 0x03F0_0000 into the same 15 MiB;
inputs ≥ ~15 MiB or deep recursion would collide. With G1's limits the input is ≤ 655 360 bytes and the deepest
recursion is the 256-level tree walk — no overlap. Documented.

## D0 — real engine ↔ port divergence: none found

Reviewed: wrapping/overflow (both release, no overflow-checks; signed div/rem overflow panics identically),
`usize` 32 vs 64 bit (only bounded counts), `HashMap`→`BTreeMap` (iteration only in order-independent folds; the
saturating sums cannot saturate within MARK_CAP×QTY_CAP), undo-journal rollback (book/account/market pre-images +
dirty noting on rollback), rejected units (seq not advanced, root still emitted). New edge-heavy generator
`engine-diff advfuzz` (zero/negative/i64::MIN/MAX deposits, prices 0/negative/MARK_CAP±, misaligned ticks, qty
0/1/QTY_CAP-1/i64::MAX/u64::MAX, client_seq gaps/repeats, foreign/stale/wrong-market cancels, isolated margins
0..4e9 USD, market GTC, two markets): **300/300 batches, 92 300 units identical** (hash, events, per-unit roots
real-scratch = port-incremental = port-scratch).

## DOC1 / DOC2 (L)

README §6 and design §7.3 step tables filled from `/data/hark/logs/rv/wit-bench-*.jsonl`; `FINALCOMMIT` in the notes
replaced; header comment corrected (isolated comes from kind 4/5).

---

## Fix status / tests

See `work/rv-rollup-notes.md` "loop round 1" for the commit hashes and the full test table.
