# rv loop round 3 — attack → fix on the RISC-V guest engine, MNWIT1, segments and the layer-1 game (2026-10-31)

Target: `lhxmall/Minuend` branch `spike/rv-bisect` @ d78003a (loop round 2 result). Reference engine read only via
`git archive 20326c0` (engine-diff/engine-src); fix/47-all, main and PR #51 untouched. This round did four work items
(commits below) and then reviewed everything they changed:

1. **S1b** — price level = arrival-ordered map (`BTreeMap<u64 arrival, OrderId>` + `arr: id → arrival`), so `cancel`
   is O(log n); funding open interest's account sum = running per-market total (`ChainState::oi_long`). No result
   changes vs the real engine.
2. **Production guest hardening** — header flags must be 0 (feature `prod`, and always on a resumed session; status
   4), `.bss` zeroed in `_start`, and **segments**: an upstream batch (≤ 200 000 units) is cut into guest runs of
   ≤ 16 384 units, one run = one rollup height, the engine state persists in guest memory from run to run
   (`mnpilot::Session`), and every run publishes its **segment boundary commitment** = MNWIT1 root before its first unit
   (OUT[0x1FFF0..8]) and after its last unit (OUT[0x1FFE8..8]); segment k starts where k−1 ended.
3. **Layer-1 game** — new referee `rv_seg_ref` (K = 16 bisection over the run's unit-boundary machine roots, then the
   existing instruction game `rv_game_ref` on the one unit left); `rv_rollup` gets `units` per submission and a
   `uopen` command; the depth-64 SMT verifier of round 2 is wired to finalized heights through `rv_witbind` (binds the
   height's segment end root from its final memory) and `rv_witproof` (membership / absence proofs).
4. This review (below), fixes for every C/H and the cheap M/L.

**Final (loop round 4 verification, 2026-10-31):** the whole round-3 suite re-ran green on the round-3 head (table at the end); mutation 34 / 44 (survivors analysed at the end). Follow-ups moved to `findings/rv-loop-4.md`: R3-H2 (dead session → upgrade path, now R4-S1/S2 + rv_rollup upgrade), R3-O1 (fixed by construction), and the 256-account heap bound (R4-H1).

Severity as in rounds 1–2: **C** = honest party loses / wrong verdict on reachable input; **H** = guest ≠ host or
undefined guest outcome on protocol-reachable input; **M** = design/spec gap with a concrete failure mode or a
defense-in-depth hole; **L** = minor / documentation; **I** = checked, no defect.

Totals: **C 0 · H 0 · M 3 · L 9 · I 6**. No real-engine ↔ port divergence (fuzz / advfuzz / witfuzz / scen / segfuzz
all equal after the changes).

| id | sev | area | title | status |
|---|---|---|---|---|
| R3-G1 | M | guest / segments | a run that **traps** (not panics) leaves the session "moved out": `rmain` unboxes `SESS` at entry, so the next height resumes from a freed box (use-after-free; deterministic but torn state) | fixed: `IN_RUN` flag in `.data`; a run that did not reach the clean exit kills the session (ST_DEAD = 5 forever) |
| R3-G2 | M | guest / rv_witbind | a trapped run leaves the PREVIOUS run's status 0 and segment end root in OUT → `rv_witbind` would bind height h−1's root as height h's | fixed: OUT status = 0xFFFF0001 ("running") and both segment roots = 0 until the clean exit rewrites them |
| R3-L1 | M | rv_seg_ref | layer-2 slot keyed by the opener's ref: anyone can open a seg game under the same ref (itself as opener) and make the honest hand-off bounce (`game exists` at rv_game_ref) → the honest picker times out | fixed before the first commit: slot = `sha256(opener ‖ ref)`; test `l1edges` front-run |
| R3-W1 | L | rv_witproof | an absence could be recorded under a non-canonical key name (only the first 16 hex chars feed the path): `A<h>:<key with upper-case tail>`, which a consumer that normalizes its input reads as the real key | fixed: full 64-char lowercase-hex check; PoC: old AA accepted 12/12, new refuses 12/12 |
| R3-W2 | L | AA (ocore) | `$T = trigger.data` with a ~10 KB proof object fails (`local_var_assignment: resulting object is too big`) | fixed: proof AAs read `trigger.data` in place (rule for every future proof AA) |
| R3-W3 | L | AA budget | bind (9 memory proofs + base64 encode) + verifier in one AA = 2 935 ops > 2 000 | split into `rv_witbind` (15 / 1 406) and `rv_witproof` (69 / 1 604) |
| R3-W4 | L | rv_witbind / rv_witproof | both kept the whole ≥ 10 000-byte trigger | fixed: refund trigger − MK (2 000), as rv_game_ref moves |
| R3-S1 | L | S1b heap | a `BTreeMap` per price level costs more than a `VecDeque` for small levels | measured (heapsim, 64-bit): crowdmax 20.16 → 22.43 MB, frag 4.08 → 5.96 MB, limit 4.31 → 4.40 MB; worst = 45 % of the 50.2 MB heap |
| R3-O1 | L | S1b OI | `oi_long` is kept current only by `put_account` / `del_account`; `ChainState::accounts` / `account_mut` stay `pub`, so a future path that edits positions in place desyncs silently (host runs assert `oi_ok` after every unit). Funding-rate markets are not in the pilot: the OI read path is not differential-tested (mutant "OI = 0" survives) | documented; port liquidate/ADL must use `put_account` |
| R3-H1 | L | prod image | `prod` is a cargo feature, not the default (test fixtures use header flags): the rollup's committed image (GENMEM) must be the `prod` build | documented |
| R3-H2 | L | segments | after an abort or trap the session is dead for good (status 5 on every later height): the rollup needs a guest-upgrade / migration path | documented (design §7.6) |
| R3-H3 | L | segments | OUT words survive across runs (per-unit roots past this run's unit count are the previous run's) | documented: readers use the unit counter OUT[0x1FFFF] (reset at run start); rv_witbind reads only the fixed slots rewritten every run |
| R3-T1 | L | harness | `segrun` on a 40 000-unit batch was OOM-killed on the 8 GB box (real engine + per-unit from-scratch root / hash) | harness only; 20 000-unit batch used (S = 16 384 and 5 000) |
| R3-L2 | I | layer 1 | soundness with operator-chosen boundaries | every point is a claim about the one trace (state after `step` steps), so an interval with a true start and a false end always exists; `l1bnd` 4/4 (random increasing boundaries, honest and fraudulent) |
| R3-L3 | I | rv_rollup | can a result from one referee settle a game opened with the other? | no: rv_rollup opens SEG games only via `uopen` (ref = its trigger unit), GAME games only via `open`; both referees key games by opener ‖ ref |
| R3-L4 | I | rv_seg_ref | solvency | keeps GF per game + MK − refund-unit fee per move, pays its response units; devnet balance after 2 games 23 701 |
| R3-S2 | I | S1b | duplicate / ghost ids in a level (would break the id → arrival index) | unreachable (ids = hash(account, market, client_seq), client_seq = last + 1; every cancel / pop removes the entry); `level_ok` asserted after every unit in fuzz / witfuzz / advfuzz / segfuzz |
| R3-B1 | I | guest | `.bss` zeroing vs state that must survive a run | every persistent static is in `.data` (`.data.alloc`, `.data.sess`); segment runs resume correctly with the zeroing in place |
| R3-U1 | I | rv_rollup | `units` is an unverified operator claim | by design: it only picks the layer-1 partition; U = 1 degenerates to the instruction game, and a challenger may always use `open` instead of `uopen` |

---

## Work item 1 — S1b (cancel O(log n), running OI)

`OrderBook` level: `VecDeque<OrderId>` → `Level = BTreeMap<u64, OrderId>` keyed by a per-book arrival counter
(`next_arr`), plus `arr: BTreeMap<OrderId, u64>` for exactly the ids present in a level. Iteration order = arrival
order = the deque's FIFO order, so matching, `commitment_bytes` (iterates `values()`), `first_maker_qty` and every
event are unchanged. Three primitives keep `arr` in lockstep: `lvl_pop_front` (pop_first + arr remove), `lvl_put`
(insert with a given arrival, used by enqueue and rollback) and `cancel` (arr lookup → level remove). The undo journal
records popped `(arrival, id)` pairs and the pushed count; rollback pops the last `pushed` entries, re-inserts the
popped ones under their original arrival numbers, drops a level that did not exist, and restores `next_arr`.
`ChainState::oi_long` = Σ positive qty per market, maintained by `put_account` / `del_account` (the only paths that
replace an account's positions: `apply_fill_pair`, journal rollback, deposit, genesis); `Engine::funding_open_interest`
reads it instead of iterating all accounts.

Measured (JS guest model, per-unit steps of the cancel units at the end of `engine-diff crowdc`, cancels in the middle
of one crowded level; old = round-2 binary, new = this round):

| batch (orders at one price) | old cancel units (steps) | new cancel units (steps) |
|---|---|---|
| crowdc256 (256) | 96 537 – 126 966 | 91 890 – 122 748 |
| crowdc4k (4 096) | 233 524 – 263 966 | 123 804 – 155 336 |
| crowdcmax (16 128, the MAX_UNITS cap) | run stopped (CPU; > 2 h in the JS model) | `l3-s1b-max-new.log` if it finished (loop 4 kept it running), else extrapolated: flat in the level length (crowdc256 → crowdc4k barely moves) |

(The remaining per-cancel cost is the MNWIT1 commit of the touched leaves, ~90 k steps; the level scan was ~35 steps per
order ahead of the cancelled one.)

## Work item 2 — production guest, segments

* `check_header_seg`: flags (word 3) ≠ 0 → `ST_BAD_FLAGS` (4) under feature `prod` and on any resumed session.
* `_start` zeroes `.bss` (`la`/`sw` loop, word-aligned bounds in link.x). Allocator state and the session pointer moved
  to `.data` so they survive.
* `mnpilot::Session {eng, w, mode, segs}`; `run_segment(rd, ev, unit, mode, &mut Option<Session>)` (None = genesis
  with the header's flags); `run_batch_wit` = one segment on a fresh session (all earlier tools unchanged).
* Guest: `SESS` (leaked Box) + `DEAD` + `IN_RUN` in `.data`; OUT[0x1FFF0..8] start root, OUT[0x1FFE8..8] end root,
  OUT[0x1FFE7] segments run; the event log cap moved to 0x1FFE0 − 13 (still ≥ 7 × MAX_UNITS + 13).
* Segment boundary commitment (design §7.6): `start_root(k) == end_root(k−1)`, `start_root(0)` = genesis root;
  `engine-diff segrun` / `segfuzz` check it against the REAL engine run over the whole upstream batch (per-unit roots,
  events, state hash at every segment end), including a refused-header segment in the middle (status 4, no op, session
  unchanged); `js/segguest.js` runs the segments through the guest on ONE memory image (pc 0, registers 0, new input
  each run), as rv_rollup chains s0(h) on the final memory of h−1.

## Work item 3 — layer-1 game, SMT verifier wiring

**rv_seg_ref** (`aa/rv_seg_ref.oscript`, complexity 18 / ops 1 443). Game record
`ref:d:c:lo:hi:slo:shi:rlo:rhi:turn:deadline` (unit indices lo/hi, step indices slo/shi, machine roots). `mids`: the
defender posts `cnt` (≤ 15) points `(step, root)`, steps strictly increasing inside (slo, shi) (one `reduce`); `pick`:
the challenger names the first interval it disputes; when one unit is left the referee opens `rv_game_ref` with
`{open: sha256(gid), s0: rlo, sN: rhi, n: shi − slo}` (turn `x`), and the instruction game's result comes back as a
callback that settles the seg game and is forwarded to the opener. Timeouts as in rv_game_ref (the side to move
loses). The opener pays 2 GF (its callback + the layer-2 game); in rv_rollup a `uopen` costs CBOND + GF, payouts are
the same as for `open`.

**Why the points are (step, machine root) and not MNWIT1 roots.** The terminal must hand a well-defined instruction
range to rv_game_ref; a MNWIT1 root alone does not say which machine state it belongs to, and binding a per-unit input
(pre-root + op + leaf bundle) would need an input-tree proof per word. A machine root at a unit boundary commits the
guest's memory, which contains that unit's MNWIT1 root (OUT+0x20000 + 8u), so the per-unit witness is carried along.
Off-chain gain: the full per-step memory Merkle roots are needed for one unit (~10^5–3·10^6 steps) instead of the whole
segment (up to ~5·10^10).

**rv_witbind / rv_witproof.** `bind {h, words, wsib, ssib}`: h finalized; 8 memory proofs of the end-root words at
OUT[0x1FFE8..8] and one of status 0 at OUT[0x1FFF9] against the height's final memory root (rv_rollup `m<sid>`);
stores `W<h>` (base64 of the 8 LE words). `prove {h, leaf, sib, key?}`: the round-2 verifier (D = 64, kid via
index_of/substring) against `W<h>`; records `L<h>:<kid> = leaf` or `A<h>:<key> = 1` for a vault / bridge AA.

Static cost (ocore 0.4.8 validator; limits 100 / 2 000): rv_step 10 / 1 850, rv_game_ref 10 / 848, **rv_seg_ref
18 / 1 443**, rv_rollup 42 / 750 → **44 / 829**, **rv_witbind 15 / 1 406**, **rv_witproof 69 / 1 604**.

Devnet unit sizes (headers + payload, bytes): uopen 884, seg mids avg 1 419 / max 1 705, seg pick 924, layer-2 resolve
(3 AA responses) 918 + tps up to 7 965, bind 10 428 (9 × 24 siblings), prove 1 211 avg / 1 305 max.

---

## R3-G1 / R3-G2 (M) — a trapped run

`rmain` moves the session out of its box at entry (`Box::from_raw`) and boxes it again at the clean exit. A panic set
`DEAD`, but a **trap** (illegal instruction, misaligned access — unreachable in correct code, but the rollup carries
the trapped memory into the next height) did neither: the next run unboxed `SESS` again from freed memory. And the
trapped run left OUT exactly as the previous run wrote it: status 0 and the previous end root.

PoC (`TRAP=1:5000000 node js/segguest.js <elf> seg-small`: segment 1 stopped after 5 M steps as if it trapped):
round-3 pre-fix build (target-l3c): trapped segment shows **status 0, end root = segment 0's end root** (bindable as
height 2's root); segment 2 (refused header) status 4; segment 3 resumes from the freed box and **aborts (a0 = 77)**.
Fixed build (target-l3d): trapped segment shows status 0xFFFF0001 and zero roots; every later segment status 5,
nothing executed. (`results-loop3/l3-trap-old.log`, `l3-trap-new.log`.)

## R3-L1 (M) — layer-2 slot front-running

rv_game_ref keys games by `opener ‖ ref`; the first rv_seg_ref draft passed the opener's own ref through, so every seg
game of every opener used the slot `SEG ‖ ref`. A stranger who sees the rollup's open unit can open its own seg game
with `uopen = that ref` (itself as opener, any players): its hand-off occupies `SEG ‖ ref` first and the honest
game's hand-off bounces → the honest challenger's pick bounces until it times out. Fixed in the design before the first
commit (slot `SEG ‖ sha256(opener ‖ ref)`); `rolltest l1edges` opens the front-running game and checks that the honest
hand-off still happens.

## R3-W1 … W4 (L) — see table.

---

## Fix status / tests

Commits on `spike/rv-bisect` (parent d78003a): f58a491 (S1b), 8ad4d5e + fa91c12 (segments, prod guest, layer 1,
witbind/witproof), 7b8daf8 (review fixes G1/G2/W1, scripts), and the results commit (`guest-engine/results-loop3/`).

### Round-3 suite (`guest-engine/results-loop3/`, run by `scripts/loop3-suite.sh` on the InstaBox VM, build target-l3d)

| check | result |
|---|---|
| fuzz 300 × 300 (real engine vs port: hash + events) | 300 / 300 |
| witfuzz 300 (per-unit MNWIT1 roots: real-scratch / port-incremental / port-scratch) | 300 / 300 |
| advfuzz 300 (adversarial batches) | 300 / 300 |
| segfuzz 300 (segment chaining vs the real engine, refused-header segments included) | 300 / 300 (12 621 segments) |
| proofs (membership / absence vs the host reference) | 177 087 membership, 61 540 absence ok, 0 forged |
| scen upstream.scn (host) / guest | 47 / 47 · 47 / 47 |
| selftest / depthsel | clean |
| depth8 (MAX_WIT_DEPTH = 8 build) host / guest | 20 / 20 |
| prodflags (prod image refuses header flags) | ok |
| segrun 300 / 3 000-unit batches | ok |
| segguest small (default + prod image) / big3k | 7 / 7 · 5 / 5 |
| segbig 20 000 units | segrun OOM-killed (harness, R3-T1) → segbig-adv 25 012 units ok |
| extra-guest | 9 / 9 |
| robust 15 / 15 + limit batch through the JS guest | ok (1.219 G steps) |
| guest-poc (crowd1800, frag16, grind1any) | 3 / 3 |
| witproof e2e (bind + prove through the guest's real OUT layout) | 8 / 8 |
| sail-riscv spot check (incl. adv21, crowdc256) | 6 / 6 |
| rolltest (rv_rollup + referees + witbind/witproof, real ocore evaluator) | 277 / 277 |
| rolldevnet (devnet, 10 sections) | 149 / 149 |
| Oscript verifier (synthetic + real proofs) | 36 / 36 + 12 / 12, 0 / 156 forged |
| AA static cost | see "Static cost" above |
| trap PoC (R3-G1/G2) old / new build | old: status 0 + previous root, later abort; new: 0xFFFF0001 + zero roots, then status 5 |

### Round-3 mutation test (`scripts/loop3-mut.sh`, `results-loop3/l3-mut.log`)

**34 / 44 killed.** The 10 survivors and what became of them in loop round 4:

| # | mutant | why it survived | loop 4 |
|---|---|---|---|
| 3 | journal does not restore `next_arr` | arrival numbers only order entries inside a level; a gap after a rollback does not change the order | equivalent (order-preserving); kept in the round-4 list |
| 5 | deposit inserts the account without `put_account` (OI index not updated) | deposit never changes positions, so the OI index stays right | removed by construction (R3-O1 fix: `Accounts` keeps the indexes on every insert) |
| 7 | funding OI = 0 | no funding-rate market in the round-3 batches (R3-O1) | **killed by liqfuzz** (29 / 30) in round 4 |
| 10 | `segs` not incremented | the segment counter is published but no check read it | re-tested in round 4 (snapshot carries `segs`) |
| 15 | report band `dev < old/10` | no ReportPrice in round 3 | ReportPrice ported in round 4; re-tested |
| 18 | liquidatable `<` instead of `<=` | no Liquidate in round 3 | Liquidate ported; re-tested |
| 20 | ADL `collateral.max(0)` dropped | no liquidation / ADL in round 3 | ported; re-tested |
| 35 | smt_ref absence check without `k2 == k` | the other disjunct already rejects every forged absence the generator produces | proof generator gap, documented |
| 38 / 39 | journal rollback replays popped entries in the wrong order / not the pushed count | a rollback after a partially filled book walk is rare in random batches | re-tested in round 4 (liqfuzz rolls back liquidation book paths) |

