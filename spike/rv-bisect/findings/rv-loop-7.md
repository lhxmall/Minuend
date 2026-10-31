# rv loop round 7 — per-height timestamp binding (R6-M2), review of the whole guest (2026-10-31)

**Status: FINAL (closed in loop round 8, 2026-11-01 ~00:50 CST, branch spike/rv-bisect).** Rows marked *not reached* / "still running" are suite jobs that had not finished on the shared VM when the logs were collected; later rounds re-run the same checks on newer code.

Target: `lhxmall/Minuend` branch `spike/rv-bisect` @ db49ccb (loop round 6). Reference engine read only via
`git archive 20326c0` (engine-diff/engine-src); fix/47-all, main and PR #51 untouched.

Work items:

1. **R6-M2 implemented — a timestamp per rollup height, bound into s0.** rv_rollup `submit` takes `ts` (integer,
   `1 <= ts < 2^32`, `timestamp − TSLACK <= ts <= timestamp` with `TSLACK = 600` s, and for h > 1
   `ts >= t(h−1) + MINGAP`; `MINGAP` baked by mkrollup.js, env `RV_MINGAP`, default 60 s) and stores it
   (`var t<sid>`). s0 is now `sha256('0:' || x0..x9 = 0 || ',' || ts || ',' || x11..x31 = 0 || ':' || pmem || ':' || inp || ':0')`:
   the machine starts with register x10 (a0) = ts. The guest's `_start` leaves a0 untouched until `call rmain`, so
   `rmain(ts)` receives it without an input-format change and without a memory proof; the guest publishes it at
   `OUT[0x1FFE5]` (written first in every run, also dead / refused runs), so the final memory root commits it next to
   the engine height (`OUT[0x1FFE6]`) and the run counter (`OUT[0x1FFE7]`). Consequence: the engine clock (= height,
   R4-M4) can no longer outrun wall-clock time — over any interval, heights ≤ elapsed / MINGAP + 1, plus a one-off
   TSLACK / MINGAP (= 10) of backdating headroom.
2. **Traces / tests.** rolltrace.js `batch(.., {ts})`, `retime(tr, ts)` (in place) / `at(tr, ts)` (copy), `s0Of`,
   `regsTs`; rolltest.js picks `ts = max(C.ts − TSLACK, t(h−1) + MINGAP)` per submit (advancing the simulated clock
   only when the gap needs it) and re-times challenger / step-witness traces to the defended submission's ts; new group
   `ts` (23 checks). rolldevnet.js takes ts from the devnet clock (`wallet.getTime()`, follows timetravel) with
   `RV_MINGAP=1`. witproofe2e.js runs the real prod guest with a0 = ts and checks `OUT[0x1FFE5]`.
3. **Fresh adversarial review of the whole guest** (below): cross-module interactions (governance × liquidation ×
   oracle × snapshot), the code-19 caps as a griefing surface, segment boundaries, rv_rollup / rv_seg_ref /
   rv_witbind / rv_witproof with the new formats.
4. **Cross-module differential fuzz** `xfuzz` (engine-diff gov.rs `gov_build_x`): the govfuzz mix plus liquidations
   (any target, mostly market 1), slashes, collateral withdrawals and leveraged IOC trades (1–15 × 0.1 BTC) while
   proposals change im / mm / fees of the traded market and oracle reports move the mark — real vs port: hash, events,
   per-unit MNWIT1 roots, snapshot round trip, segment cut with export / import.
5. Quick + full suite (`loop7-suite.sh`), AA mutation test (`js/aamut-l7.py`), guest mutation subset
   (`loop7-mut.sh`).

Severity as in rounds 1–6: **C** = honest party loses / wrong verdict on reachable input; **H** = guest ≠ host,
undefined guest outcome, or a protocol-reachable state loss / halt; **M** = design/spec gap with a concrete failure
mode or a defense-in-depth hole; **L** = minor / documentation; **I** = checked, no defect.

Totals: **C 0 · H 0 · M 3 · L 5 · I 8** — R6-M2 and R7-M1 fixed, R7-M2 documented (needs fees per stored item).

| id | sev | area | title | status |
|---|---|---|---|---|
| R6-M2 | M | clock | the operator sets the clock's pace (R5-M2): heights can be submitted back to back | **fixed**: per-height ts in s0 (x10), TSLACK 600 s, MINGAP per height; rolltest `ts` 23/23, AA mutation 8/9 killed (1 equivalent until 2106) |
| R7-M1 | M | caps / griefing | the R6-H3 PERP-ledger cap is shared by GovDeposit / GovWithdraw / Slash, and a **GovWithdraw of 0 by an id without a ledger entry costs nothing** (succeeds upstream, R6-L3): 249 such units fill the ledger, after which every GovDeposit **and every Slash** by a new id is refused (code 19) — new stakers are locked out of governance and a misbehaving oracle can only be slashed by ids already in the ledger. Cheaper than R4-M6 (no deposit needed) and it disables a security function | **fixed**: GovWithdraw(0) by an id without a ledger entry is refused (code 19) at any ledger size, also as a Reveal's inner op; govedge case 8 (`r7:*`) + case 7 fills the ledger with real deposits and checks GovWithdraw(5) by a new id at the cap; harness mirror `pilot_gov_refused` (builder + `run_real_eng_h`) |
| R7-M2 | M | caps / griefing | commit cap (R6-H1, 1 024 live commits incl. revealed ones until TTL): any fresh id may commit (8 pending each), so ≈ 64 units per height keep the cap full and commit-reveal (MEV protection) unavailable to everyone; re-rated from R6-L4 because the cost is only unit fees and the effect is protocol-wide | documented: a per-id quota is bypassed by fresh ids; production needs a fee / deposit per stored commit or a stateless guest (R4-H1) |
| R7-L1 | L | clock | TSLACK lets the first heights after a quiet period be backdated: up to TSLACK / MINGAP (= 10) heights can be submitted at once; afterwards the pace is ≤ 1 / MINGAP | documented (bounded, one-off) |
| R7-L2 | L | clock | the guest does not check ts (no monotonicity in the guest; an upgrade image starts without the previous ts); the binding lives entirely in rv_rollup, which computes s0 itself | documented: the engine does not consume ts yet; a future time-based rule must read `OUT[0x1FFE5]` / rv_rollup `t<sid>` |
| R7-L3 | L | witness | MNWIT1 commits accounts, positions, orders, markets (`band:` / `meta:`) but not proposals, commits or gov nonces (as upstream `wit_leaves` @ 20326c0): rv_witproof cannot prove governance state | documented |
| R7-L4 | L | caps | `MAX_STATE_MARKETS` counts delisted markets (never removed): 255 listings (2.55 M PERP burned) block new listings for good | documented (R6-M1 pilot rule) |
| R7-L5 | L | tests | the round-4/5/6 suites ran `segguest` on the PROD image without `PROD=1` (the prod image returns a zero state hash by design, round 4 item c): a false "match 1/7" | loop7-suite fixed; prod segguest re-run with `PROD=1` (results table) |
| R7-I1 | I | AA input | does ocore's numeric-string cast let a non-canonical ts into s0? | no: trigger.data `'1e9'` / `'01000000000'` become the number 1000000000 and concatenate canonically; `' 1000000000'` / `'0x…'` are refused (rolltest `ts`) |
| R7-I2 | I | caps | does a Reveal bypass the caps or the depth rule through its inner op? | no: `state_cap_ok` and `wit_depth_ok` are checked for the inner op with the Reveal's author before dispatch (govedge `r7:reveal_inner_gwd0_fresh`) |
| R7-I3 | I | event log | does a liquidation emit more than one fill (event log bound `13 + 7·MAX_UNITS`)? | no: ADL runs only when the book IOC filled nothing and stops after one counterparty (one fill per unit) |
| R7-I4 | I | rv_witproof | does the kid rule cover the round-6 leaf kinds? | yes: `band:<m>` / `meta:<m>` have one ':' in the kid, the rule takes the text before the 2nd ':' |
| R7-I5 | I | games | does the bisection still start from the bound state? | yes: the referee games take s0 from the rollup record; a trace started with x10 = 0 differs at root 0 (rolltest `ts`), all 333 rolltest checks pass with re-timed traces |
| R7-I6 | I | voids | after a fraud void, is the new h's ts checked against h−1 (not the voided h)? | yes (rolltest `ts`: re-submitted h2 may carry a ts below the voided h2's) |
| R7-I7 | I | AA budget | do the ts checks fit ocore's limits? | rv_rollup complexity 69, ops 1 536 (< 2 000) |
| R7-I8 | I | cross-module | do gov × liq × oracle sequences diverge between port and real engine? | see `xfuzz` in the results table |

### Round-7 results (`scripts/loop7-suite.sh c`, build target-l7c-*, sha1 in `results-loop7/l7-bins.txt`; logs `guest-engine/results-loop7/`)

| check | result |
|---|---|
| govedge (host rebuilt with the round-8 test fixes, `l7d-host.log` in the notes) | 8 / 8 (first run 6 / 8: `cap:votes`, `r7:commit` = test bugs, R8-T1) |
| quick l7c-q: xfuzz 60, govfuzz 60, orafuzz 60, liqfuzz 30, hbind 30, snaptest 30, snapcap, capcheck 10, liqedge, fuzz 50, segfuzz 30, witfuzz 30, advfuzz 30, scen 47 | all green (xfuzz 60 / 60, 20 089 units incl. liquidations / slashes / withdraws / leveraged IOC) |
| fuzz 300 / advfuzz 300 / witfuzz 300 / segfuzz 300 | 300 / 300 each (12 621 segments) |
| proofs / scen host / selftest + depthsel / heapsim | 0 / 829 291 forged · 47 / 47 · clean · ≤ 19.2 MB |
| AA mutation (`js/aamut-l7.py`, ts rules) | 8 / 9 killed, 1 equivalent until 2106 |
| rolltest (round-7 AAs, sandbox ocore 0.4.8) | 333 / 333 incl. group `ts` 23 / 23 |
| rolldevnet (round-7 AAs, devnet clock ts, `l7rd.sh`) | 82 PASS / 0 FAIL at collection (2026-11-01 00:50 CST; still running, the round-4 devnet run has 149 checks) |
| prodheight.js on the round-7/8 prod image | 15 / 16 with the round-7 script (stale GovWithdraw(0) expectation, R8-T2) → 16 / 16 fixed |
| robust-limit, guest-poc, liq/snap/cap 300, JS-guest runs, sail, statecap | liq / snap / cap 300 still running at collection; robust-limit, guest-poc, JS-guest runs, sail, statecap *not reached* |

### Round-7 guest mutation subset (`scripts/loop7-mut.sh`, fail-fast; `l7-mut.log`; the first run is void: `l7-mut-invalid.log`)

| # | mutant | result |
|---|---|---|
| 1 | R7-M1 rule deleted (GovWithdraw(0) by a new id) | killed (govedge) |
| 2 | R7-M1 rule → ledger-size condition | killed (govedge) |
| 3 | GovWithdraw dropped from the shared ledger cap | killed (govedge) |
| 4 | Slash dropped from the shared ledger cap | **survived** every round-7 check → killed by the round-8 govedge `cap:perp_slash_new` (R8-T4) |
| 5 | inner-op `state_cap_ok` dropped | killed (govedge) |
| 6 | inner-op W2 depth check dropped | **survived** every check → R8-L4 (no test reaches a too-deep key through a reveal) |
| 7 | ADL one-fill rule dropped | killed (hbind) |
| 8 | vote cap: snapshot voters no longer exempt | killed (govedge) |

---

## R6-M2 — design as implemented

* **Where the value enters.** rv_rollup computes s0, so the operator cannot choose any other start state; the only
  freedom is ts itself, inside `[timestamp − TSLACK, timestamp]` and ≥ `t(h−1) + MINGAP`. `timestamp` is the AA's
  trigger time (the MCI timestamp of the trigger), so an honest operator posts `ts = now − a few seconds`.
* **Why a register.** No input-format change (the batch input tree is untouched), no memory proof, no change to
  rv_step / rv_game_ref / rv_seg_ref: the referee games already start from s0.
* **Voids and upgrades.** A re-submitted h after a fraud void is checked against `t(h−1)` of the live chain; an upgrade
  height is an ordinary height for the clock.
* **Tooling.** Every off-chain trace of a height must start with x10 = ts (rolltrace `regsTs`); a challenger that
  starts from zero registers disagrees at root 0 and loses its own game. Off-chain harnesses (robust / segguest /
  snapguest / witscen) keep ts = 0 (their memory is unchanged: `OUT[0x1FFE5]` = 0).

## R7-M1 — PoC (before the fix)

govedge case 7 of round 6 *was* the PoC: `GovWithdraw(11 + k, 0, 1)` for k = 0..249 all applied (fresh ids, no PERP),
the 250th was refused with code 19, and from then on `GovDeposit` / `Slash` by any new id returned 19. With the fix the
first such unit already returns 19 and the ledger size is unchanged (`r7:gwd0_fresh`, `r7:ledger_unchanged_by_refusals`);
a holder's GovWithdraw(0) still applies (`r7:gwd0_holder`, also for an exact-zero balance `r7:gwd0_zero_balance_holder`);
GovWithdraw(5) by a fresh id keeps the upstream rejection below the cap (`r7:gwd_pos_fresh`) and is refused 19 at
the cap (`cap:perp_gwd_new`).

## R7-M2 — commit cap griefing

`MAX_STATE_COMMITS = 1024` counts every live commit, revealed or not, until its TTL (≤ 16 heights). Upstream caps
pending commits per account (8), but ids are free, so 128 fresh ids fill the global cap; refilling costs ≈ 1 024 units
per 16 heights. Effect: every honest Commit is refused (code 19) while the spam lasts — MEV protection off for all.
Options for production: a refundable deposit per commit (returned at reveal / TTL), pruning revealed commits early
(changes the double-reveal error code vs upstream), or a stateless guest.
