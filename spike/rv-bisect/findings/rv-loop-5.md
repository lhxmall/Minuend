# rv loop round 5 — unit id input, engine height = rollup height, oracle stake / unstake / slash port, review of rounds 4–5 (2026-10-31)

**Status: FINAL (closed in loop round 8, 2026-11-01 ~00:50 CST, branch spike/rv-bisect).** Rows marked *not reached* / "still running" are suite jobs that had not finished on the shared VM when the logs were collected; later rounds re-run the same checks on newer code.

Target: `lhxmall/Minuend` branch `spike/rv-bisect` @ 4b039c2 (loop round 4 result + loop4-post.sh). Reference engine read
only via `git archive 20326c0` (engine-diff/engine-src); fix/47-all, main and PR #51 untouched.

Work items (round-4 open items):

1. **R4-M2 — unit id as guest input.** Batch format v2 `MNP2` = MNP1 + a unit-id table (n_ops × 8 words after the ops).
   The port passes the unit id to `liquidate` (`liq_order_id(unit id)`), so liquidation fills carry the real taker id and
   the event log is no longer masked. MNP1 keeps unit id 0 + `LIQ_TAKER_EV` (test fixtures); the `prod` image refuses an
   MNP1 `Liquidate` (BadAccount). Harness: the real engine reports every op's unit id (`Out::uids`), `to_v2` builds the
   MNP2 twin of a batch, `liqfuzz` runs every batch both ways, `liqgen … v2` writes MNP2 batches for the JS guest.
2. **R4-M4 — engine height bound to the rollup height**, without an rv_rollup change: a rollup height is exactly one
   guest run from the previous height's final memory, so a run counter in guest memory (`RUNS`, `.data`) *is* the rollup
   height. `Session::segs` follows it (synced every run; an import counts as a run and restores the count from the
   snapshot: export at h−1 → import at h). With height binding (`Session::bind_height`, always in `prod`) every batch run
   first runs the batch-commit hook (height = segs, prune withdrawals, release finished unbondings), so units of rollup
   height h see engine height h; `SetHeight` is refused. `OUT[0x1FFE6]` = engine height; `rv_witbind` additionally proves
   `OUT[0x1FFE7]` (segs) = h, so a bound segment root is the root of the run that knew it was height h.
3. **R4-L4** — `Accounts::oi_long / holders / dirty` are private (`oi_long_of`, `holders_of`, `mark_dirty`,
   `drain_dirty`).
4. **R4-M3 (partial) — oracle stake / unstake / slash ported** verbatim (`apply_stake`, `apply_unstake`, `apply_slash`,
   `prune_oracle_unbonding` in the batch-commit hook) with the PERP ledger (`perp_balances`, `perp_supply`,
   `perp_burned`, `oracle_unbonding`, `oracle_slash_nonce`): batch kinds 11 / 12 / 13, header fixture bit 27 (accounts
   4..=9 hold 2 × ORACLE_BOND_PERP; upstream gets there with GovDeposit, not ported). PERP-only ids get an `acct:` leaf
   like upstream (R8-C3); state hash section `MNPILOT3`; snapshot v2. New differential test `orafuzz` (real vs port +
   per-unit roots + snapshot round trip). Governance ops (listing, parameter proposals) and commit-reveal stay unported.
5. Fresh adversarial review of the round-4 and round-5 code (below), the round-5 suite and mutation test.

Severity as in rounds 1–4: **C** = honest party loses / wrong verdict on reachable input; **H** = guest ≠ host, undefined
guest outcome, or a protocol-reachable state loss / halt; **M** = design/spec gap with a concrete failure mode or a
defense-in-depth hole; **L** = minor / documentation; **I** = checked, no defect.

Totals: **C 0 · H 0 · M 2 · L 6 · I 6** (round-5 review) — plus the round-4 open items closed or reduced in this round:
R4-M2 fixed, R4-M4 fixed, R4-L4 fixed, R4-M3 partially ported. No real-engine ↔ port divergence (fuzz / advfuzz /
witfuzz / scen / segfuzz / liqfuzz incl. MNP2 / orafuzz / hbind all equal after the changes).

| id | sev | area | title | status |
|---|---|---|---|---|
| R4-M2 | M | port / liquidation | liquidation order id from unit id 0, taker masked in the event log | **fixed**: MNP2 unit-id table; `liqfuzz` runs every batch as MNP2 too (unmasked real vs port); `prod` refuses an MNP1 Liquidate (`prodheight.js`) |
| R4-M4 | M | height binding | engine height not bound to the rollup height (operator decides whether a segment carries SetHeight) | **fixed**: guest run counter = rollup height, batch-commit hook at every batch run (prod), SetHeight refused; `rv_witbind` proves OUT segs == h; `hbind` + `prodheight.js` |
| R4-L4 | L | Accounts guard | derived index fields `pub` | **fixed**: private, read accessors |
| R4-M3 | M | port coverage | oracle stake / unstake / slash, governance, commit-reveal not ported | **partially fixed**: stake / unstake / slash + PERP ledger + unbonding release ported and differential-tested (`orafuzz`); GovDeposit (PERP comes from a fixture), governance ops and commit-reveal still open |
| R5-M1 | M | rv_rollup / upgrade | re-scheduling an upgrade at an earlier height left the later `U<h'>` in place: height h' would again start from the old image, whose compiled-in import digest can never equal the new export at h'−1, so h' never finalizes (rollup halt until governance notices and re-schedules h' as well) | **fixed**: at most one pending upgrade (`uh`); re-scheduling at the same or an earlier height clears the old `U<uh>`; a later upgrade is refused while one is pending. rolltest `upgrade` +6 checks (33 / 33) |
| R5-M2 | M | design / clock | with R4-M4 the engine clock is the rollup height — and the operator still sets the pace: heights can be submitted back to back (each locks OBOND for the 24 h window, nothing enforces spacing), so feeds can be aged past the 32-height staleness in minutes and a 14 400-height funding-peg interval costs 14 400 × OBOND locked for a day | documented (same trust as upstream, where the sequencer's batch cadence is the clock); options: minimum wall-clock spacing per height in rv_rollup, or a timestamp per height bound into the input and checked by the guest |
| R5-L1 | L | MNP2 | unit ids are operator input, not checked against the unit (the pilot verifies no signatures: the whole op table is operator input until a DA / signature layer exists); a zero or duplicated id only changes the id of an IOC liquidation order, which is never stored | documented |
| R5-L2 | L | upgrade | upgrades at h and h+1 cannot both finalize (h+1 needs an export at h, which is an import run) | documented; with R5-M1 a second upgrade waits until the first is finalized anyway |
| R5-L3 | L | heap bound | PERP-only ids (a slash reward to a fresh challenger) are outside the account cap | documented: bounded today (≤ one new id per successful slash, ≤ bonds ever created; no GovDeposit port); production with GovDeposit must count them |
| R5-L4 | L | height hook | the batch-commit hook ran before the start root but its effects (an unbonding release changes an `acct:` leaf) reached a root only with the next unit: the end root of an empty segment — the `W<h>` rv_witbind binds — showed the pre-release PERP balance | **fixed**: the witness is committed right after the hook; `hbind` checks end root == scratch root for every segment incl. empty ones |
| R5-L5 | L | height semantics | upstream units of batch N run at height N−1 (hook at commit); the pilot's units of rollup height h run at engine height h (hook at segment start) | documented: a constant offset, identical in port and harness |
| R5-L6 | L | tests | round-4 mutation survivors (see the round-4 table): equivalent 11, 21, 23, 24; reachable but not killed 35 (liquidatable boundary), 37 (ADL counterparty with negative collateral), 52 (host reference absence check) | 4, 5, 6, 10, 13, 15, 17, 18, 27, 32 now killed (9: NOT killed -- equivalent, corrected in round 8 R8-T3) (liqedge incl. new `wd_equity`, capcheck fire rule, snaptest trailing word, snapcap, segfuzz segs check); see the round-5 mutation table |
| R5-I1 | I | run counter | does RUNS stay equal to the rollup height through refused headers, exports, imports, NEED_IMPORT runs and a refused first header? | yes: `prodheight.js` (export jump, refused header counts, fresh image genesis at height 2) and `snapguest` (import = run) |
| R5-I2 | I | segment chain | does the hook break start(h) = end(h−1)? | no: the start root is taken before the hook; `segfuzz` / `hbind` |
| R5-I3 | I | MNP2 bounds | can the unit-id table index reach the input trap range? | no: 4 + 8·(MAX_ACCOUNTS + 2·MAX_UNITS) < 2^24 (const assert); a truncated table reads 0 |
| R5-I4 | I | slash port | does the port match upstream on stake / unstake / slash / release, incl. PERP-only `acct:` leaves? | yes: `orafuzz` (hash, events, per-unit roots, snapshot v2 round trip) |
| R5-I5 | I | R4-L4 | any writer of the indexes outside the guard? | no: the fields are private now (compiler-enforced) |
| R5-I6 | I | witbind × import | is an upgrade height still bindable with the counter proof? | yes: the import run sets segs = h (export h−1 + 1) |

---

## R5-M1 (M) — stale upgrade image after re-scheduling (PoC + fix)

PoC (rolltest `upgrade`, old rv_rollup): heights 1..3 live, governance `upgrade 4` (U4 = image A, top = 3), then
governance `upgrade 3` (U3 = image B, top = 2). U4 is still set. After the import at 3 from B, the honest operator submits
height 4 chained on m(3): `bad s0` — rv_rollup insists that s0(4) starts from U4 = image A. The only accepted height-4
submission runs image A, an upgrade image that refuses every batch until it imports, and whose compiled-in digest names
the export governance chose for the *first* schedule: the export at height 3 can no longer produce it, so height 4 never
finalizes and every height above it waits. Nothing in the AA tells governance that a stale U4 exists.

Fix: `var uh` = the one pending upgrade height. `upgrade h` requires `uh <= lf` (nothing pending) or `h <= uh`; when it
replaces a pending one at another height it clears `U<uh>`. Checks: "upgrade height 4 scheduled", "re-scheduled earlier
at height 3", "the stale U4 is cleared", "height 4 chains on m(3)", "a second upgrade above the pending one refused".

## R5-M2 (M) — the operator sets the clock's pace

R4-M4 removes the operator's *choice* (the engine height is now exactly the rollup height), not its *pace*. rv_rollup
lets height h+1 be submitted as soon as h is (each submission chains on the previous final root, finalization comes
later), so an operator — or a coalition of operators racing honestly — can advance the engine clock as fast as it can
post units, paying only OBOND per height, locked for one window. Effects: external funding prints go stale after 32
heights, a funding peg interval is 14 400 heights, the withdrawal replay window 2 048 heights, unbonding 256 heights.
Upstream has the same property (batches are its only clock). Recommendation for a production design: bind a timestamp
per height (rv_rollup `timestamp` at submit, carried into the input and checked by the guest), or enforce a minimum
spacing between submissions.

## R5-L4 (L) — hook effects in empty segments

With the oracle port the batch-commit hook can change committed state (an unbonding that ends returns its bond to the
reporter's PERP balance: its `acct:` leaf). The hook ran before the first unit, the MNWIT1 tree was committed only after
units, so a height whose batch had no unit ended with end root = start root while the state had changed. Fix: commit
right after the hook (the start root is still taken before it, so start(h) = end(h−1) holds). `hbind` now inserts empty
segments and checks every segment's end root against a from-scratch root of the port state.

## R4-M2 — MNP2

```
MNP2 = MAGIC2 "MNP2" | n_accounts | n_ops | flags | accounts (8 words each) | ops (8 words each) | unit ids (8 words each)
```

The unit id is read only by `Liquidate` (`liq_order_id(uid)`: the IOC order's id, which appears as the taker id of the
fill in the event log). The real-engine harness signs every op as a unit in a linear chain; its unit ids are the ones
`to_v2` writes, and `run_real_eng_h` asserts the table entries equal them. `liqfuzz`: every seed is compared as MNP1
(masked) and as MNP2 (unmasked), plus state hash MNP1 == MNP2 (the id is not state).

## R4-M4 — engine height = rollup height

```
guest run (main.rs)      RUNS += 1 (unless dead); a live session's segs := RUNS - 1, the run adds 1
batch run, bind_height   hook(height := segs, prune withdrawals, release unbondings) before the first unit
SetHeight (kind 10)      refused when bind_height (always in prod); test images keep fixture jumps
export run               segs += 1 (the snapshot carries it), height unchanged
import run               segs := snapshot segs + 1, RUNS := segs (export at h-1, import at h)
OUT[0x1FFE6]             engine height (low word); OUT[0x1FFE7] = segs
rv_witbind bind h        + memory proof OUT[0x1FFE7] == h (hsib)
```

No rv_rollup change is needed for the binding itself: rv_rollup already forces s0(h) to start from the final memory of
h−1 (or from governance's `U<h>`), so the count in memory can only be the number of heights since genesis (or since the
upgrade's export, whose count the import restores and the xbind digest check pins).

## R4-M3 (partial) — oracle stake / unstake / slash

Ported verbatim from minuend-state (`apply_stake`, `apply_unstake`, `apply_slash`, `prune_oracle_unbonding`) and
minuend-exec (`stake_oracle`, `unstake_oracle`, `slash_oracle`, error mapping). The PERP ledger is new port state; every
write marks the id's MNWIT1 key dirty (`ChainState::set_perp`); an id holding only PERP gets `acct:<id>:0:<perp>:<w>`
like upstream R8-C3. The W2 depth rule pre-checks the challenger's `acct:` key for a Slash (the reward may create it).
Not ported: GovDeposit / GovWithdraw (PERP comes from the header fixture bit 27), CreateMarket / proposals / votes,
Commit / Reveal.

---

### Round-5 results (`scripts/loop5-suite.sh c`, InstaBox VM, build target-l5c-*, sha1 in `results-loop5/l5-bins.txt`; logs `guest-engine/results-loop5/`)

Status at the end of the session (loop round 8, 2026-11-01 ~00:40 CST): the round-5 suite ran from 12:36 UTC at load
25–35 on 4 vCPU next to the round-4/6/7 jobs and was reniced to 19 once the round-7/8 code superseded it; the rows marked
*not reached* had not run when the logs were collected (their round-7/8 counterparts are in the round-7/8 tables).

| check | result |
|---|---|
| quick (l5c-q3: orafuzz 100, liqfuzz 30, hbind 30, snaptest 30, snapcap, capcheck 10, liqedge, fuzz 50, segfuzz 30, witfuzz 30, advfuzz 30, scen) | all green (orafuzz 100 / 100, 116 683 units) |
| fuzz 300 × 300 / advfuzz 300 / witfuzz 300 | 300 / 300 · 300 / 300 · 300 / 300 |
| segfuzz 300 | 300 / 300 (12 621 segments) |
| proofs (host reference) | 177 087 membership, 61 540 absence ok, 0 / 829 291 forged |
| scen upstream.scn (host) | 47 / 47 |
| selftest / depthsel (64, 8) | clean |
| heapsim (crowd / gen / adv / frag / limit) | ≤ 19.2 MB (crowdmax) < 50.2 MB |
| robust-limit (16 384-unit limit batch through the JS guest) | 1 / 1 match (370 M steps) |
| rolltest upgrade group / witproof group (round-5 AAs) | 33 / 33 · 19 / 19 |
| segguest small, PROD image with `PROD=1` (own seg-small: genbig 7 300, segrun 90; `sg56.sh`) | **7 / 7 match** |
| liqfuzz 300 / snaptest 300 / capcheck / orafuzz 300 / hbind 300 / statecap, guest-poc, JS-guest scen / extra / robust / depth8, snapimg, segrun / segbig, sail, rolltest full, rolldevnet | *not reached* (suite still running at collection) |

### Round-5 mutation test (`scripts/loop5-mut.sh` → killed by load and restarted fail-fast as `loop5-mutff.sh`; `l5-mut.log`, `l5-mutff.log`)

| # | mutant | result |
|---|---|---|
| 4, 5 | pending `>`, min-withdraw `<=` | killed (liqedge) |
| 6, 10, 13 | withdraw equity `<=`, staleness `>=`, prune `>=` | killed (liqedge) |
| 15 | capcheck fire rule | killed (capcheck) |
| 9 | ADL last share | **survived** → equivalent under one fill per liquidation (R8-T3) |
| 11 | TWAP min samples | survived → equivalent (`external_twap` unreachable, round 4) |
| 17 … 79 | rest of the list | *not reached* (fail-fast run still going at collection) |
