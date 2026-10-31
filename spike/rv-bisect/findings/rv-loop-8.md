# rv loop round 8 — round-7 completion, commit bond (R7-M2), R7-L3 / R7-L4, review (2026-10-31)

**Status: FINAL (closed in loop round 8, 2026-11-01 ~00:50 CST, branch spike/rv-bisect).** Rows marked *not reached* / "still running" are suite jobs that had not finished on the shared VM when the logs were collected; later rounds re-run the same checks on newer code.

Target: `lhxmall/Minuend` branch `spike/rv-bisect` @ e3cfbf9 (loop round 7). Reference engine read only via
`git archive 20326c0` (engine-diff/engine-src); fix/47-all, main and PR #51 untouched.

Work items:

1. **Round-7 test failures resolved.** govedge on the round-7 host failed `cap:votes` and `r7:commit`. Both were
   **test bugs**, the port was right:
   * `r7:commit` committed with ttl 120 at engine height 0; upstream (and the port) allow `ttl <= height + 16`
     (`COMMIT_TTL_HEIGHTS`) → BadCommit (17). ttl 5 now.
   * `cap:votes` computed the zero-voter cap (`snapshot + MAX_ZERO_VOTERS`) from the **real** engine's weight snapshot.
     The real engine has no caps, so its PERP ledger also holds the id whose gov deposit the port's ledger cap refused
     one step earlier (`cap:perp`): 257 snapshot entries instead of the port's 256, and the port's cap (correctly) fired
     one vote earlier than the test expected. The test now counts the port's snapshot (the real one minus that id).
   The first round-7 guest mutation run had used the failing govedge as its first fail-fast check, so its "KILLED by
   govedge" verdicts were meaningless; it was discarded (`results-loop7/l7-mut-invalid.log`) and re-run.
2. **R7-M2 fixed (PILOT rule): a bond per live commit.** See below.
3. **R7-L3** (governance state not in MNWIT1) — kept as documented, with the design for a later round (below).
4. **R7-L4** (market cap counts delisted markets) — accepted pilot limit, rationale in `state_cap_ok`.
5. Fresh adversarial review of the round-8 rule and its interaction with the round-6/7 caps (table).

Severity as in rounds 1–7: **C** = honest party loses / wrong verdict on reachable input; **H** = guest ≠ host,
undefined guest outcome, or a protocol-reachable state loss / halt; **M** = design/spec gap with a concrete failure
mode or a defense-in-depth hole; **L** = minor / documentation; **I** = checked, no defect.

Totals: **C 0 · H 0 · M 0 new (R7-M2 fixed) · L 10 (incl. R7-L3 / R7-L4, four fixed test defects and one open test gap) · I 6**.

| id | sev | area | title | status |
|---|---|---|---|---|
| R7-M2 | M | caps / griefing | any fresh id could commit, so ≈ 64 units per height kept the 1 024-commit cap full and commit-reveal unavailable to everyone (cost: unit fees only) | **fixed (PILOT rule, not upstream semantics)**: every live commit reserves `COMMIT_BOND_PERP` (1 000) of its author's PERP until it is pruned at its TTL (revealed ones too); Commit needs `balance >= (live + 1) · bond`; GovWithdraw / CreateMarket fee / oracle Stake may not eat the reserve (code 19). Filling the cap now locks 1 024 000 PERP for up to 16 heights. govedge case 8 `r8:*`, case 4/5/7 updated |
| R7-L3 | L | witness | proposals, commits and gov nonces are not MNWIT1 leaves (as upstream `wit_leaves` @ 20326c0) | documented, deferred (design below); no consumer needs them yet |
| R7-L4 | L | caps | `MAX_STATE_MARKETS` counts delisted markets | accepted: upstream never removes a market (params, marks, book indexes stay), so the heap they hold is real; filling the cap burns 2.55 M PERP; recovery = an upgrade image with a larger cap (`rv_rollup upgrade`) |
| R8-T1 | L | tests | govedge `cap:votes` / `r7:commit` expectations wrong (item 1); round-7 mutation run invalid | fixed (885f3d2, dfc1ee5); govedge 8/8; mutation re-run |
| R8-T2 | L | tests | `prodheight.js` still expected a GovWithdraw(0) by a PERP-less id to apply (then DuplicateNonce) — wrong since R7-M1 (now 19, 19); the round-7 prod image would have failed it 15 / 16 | fixed (42d0a1b): 16 / 16 on the round-8 prod image; the fixed script is also what the round-7 suite runs |
| R8-T3 | L | tests | round-4 mutant 9 (ADL last share, `is_last` → false) was listed as "killed in round 5"; the round-5 fail-fast run shows it **survived** every check | corrected: **equivalent** under one fill per liquidation (R7-I3): `pos_deltas` holds ≤ 1 entry, so `total = delta` and `hole · delta / total = hole` = the last-share value |
| R8-T4 | L | tests | round-7 guest mutant 4 (Slash dropped from the shared PERP-ledger cap, R6-H3) survived every round-7 check: no test sent a Slash by a new id at the cap | fixed: govedge `cap:perp_slash_new`; the mutant is now killed (`l8-e.log`) |
| R8-L1 | L | commit-reveal | commit-reveal (MEV protection) now needs PERP: an account holding only USD collateral cannot commit (upstream: anyone may) | documented pilot trade-off; a collateral-denominated bond would touch every margin / withdraw check |
| R8-L2 | L | griefing (residual) | the bond is locked, not burned: one id with 1.024 M PERP can keep the cap full (a reveal frees the per-account pending slot, the revealed entry keeps its bond), at an opportunity cost only | documented; production: a burned per-commit fee, a larger bond, or a stateless guest (R4-H1) |
| R8-L3 | L | steps | `live` is an O(commits) scan (≤ 1 024) for every Commit / GovWithdraw / CreateMarket / Stake unit: ≤ 1.7 · 10^7 entry visits per height | documented: same order as upstream's own per-Commit pending scan; evaluated lazily (other kinds never scan) |
| R8-L4 | L | tests | round-7 guest mutant 6 (drop the W2 depth check of a Reveal's **inner** op) survives every check: no test reaches a too-deep key through a reveal (needs a 2^MAX_WIT_DEPTH prefix grind; only the depth8 build makes that cheap, and its tests have no governance batches) | open: add a depth8 govedge case. Since the bond, a committer already has an `acct:` leaf, so the only reachable inner-op keys are `pos:` / `ord:` of an inner Place: grind an id whose `pos:<id>:<m>` shares ≥ 8 bits with an existing key (cf. l2.rs `depth8_batch`), GovDeposit + Commit, then Reveal(Place in m) → 18. The rule itself is in place (R7-I2) |
| R8-I1 | I | invariant | can an author's PERP balance drop below its reserve? | no: the only PERP debits are `gov_withdraw`, `create_market`, `apply_stake` (`set_perp` callers), all guarded; credits (gov deposit, slash reward, unbond release) only raise it; a prune only lowers the reserve |
| R8-I2 | I | reveal | does a Reveal's inner op bypass the reserve? | no: `state_cap_ok` (which runs the bond first) is applied to the inner op with the Reveal's author (`r8:reveal_inner_reserved`) |
| R8-I3 | I | formats | does the rule change state, snapshot, MNWIT1 or the state hash? | no: it is a predicate over (balance, live commits); round-7 exports / upgrade images import unchanged |
| R8-I4 | I | harness | does the differential harness agree with the port on bond refusals? | yes by construction: `pilot_gov_refused` calls the same `commit_bond_ok` on the real engine's balance / commits — so predicate mutations are invisible to govfuzz / xfuzz and are covered by govedge's absolute expectations (`loop8-mut.sh`) |
| R8-I5 | I | ordering | does the pre-check change upstream codes for valid units? | only for units the rule refuses; a debit above the balance keeps upstream's Insufficient (`r8:gwd_over` = 9); a doubly invalid unit gets 19 deterministically in port and mirror |
| R8-I6 | I | prune | is the reserve released exactly at the TTL prune? | yes: ttl 5, `SetHeight 6` → withdraw / listing / stake apply (`r8:*_after_ttl`); bound sessions prune at the height hook (govedge case 5) |

### Round-8 results (InstaBox VM, build target-l8-{host,g,gprod}, sha1 in `results-loop8/l8-gbuild.log`; logs `guest-engine/results-loop8/`)

| check | result |
|---|---|
| govedge (8 cases incl. `r8:*`, `cap:votes` fixed, `cap:perp_slash_new`) | 8 / 8 |
| quick l8-q (final code): govfuzz 60, xfuzz 60, capcheck 10, snaptest 30, snapcap, liqedge, hbind 30, orafuzz 30, fuzz 50 | all green (govfuzz 60 / 60: commit ok 1 421, commit refused by the bond 809, withdraw / listing / reveal refused by the reserve 1 / 5 / 8; xfuzz 60 / 60) |
| guest images (default, prod) | build clean |
| govgen 11–13 through the JS guest (round-8 default image) | 3 / 3 engine + roots match (695 units, 54.8 M steps) |
| prodheight.js on the round-8 prod image (fixed script, R8-T2) | 16 / 16 |
| guest mutation, commit bond (`loop8-mut.sh`, 11 mutants: rule off, `>=` / `>` / +bond variants, debit arms dropped, revealed not counted, live − 1, inner-op cap dropped) | **11 / 11 killed** (all by govedge; the harness mirror shares the predicate, so govfuzz cannot) |
| round-7 mutant 4 (Slash out of the ledger cap) vs the round-8 govedge | killed (`cap:perp_slash_new`; survived the round-7 checks) |
| AA / rolltest | unchanged in round 8 (no AA change); round-7 values apply |

---

## R7-M2 — the commit bond as implemented

```
COMMIT_BOND_PERP = 1 000          (= PROPOSAL_MIN_STAKE_PERP; a pilot parameter)
live(a)  = |{ c in commits : c.account = a }|        revealed or not, until prune_commits (ttl < height)
Commit by a                       refused (19) unless  bal(a) >= (live(a) + 1) * bond
GovWithdraw(x) / CreateMarket / Stake by a, debit d = x / CREATE_MARKET_FEE_PERP / ORACLE_BOND_PERP:
                                  refused (19) if d <= bal(a) and bal(a) - d < live(a) * bond
                                  (d > bal(a): upstream's Insufficient unchanged)
```

* Where: `guest-engine/src/lib.rs` `commit_bond_ok`, called first in `state_cap_ok` — so it also covers a Reveal's
  inner op and shares the code-19 path of the caps. Nothing is moved; the bond is "returned" when the commit is pruned.
* Why a predicate and not an escrow: an escrow changes the PERP ledger, the MNWIT1 `acct:` leaves, the snapshot and the
  real-vs-port comparison everywhere; the predicate gives the same anti-spam property (capital per stored commit) with
  no format change.
* Why revealed commits keep the bond: they stay in `commits` (and in the 1 024 cap) until their TTL, so they are what
  the cap counts.
* Not upstream: upstream @ 20326c0 has no commit deposit. Marked PILOT like the caps (R4-H1 stopgaps).

PoC before the fix: govedge case 7 of round 7 filled the cap with 1 025 commits by 129 fresh, PERP-less ids. Now such
ids are refused at their first commit (`r8:commit_no_bond`); case 7 needs 129 ledger ids topped up to 10 000 PERP.

## R7-L3 — governance state in MNWIT1 (design, deferred)

Leaves `prop:<id>` (creator, market, key, value, deadline, supply, yes, no, |voted|, snapshot digest), `cmt:<hash>`
(account, commit unit, heights, revealed) and `gnon:<account>`; dirty-marked by the writers in engine.rs like `meta:`.
rv_witproof's kid rule (text before the 2nd ':') would have to be re-checked for them. Cost: three new leaf kinds in the harness's
`wit_leaves` mirror and the depth rule (W2) for keys a Commit / Vote creates for its author. Deferred because no AA
consumes governance state and upstream `wit_leaves` does not commit it either.
