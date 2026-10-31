# rv loop round 6 — governance + commit-reveal port, review of the new code (2026-10-31)

Target: `lhxmall/Minuend` branch `spike/rv-bisect` @ 6f33165 (loop round 5). Reference engine read only via
`git archive 20326c0` (engine-diff/engine-src); fix/47-all, main and PR #51 untouched.

Work items:

1. **R4-M3 (rest) — governance and commit-reveal ported** (minuend-exec @ 20326c0, verbatim except the edits marked
   PILOT): `gov_deposit` (pilot deposit model: anchor / backing / address binding not modelled, PERP arithmetic
   verbatim), `gov_withdraw` (nonce watermark; the node-local WAL is not consensus), `create_market` (all listing
   rules, fee burn, id allocation, funding-rate creator = external feed), `create_proposal` / `vote` /
   `finalize_proposal` (weight snapshot at creation, quorum, deadline in seqs, spot fee-raise rule, illegal-at-finalize
   no-op, delist), `commit_op` / `reveal_op` (TTL, per-account pending cap, preimage = upstream `encode_op(inner) ||
   salt`, parent edge, inner op through the same dispatch with the Reveal's unit id, "rejected = unchanged"),
   `prune_commits` in the batch-commit hook. New state: `next_market_id`, `proposals`, `next_proposal_id`,
   `seen_gov_nonces`, `commits` (state hash section `MNPILOT4`, which also covers every market's parameters and the
   external sources; snapshot v3, v2 still importable).
2. **Batch format.** Kinds 14 GovDeposit, 15 GovWithdraw, 16 CreateMarket, 17 CreateProposal, 18 Vote, 19
   FinalizeProposal, 20 Commit, 21 Reveal, 22 SetSeq (test fixture: proposal deadlines are 20 000 applied units away;
   refused in prod). CreateMarket / Commit / Reveal carry their payload in an **MNP2 extension area** after the
   unit-id table (word `n_ext`, then `n_ext` words; an op names an offset): a listing is 23 words, a commit hash 8, a
   reveal 40 (commit_ref, salt, inner op words, parents P1, P2). MNP1 has no extension area (those ops are refused
   BadAccount). Bounds: `n_ext <= MAX_EXT = 64 x MAX_UNITS`, every read index < 2^24 (const assert).
3. **Differential tests** (engine-diff `gov.rs`): `govfuzz` (random governance / listing / trading / commit-reveal
   batches; the builder steps the REAL engine while writing the batch because a Reveal names its commit unit as a
   parent; commit hashes are computed with upstream `minuend_dag::reveal_commit_hash`, so the port's own `encode_op` is
   checked): hash, events, per-unit MNWIT1 roots (real scratch / port incremental / port scratch), snapshot v3 round
   trip, and the batch cut into three segments on one session with an export + import at one cut. `govedge`:
   deterministic boundary batches with intended outcomes (quorum exactly at / one below the boundary, vote / finalize at
   deadline − 1 / deadline, weight snapshot, spot fee raise, delist then trading refused, listing fee exact / short,
   64-proposal cap, nonce watermark incl. "a rejected high nonce does not advance it", supply cap, TTL bounds, reveal at
   ttl / ttl + 1, missing / non-linear parent, wrong salt, foreign signer, double reveal, inner reject keeps the
   commit, pending cap 8, forbidden inner kinds, inner CreateMarket, prune at the bound hook, malformed extension,
   review caps). `govcap`: heap of the governance state at its caps.
4. Fresh adversarial review of the round-6 code (below), quick + full suite, mutation test.

Severity as in rounds 1–5: **C** = honest party loses / wrong verdict on reachable input; **H** = guest ≠ host,
undefined guest outcome, or a protocol-reachable state loss / halt; **M** = design/spec gap with a concrete failure
mode or a defense-in-depth hole; **L** = minor / documentation; **I** = checked, no defect.

Totals: **C 0 · H 3 · M 2 · L 5 · I 7** — all three H fixed in this round. No real-engine ↔ port divergence on
honest input (govfuzz / govedge / orafuzz / liqfuzz / fuzz / advfuzz / witfuzz / segfuzz / hbind / scen all equal).

| id | sev | area | title | status |
|---|---|---|---|---|
| R6-H1 | H | heap / steps | commits live until their TTL passes (revealed ones too) and ANY id may commit (8 pending per id, fresh ids are free): ≤ 16 384 per height × 17 heights ≈ 278 k entries ≈ 40 MB of the 50 MB guest heap, and upstream's per-Commit pending scan is O(commits) (≈ 4.5 · 10^9 iterations per height) — a cheap, permissionless way to exhaust the guest heap (abort = dead session = rollup halt until a revive) or the operator's step budget | **fixed**: `MAX_STATE_COMMITS = 1024` live commits (pilot consensus rule, code 19 like the account cap); govedge `cap:commits` |
| R6-H2 | H | heap | `Proposal::voted` records every voter, also weight-0 ids outside the creation snapshot: 64 open proposals × 20 000 votes each (votes count in the 20 000-seq window, nobody has to finalize) ≈ 1.28 M entries > the heap | **fixed**: a voter outside the weight snapshot is refused (code 19) once `voted.len() >= snapshot.len() + MAX_ZERO_VOTERS (64)`; snapshot voters (the only ones with weight) always pass; govedge `cap:votes` |
| R6-H3 | H | heap | the PERP ledger grows without the account cap: GovDeposit by fresh ids, **GovWithdraw of 0 by ANY id** (succeeds upstream: `bal < amount` is false, nonce 1 > watermark 0 — inserts a zero balance, an `acct:` leaf and a nonce entry), slash rewards to fresh challengers | **fixed**: GovDeposit / GovWithdraw / Slash by an id not yet in the ledger are refused (code 19) once it holds `MAX_STATE_ACCOUNTS` ids; govedge `cap:perp`, `cap:perp_existing` |
| R6-M1 | M | heap / listings | listings are bounded only by the burned fee (10 000 PERP each); every market adds two leaves, params, a book and per-market rings | **fixed** (pilot rule): `MAX_STATE_MARKETS = 256`; govedge `cap:markets` |
| R6-M2 | M | design / clock | R5-M2 (operator sets the clock's pace) carried over; a per-height timestamp was designed but not implemented this round (see below) | open (design below) |
| R6-L1 | L | port fidelity | GovDeposit keeps the pilot deposit model (no anchor set, backing, payer account, Obyte address or one-address-one-account binding: `adr:` / `adrx:` / `dep:` leaves are not modelled, as for collateral deposits since round 1) | documented |
| R6-L2 | L | commit-reveal | the Reveal's parents (P1, P2) and every unit id are operator input (as R5-L1): the parent-edge rule is checked against what the batch claims, not against signed units; a unit the real engine refuses at ingest (foreign inner signer, nested Commit / Reveal, inner Deposit / GovDeposit, unknown parent) is refused BadAccount by the port (the inner-op rule is checked before the commit lookup so the code does not depend on the commit's existence) | documented; govedge `c:foreign`, `c:inner_deposit[_nocommit]` |
| R6-L3 | L | upstream | upstream itself: GovWithdraw of 0 by any id creates a PERP ledger entry, a nonce watermark and an `acct:` leaf for the price of a signed unit (state / witness bloat on every node) | reported (upstream unchanged; the pilot caps it, R6-H3) |
| R6-L4 | L | caps | the R6 caps change outcomes only at the cap (code 19 instead of the upstream result, so seq does not advance); a spammer can fill the commit cap (MEV protection unavailable for ≤ 16 heights) or the zero-weight voter slots (no effect on tallies) | documented: production needs a stateless guest (R4-H1) or fees per stored item |
| R6-L5 | L | tests | SetSeq is a fixture like SetHeight; prod refuses it | `prodheight.js` (prod: refused; test image: jump allowed, going back refused) |
| R6-I1 | I | commit hash | does the port's `encode_op` equal upstream's for every inner kind it can carry? | yes: govfuzz computes every commit with `minuend_dag::reveal_commit_hash` and the reveals apply identically (incl. inner CreateMarket with its own extension) |
| R6-I2 | I | rejected = unchanged | does a rejected inner op leave the commit consumed or a dirty witness key? | no: `reveal_undo`, per-unit roots equal (govedge `c:inner_reject` / `c:inner_retry`) |
| R6-I3 | I | extension bounds | can an extension offset reach the input trap range or overflow? | no: `off.checked_add(len) <= n_ext <= MAX_EXT`, const assert < 2^24; malformed offsets → BadAccount (govedge case 6) |
| R6-I4 | I | depth rule | do the new kinds create keys outside the W2 pre-check? | GovDeposit (author `acct:`), CreateMarket (`band:` + `meta:` of the next id) are pre-checked; a Reveal is checked with its inner op |
| R6-I5 | I | snapshot | does an upgrade image still import a round-5 (v2) export? | yes: v2 decodes with the governance cursors at their genesis values; v3 round trip in govfuzz |
| R6-I6 | I | segments | does governance state survive segment cuts and export / import? | yes: govfuzz cuts every batch into three segments with an export + import at one cut |
| R6-I7 | I | height hook | are commits pruned at the bound height? | yes: `commit_height` prunes; govedge case 5 (bound session, ttl h+1 survives h+1, gone at h+2) |

### Round-6 results (`scripts/loop6-suite.sh c` + targeted runs, build target-l6c-*, sha1 in `results-loop6/l6-bins.txt`; logs `guest-engine/results-loop6/`)

Same caveat as round 5: the suite (started 14:00 UTC) was reniced to 19 behind the round-7/8 jobs; *not reached* rows
have round-7/8 counterparts.

| check | result |
|---|---|
| quick (l6b-q1, notes): govedge 7, govfuzz 60, orafuzz 60, liqfuzz 30, hbind 30, snaptest 30, snapcap, capcheck 10, liqedge, fuzz 50, segfuzz 30, witfuzz 30, advfuzz 30, scen 47 | all green |
| l6c-gov: govedge / govcap / liqedge / govfuzz 300 | 7 / 7 · caps: 256 PERP ids, 256 markets, 64 proposals / 19 999 voters, 1 024 commits → size-class high-water 3.89 MB (host 64-bit) · 10 / 10 incl. liq_eq / liq_eq_plus1 · 300 / 300 (100 526 units) |
| l6c-guestq: prodheight.js | 16 / 16 (prod refuses SetSeq; governance ops + extension area in prod; MNP1 ext op → 2) |
| l6gq: 4 govgen batches through the JS guest | 4 / 4 engine + roots match (914 units, 67.8 M steps) |
| fuzz 300 / advfuzz 300 / witfuzz 300 / segfuzz 300 | 300 / 300 each (12 621 segments) |
| proofs / scen host / selftest / heapsim | 0 / 829 291 forged · 47 / 47 · clean · ≤ 19.2 MB |
| segguest small, PROD image with `PROD=1` (`sg56.sh`, own seg-small) | **7 / 7 match** |
| robust-limit, guest-poc, liqfuzz 300 and the rest of the suite | *not reached* (still running at collection) |

### Round-6 mutation test (`loop6-mut.sh` → fail-fast `loop6-mutff.sh`; `l6-mut.log`, `l6-mutff.log`)

| # | mutant | result |
|---|---|---|
| 35 | liquidatable `<` | killed (liqedge `liq_eq`) |
| 37 | ADL counterparty collateral `.max(0)` dropped | survived → equivalent (round 6 argument) |
| 52 | smt_ref absence check without the prefix test | survived → equivalent under honest roots (round 6) |
| 80, 81 | round-6 governance / commit-reveal mutants | killed (govedge) |
| 82 … 111 | rest | *not reached* (fail-fast run still going at collection) |

---

## R6-H1 / R6-H2 / R6-H3 / R6-M1 — governance state outside the heap bound

Round 4 bounded the session heap by capping accounts (R4-H1 stopgap, 31.1 MB of the 50.2 MB heap at the cap). The
governance port adds four collections whose size is not tied to accounts:

* `commits` — keyed by hash, any signer, kept until `ttl < height` (revealed or not). The per-account cap counts only
  unrevealed entries, and fresh ids cost nothing. With height binding one height can add 16 384 commits and they live
  up to 17 heights.
* `Proposal::voted` — every voter id, weight or not. Votes are applied units; each proposal accepts votes for 20 000
  seqs and stays until someone finalizes it.
* `perp_balances` / `seen_gov_nonces` — GovWithdraw(0) succeeds for any id.
* `markets` — each listing costs 10 000 PERP; PERP_SUPPLY_MAX is 10^14.

Fix (pilot consensus rules, the same mechanism as the account cap: `state_cap_ok`, code 19, checked before the
engine): ≤ 1 024 live commits, ≤ snapshot + 64 voters per proposal (snapshot voters always pass), ≤ 256 PERP ledger
ids (GovDeposit / GovWithdraw / Slash by a new id), ≤ 256 markets. `govcap` measures the governance state at all caps
(see the results table).

## R6-M2 — timestamp per height (design, not implemented)

The cheapest binding found: rv_rollup's `submit` takes an operator-declared `ts` and requires
`ts <= timestamp`, `ts >= timestamp − TSLACK` and `ts >= ts(h−1) + MINGAP`; `s0` is computed with register x10 = ts
(`'0:' || '0,…,0,' || ts || ',0,…' || ':' || pmem || ':' || inp || ':0'`) instead of 32 zeros. The guest's `_start`
leaves a0 untouched until `call rmain`, so `rmain(ts)` receives it without an input-format change and without any
memory proof (s0 is computed by the AA, so the value is bound by construction). The guest can then refuse a
non-monotone ts and publish it (OUT). MINGAP bounds the clock's pace (32-height staleness ≥ 32 × MINGAP). Not done in
this round because the s0 preimage is used by every rolltest / rolldevnet / rolltrace / witproofe2e trace (≈ 300 AA
checks would need new traces and advancing chain time between heights).
