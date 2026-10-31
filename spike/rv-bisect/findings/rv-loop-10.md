# rv loop round 10 — round-7/8 collection, govwit full suite, R9-T1 devnet, review of heap / snapshot / MNP2 / images / economics (2026-11-01)

Branch `spike/rv-bisect`, parent a562c12. Status: **DRAFT** (box jobs still running at the time of writing; rows marked
_running_ are filled by the next collection, see work/rv-rollup-notes.md "Loop round 10").

## Summary

1. **R10-H1 (H, fixed)** — the long-run heap bound (R4-H1 / R6-M1) never measured the per-(account, market) state:
   every account may hold one position (+ an isolated-margin entry) in **every** listed market, and every bonded oracle
   one report + an 8-deep report ring per market. With the pilot caps (256 accounts, 256 markets, oracles under the
   256-id PERP ledger) that is 65 536 positions + 65 536 oracle pairs. Measured with the real engine entry points
   (`engine-diff mktcap`, host allocator simulation, 64-bit sizes = upper bound of rv32): **positions alone 46.1 MB**
   size-class high-water (256 × 256), **oracle reports alone 25.6 MB** (256 × 256 × 256, one sample each) — together
   ≈ 72 MB against the 50.2 MB guest heap, before any order / withdrawal / governance state. A run that OOMs aborts,
   the session is dead (ST_DEAD) and the rollup halts until a governance upgrade imports the last export (state since
   that export is lost, R4-M5). Cost to an attacker: 255 listings (CREATE_MARKET_FEE_PERP each, burned), bonds and
   collateral it keeps, unit fees. The round-4 `statecap` number missed it twice over: it used two markets, and its
   chain of trades (account i buys q from i−1, sells q to i+1) **nets every middle account's position to zero**, so
   only the two end accounts held positions at all. Fix: `MAX_STATE_MARKETS` 256 → **RESULT_CAP** (pilot rule, code 19
   as before), chosen from the whole-state measurement `mktcap 256 m 256 64 64` (below).
2. **R10-M1 (M, open — design)** — stall economics of the fraud-resubmit loop (design §8.3 quantified): a fraudster
   that re-submits a fraudulent h after every void and defends each game as slowly as the move deadlines allow stalls
   finalization for ≈ one game per cycle (rolltest `stall10`: 3.08 h per cycle at 3 bisection rounds; ≈ 8–10 h at
   real guest step counts 10^8–2^40) for **OBOND = 200 000 bytes per cycle** (half burned, half to the first winning
   challenger; ≈ 100 000 if its own puppet wins first) — ≈ 0.3–0.6 MB of bytes per stall-day, independent of the value
   the rollup holds. Options (owner decision): bond escalation per fraud-voided height, a submit reservation for the
   winning challenger, a value-scaled OBOND. Not fixed this round (each option changes the payout / race rules).
3. **R9-T1 (closed)** — devnet run of governance with `$GOV` = a devnet wallet (rolldevnet section 9: a second rv_rollup
   whose `$GOV` is the `gov` wallet): upgrade → import → xbind (real 9-word proof triggers, ~10.5 KB fee) → finalize,
   then the R9-H1 brick path (upgrade above a non-export height) and its governance `cancel` recovery, reclaim of the
   voided bond, re-scheduled upgrade finalizing. **43 / 43** (`results-loop10/l10-rolldevnet9.log`). Full rolldevnet
   with section 9: _running_.
4. **R7-L3 / govwit** — full suite on the govwit build: _running_ (`l10-*`). Fixture check: the MNWIT1 roots of every
   committed proof fixture (adv5–7, g1000) and of liquidation batches are **identical** under govwit; governance batches
   (govgen 21–23) change, as designed. New fixture `js/testdata/proofs/gov21.json` (a real `prop:` membership from the
   govwit host): rolltest witproof 19 / 19, 44 memberships (was 41). Default switch: pending the suite (see notes).
5. Review areas with no new defect (I): snapshot v3 import/export, MNP2 extension area, guest images vs rv_step (static
   opcode scan), allocator behaviour across heights apart from R10-H1.

Totals (draft): **C 0 · H 1 (fixed) · M 1 (open, design) · L 1 · I 6**; R9-T1 closed.

| id | sev | area | title | status |
|---|---|---|---|---|
| R10-H1 | H | guest heap / caps | positions (+ isolated margin) per (account, market) and oracle reports / rings per (market, oracle) were outside the heap bound: 256 × 256 → ≈ 72 MB > 50.2 MB heap → OOM → dead session → rollup halted | **fixed**: MAX_STATE_MARKETS → RESULT_CAP (whole-state measurement below); `mktcap` command; govedge `cap:markets` follows the constant |
| R10-M1 | M | rv_rollup economics | indefinite finalization stall for OBOND per ≈ one slow game (rolltest `stall10`) | open (design options listed) |
| R10-L1 | L | tests | round-4 `statecap` netted positions to zero (equal-size buy/sell chain) and used 2 markets, so the R4-H1 bound never contained per-market state | fixed in `mktcap` (sizes (i + 1) units: every account keeps a position in every market); R4-H1 numbers superseded by the R10-H1 table |
| R10-I1 | I | snapshot v3 | import edge cases: duplicate / unsorted keys, counts above SNAP_MAX_ITEMS or the remaining words, v2 → v3, trailing words, kind / mode values, books of unlisted markets, accounts above the cap | all refused or digest-bound (an import is accepted only for the compiled-in export digest, so a non-canonical-but-decodable snapshot can never be imported; the decoder checks are liveness / OOM guards); every ChainState field is encoded (field-by-field comparison with state.rs) |
| R10-I2 | I | MNP2 extension | offsets / lengths, area size, MNP1 ops that need the area, nested Reveal, inner CreateMarket offsets | `Ext::read` checks `n ≤ MAX_EXT` and `off + len ≤ n` with checked_add; base + 1 + MAX_EXT stays < 2^24 (const assert); MNP1 → BadAccount; nested Reveal → BadAccount; the Reveal pre-check and dispatch read the same words |
| R10-I3 | I | guest images vs rv_step | do the round-8 prod and the govwit images contain instructions rv_step does not model? | `js/opscan.js` (static scan of every .text word with ref.js's decode rules): 184 893 / 197 711 words, the only non-RV32IM-as-modelled words are 5 × `unimp` (0xc0001073, Rust's abort / unreachable trap; both rv_step and sail trap) — no fence / csr / A-extension; sail spot-check on the govwit embed image: in the l10 suite (_running_) |
| R10-I4 | I | allocator | multi-height behaviour of the size-class allocator under the caps | carved bytes = Σ per-class peaks over the whole session (never returned across classes); with every per-account kind bounded the per-class peaks are bounded by the simultaneous-load measurement (`mktcap 256 m 256 64 64`), so R10-H1's cap is the binding bound |
| R10-I5 | I | test fixture | with header flag MARKET2_FLAG (test-only) `next_market_id` stays 2, so the first CreateMarket overwrites market 2's params | test-only (prod requires flags = 0); both harness sides do the same, so differential results are unaffected; seen in the first `mktcap` run (16 listings → 15 markets) |
| R10-I6 | I | R9-T1 fees | upgrade / xbind / cancel on a devnet | upgrade 897 B, cancel 849 B, xbind ≈ 10.5 KB + ≈ 0.5 KB tps fee (9 Merkle proofs of depth 24) |

## R10-H1 — per-(account, market) state outside the heap bound

`engine-diff mktcap n m r [orders wd]` (engine-diff/src/snap.rs): genesis, a PERP-funded creator lists `m − 1` markets
(CreateMarket) and, as a bonded oracle, reports a mark for each; `n` accounts deposit and trade in every market
(account i buys (i + 1) units from i − 1, so positions never net to zero); the first `r` accounts bond and report in
every market; optionally `orders` resting bids and `wd` withdrawals per account. MNWIT1 tree committed after every
account. Host allocator simulation (heapsim, 64-bit sizes).

| run (n m r orders wd) | positions | oracle pairs | size-class high-water |
|---|---|---|---|
| 128 128 0 | 16 384 | 127 | 11.89 MB |
| 256 64 0 | 16 384 | 63 | 11.53 MB |
| 256 128 0 | 32 768 | 127 | 23.09 MB |
| 256 256 0 | 65 536 | 255 | **46.05 MB** |
| 256 256 256 (round-10 v1, positions netted) | 512 | 65 791 | **25.55 MB** |
WHOLE_ROWS

≈ 700 B per position (BTreeMap entry, `pos:` leaf + its MNWIT1 path) and ≈ 390 B per (market, oracle) pair with
one ring sample (more with the 8-deep ring).

Fix: `MAX_STATE_MARKETS` = RESULT_CAP. Bound: FIX_BOUND.

## R10-M1 — stall economics (PoC: rolltest `stall10`)

```
cycle: fraudster submits a fraudulent h1 first; honest challenger opens at once and moves within 60 s;
       the fraudster's every mids comes at its deadline − 1 s; the challenger wins, h1 is voided (top = 0)
3 cycles: 3.08 h each (3 bisection rounds, 4 062 steps); fraudster paid 600 000 = 3 × OBOND; burned 300 000;
          lf stays 0 throughout
```

At real step counts the whole-run game has ⌈log16 steps⌉ rounds (8 for 6 · 10^8 steps, 10 at MAXSTEPS = 2^40), so one
cycle stalls ≈ 8–10 h. The fraudster can race the honest re-submission each time (it only needs its submit to reach the
MCI first). Its net cost per cycle is OBOND/2 burned plus OBOND/2 paid to the first winning challenger (its own
puppet can be that challenger if it times the puppet's win just before the honest game's end, leaving ≈ OBOND/2 per
cycle). Options, each a rule change for the owner:

* **bond escalation per fraud-voided height**: the k-th submission of h after k fraud voids at h posts OBOND · 2^k
  (stored per submission; payouts use it): the attack becomes exponential, an honest re-submitter posts the escalated
  bond once and gets it back at finalize;
* **reservation for the winning challenger**: after a fraud void at h, only the first winning challenger may submit h
  for a short window — defeated by a puppet that wins first, so only useful together with escalation;
* **value-scaled OBOND** (governance parameter tied to the value the rollup secures).

## Tests this round

| test | result |
|---|---|
| R9-T1 rolldevnet section 9 (ONLY9, devnet, `$GOV` = devnet wallet) | 43 / 43 |
| rolltest `stall10` (R10-M1 PoC, sandbox ocore) | 13 / 13 |
| rolltest `witproof` with `gov21.json` | 19 / 19 (44 memberships) |
| govwit fixture check (`l10fx.sh`) | adv5/6/7, g1000, liq1/2 roots identical; gov21–23 change |
| `mktcap` (R10-H1) | table above |
| opscan (round-8 prod image, govwit image) | only `unimp` outside the modelled set |
SUITE_ROWS
