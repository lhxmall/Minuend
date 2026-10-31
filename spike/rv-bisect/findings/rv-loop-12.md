# rv loop round 12 — R11-M1 fix (global decaying fraud-void counter), review of rounds 11/12 (2026-11-01)

Branch `spike/rv-bisect`, parent b74ed8f. Status: **FINAL** (all box rows collected; the govwit default switch landed in round 15 after SUITEDONE, see below).

## Summary

| id | sev | where | what | status |
|---|---|---|---|---|
| R11-M1 | M | rv_rollup economics | moving-height stall: every fraud is the first at its height, so the per-height escalation never bites (OBOND per cycle) | **fixed** (decision 2026-11-01, made by the assistant per the owner's brief; owner may override): global counter `V` in the exponent |
| R12-M1 | M | rv_rollup economics | the global counter amplifies the honest capital requirement across every concurrent height: at V = 10 every height locks 204.8 M bytes for its 24 h window while the attacker keeps V at the cap with one fraud void per day (≈ 102.4 M burned) — honest-locked / attacker-burned ≈ 2 × heights per day | **fixed in round 13** (option (a), VCAP = 6: `findings/rv-loop-13.md`); PoC rolltest `r12` (b) |
| R12-L1 | L | rv_rollup | `V` was uncapped: each fraud void beyond the cap added one more day at the maximum bond for every honest operator, at no extra cost to the attacker (it pays the capped bond either way) | **fixed**: `V = min(Vdecayed + 1, MAXESC)` (rolltest `r12` (a); mutant 25 killed) |
| R12-L2 | L | rv_rollup / operators | the required bond depends on V at the trigger's MCI time: a fraud void (or a decay step) landing between an operator's composition and its MCI makes an exact-bond submit bounce (10 000 bounce fee) | documented: operators overpay; the excess above bond + FEE is refunded at submit (existing `rf`) |
| R12-I1 | I | rv_rollup | a new fraud void restarts the decay clock (`Vt = now`) and discards the partial day since the previous void: V decays "1 per 24 h since the LAST fraud void", not per calendar day | by design (conservative) |
| R12-I2 | I | rv_rollup | a priority window `p<h>` survives a later non-fraud void of h (governance upgrade / cancel within PRIO): only the winner may submit the import run of h until `until` (≤ 1 800 s) | accepted (bounded delay; governance can wait PRIO) |
| R12-I3 | I | tests | interactions checked and pinned: upgrade / cancel voids leave V (and v_h) untouched; two challengers winning on the same fraudulent submission count one void (V = v1 = 1, burned = bond/2 once); a voided escalated submission is reclaimed at its own bond; the decayed value + 1 is what a new void stores | rolltest `r12` (c)(d), `stall11` |

No C / H this round.

## R11-M1 fix — rule

```
init (after $now):  Vdec = floor((now - Vt) / 86400);  Vnow = V > Vdec ? V - Vdec : 0
submit h:           bond = OBOND * 2^min(max(v_h, Vnow), MAXESC)       (MAXESC = 10)
fraud void at h:    v_h += 1;  V = min(Vnow + 1, MAXESC);  Vt = now;  p_h = winner:(now + PRIO)
```

* "Fraud void" is unchanged from round 11: a winning challenger result on the **live** submission of h (`$st.void`).
  Governance upgrade / cancel voids and results on already-voided submissions do not touch v_h or V.
* Refunds: an honest submission posts the escalated bond; it is stored as `b<sid>` (round 11) and every payout uses it:
  finalize / reclaim `b − FEE`; submit refunds `paid − bond − FEE`.
* Budget: rv_rollup complexity 86 / ops 1 699 (limits 100 / 2 000; round 11: 82 / 1 663).

PoC → fix (rolltest `stall11`, sandbox ocore, 4 cycles, EXTRA 4000):

```
before (round 11):  fraud bonds 200 000 / 200 000 / 200 000 / 200 000      cost   800 000
after  (round 12):  fraud bonds 200 000 / 400 000 / 800 000 / 1 600 000    cost 3 000 000 (+ 3 x 10 000 test bounce fees)
honest re-submits:  400 000 / 800 000 / 1 600 000 / 3 200 000, all finalize, refunded 5 992 000 = sum - 4 x FEE
decay:              one day after the last void the next height posts OBOND x 2^3; after V days OBOND again;
                    a new fraud after full decay sets V = 1 (decayed value + 1), not 5
throughput:         unchanged, 3.08 h per height (one slow game) -- the attack is now geometric in cost, not slower
```

`NOR11=1 node js/rolltest.js stall11` reproduces the round-11 bonds through the JS `bondFor` mirror (the AA side has
no switch; use `findings/r11m1-option.patch` reverse-applied for the old AA).

## R12-M1 — capital amplification (PoC rolltest `r12` (b))

```
state: V = 10, Vt = now (as after an attacker pushed V to the cap)
honest h1 with OBOND x 2^9            -> bounce "bond 204800000"
honest h1..h3 each OBOND x 2^10       -> accepted; locked 614 400 000 for the 24 h window
after WIN: finalize 1..3              -> refunded 614 394 000 (bond - FEE each)
attacker upkeep at the cap            -> one fraud void per day: bond/2 + GF + FEE = 102 412 000 (puppet first winner)
ratio honest-locked / attacker-burn   -> 2 x N  (N heights submitted per 24 h; 6.0 for N = 3)
```

The bond is returned, so the honest cost is opportunity cost plus a liveness requirement: operators that cannot lock
N × 204.8 M stop submitting and throughput falls to what the available capital covers (or to fewer, larger heights:
≤ 16 384 units per height). Round 11's per-height rule only escalated the attacked height. Getting V to the cap costs
Σ OBOND × 2^k / 2 (k = 0..9) ≈ 102 M plus one won top+1 race and one slow game per step (≈ 10 cycles, 3–10 h each).

Options (owner): (a) cap the global term separately, e.g. `max(v_h, min(V, 6))` — the moving-height fraudster still pays
geometric up to 64 × OBOND per cycle while honest capital stays ≤ 12.8 M per height; (b) shorter VDECAY (e.g. 6 h) —
faster recovery, cheaper upkeep for the attacker; (c) accept and size operator capital at 0.2 GB × heights per day.
Not changed this round (no C/H; this is the trade-off R11-M1 already named, now quantified).

## Other checks (no finding)

* Priority window × global V: the winner must post `max(v_h, V)` — the same as v_h + 1 at the attacked height; its payout
  (`CBOND − GF − FEE + bd/2`) covers about a quarter of the next bond (R11-L1 already documents the honest-capital
  requirement; unchanged).
* Bond escalation × refunds accounting: rolltest's `liabilities()` invariant (rollup balance ≥ outstanding bonds incl.
  `b<sid>` + burned after every transaction) holds across all 444 assertions, including the V = 10 runs.
* Multi-challenger games with `uopen` (rv_seg_ref) use the same callback path (`$st.void` on a live submission) — one
  increment per void regardless of the referee.
* Upgrade × V: an import run at an upgrade height posts `max(v_h, V)` like any submission; reclaim after a cancel pays it back.
* `Vt` defaults to 0 → Vdec is huge → Vnow = 0 on a fresh rollup; Oscript `floor` / comparisons on Decimal state vars
  checked through the real ocore evaluator (rolltest injects `V`, `Vt` as Decimal state).

## Tests this round

| test | result |
|---|---|
| rolltest (sandbox ocore; `stall11` rewritten to show the fix, new group `r12`) | 444 / 444 (`js/rolltest-l12.log`) |
| AA mutants `js/aamut-l12.py` (round-11 set + exponent max / V-only / min, VDECAY ×½ / ×2, no decay, raw V at increment, V write removed, V cap removed, Vt write removed) | 26 / 26 killed (`js/aamut-l12.log`) |
| aacost | rv_rollup 86 / 1 699 (`js/aacost-l12.log`) |
| rolldevnet: `bondAt` = max(v_h, decayed V) on the devnet clock; section 10 adds the R11-M1 checks (V = 1 escalates h2 right after the void; decayed to 0 one day later) | box, see below |

## Box runs

| run | result |
|---|---|
| R10-H1 cap mutation (`loop11-mut.sh`, round-11 step) | **7 / 7 killed** (1–2 cap:markets, 3–5 r10:port_events, 6–7 r10:cap_values) — `guest-engine/results-loop11/l11-mut.log` |
| rolldevnet ONLY10 on the round-12 AAs (`l11go.sh`) | **19 / 19** incl. the two R11-M1 checks (V = 1 → h2 bounces at OBOND with `bond 400000`; one day later V = 0, OBOND) — `guest-engine/results-loop12/l11-rolldevnet10.log` |
| full rolldevnet on the round-12 AAs, first run (`l11-rolldevnet-v1.log`) | 76 PASS / 38 FAIL, exit 1: section 6c submitted h5 at OBOND 1801 + 3601 s after the 6a fraud void — the global V = 1 still applied (`bond 400000`), and every later step cascaded. A test-timeline error (the round-11 script assumed per-height bonds), i.e. the devnet confirms the new rule: 6c now asserts 2 × OBOND for h5 (never voided), the OBOND bounce, and the 2 × OBOND − FEE refund at finalize |
| full rolldevnet, rerun with 6c adapted (`l12rd.sh` → `l12-rolldevnet.log`) | **204 / 204** (RDDONE exit 0; all sections 1–10 incl. section 9 governance and the 4 new R11-M1 devnet checks) — `guest-engine/results-loop12/l12-rolldevnet.log` |
| govwit as the DEFAULT feature (`l11gw.sh` on loop11gw = head + work/govwit-default.patch; no `--features`) | **all green** (GWDONE): default host / guest / prod built with `default = ["govwit"]`; govedge 9/9, govwit leaf-flip 1/1, govfuzz 100/100, xfuzz 100/100, witfuzz 100/100 (37 581 units), segfuzz 100/100, proofs 30 (0 / 78 546 forged), govgen 41–43 through the JS guest 3/3 (1 000 units, engine + roots match), prodheight 16/16, snapguest default 9/9 + prod 9/9 (`results-loop12/l11gw*.log`) |
| govwit default applied in the repo | **done in round 15** (consensus change: MNWIT1 roots of batches with governance state change, others identical; design §7.3.4, `results-loop14/l14-gw.log` green, l10 suite SUITEDONE all green). Was gated on SUITEDONE of the round-10 govwit full suite (`loop10-suite.sh g`; at 19:5x UTC its parts so far are green — fuzz / advfuzz / witfuzz / segfuzz / proofs / scen / selftest / heapsim / liq-snap-cap / robust-limit / guest-poc crowd1800 — and its sequential tail ora / gov / statecap / JS-guest / segments / depth8 / robust is still running) |
