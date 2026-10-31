# rv loop round 13 — R12-M1 fixed (global term capped separately), end-to-end review of the guest ↔ AA boundary (2026-11-01)

Branch `spike/rv-bisect`, parent fa003f5. Status of box runs: table "Box runs" at the end; work/rv-rollup-notes.md
"Loop round 13".

## Summary

| id | sev | where | what | status |
|---|---|---|---|---|
| R12-M1 | M | rv_rollup economics | the global counter amplified honest locked capital on every concurrent height (204.8 M per height at V = 10) | **fixed** (decision 2026-11-01 by the assistant per the owner's brief; owner may override): global term capped separately at VCAP = 6 |
| R13-L1 | L | rv_rollup economics | residual of the R12-M1 trade-off: at the VCAP plateau a moving-height stall costs the fraudster 6.412 M per cycle with a puppet first winner (12.8 M with an honest first winner), linear instead of 102.4 M per cycle at the round-12 cap; stall per cycle still ≈ one slow game | **accepted** with the decision (options: VCAP 7–8, longer VDECAY); quantified in rolltest `r13` (a) and devnet 11a |
| R13-L2 | L | operators | a submission voided by a lower fraud void (not fraud itself) must still be defended in every game opened while it was live: a silent defender loses on the timeout and its stored, possibly escalated, bond (up to 64 × OBOND from the global term, 1 024 × at an attacked height) is split between the challenger and `burned`; `reclaim` stays blocked while `n<sid> > 0` | documented; PoC rolltest `r13` (d): V = 3, honest h2 at 8 × OBOND voided by the h1 fraud void, silent defender → griefer paid `CBOND − GF − FEE + bd/2` (908 000), burned += 800 000, reclaim bounces (operator rule; the rollup cannot tell a timeout win from a step-proof win, and slashing a voided fraudulent submission is wanted) |
| R13-I1 | I | rv_rollup | a defender-timeout win is a fraud void like a step-proof win: it bumps `v_h` and `V`, so an honest operator knocked offline during a griefer game raises every operator's bond (≤ 64 ×, decaying) | by design (liveness is part of the operator's bond); rolltest `r13` (d): silent honest h1 vs a griefer → top 0, v1 = 1, V = 1 |
| R13-I2 | I | rv_game_ref | at a single step with no rv_step memo, the defender wins at the deadline: an honest challenger must post the witness within T (design §8 item 7) | known, re-checked on devnet (11a: every cycle posts the witness, then resolves) |
| R13-I3 | I | rv_seg_ref / rv_rollup | timeout / deadline paths re-checked end-to-end: seg resolve before the deadline bounces (`undecided`), after T the side to move loses; `finalize` before WIN bounces; `reclaim` of a live submission bounces; callbacks on voided submissions do not void again; every payout uses the stored bond | pinned by devnet section 11 (b)–(e) and rolltest |

No C / H this round.

## R12-M1 fix — rule

```
init (after $now):  Vdec = floor((now - Vt) / 86400);  Vnow = V > Vdec ? V - Vdec : 0
submit h:           Vg = min(Vnow, VCAP);  bond = OBOND * 2^min(max(v_h, Vg), MAXESC)      (VCAP = 6, MAXESC = 10)
fraud void at h:    v_h += 1;  V = min(Vnow + 1, VCAP);  Vt = now;  p_h = winner:(now + PRIO)
```

* The per-height term `v_h` still escalates to 2^10 at a repeatedly attacked height (rolltest `r13` (b): V = 6 with
  v1 = 3 / 8 / 15 → 2^6 / 2^8 / 2^10).
* The global term — what every honest operator pays on every height while an attack lasts — is at most 2^6 = 64 × OBOND
  = 12.8 M bytes per height (was 204.8 M). V is stored capped at VCAP, so full decay from the cap takes 6 days
  (was 10). A legacy stored V > 6 is still read through `min(V, VCAP)` (rolltest `r12` (b)).
* rv_rollup complexity 86 / ops 1 707 (round 12: 86 / 1 699; limits 100 / 2 000).

PoC → fix (rolltest `r13`, sandbox ocore):

```
moving-height fraudster, 8 cycles, honest first winner:
  fraud bonds        200 000 / 400 000 / 800 000 / 1.6 M / 3.2 M / 6.4 M / 12.8 M / 12.8 M     total 38.2 M (lost in full)
  V after the void   1 / 2 / 3 / 4 / 5 / 6 / 6 / 6
  honest re-submits  400 000 / ... / 12.8 M / 12.8 M / 12.8 M   (max 12.8 M per height); refunded sum - FEE each at finalize
decay from the cap   days 1..6 after the last void: 2^5 .. 2^0 x OBOND; a new height posts OBOND on chain after 6 days
plateau economics    N = 3 heights / day: honest locked 3 x 12.8 M = 38.4 M (returned) vs attacker burn 6.412 M / day
                     (puppet first winner: bond/2 + GF + FEE); round 12: 614.4 M locked vs 102.412 M burned
```

The ratio honest-locked / attacker-burn is still 2N; what changes is the absolute bound (12.8 M per height) and the
attacker's sustained cost (6.4 M per cycle instead of 102.4 M). That residual is R13-L1.

## End-to-end review of a fraudulent height (guest ↔ AA boundary)

Flow checked step by step against the AA sources (rv_rollup, rv_seg_ref, rv_game_ref, rv_step) and on the devnet
(section 11, rollup-4):

1. **submit** — bond `OBOND × 2^min(max(v_h, min(V, 6)), 10)` at the trigger's MCI time (R12-L2: overpay, refunded
   `paid − bond − FEE`); s0 bound to (ts in x10, carried memory or upgrade image, input root, pc 0, step 0); final root
   bound to (fpc, fregs, fmem, inp, steps); `units` an unverified partition claim (R3-U1).
2. **open / uopen** — live, within WIN, not self, not an AA; uopen forwards 2 GF to rv_seg_ref (devnet 11b: 2 GF real
   output); the referee keys games by opener ‖ ref, so a game opened by anyone else calls back to its own opener.
3. **layer 1 (rv_seg_ref)** — defender posts strictly increasing steps; challenger picks the first disputed interval;
   hand-off to rv_game_ref under `SEG ‖ sha256(gid)` when one unit is left; resolve refused while turn x; a silent side
   loses after T (devnet 11c defender silent → c; 11d griefer silent → d).
4. **layer 2 (rv_game_ref) → rv_step** — bisection to one step; the witness memo decides; without a memo the defender
   wins at the deadline (R13-I2).
5. **callback → void** — only `$GAME` / `$SEG` callbacks with an open `G<ref>`; a fraud win on the live submission sets
   `top = h − 1`, `v_h += 1`, `V = min(Vnow + 1, 6)`, `Vt`, `p_h`; the first winner gets `CBOND − GF − FEE + bd/2`,
   `burned += bd − bd/2` (bd = stored bond); later wins on the same (now voided) submission pay only `CBOND − GF − FEE`.
   Money balance per game: open receives CBOND (uopen CBOND + GF), forwards GF (2 GF), pays 108 000, keeps FEE.
6. **resubmit** — only the winner for PRIO s (devnet 11b: op1 bounces inside ch2's window), at the escalated bond.
7. **finalize / reclaim** — window over, no open game, chained on h − 1; pays the stored bond − FEE (devnet 11e: nine
   real payouts equal `b<sid> − FEE`); reclaim only for non-live, non-fraud, no-game submissions (R13-L2).

No C / H / M found. The liabilities invariant (rollup balance ≥ outstanding bonds incl. `b<sid>` + burned after every
transaction) holds across all 475 rolltest assertions.

## Tests this round

| test | result |
|---|---|
| rolltest (sandbox ocore; `r12` (a)/(b) adapted to VCAP, new group `r13` (a) plateau (b) per-height to 2^10 (c) decay (d) R13-L2 / R13-I1 PoCs) | **475 / 475** (`js/rolltest-l13.log`) |
| AA mutants `js/aamut-l13.py` (round-12 set re-targeted + 6 VCAP mutants: no global cap, max instead of min, cap at MAXESC, VCAP 7 / 5, V stored at MAXESC) | **32 / 32 killed** (`js/aamut-l13.log`) |
| aacost | rv_rollup 86 / 1 707 (`js/aacost-l13.log`) |
| rolldevnet section 11 (ONLY11) / full | box: **57 / 57** / **255 / 255**, see below |

## Box runs

| run | result |
|---|---|
| rolldevnet ONLY11 on the round-13 AAs, first run (`l13-rolldevnet11-v1.log`) | 20 PASS then FAIL cascade from cycle 3: a test bug — the fraud traces used mutation step k = 63..66 but a height runs 62 steps, so h4..h7 were not fraudulent and the defender won (`d`). Stopped (ours), k changed to 3 + c / 20 / 21 / 30 |
| rolldevnet ONLY11 rerun (`l13rd.sh`, /data/hark/spike-rv/loop13) | **57 / 57** (RDDONE exit 0) — `guest-engine/results-loop13/l13-rolldevnet11.log`: 7 cycles bonds 0.2 → 12.8 M, V 1 → 6 and stays 6, each first winner paid `CBOND − GF − FEE + bond/2` as a real output; 11b layer-1 → layer-2 → rv_step fraud proof at h8 (unit [1,2], steps [12,24]) pays 6 508 000, op1 bounces inside ch2's priority window; 11c defender-silent seg game → c after T (V stays 6, v9 = 1); 11d griefer-silent → d, operator paid 108 000; 11e nine finalize payouts = stored bond − FEE (398 000 … 12 798 000), burned 25 500 000 = Σ fraud bonds / 2, balance − burned = 155 499 (kept FEEs / bounce fees), decay V 5 → 0, h10 at OBOND |
| full rolldevnet on the round-13 AAs (`l13full.sh`) | **255 / 255** (RDDONE exit 0; sections 1–10 = the 204 round-12 checks unchanged + section 11's 51 checks after its deploy) — `guest-engine/results-loop13/l13-rolldevnet.log` |
