# rv loop round 11 — R10-M1 fix (escalating bond + winner priority), cap mutation, govwit default, review (2026-11-01)

Branch `spike/rv-bisect`, parent 6831c2d. Status: **DRAFT** (box steps pending at the time of writing; see
work/rv-rollup-notes.md "Loop round 11" for what ran where).

## Summary

| id | sev | where | what | status |
|---|---|---|---|---|
| R10-M1 | M | rv_rollup economics | stall for OBOND per slow game by re-submitting a fraudulent h | **fixed** (owner decision 2026-11-01): escalating bond per height + 1800 s winner priority |
| R11-M1 | M | rv_rollup economics | the per-height escalation does not cover a fraudster that moves up one height per cycle: throughput ≤ 1 height per slow game for OBOND per cycle (rolltest `stall11`) | **open** (design option below; owner decision) |
| R11-L1 | L | rv_rollup economics | the bond cap 2^10 × OBOND = 204 800 000 bytes must be posted by whoever re-submits h after 10 fraud voids (the honest party too; returned at finalize) — a liveness requirement on honest capital | accepted (documented) |
| R11-L2 | L | rv_rollup | the priority window binds h for PRIO even when the winner never submits (puppet case): +1800 s per cycle on top of the game | accepted |
| R11-I1 | I | port (upstream verbatim) | `apply_slash` removes the target's report / history in the slashed market only; its reports in the other markets stay (filtered by `oracle_bonds` when read, revived if the id re-stakes). Bounded: keys are (market, oracle id), oracle ids need a PERP ledger entry (≤ 256), markets ≤ 16 → already inside the R10-H1 measurement `mktcap 256 16 256` (28.55 MB). No fix in the pilot. | info |
| R11-I2 | I | tests | govedge `r10:cap_values`: harness and port share MAX_STATE_MARKETS / MAX_STATE_ORACLES, so only an absolute check sees a changed cap value (the 46.1 MB bound was measured at 16 / 32) | added |

No C / H this round (review of the round-10 caps and the round-11 rollup change).

## R10-M1 fix — rule (rv_rollup, mkrollup.js state)

* `bond_h = OBOND × 2^min(v_h, MAXESC)`, `MAXESC = 10`; `v<h>` counts **fraud voids** at h (a winning challenger result on
  the live submission of h; upgrade / cancel voids and results on already-voided submissions do not count).
* The posted bond is stored as `b<sid>` when above OBOND; every payout uses it: finalize / reclaim `bond − FEE`, the first
  winner `CBOND − GF − FEE + bond/2`, `burned += bond − bond/2`, submit refund `paid − bond − FEE`.
* After a fraud void at h, `p<h> = winner:until` (until = void time + PRIO, PRIO = 1800 s): only the winner may submit h
  before `until`; at `until` anyone may.
* Cap reasoning: 2^10 keeps the worst-case bond (0.2 GB) payable by an honest operator; at the cap the per-cycle cost is
  constant at ≈ OBOND × 2^9 = 102 400 000 bytes per stall cycle (through a puppet) instead of doubling.
* Budgets: rv_rollup complexity 82 / ops 1 663 (was 73 / 1 573; limits 100 / 2 000).

PoC / evidence (rolltest `stall10`, sandbox ocore, 4 cycles, 3 bisection rounds):

```
worst case: the fraudster's puppet challenger wins first every cycle (holds the window, re-submits the fraud)
bond per cycle      200 000 / 400 000 / 800 000 / 1 600 000
net cost per cycle  112 000 / 222 000 / 422 000 / 822 000   (bond/2 + GF + FEE; +10 000 test bounce fee in cycles >= 1)
ratio               1.98 / 1.90 / 1.95  -> 2
stall per cycle     3.07 h (unchanged: ≈ one slow game; 8–10 h at real step counts)
burned              1 500 000 = Σ bond/2
honest winner first: the fraudster's re-submit inside the window bounces, the winner submits the honest h (2 × OBOND), h finalizes
after the window: anyone submits h at OBOND × 2^4; it finalizes and gets bond − FEE back
cap: at v = 15 the bond is OBOND × 2^10 (−1 bounces, exact accepted)
```

So the priority window alone is beaten by a puppet that wins first (the fraudster defends both games and can always
let the puppet's game end first); the escalation is what bounds the attack: n stall cycles at one height cost
≈ OBOND × 2^(n−1).

## R11-M1 — moving-height stall (PoC: rolltest `stall11`)

```
cycle c: the fraudster wins the top+1 race for h = c+1 (chained on the honest h-1), bond OBOND (first void at h);
         the honest challenger proves fraud (slow defence), h is voided, the winner re-submits the honest h
4 cycles: bonds 200 000 each (no escalation), 3.08 h between consecutive honest heights; cost 800 000
```

Each height can only start its 24 h window after the previous fraud at that height is resolved, so throughput drops to
≈ one height per slow game (8–10 h at real step counts) for OBOND per cycle (≈ OBOND/2 with a puppet first winner).
Precondition: the fraudster wins the top+1 race once per cycle (it races honest operators' submits of the next height;
MCI order decides). Option (owner decision, not implemented): a **global** fraud-void counter with time decay
(`V` = voids, −1 per 24 h) entering the exponent as `max(v_h, V)`: the attack becomes geometric across heights; cost:
during an attack honest operators post the escalated bond too (returned at finalize). **Prototyped, not adopted:**
`findings/r11m1-option.patch` (rv_rollup `V` / `Vt`, VDECAY 86 400 s; rolltest `bondFor` honours it under `R11OPT=1`):
rv_rollup 86 / 1 697; rolltest 410 / 415 with only the five `stall11` PoC assertions failing as intended — the moving-height
fraudster now posts 200 000 / 400 000 / 800 000 / 1 600 000 (cost 3 000 000 for 4 cycles instead of 800 000)
(`findings/r11m1-option-rolltest.log`). Pitfall found while prototyping: Oscript locals defined before `$now = timestamp`
read it as false/0 — the decay term must come after `$now` (the adopted code only uses `$now` in the submit branch and
in the state block, both after it).

## Tests this round

| test | result |
|---|---|
| rolltest (sandbox ocore, all groups incl. `stall10` rewritten, `stall11`) | 415 / 415 |
| AA mutants `js/aamut-l11.py` (bond formula, cap, priority check / boundary / PRIO, refund, payouts, b / v / p state writes, burned) | 16 / 16 killed |
| aacost | rv_rollup 82 / 1 663; others unchanged |
| R10-H1 cap mutants (`loop11-mut.sh`, box) | _pending_ |
| govwit default (step 2) | _pending_ (needs l10 suite + l10h green) |
| collection rounds 7 / 8 / 10 | _pending_ (box suspended) |
