# rv loop round 9 — R8-L4 test, round-8 suite, R7-L3 design refinement, fresh review of the rollup / AA layer (2026-11-01)

**Status: DRAFT (loop round 9, 2026-11-01 ~01:00 CST, branch spike/rv-bisect).** Suite rows marked *running* were not
finished when the shared VM's logs were collected; the VM auto-suspends ~02:58 CST and keeps its processes.

Target: `lhxmall/Minuend` branch `spike/rv-bisect` @ 95f79e9 (loop round 8). Reference engine read only via
`git archive 20326c0` (engine-diff/engine-src); fix/47-all, main and PR #51 untouched.

Work items:

1. **Box hygiene** (VM load ~30 on 4 vCPU, 78 % steal; /data 83 %). Stopped our own superseded jobs (all under
   /data/hark/spike-rv, process groups we started): `loop5-suite.sh c` and `loop6-suite.sh c` (round-5/6 code, superseded
   by the round-7/8 suites; were in robust-limit / guest-poc / liqfuzz 300 at nice 19), `l4-post.sh` → `loop4-mut2.sh`
   (round-4 survivor re-run; the survivors were settled in rounds 6/8: 35 killed, 37 / 52 / 9 equivalent), `loop5-mutff.sh`
   and `loop6-mutff.sh` (fail-fast mutation of round-5/6 code; superseded by the round-7/8 mutation subsets). Partial
   results kept in `l4-mut2.log` (survivors 4, 5, 6, 9, 10, 11, 13, 15, 17, 18, 21, 23, 24, 27, 32 re-run: all survived the round-4 checks, as
   recorded; their later status is in rv-loop-5/6/8),
   `l5-mutff.log` (6, 10, 13, 15, 17, 18 killed; 9, 11 survived = equivalent per R8-T3 / rv-loop-4 #11 (`external_twap`
   unreachable); stopped before the round-5 mutants 62..79), `l6-mutff.log` (80, 81 killed; 37, 52 survived = equivalent, round 6; stopped before 82..111 — the round-6 governance
   rules they mutate were re-mutated against newer code in the round-7/8 subsets). Deleted our old build
   dirs `/data/hark/target-l4*`, `-l5*`, `-l6*`, `-l7a-*`, `-l7-mut*`, `-wit-mut` (list in `/data/hark/logs/rv/r9-deleted-dirs.txt`):
   /data 83 % → 73 %. Kept: round-7/8 builds (suites still running), target-r2-* / target-all (other workstreams of the
   project), devnet testdata (a devnet was running). Load after the stop: ~9–15.
2. **Round-7 collection**: rolldevnet **149 / 149** (rv-loop-7 row filled). The round-7 suite's JS-guest jobs
   (robust-limit, guest-poc) and liq/snap/cap 300 were still running; the round-8 suite re-runs all of them.
3. **R8-L4 closed**: `engine-diff govd8` (depth8 build only) — a table id G whose `acct:` / first `ord:` keys are shallow
   but whose `pos:<G>:1` key shares ≥ 8 bits with an existing key (found at id 30, first candidate), G deposits, gov-deposits
   the bond, commits Place(G, market 1), reveals it → the port emits **18** for the Reveal (upstream would apply it; the unit
   is appended port-only with its real unit id, `GB::port_only`), a direct Place → 18 too; control: a shallow author's
   commit + reveal applies and real == port. govd8 2 / 2 on the round-8 code; **round-7 mutant 6 (inner-op depth check
   dropped) is KILLED** (`d8:reveal_inner_deep`). Test-bug fixed on the way: the first govd8 compared `run_port` events,
   which runs `WitMode::Off` (no tree → no depth rule); it now uses the incremental-mode per-unit slices (`l2::port_units`).
4. **Round-8 full suite** (`loop8-suite.sh c`, sources = round-8 code + govd8, builds `target-l8c-*`; + xfuzz 300 and
   govd8 added) started 16:54 UTC; round-8 devnet (`l8rd.sh`, roll8) after the round-7 devnet; rolltest / aacost on the
   round-8 and round-9 AAs on the box (`l9rt.sh`); round-9 devnet queued (`l9rd.sh`).
5. **R7-L3** — design refined, then **implemented as an opt-in cargo feature `govwit`** (default builds unchanged): governance
   leaves `prop:` / `cmt:` / `gnon:` in the port's MNWIT1 tree and in the harness's real-engine mirror; quick differential
   suite green on the govwit build (results below). Not yet the default: rv_witproof has no rolltest case for the new kinds
   and the full suite has not run on it.
6. **Fresh adversarial review of the rollup / AA layer** (rv_rollup incl. ts / upgrade / xbind, rv_seg_ref, rv_game_ref,
   rv_step, rv_witbind, rv_witproof): one **H** (R9-H1, fixed), three L, eight I.

Severity as in rounds 1–8: **C** = honest party loses / wrong verdict on reachable input; **H** = guest ≠ host,
undefined guest outcome, or a protocol-reachable state loss / halt; **M** = design/spec gap with a concrete failure
mode or a defense-in-depth hole; **L** = minor / documentation; **I** = checked, no defect.

Totals: **C 0 · H 1 (fixed) · M 0 · L 4 (R8-L4 closed, R9-L1, R9-L2, R9-T1 open) + R7-L3 implemented opt-in (`govwit`) · I 8**.

| id | sev | area | title | status |
|---|---|---|---|---|
| R9-H1 | H | rv_rollup upgrade | **an upgrade at h whose h−1 is not a proven export run bricks finalization for good**: `finalize h` needs `x(h)` kind 2 and `x(h−1)` kind 1 with equal digests; once h−1 is finalized as a normal run (kind 0) that can never hold, and a re-schedule must satisfy `h' > lf` and `h' ≤ uh` (R5-M1), i.e. `h' = h` — no command could leave the state. Reachable (a) by a governance mistake (schedule at `top + 1` while `top` is a normal run, then 24 h pass — `finalize` is permissionless) and (b) **permissionlessly**: with an upgrade pending, any fraud void at a height ≤ h−1 (one's own pre-placed fraudulent height, half its bond burned) re-opens the race at h−1, and any submitter may re-submit h−1 as a valid normal run that no challenger can dispute | **fixed** (2dd7811, f48109e): governance `cancel` clears `U<uh>` / `uh` and voids the live heights ≥ uh (`top = min(top, uh − 1)`, not fraud, bonds reclaimable). PoC + fix in rolltest `upgrade R9-H1` (17) and `cancel9` (7); rolltest 357 / 357; AA mutation `aamut-l9.py` 6 / 6 killed; rv_rollup complexity 73, ops 1 573 |
| R8-L4 | L | tests | round-7 guest mutant 6 (inner-op W2 depth check dropped) survived every check | **closed**: `govd8` kills it (item 3) |
| R7-L3 | L | witness | proposals, commits and gov nonces are not MNWIT1 leaves | **implemented behind feature `govwit`** (opt-in; GOVWITROW); default off until the full suite and rv_witproof cases run on it |
| R9-L1 | L | rv_rollup upgrade | `finalize` of uh−1 does not require its export proof, so a non-export uh−1 still finalizes and the stall only shows at uh | documented: a guard (`U<h+1>` pending ⇒ `x(h)` kind 1 before `finalize h`) would stop h−1 instead — still a stall that needs governance; `cancel` is the recovery either way. Operational rule: schedule an upgrade at `top + 1` only when `top` is an export run that has been xbound (`x(top)` kind 1), and cancel if a void re-opens uh−1 |
| R9-L2 | L | rv_rollup trust | the governance address can void every live height ≥ lf + 1 at will (upgrade / cancel), discarding operators' work (bonds are reclaimable) | documented trust assumption (as R3-H2 / R4-S1): `$GOV` is a fixed address baked by mkrollup |
| R9-T1 | L | tests | upgrade / xbind / cancel run only on the sim chain (real ocore evaluator, `chain.js`), never on a devnet: rolldevnet bakes `GOV` = the fixed test address `GOVXXX…`, which no devnet wallet controls | open: rolldevnet with `GOV` = a devnet wallet and one upgrade → xbind → finalize + one cancel flow |
| R9-I1 | I | rv_rollup → rv_game_ref | `open` forwards `n: $r[4]` (a string from `split`) while `uopen` uses `+$r[4]` | no defect: ocore casts numeric strings in trigger data (R7-I1), rolltest / rolldevnet games pass `is_integer($d.n)`; noted for a cleanup |
| R9-I2 | I | rv_seg_ref | can an honest defender be unable to post points (`need cnt points` strictly inside (slo, shi))? | no, if it places points at true unit ends: every unit runs ≥ 1 instruction, so an interval of k units spans ≥ k steps; a defender placing points elsewhere only hurts itself |
| R9-I3 | I | rv_seg_ref / layer 2 | is the layer-2 game slot unique and the callback routed back? | yes: rv_game_ref id = SEG ‖ sha256(opener ‖ ref), `x_<sha256(gid)>` maps back (round-3 design, unchanged) |
| R9-I4 | I | xbind | xbind of a voided or non-upgrade submission | harmless: the value is a Merkle-proven function of the final memory root; only `finalize` of an upgrade height reads it |
| R9-I5 | I | rv_witbind × cancel / upgrade | can cancel / upgrade change what a bound height means? | no: both act only above lf (`p > lf`, `h > lf`); rv_witbind binds `h ≤ lf` only, and a finalized height's winner never changes (`submit` needs `h = top + 1 > lf`) |
| R9-I6 | I | rv_rollup callbacks | a referee result for a submission voided by upgrade / cancel | fraud is still recorded and paid (first fraud: OBOND / 2 to the challenger, half burned); `reclaim` waits for `n = 0`; covered by rolltest `upgrade` / `cancel9` and the invariant check |
| R9-I7 | I | constants | rv_witbind / xbind word indices | `0x03F00000/4 +` 0x1FFE8 = 16646120, 0x1FFF9 = 16646137, 0x1FFE7 = 16646119, 0x1FFD6 = 16646102 (digest words at +2..+9) — all match the guest's OUT layout |
| R9-I8 | I | AA budgets | after the cancel branch | rv_rollup 73 / 1 573, rv_witproof 69 / 1 604, rv_witbind 16 / 1 425, rv_seg_ref 18 / 1 443, rv_game_ref 10 / 848, rv_step 10 / 1 850 (ocore 0.4.8 validateAADefinition, sandbox) |

## R9-H1 — PoC and fix

```
h1 normal run (kind 0) submitted
GOV {upgrade: 2, mem: UM}            accepted (h = top + 1 = 2 > lf = 0)
import h2 from UM submitted; 24 h pass
{finalize: 1}                        accepted  -- h1 (kind 0) is final now
{xbind: h1}                          bounce 'kind'           (no export to prove)
{finalize: 2}                        bounce 'import digest'  -- forever
GOV {upgrade: 3, mem: UM}            bounce 'upgrade pending at 2'
GOV {upgrade: 2, mem: UM}            accepted, but U2 stays: still stuck
```

Permissionless variant (`cancel9`): h1 honest, h2 fraudulent (pre-placed), `upgrade 3` while h2 is live, the fraud is
proven (top = 1 < uh − 1 = 2), and anyone re-submits h2 as a normal run — after its window it finalizes and the rollup
is in the state above.

Fix (rv_rollup.oscript, mkrollup.js state):

```
else if ($d.cancel) {
	require(trigger.address == $GOV, 'not governance');
	$p = var['uh'] OTHERWISE 0;
	require($p > $lf, 'no pending upgrade');
	$st = {cx: $p, ctop: min($top, $p - 1)};
}
state:  var['U' || $st.cx] = false;  var['uh'] = false;  var['top'] = $st.ctop;
```

Why not "allow re-scheduling above a pending upgrade": the heights ≥ uh were started from `U<uh>`; clearing `U<uh>`
without voiding them would let them finalize as **normal** heights (no digest check) — an unchecked state import.
`min(top, uh − 1)` keeps a top a fraud void already lowered (otherwise a voided fraudulent height would become live
again; `aamut-l9` mutant 3).

## R7-L3 — governance state in MNWIT1 (refined design, then implemented behind feature `govwit`)

### As implemented (round 9, feature `govwit`; guest-engine + engine-diff)

* `wit.rs`: `prop_leaf` / `cmt_leaf` / `gnon_leaf` (+ `*_kid`), texts exactly as in the design below except that the
  weight snapshot is committed **by its size** (`|weight_snapshot|`, no digest: the cost trap below); `WitDirty` gains
  `props` / `cmts` / `gnon`; `Wit::apply` puts / deletes them; `Wit::from_state` (genesis, snapshot import) and
  `all_leaves` (scratch roots) include them.
* Dirty marks at every write site (all `#[cfg(feature = "govwit")]`): GovWithdraw nonce, CreateProposal, Vote (marked
  before the lookup; a rejected vote re-puts an unchanged leaf), FinalizeProposal (delete), Commit, Reveal + reveal_undo,
  `prune_commits` (every pruned hash; runs in the height hook, so empty segments carry it, R5-L4).
* Harness: `real_pilot_leaves` mirrors the three kinds from the REAL engine's `proposals` / `commits` /
  `seen_gov_nonces` (HashMap / HashSet iterated sorted); `smt_ref::pilot_leaf` accepts the tags; `engine-diff govwit`
  checks each writer flips exactly its leaf (create, vote changes the value but not the kid, nonce, commit, reveal flips
  `revealed`, prune deletes `cmt:`, finalize deletes `prop:`) and real == port per unit.
* Not done: W2 depth arms for `cmt:<hash>` (author-chosen hash; at MAX_WIT_DEPTH 64 a too-deep key needs a 2^64 grind,
  so this is the same class as the unchecked side-effect insertions), rv_witproof rolltest cases for the new kinds (the
  Oscript kid rule handles them by construction: one ':' in each kid), full suite / JS-guest-at-scale on the govwit image.

### Design (as refined before implementation)

Leaves (text as `wit.rs` writes it; kid = text before the 2nd ':' — rv_witproof's rule needs no change because every
new kid has exactly one ':'):

```
prop:<id>   ':' creator_hex ':' market ':' key ':' value ':' created_seq ':' deadline_seq ':' supply ':' yes ':' no ':' |voted| ':' snap_digest
cmt:<hash_hex> ':' account_hex ':' commit_unit_hex ':' commit_height ':' ttl_height ':' revealed(0|1)
gnon:<account_hex> ':' last_nonce
```

* `snap_digest` = sha256 over the proposal's `weight_snapshot` in key order (`acct_hex ':' weight` joined by ','), so a
  vault can prove a voter's weight with the snapshot it reads elsewhere; `voted` is committed as a count only (the set is
  bounded by R6-H2's 64 + snapshot). **Cost trap found while refining:** the snapshot is immutable after CreateProposal
  but can hold ~20 000 entries (govcap: 19 999 voters), so re-hashing it whenever `prop:<id>` is dirty (every Vote) costs
  ~1.6 MB of SHA-256 per vote unit in the guest. The digest must be computed once at creation and cached next to the
  proposal (a pilot-only field, recomputed on snapshot import, not part of the snapshot format or the state hash), or the
  leaf commits `|weight_snapshot|` only (weaker: no weight proofs).
* Writers / dirty hooks (guest @ 95f79e9, every write site of the three maps): `engine.rs` 955
  (`seen_gov_nonces.insert`, GovWithdraw) → `gnon:<acct>`; 1067–1070 (CreateProposal, `next_proposal_id`), 1091 (Vote,
  `get_mut`), 1139 (FinalizeProposal, `remove` → delete the leaf) → `prop:<id>`; 1156 (Commit `insert`), 1186 / 1190
  (Reveal `revealed = true`) → `cmt:<hash>`; `state.rs` 358 (`prune_commits` `retain` → mark every removed hash; it runs
  in the height hook, so the empty-segment end root must include it, cf. R5-L4); snapshot import (`snapshot.rs` 648 /
  654 / 665) is covered by `Wit::from_state`. A dirty mark on a unit that is then rolled back is harmless (an unchanged
  leaf re-puts to the same hash; an absent one is a no-op remove).
  A per-kind dirty set in ChainState (`dirty_props`, `dirty_cmts`, `dirty_gnon`), drained by `Wit::commit_unit` next to
  the account set; `all_leaves` emits the three kinds for scratch roots, snapshot import rebuilds them from state.
* W2 depth rule (`wit_depth_ok`) new arms: CreateProposal → `prop:<next_id>`, Commit → `cmt:<hash>`, GovWithdraw by an
  author without a nonce → `gnon:<author>`; a Reveal's inner op is checked as today. Of these only `cmt:<hash>` is
  author-chosen (the hash is free): it is the one that needs the check most (a 2^64 grind at depth 64 stays infeasible).
* Harness: upstream `wit_leaves` has no such leaves, so `real_pilot_leaves` gains a mirror built from the real engine's
  `proposals` / `commits` / `seen_gov_nonces` with the same text; witfuzz / govfuzz / xfuzz then compare port-incremental,
  port-scratch and real-mirror roots per unit as for the other kinds; `proofs` adds membership / absence for the three kinds.
* Tests: govedge case 9 (each writer flips exactly one leaf; prune deletes `cmt:`), depth8 arms in `govd8`, rv_witproof
  rolltest cases for `prop:` / `cmt:` / `gnon:` membership + absence, snapshot round trip.
* Harness specifics: `smt_ref::pilot_leaf` gains `prop` / `cmt` / `gnon`; upstream's `seen_gov_nonces` is a HashMap and
  `Proposal::voted` a HashSet (iterate sorted); `ParamKey` must print as the port's u8.
* Cost estimate: ~250 lines guest + ~120 harness + tests; all MNWIT1 roots of governance batches change (round-6+ fixtures
  and JS-guest expectations are recomputed by the harness, not hand-kept); one full suite (~3–4 h on the shared VM).
  First judged too large for the round; once the round-8 suite was moving it was implemented **opt-in** (feature
  `govwit`), so the default images and every running suite stay on the round-8 commitment format until the govwit build
  has had its own full suite.

## Round-9 results (sandbox + InstaBox VM; logs `guest-engine/results-loop8/`, `results-loop9/`)

| check | result |
|---|---|
| govd8 (depth8 build, round-8 code) | 2 / 2 (ground id 30) |
| round-7 mutant 6 vs govd8 | **killed** (`d8:reveal_inner_deep`) |
| govedge / depth8 on the d8 build | 8 / 8 · 5 / 5 |
| rolltest (round-9 AAs, sandbox ocore 0.4.8) | 357 / 357 (new: `upgrade R9-H1` 17, `cancel9` 7) |
| AA mutation `aamut-l9.py` (cancel: gov check, `p > lf`, `min(top, ·)`, U / uh / top writes) | 6 / 6 killed |
| aacost | see R9-I8 |
| rolltest / aacost on the box ocore (`l9rt.sh`) | round-8 AAs 333 / 333 · round-9 AAs 357 / 357; aacost as R9-I8 |
| rolldevnet round 9 (`l9rd.sh`, after the round-8 devnet) | RD9 |
