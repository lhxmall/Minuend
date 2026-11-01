# rv loop round 21 — stateless ADL remainder (rank sub-trees), round-20 close-out (2026-11-01)

Branch `spike/rv-bisect`, parent 960e87b (round-20 head). Design: `docs/rv-stateless-guest.md` §2 (leaves), §4
(Liquidate / rank maintenance), §11, §12.2 "Round-21 implementation". Code: `guest-engine/src/stateless/adl.rs` (new),
`PTree::decode_raw` + tag 5, run-loop wiring and `Need::Adl / AdlTop / AdlKey` in `stateless.rs`, `SL_ADL_SIDE` in
`engine.rs`; harness `engine-diff/src/sl.rs` (`slpoc21`, `adl_segments`, `slpoc17` round-21 semantics). Box logs:
`guest-engine/results-loop21/`. Notes: work/rv-rollup-notes.md "Loop round 21". Pushes: Radicle first, then GitHub.

Status: **FINAL** (closed in round 22: mutant passes, kills of the non-equivalent survivors, CI)

## What was done

1. **Round-20 close-out**: final-binary (9f20286) logs collected (results-loop20), rv-loop-20 Tests filled and FINAL;
   pass-2 mutant survivors pre-slash-omk-off / pre-slash-hist-off killed by the new `slpoc20` P9 (single omissions from
   the Slash witness); the remaining survivors explained as equivalent (rv-loop-20 Tests). Sail 64-account
   measurement: see Tests.
2. **Stateless ADL remainder (R17-H1, design §12.2)** — bounded alternative to the `adlq:` trie + `adlv:` / `alk:` lists:
   one **rank sub-tree** per (market, sign), a compact SMT whose keys are the ADL rank itself
   (`BE(u64::MAX − |qty|) ‖ AccountId[0..24]`), its root in the MNWIT-S leaf `adlr:<m>:<sign>`. The leftmost leaf is
   the session's counterparty (|qty| descending, AccountId ascending). A unit that reaches the remainder must show the
   candidates' tree's leftmost leaf (tag 5: key + id, verified) and load that holder; every position change moves the
   holder in the trees (post-unit and post-hook maintenance); the end root writes each loaded tree's root.
   Rounds 17–20: such a unit was UNSUPPORTED (a height with one could not be proven statelessly).
3. Adversarial review (below), PoCs (`slpoc21` P1 / P2, `slpoc17` now requires the ADL segments PROVEN), guard mutants
   (`loop21-mut.py`), full stateless regression, riscv32 stateless guest build, Radicle CI.

## Summary of findings

| id | sev | where | what | status |
|---|---|---|---|---|
| R21-L1 | L | operator builder of the rank sub-trees (first form, 3756542) | a rank leaf was sent unverified (tag 2) when only its own key was on the path; an in-segment removal can collapse its parent and lift it onto another key's path, where an insertion needs a verified split leaf -> the guest asks `AdlKey` again and the honest operator loops (no witness: the segment cannot be proven by this operator). Seen as need loops in slmig / slfuzz gen / perp / gov / slpoc21 and a Radicle CI failure on 3756542. The guest was right (refusal, never status 0) | **fixed** (5c8bcfa): every emitted rank leaf is tag 5 (64 bytes, as long as tag 2) |
| R21-I1 | I | ADL remainder (R17-H1) | the book-path ADL remainder is now proven: slpoc17 6/6 ADL segments status 0 = session (round 20: 6/6 unsupported), slpoc21 P1 with 2 000 extra holders + whale / tie = session | closes R17-H1 for the book path |
| R21-I2 | I | rank key | the key holds 24 of the 32 id bytes: two holders of one market with the same |qty| and the same 24-byte id prefix would collide. Ids are hashes of ed25519 keys (192-bit prefix collision not reachable); the guest refuses an insertion onto a present key as UNSUPPORTED instead of mis-ranking | documented assumption |
| R21-I3 | I | cost | every position change of a non-insurance account costs a removal + an insertion path in the market's rank sub-trees (O(log holders) + the shared-prefix chain of equal |qty| — 2 witness bytes per single-child level), plus one leftmost path per ADL unit. Measured: rank section of an ADL segment's witness 1.4–2.1 KB, 1.9–3.1 KB with 2 000 extra holders in the market (the rest of the witness growth with the extra holders — 179 -> 431 KB — is the MNWIT-S multiproof: deeper paths and more single-leaf siblings sent as verified leaf strings; the account records grow by one, the whale); guest hashes +5 % (liq) to +34 % (perp) over round 20, witness bytes +1.6–4 % (Tests) | measured |
| R21-I4 | I | funding-rate markets | the off-book ADL of a funding-rate market ranks by unrealized funding cash (mark-dependent): still unsupported with the whole liquidation of such a market (and with funding, R20-I1). A revealed Liquidate stays unsupported | unchanged |

Review notes (no finding): the tree content is bound by `adlr:` (checked present / absent against MNWIT-S) and the
sub-tree root; a verified rank leaf binds key and id (`sha256("~R1:" ‖ key ‖ id)`, key[8..] = id[..24]), tag 5 is
accepted only by `decode_raw` and tag 4 is refused there; the pick runs on the tree as of unit start (this unit's
maintenance runs after it) and checks the top holder's current tree entry against the leaf; an ADL fill whose maker
is not that holder is BADWIT (defence); every loaded holder is in the start tree under its loaded position (the tree is
a pure function of the session state), so none can rank before the leftmost leaf; the maintenance moves exactly the
dirty accounts whose (sign, |qty|) changed (rolled-back units change nothing); `AdlTop(k)` = removals + 1 bounds the
start keys that can be the current minimum; insurance is in no tree (the engine never picks it); the target is in the
other sign's tree; an empty tree = no candidate anywhere = the session's empty candidate list. Grinding ids to share
prefixes lengthens only the grinder's own paths (≤ 256 levels).

Totals: **C 0 · H 0 · M 0 · L 1 (fixed) · I 4**.

## Tests

Logs: `guest-engine/results-loop21/` (box /data/hark/logs/rv). Binaries (engine-diff, CARGO_TARGET_DIR
/data/hark/target-spike, profile dir l20, copied to loop21/bin): 0ac4c10b / b8e8d7ee (first form, 3756542), 04bc0679
(R21-L1, 5c8bcfa), 77501a7d (+ sub-tree hash stats, slpoc21 P3), 6aa6f9f3 (+ P3b), b206e9e5 (+ account-record count;
final guest code = 77501a7d's).

| what | result | log |
|---|---|---|
| first form (3756542) | slpoc21 / slpoc17 ok, but the regression showed operator need loops on `AdlKey` (slmig 17/20, slfuzz gen 48/60, perp 34/40, gov 96/100, slpoc21 P1 7/8) -> **R21-L1**; Radicle CI FAILURE (slfuzz 10 300) | old21/l21-reg-pre-l1.log, old21/l21-gov-pre-l1.log |
| ADL PoCs (final) | **slpoc17 20×300: 6/6 ADL segments PROVEN** (status 0 = session root + events; round 20: 6/6 unsupported), extra-holders witness identical; **slpoc21 30×300**: 8/8 ADL segments proven; P1 (2 000 extra holders of the candidates' sign + whale + tie) 8/8 status 0 = session root (whale / tie picked in 7, the 8th inflated state does not reach the remainder), rank section 2.1 KB -> 3.1 KB, account records 19 -> 20 (the whale); P2 204 forged witnesses (omissions of Adl / AdlTop / AdlKey / Account, t_adrop 1-4) 174 refused, 30 identical, **0 wrong**; P3 the ADL unit alone 8/8 proven; P3b (forged sub-tree + top holder dropped + second holder loaded) all refused | l21-govF.log, l21-regF.log, l21-slpoc21-final.log |
| regression (final guest code) | slpoc15 / slcaps ok; slmig 20×300 (0 / 5) 20/20; slfuzz gen 60/60, perp 40/40, wd 30/30, ora 30/30, **liq 10/10 with 0 unsupported segments** (round 20: 4; 717 liquidation units proven, round 20: 705); sladv perp 6 495 + gen 5 458 + **liq 47 507** cases **0 unsound** (incl. `omit:adl`) | l21-regF.log |
| gov / oracle suites (final guest code) | slpoc18 20000 ok; slpoc20 P1–P9 ok; slfuzz gov 100/100; sladv gov 25 971 cases 0 unsound; slmiggov 30/30; slora 40×300 h1, 30×400 h40 ok; slora adv 15×600 + 10×400 h60: 82 871 cases 0 unsound; govfuzz 30/30 and liqfuzz 20/20 real engine = port | l21-govF.log |
| cost (slfuzz, sl_hashes now count the exception / rank sub-tree node hashes and the rank leaf hashes) | guest hashes vs round 20: gen 805 365 (+17 %), perp 300 658 (+34 %), wd 387 076 (+16 %), ora 343 591 (+17 %), liq 1 731 176 (+5 %); witness bytes +1.6 – 4 % (gen 21.08 MB vs 20.46, perp 6.32 vs 6.07, liq 58.9 vs 58.0) | l21-regF.log, ../results-loop20/l20-reg.log |
| riscv32 stateless guest build | clean (release, `stateless`, riscv32im) on 3756542 / 5c8bcfa / final sources | l21-b1.log, l21-b4.log, l21-b6.log |
| round-20 survivors vs slpoc20 P9 | pre-slash-omk-off **KILLED**, pre-slash-hist-off **KILLED** (slpoc20 P9), report-orep-both-off survives (equivalent: the loader's ohist-needs-its-report-set rule) | l21-mut20.log |
| ADL guard mutants (loop21-mut.py, 17) | pass 1 (tests up to P3): **7 / 17 killed** (pick-tree-need-off, pick-top-acct-off, adl-check-off, maint-off, load-root-check-off, load-leaf-check-off, cur-init-off); pass 2 (the 10 survivors vs P3c + round-22 `t_adrop` 5): **load-absent-check-off KILLED** (`t_adrop` 5: the tree claimed absent beside its `adlr:` leaf); round-22 re-tests: **end-del-off KILLED** (slpoc22 P0: both rank sub-trees emptied in a segment, the `adlr:` leaves must go), **leftmost-skip-stub: see round-22** (`t_adrop` 6: the leftmost leaf sent as an opaque stub of its own hash next to the second leaf's expanded path, P2 / P3b / P3c). Equivalent / defence in depth (below) | l21-mut.log, l21-mut2.log, ../results-loop22/l22-mut*.log |
| Radicle native CI | 3756542 FAILURE (R21-L1), 5c8bcfa / 1be84a5 / a4f80ad / 642ddf8 SUCCESS | /data/hark/radicle-ci/logs/cib.log, state/*/log.html |
| sail 64-account migration (round-19 item) | stopped at 05:31 UTC after 2 h 31 m without output (own process groups 885730 / 885731 only); no data point | l19-cap-dec.log, l19-cap-base.log |


Surviving mutants (equivalent or defence in depth; none can turn a forged witness into status 0 with a wrong result):
- `pick-cur-check-off` (the loaded top holder's current entry vs the leaf key): at unit start the rank tree and the
  account records are pure functions of the same session state (both bound by MNWIT-S), and `cur` / the tree are
  maintained together after every unit, so the entry always equals the key — defence in depth.
- `leftmost-unverified-ok` (accept an unverified leftmost leaf): such a leaf carries no id, `ids.get(key)` fails ->
  BADWIT instead of `AdlTop`: still a refusal; the honest builder sends every rank leaf verified (R21-L1).
- `fill-maker-check-off` (an ADL fill whose maker is not the pick): the engine ranks the loaded holders, and the pick
  check guarantees the true top is loaded and ranks first among them; the check is a guard on that argument.
- `maint-present-check-off` / `maint-absent-check-off`: a removal key that is not present / an insertion key that is
  present is unreachable with consistent records (the tree is derived from the loaded positions); the absent case
  only covers an R21-I2 id-prefix collision. Defence in depth.
- `removed-count-off` (AdlTop(k) without the removals): liveness only — after removals the honest operator may send
  too short a leftmost path and loop (an honest segment refused), never an accepted wrong pick (the pick still
  requires a verified leftmost leaf).
- `insurance-in-tree` (maintenance without the insurance skip): the insurance record is loaded light (no positions in
  the partial state) on every supported path, and its start entries are never in `cur`; reachable only with a full
  insurance record whose position changes, which no supported op produces (round-22 pass 2 re-test: l22-mut2.log).

## What remains

- Funding transfers / the funding-rate peg / ExtPrice and the funding-rate market's liquidation / off-book ADL:
  unsupported (R20-I1: upstream index-based funding; a mark-independent off-book rank).
- A revealed Liquidate (Reveal inner op): unsupported.
- Production items unchanged: DA, stateless export path (R16-I2), global caps (R16-I3 / R17-I3); upstream mirror of the
  leaf kinds (consensus change of the witness root).
