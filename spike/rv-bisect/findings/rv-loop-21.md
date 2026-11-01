# rv loop round 21 — stateless ADL remainder (rank sub-trees), round-20 close-out (2026-11-01)

Branch `spike/rv-bisect`, parent 960e87b (round-20 head). Design: `docs/rv-stateless-guest.md` §2 (leaves), §4
(Liquidate / rank maintenance), §11, §12.2 "Round-21 implementation". Code: `guest-engine/src/stateless/adl.rs` (new),
`PTree::decode_raw` + tag 5, run-loop wiring and `Need::Adl / AdlTop / AdlKey` in `stateless.rs`, `SL_ADL_SIDE` in
`engine.rs`; harness `engine-diff/src/sl.rs` (`slpoc21`, `adl_segments`, `slpoc17` round-21 semantics). Box logs:
`guest-engine/results-loop21/`. Notes: work/rv-rollup-notes.md "Loop round 21". Pushes: Radicle first, then GitHub.

Status: **DRAFT**

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
| R21-I3 | I | cost | every position change of a non-insurance account costs a removal + an insertion path in the market's rank sub-trees (O(log holders) + the shared-prefix chain of equal |qty| — 2 witness bytes per single-child level), plus one leftmost path per ADL unit. Measured: rank section of an ADL segment's witness 1.4 KB, 1.9–2.0 KB with 2 000 extra holders in the market (the rest of the witness growth with the extra holders is the MNWIT-S multiproof's depth, not the rank trees); guest hashes: see Tests (slfuzz sl_hashes now include the sub-trees) | measured |
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

TESTS21

## What remains

- Funding transfers / the funding-rate peg / ExtPrice and the funding-rate market's liquidation / off-book ADL:
  unsupported (R20-I1: upstream index-based funding; a mark-independent off-book rank).
- A revealed Liquidate (Reveal inner op): unsupported.
- Production items unchanged: DA, stateless export path (R16-I2), global caps (R16-I3 / R17-I3); upstream mirror of the
  leaf kinds (consensus change of the witness root).
