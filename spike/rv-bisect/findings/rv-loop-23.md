# rv loop round 23 — eager commit expiry (`cexp:` groups, stale `cmt:` deletion, commit count) (2026-11-01)

Branch `spike/rv-bisect`, parent f80fe62 (round-22 head). Design: `docs/rv-stateless-guest.md` §2 (`cexp:<u>`, `gcnt:0`
fifth field), §5 "Commits (round 23)", §9 "Round 23: eager commit expiry", §11 items 2 / 8. Code:
`guest-engine/src/stateless.rs` (`cexp_*`, `Sl.acmt_all / cmtx / cx`, loader section after `gcnt:0`, `cexp_hook`,
`cexp_gone` / `cexp_now` / `ttl_ok`, `gcnt_delta` field 4, `gcap_pre` / `gcap_ok` Commit, end root, migration bounds,
builder `Need::Cexp` / `t_cdrop` / `t_gdrop` 5, `SlCaps.commits / commit_group`, `SL_MAX_CMT_LIVE / SL_MAX_CMT_RECS /
SL_MAX_CEXP*`); R23-H2: `state.rs` `prune_oracle_unbonding_n`, `lib.rs` `commit_height_bound`, `stateless/ora.rs`
`hook_pre`. Harness `engine-diff/src/sl.rs`: `cr_batch` / `slcr` / `cr_adv`, `slpoc23` (P1–P9), `sess_seg_h`,
`operate_deny_h`, operator shortcut for `Need::Cexp`. Mutants `guest-engine/scripts/loop23-mut.py`. Box logs:
`guest-engine/results-loop23/`. Notes: work/rv-rollup-notes.md "Loop round 23". Pushes: Radicle first, then GitHub.

Status: **DRAFT**

## Choice of the round-23 gap (decision D0)

Candidates (user): eager commit expiry / stale `cmt:` deletion (R16-I1, which also lets the session commit cap be
mirrored, R22-I2) or the stateless lineage export run (R16-I2 / R22-I3). Picked **eager commit expiry**: it is the last
place where the stateless root is not a function of the session state for an op the lineage supports (stale `cmt:` /
`acmt:` entries; at bound heights no commit-reveal workload could be checked against the session root — round 20 had to
leave commits out of the `orc` workload), the last session global cap the lineage did not apply (MAX_STATE_COMMITS), and
a precondition of a clean export (an exported state must not carry stale commit leaves). Export stays open.

## What was done

1. **Eager commit expiry.** Per-TTL expiry groups `cexp:<u>` (`:<n>:<sha256(hashes)>`), a pure function of the state.
   Every live TTL lies in [height, height + 16] (Commit's TTL rule, the height only grows, the hook drops ttl < height),
   so a hook from the committed height h0 to the run's height h reads at most 17 groups u ∈ [h0, min(h, h0 + 17)) — no
   queue. The hook (`cexp_hook`) requires each group, each group member's `cmt:` record (TTL must equal u, else BADWIT)
   and each owner's `acmt:`; the loader already reads those commits as absent (as before); the end root deletes their
   `cmt:` leaves (unless a unit of the run re-commits the hash — then it is rewritten), deletes the expired groups and
   rewrites the owners' indexes (an index is now compared with its committed entry list, not its live set). A created
   commit joins its TTL's group (per-unit catch-all `Need::Cexp`).
2. **Commit count / caps.** `gcnt:0` gets a fifth field (live commits; delta = created − dropped by the hook); every
   Commit reads it (`gcap_pre`) and the session's MAX_STATE_COMMITS rule runs on it, plus a per-TTL group bound (the
   Commit's group is an input). Values: decision D1 / R23-M1 / R23-H1 below.
3. **Migration:** refuses a commit TTL outside [height, height + 16], a count above `SL_CAPS.commits`, a group above
   `SL_CAPS.commit_group`.
4. **Harness:** `slcr` = commit-reveal at BOUND heights (commits with TTLs relative to the run height, reveals — many
   after expiry —, re-commits of expired hashes, bond refusals, invalid TTLs; hook-only runs, height jumps), reference =
   the **session image's** root (impossible before this round); `adv` mode: omission of each supplied need, adversarial
   operators that never supply Cexp / Cmt / Acmt / Gcnt, forged groups (`t_cdrop` 1–3), forged count (`t_gdrop` 5),
   extra valid records, byte flips. `slpoc23` P1–P9 (Tests).
5. Review (below) found two highs in the round's own draft / the round-20 oracle hook; both fixed.

## Summary of findings

| id | sev | where | what | status |
|---|---|---|---|---|
| R23-H1 | H | commit caps (draft f0cb05d) | a failed run (status ≠ 0) leaves the root but still counts as a height, so the next hook can drop up to 17 groups = **every** live commit at once. With the draft's uncapped total (R23-M1 fix, first form) an attacker filling > 4 096 commits (64 bonds × 64 accounts each; 17 × 1 024 fit the group bound) and one or more failed runs would make that height need more `cmt:` / `acmt:` records than the loader's sections allow (SL_MAX_ACCOUNTS) — **no witness exists, the lineage halts** | **fixed** (f4716dc): production total `SL_MAX_CMT_LIVE` = 4 096, commit-record sections bounded by `SL_MAX_CMT_RECS` = 8 192 (every expiring record + owner index + the units' own), const asserts tie caps and loader bounds; slpoc23 P8: a 40-height jump expiring 4 096 commits is proven (1.2 MB witness), 8 200 commits are unprovable (BADWIT) |
| R23-H2 | H | oracle hook (round 20, R20-M3) | same jump on the oracle expiry queue: R20-M3 sized ONE height's expiry (16 oracles × 16 markets = SL_MAX_MARKETS report sets), but the hook released every due group; after one failed run two adjacent full groups with disjoint markets (32 oracles, 512 listed markets) need 512 report-set / market records → unprovable height (PoC on the round-22 code: status 12), i.e. a lineage halt for the price of 512 listings + 32 bonds + one failed run | **fixed** (23d6728) by a pilot rule in BOTH images (decision D2): the bound hook releases at most MAX_UNSTAKES_PER_HEIGHT due unbondings per run, in (unlock height, id) order (`state::prune_oracle_unbonding_n`, `lib::commit_height_bound`, `ora::hook_pre`); the rest follows in later runs (a bounded release lag after jumps). Unbound SetHeight keeps upstream's release-all (real-vs-port tests unchanged). slpoc23 P9: jump hook 16 + 16 over two runs, root = session |
| R23-M1 | M | commit cap (draft d01539f) | mirroring the session's MAX_STATE_COMMITS = 1 024 in the lineage (first draft) adds a **renewable global commit-reveal lockout** the lineage did not have (rounds 16–22: only the per-account bound): 1 024 commits × COMMIT_BOND_PERP of bonded PERP and 1 024 unit fees per 16 heights lock every other user out of commit-reveal | **mitigated by decision D1** (f0cb05d / f4716dc): production total 4 096 (4× the session's cost; the ceiling is R23-H1's loader bound — raising it needs larger witness sections) + 1 024 per TTL group (bounds the normal one-step hook); the session keeps 1 024 (pilot limit). With the session's values both images agree (P1–P6) |
| R23-I1 | I | R16-I1 | closed: expired `cmt:` leaves are deleted by the hook; commit leaves (`cmt:` / `acmt:` / `cexp:`) are a pure function of the session state; at bound heights the stateless root equals the session root (`slcr`, 0 bad segments) | closed |
| R23-I2 | I | R22-I2 | closed: the commit count is a `gcnt:0` field and MAX_STATE_COMMITS is applied (session values: P1 at / one below the cap = session) | closed |
| R23-I3 | I | cost | every Commit reads `gcnt:0` + its TTL group (+2 leaves on commit segments); a hook that expires commits loads their records and the owners' whole `acmt:` records (dominant: P2 61 expirations of 16 owners × 64 entries = 173 KB; P3 1 024 = 310 KB; P8 4 096 = 1.2 MB, all well under SL_MAX_WIT_BYTES 16 MB) | measured (Tests) |
| R23-I4 | I | consensus | MNWIT-S changes (`gcnt:0` has 5 fields, new `cexp:` leaves, eager `acmt:` semantics): a lineage started by a round-16..22 image (stale `cmt:` leaves, 4-field `gcnt:0`) cannot be continued by this image — a new lineage by migration (no lineage is deployed). The R23-H2 rule changes the SESSION image too (bound runs only) — upstream mirror needed like R20-L1 | documented |
| R23-I5 | I | withdrawals | `wdl:` stays lazy (rewritten on touch): at bound heights with expiring withdrawal records the stateless root is still the lazily committed one (reference `lazy_state`); an eager form would need groups by record height (REPLAY_WINDOW 2 048 → a jump hook could need many groups; bounded per run like D2) | open (design note) |
| R23-I6 | I | export (R16-I2) | not attempted this round (D0); precondition unchanged (O(1) on `gcnt:0`, now incl. commits; no stale commit leaves to strip) | open |

Decisions (for the owner to overrule):
- **D0** gap choice: eager commit expiry before export (above).
- **D1** commit caps of the lineage: total 4 096 (= SL_MAX_CMT_LIVE; R23-H1 bound), per TTL group 1 024; session 1 024
  total (unchanged pilot limit). Alternatives: total = session's 1 024 (cheaper lockout, images equal without host-test
  caps) or a larger total with larger commit-record sections (witness of a jump hook grows linearly, ~300 B per commit).
- **D2** R23-H2 fix = at most 16 releases per bound run in (unlock, id) order, in both images. Alternatives: count only
  successful runs as heights (rollup change), or a total in-flight unbonding bound (griefable: 16 cyclers block exits).
  Side effect: after a jump, due bonds come back up to k runs late; a due-but-unreleased oracle keeps its bond and its
  unbonding entry until released (it is treated exactly as an oracle whose unlock height has not come) — both images
  agree (P9 root = session; slora / slpoc20 unchanged).
- Operator shortcut (harness, not a guest rule): a `Need::Cexp(u)` for an expiring group brings its records and owners at
  once.

Review notes (no finding):
- **Completeness of the hook.** Groups are verified leaves (forged / dropped / fake hash: refused, P4 / adv); the range
  [h0, min(h, h0 + 17)) covers every live TTL by the TTL invariant (migration enforces it; Commit's TTL rule keeps it);
  a group's member with another TTL is BADWIT (unreachable on valid states: mutant `cexp-hook-ttl-check-off` survives as
  defence in depth); each expiring `cmt:` is required (`cmtx`), and its owner's index (else the index would keep the
  entry and the root would differ: `deny23:acmt` refused).
- **Re-commit in the hook's run** (session: the old commit is pruned, the hash is free): the `cmt:` leaf is rewritten
  with the new entry, the old group deleted, the new group extended (P5; `recommits_of_expiring_hash` in slcr).
- **Reveal of an expiring commit** reads the record, finds it expired (absent in the partial state) → BadCommit =
  session (P5; slcr reveal rejections code 17).
- **Count delta**: commits are never removed inside a run except by the hook, and only as whole loaded groups; the delta
  `|commits| − |cmt0| − dropped` is exact; a forged count is refused (`forge23:gcnt-commits`).
- **Refused Commit into a full group** must load the group (input of the rule): an operator denying Cexp is refused
  (P7b), never a different result.
- **Oracle and commit hooks** run in the same hook block before any unit; order between them is irrelevant (disjoint
  leaves).

Totals: **C 0 · H 2 (fixed) · M 1 (mitigated by decision) · L 0 · I 6**.

## Tests

(filled at round close)

## What remains

- Stateless lineage export (R16-I2 / R22-I3).
- Eager withdrawal expiry (R23-I5), id eviction (R22-M1), DA of the witness, funding / peg / ExtPrice, revealed
  Liquidate / Slash, upstream mirror of the leaf kinds and of the R20-L1 / R23-H2 pilot rules.
