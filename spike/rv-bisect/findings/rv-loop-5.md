# rv loop round 5 — unit id input, engine height = rollup height, oracle stake / unstake / slash port, review of rounds 4–5 (2026-10-31)

Target: `lhxmall/Minuend` branch `spike/rv-bisect` @ 4b039c2 (loop round 4 result + loop4-post.sh). Reference engine read
only via `git archive 20326c0` (engine-diff/engine-src); fix/47-all, main and PR #51 untouched.

Work items (round-4 open items):

1. **R4-M2 — unit id as guest input.** Batch format v2 `MNP2` = MNP1 + a unit-id table (n_ops × 8 words after the ops).
   The port passes the unit id to `liquidate` (`liq_order_id(unit id)`), so liquidation fills carry the real taker id and
   the event log is no longer masked. MNP1 keeps unit id 0 + `LIQ_TAKER_EV` (test fixtures); the `prod` image refuses an
   MNP1 `Liquidate` (BadAccount). Harness: the real engine reports every op's unit id (`Out::uids`), `to_v2` builds the
   MNP2 twin of a batch, `liqfuzz` runs every batch both ways, `liqgen … v2` writes MNP2 batches for the JS guest.
2. **R4-M4 — engine height bound to the rollup height**, without an rv_rollup change: a rollup height is exactly one
   guest run from the previous height's final memory, so a run counter in guest memory (`RUNS`, `.data`) *is* the rollup
   height. `Session::segs` follows it (synced every run; an import counts as a run and restores the count from the
   snapshot: export at h−1 → import at h). With height binding (`Session::bind_height`, always in `prod`) every batch run
   first runs the batch-commit hook (height = segs, prune withdrawals, release finished unbondings), so units of rollup
   height h see engine height h; `SetHeight` is refused. `OUT[0x1FFE6]` = engine height; `rv_witbind` additionally proves
   `OUT[0x1FFE7]` (segs) = h, so a bound segment root is the root of the run that knew it was height h.
3. **R4-L4** — `Accounts::oi_long / holders / dirty` are private (`oi_long_of`, `holders_of`, `mark_dirty`,
   `drain_dirty`).
4. **R4-M3 (partial) — oracle stake / unstake / slash ported** verbatim (`apply_stake`, `apply_unstake`, `apply_slash`,
   `prune_oracle_unbonding` in the batch-commit hook) with the PERP ledger (`perp_balances`, `perp_supply`,
   `perp_burned`, `oracle_unbonding`, `oracle_slash_nonce`): batch kinds 11 / 12 / 13, header fixture bit 27 (accounts
   4..=9 hold 2 × ORACLE_BOND_PERP; upstream gets there with GovDeposit, not ported). PERP-only ids get an `acct:` leaf
   like upstream (R8-C3); state hash section `MNPILOT3`; snapshot v2. New differential test `orafuzz` (real vs port +
   per-unit roots + snapshot round trip). Governance ops (listing, parameter proposals) and commit-reveal stay unported.
5. Fresh adversarial review of the round-4 and round-5 code (below), the round-5 suite and mutation test.

Severity as in rounds 1–4: **C** = honest party loses / wrong verdict on reachable input; **H** = guest ≠ host, undefined
guest outcome, or a protocol-reachable state loss / halt; **M** = design/spec gap with a concrete failure mode or a
defense-in-depth hole; **L** = minor / documentation; **I** = checked, no defect.

FINDINGS_TABLE_5

---

RESULTS_TABLE_5
