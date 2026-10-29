//! Watcher fraud-proof builder: locates the first divergence between a
//! posted batch and a local replay, then emits the `proof.json` payload the
//! dispute AAs verify one-shot on-chain.
//!
//! The builder never talks to the network. The caller supplies the posted
//! [`Batch`] (already rebuilt from temp_data DA), a replay [`Engine`] at the
//! batch's prev state, and the inbox pairs `(unit_id_hex, force_ts)` with the
//! rollup's `submitted_at` for staleness comparison.

use minuend_exec::Engine;
use minuend_settle::{ops_element, Batch};
use minuend_state::obyte_merkle;

/// A fraud proof ready for `post_challenge.js --pred PRED --proof PATH`.
#[derive(Clone, Debug)]
pub struct BuiltProof {
    /// Dispute predicate name (`deposit`, `withdraw`, `omit`, `fill_math`,
    /// `ghost`, `skip`).
    pub pred: String,
    /// True → post to the fill dispute AA (`--fill`); false → main dispute AA.
    pub fill_aa: bool,
    /// Exact `trigger.data` supplement (merged with `height`/`pred` by the
    /// poster): `k`, `op`, proofs, leaves, roots the AA stale-checks.
    pub data: serde_json::Value,
}

fn proof_json(elements: &[String], index: usize) -> serde_json::Value {
    let p = obyte_merkle::proof(elements, index);
    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
}

fn index_of(elements: &[String], needle: &str) -> Option<usize> {
    elements.iter().position(|e| e == needle)
}

/// Locate the first divergence and build the on-chain proof.
///
/// Returns `None` when the batch replays cleanly (honest) or when the
/// divergence is not predicate-expressible (watcher stays print-only).
pub fn build_proof(
    batch: &Batch,
    replay: &mut Engine,
    inbox: &[(String, u64)],
    submit_ts: u64,
) -> Option<BuiltProof> {
    let n = batch.units.len();
    if n == 0 || batch.checkpoint.unit_ids.len() != n || batch.ops.len() != n {
        return None;
    }
    let unit_hexes: Vec<String> = batch
        .checkpoint
        .unit_ids
        .iter()
        .map(|id| hex::encode(id.0))
        .collect();
    // 1. P-omit: forced id older than the submit but missing from the batch.
    for (id, ts) in inbox {
        if *ts < submit_ts && !unit_hexes.iter().any(|u| u == id) {
            return omit_proof(batch, &unit_hexes, id);
        }
    }
    // 2+. Walk units: ingest one at a time, compare wit root + ops string.
    for (k, unit_hex) in unit_hexes.iter().enumerate() {
        let pre_leaves = minuend_state::wit_leaves(&replay.state);
        let pre_wit = obyte_merkle::root(&pre_leaves);
        let expected_op = ops_element(unit_hex, &batch.units[k].op);
        let op_ok = batch.ops.get(k).map(|o| o == &expected_op).unwrap_or(false);
        let wit_ok = batch.trace.get(k).map(|t| t == &pre_wit).unwrap_or(false);
        if !op_ok || !wit_ok {
            // Poster committed something unreplayable at k; the pre-state
            // leaves are still honest replay output — fall through to the
            // per-op proofs against the POSTED commitments below.
        }
        let events = match replay.ingest(batch.units[k].clone()) {
            Ok(ev) => ev,
            Err(_) => return None,
        };
        // The honest fill strings of this unit (replay output): a posted
        // fill that is not among them is itself a lie, so the honest-tree
        // gate in fill_math (built from the TRUE fills) does not apply.
        let unit_id_k = batch.checkpoint.unit_ids[k];
        let honest_fills: Vec<String> = events
            .iter()
            .filter_map(|e| match e {
                minuend_exec::ExecEvent::Applied { unit, fills, .. } if *unit == unit_id_k => {
                    Some(fills)
                }
                _ => None,
            })
            .flat_map(|fills| {
                fills
                    .iter()
                    .enumerate()
                    .map(|(i, f)| minuend_settle::fills_element(unit_hex, i, f))
                    .collect::<Vec<_>>()
            })
            .collect();
        let post_leaves = minuend_state::wit_leaves(&replay.state);
        let op = batch.ops.get(k)?.clone();
        if op.starts_with("d:") || op.starts_with("D:") {
            if let Some(p) = deposit_proof(batch, k, &op, &pre_leaves, true) {
                return Some(p);
            }
        } else if op.starts_with("w:") || op.starts_with("W:") {
            if let Some(p) = deposit_proof(batch, k, &op, &pre_leaves, false) {
                return Some(p);
            }
        } else {
            // Fill-bearing unit: check fills of this unit against post state.
            if let Some(p) =
                fill_proof(batch, k, unit_hex, &pre_leaves, &post_leaves, &honest_fills)
            {
                return Some(p);
            }
        }
    }
    None
}

fn trace_roots(batch: &Batch) -> serde_json::Value {
    serde_json::json!({
        "trace_root": batch.checkpoint.trace_root,
        "ops_root": batch.checkpoint.ops_root,
        "units_root": batch.checkpoint.units_root,
        "units_set_root": batch.checkpoint.units_set_root,
        "fills_root": batch.checkpoint.fills_root,
    })
}

fn pre_wit_fields(batch: &Batch, k: usize, pre_leaves: &[String]) -> serde_json::Value {
    let pre_wit = obyte_merkle::root(pre_leaves);
    if k == 0 {
        serde_json::json!({"pre_wit": pre_wit})
    } else {
        let pre_proof = proof_json(&batch.trace, k - 1);
        serde_json::json!({"pre_wit": pre_wit, "pre_proof": pre_proof})
    }
}

fn deposit_proof(
    batch: &Batch,
    k: usize,
    op: &str,
    pre_leaves: &[String],
    is_deposit: bool,
) -> Option<BuiltProof> {
    // Parse op: d:{acct}:{amount} (3 parts) or w:{acct}:{amount}:{nonce}.
    let parts: Vec<&str> = op.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    let acct_hex = parts[1].to_string();
    let amount: i128 = parts[2].parse().ok()?;
    // #37-5: gov ops (D:/W:) move the PERP column, never collateral —
    // mirror the dispute AA's split arm, else the watcher would flag
    // honest gov batches (or miss gov lies aimed at the wrong column).
    let is_gov = op.starts_with("D:") || op.starts_with("W:");
    // Fresh account: no pre leaf — pre col is 0, and the AA takes the
    // pre_absent non-membership geometry over the sorted pre leaves.
    let pre_hit = pre_leaves
        .iter()
        .find(|l| l.starts_with(&format!("acct:{acct_hex}:")))
        .cloned();
    let (pre_col, pre_perp, pre_absent_fields): (i128, u128, serde_json::Value) =
        match pre_hit.clone() {
            Some(pre_leaf) => {
                let c: i128 = pre_leaf.split(':').nth(2)?.parse().ok()?;
                let p: u128 = pre_leaf.split(':').nth(3)?.parse().ok()?;
                (c, p, serde_json::json!({}))
            }
            None => {
                let mut sorted = pre_leaves.to_vec();
                sorted.sort();
                let ghost_key = format!("acct:{acct_hex}:");
                let pos = sorted
                    .iter()
                    .position(|s| s.as_str() > ghost_key.as_str())
                    .unwrap_or(sorted.len());
                let mut f = serde_json::json!({"pre_absent": true});
                let obj = f.as_object_mut()?;
                if pos > 0 && pos < sorted.len() {
                    obj.insert("left".into(), sorted[pos - 1].clone().into());
                    obj.insert("left_proof".into(), {
                    let p = obyte_merkle::proof(&sorted, pos - 1);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
                    obj.insert("right".into(), sorted[pos].clone().into());
                    obj.insert("right_proof".into(), {
                    let p = obyte_merkle::proof(&sorted, pos);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
                } else if !sorted.is_empty() {
                    let i = if pos == 0 { 0 } else { sorted.len() - 1 };
                    obj.insert("left".into(), sorted[i].clone().into());
                    obj.insert("left_proof".into(), {
                    let p = obyte_merkle::proof(&sorted, i);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
                } else {
                    return None;
                }
                (0, 0, f)
            }
        };
    // Gov leg: PERP moves by amount, collateral pinned. Non-gov: the
    // collateral identity as before.
    let (expected, gov_col_must_match): (i128, Option<i128>) = if is_gov {
        let e = if is_deposit {
            (pre_perp as i128) + amount
        } else {
            (pre_perp as i128) - amount
        };
        (e, Some(pre_col))
    } else if is_deposit {
        (pre_col + amount, None)
    } else {
        (pre_col - amount, None)
    };
    let posted_post: Vec<String> = batch.leaf_trace.get(k)?.clone();
    let liar_leaf = posted_post
        .iter()
        .find(|l| l.starts_with(&format!("acct:{acct_hex}:")))?
        .clone();
    let liar_col: i128 = liar_leaf.split(':').nth(2)?.parse().ok()?;
    let liar_perp: i128 = liar_leaf.split(':').nth(3)?.parse().ok()?;
    let (liar_val, col_pinned) = if is_gov {
        (liar_perp, Some(liar_col))
    } else {
        (liar_col, None)
    };
    // #47 B6 (mirrors the AA): gov ops never create an account, so a gov
    // unit's post tree can never hold an acct leaf for a pre-absent
    // account (a PERP-only holder has none either) — any posted leaf is
    // fraud, whatever its numbers. There is no PERP baseline to compare.
    let gov_fresh = is_gov && pre_hit.is_none();
    // #47 (cross-PR, mirrors the AA): a REJECTED op leaves the moving
    // column unchanged (fresh non-gov account: absent or col 0). Rejected
    // units are committed like applied ones, so "unchanged" is an honest
    // outcome the AA bounces — never build a proof for it.
    let unchanged = match &pre_hit {
        Some(_) => {
            let pre_val = if is_gov { pre_perp as i128 } else { pre_col };
            liar_val == pre_val
        }
        None => !is_gov && liar_col == 0,
    };
    let col_ok = col_pinned
        .map(|c| Some(c) == gov_col_must_match)
        .unwrap_or(true);
    if !gov_fresh && (liar_val == expected || unchanged) && col_ok {
        return None; // honest leg — keep scanning
    }
    let mut roots = trace_roots(batch);
    let pre_fields = pre_wit_fields(batch, k, pre_leaves);
    let post_wit = batch.trace.get(k)?.clone();
    let ops_proof = proof_json(&batch.ops, k);
    let post_proof = proof_json(&batch.trace, k);
    let post_idx = index_of(&posted_post, &liar_leaf)?;
    let post_leaf_proof = {
        let p = obyte_merkle::proof(&posted_post, post_idx);
        serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
    };
    roots
        .as_object_mut()?
        .extend(pre_fields.as_object()?.clone());
    roots
        .as_object_mut()?
        .extend(pre_absent_fields.as_object()?.clone());
    let mut data = roots;
    let obj = data.as_object_mut()?;
    obj.insert("k".into(), k.into());
    obj.insert("op".into(), op.into());
    obj.insert("ops_proof".into(), ops_proof);
    obj.insert("post_wit".into(), post_wit.into());
    obj.insert("post_proof".into(), post_proof);
    obj.insert("post_leaf".into(), liar_leaf.into());
    obj.insert("post_leaf_proof".into(), post_leaf_proof);
    if let Some(pre_leaf) = pre_hit {
        let pre_idx = index_of(pre_leaves, &pre_leaf)?;
        obj.insert("pre_leaf".into(), pre_leaf.into());
        obj.insert("pre_leaf_proof".into(), {
            let p = obyte_merkle::proof(pre_leaves, pre_idx);
            serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
        });
    }
    Some(BuiltProof {
        pred: if is_deposit {
            "deposit".into()
        } else {
            "withdraw".into()
        },
        fill_aa: false,
        data,
    })
}

fn omit_proof(batch: &Batch, unit_hexes: &[String], id: &str) -> Option<BuiltProof> {
    let mut sorted = unit_hexes.to_vec();
    sorted.sort();
    let n = sorted.len();
    // Adjacent pair straddling id, or outside min/max.
    let mut data = trace_roots(batch);
    let obj = data.as_object_mut()?;
    obj.insert("unit_id".into(), id.into());
    // Find insertion point.
    let pos = sorted.iter().position(|s| s.as_str() > id).unwrap_or(n);
    if pos > 0 && pos < n {
        let li = pos - 1;
        let ri = pos;
        obj.insert("left".into(), sorted[li].clone().into());
        obj.insert("left_proof".into(), proof_json(&sorted, li));
        obj.insert("right".into(), sorted[ri].clone().into());
        obj.insert("right_proof".into(), proof_json(&sorted, ri));
    } else if pos == 0 {
        obj.insert("left".into(), sorted[0].clone().into());
        obj.insert("left_proof".into(), proof_json(&sorted, 0));
    } else {
        obj.insert("left".into(), sorted[n - 1].clone().into());
        obj.insert("left_proof".into(), proof_json(&sorted, n - 1));
    }
    Some(BuiltProof {
        pred: "omit".into(),
        fill_aa: false,
        data,
    })
}

/// First pair (i, i+1) straddling [lo, hi): everything between the two
/// adjacent leaves is outside the range — the AA's pe1/ps1 geometry.
/// `allow_last` enables the final-tree-only branch (AA: k+1==n plus the
/// committed wit_count), where only a left neighbor below the range exists.
fn range_straddle(
    tree: &[String],
    lo: &str,
    hi: &str,
    allow_last: bool,
) -> Option<(usize, Option<usize>)> {
    if let Some(i) = tree
        .windows(2)
        .position(|w| w[0].as_str() < lo && hi <= w[1].as_str())
    {
        return Some((i, Some(i + 1)));
    }
    if let Some(first) = tree.first() {
        if first.as_str() >= hi {
            return Some((0, None));
        }
    }
    if allow_last {
        if let Some(last) = tree.last() {
            if last.as_str() < lo {
                return Some((tree.len() - 1, None));
            }
        }
    }
    None
}

fn acct_pos_range(
    tree: &[String],
    acct_hex: &str,
    allow_last: bool,
) -> Option<(usize, Option<usize>)> {
    range_straddle(
        tree,
        &format!("pos:{acct_hex}:"),
        &format!("pos:{acct_hex};"),
        allow_last,
    )
}

fn mkt_pos_range(
    tree: &[String],
    acct_hex: &str,
    market: &str,
    allow_last: bool,
) -> Option<(usize, Option<usize>)> {
    range_straddle(
        tree,
        &format!("pos:{acct_hex}:{market}:"),
        &format!("pos:{acct_hex}:{market};"),
        allow_last,
    )
}

/// What the fill AA derives for a kind 0/1 TAKER leg from the unit's own
/// Place op (#47 A3): the committed `taker_post`, whether the unfilled
/// remainder rests (Limit + Gtc + qty left) and, if so, the exact fields
/// its post ord leaf (id = the fill's `taker_order`) must carry.
struct TakerPlace<'a> {
    tord: &'a str,
    tpost: i128,
    pback: i128,
    rest: bool,
    /// margin_left the resting order keeps (`margin - taker_post`, 0 cross).
    tml: i128,
    side: &'a str,
    price: &'a str,
    remaining: i128,
    iso: &'a str,
}

/// Kind 2/3 leg on the Liquidate order-book path (#47 B1/B2): for the
/// taker (= liquidation target), the keeper reward seized after the fill.
/// (The positive-counterparty gate lives on [`Leg::counterparty`].)
struct LiqLeg {
    reward: Option<i128>,
}

/// One challenged leg, fully pre-computed from the PRE leaves, the fill
/// string and the op — everything the AA recomputes before it looks at a
/// post tree.
struct Leg<'a> {
    acct_hex: &'a str,
    market: &'a str,
    exp_qty: i64,
    exp_entry: i64,
    exp_absent: bool,
    /// Some(expected post bucket) when the AA checks it.
    exp_bucket: Option<i128>,
    exp_fill: i128,
    taker_place: Option<TakerPlace<'a>>,
    liq: Option<LiqLeg>,
    allow_last: bool,
    /// The other fill party (claw guard: its proven post collateral must be
    /// > 0 before a collateral mismatch on THIS leg is fraud).
    counterparty: &'a str,
    /// #47 claw guard: may a collateral mismatch count at all? False for a
    /// kind 0/1 maker leg whose taker Place is isolated (its escrow refund
    /// lands on the taker after the claw, so "taker post > 0" proves
    /// nothing) — the AA bounces such a mismatch.
    claw_checkable: bool,
}

fn acct_col(tree: &[String], acct_hex: &str) -> Option<i128> {
    tree.iter()
        .find(|l| l.starts_with(&format!("acct:{acct_hex}:")))
        .and_then(|l| l.split(':').nth(2))
        .and_then(|c| c.parse().ok())
}

/// Mirror of the fill-math AA's per-leg verdict for one candidate tree
/// (honest replay or committed post): true = the AA would reach the fee
/// gate (verdict) on this tree. Evaluated in the AA's own order: every
/// bounce (missing leaf, kind 2/3 counterparty gate, negative expected
/// collateral) returns false BEFORE any fraud term is considered.
///
/// `op_lie` = the committed fill disagrees with its own Place op (taker
/// account / market / side / qty / taker_post) — fraud on its own, folded
/// in after the bounces like the AA's `$op_ok`. `pre_perp_w` enables the
/// #37-17 perp/W pin (committed tree only).
fn aa_fill_verdict(
    tree: &[String],
    leg: &Leg,
    op_lie: bool,
    pre_perp_w: Option<(&str, &str)>,
) -> bool {
    // Missing post acct leaf bounces the AA prelude — no verdict at all.
    let post_acct = match tree
        .iter()
        .find(|l| l.starts_with(&format!("acct:{}:", leg.acct_hex)))
    {
        Some(a) => a,
        None => return false,
    };
    let post_col: i128 = match post_acct.split(':').nth(2).and_then(|c| c.parse().ok()) {
        Some(c) => c,
        None => return false,
    };
    // #37-17 pin: post.perp == pre.perp and post.W == pre.W.
    let pin_ok = match pre_perp_w {
        Some((pp, pw)) => {
            let mut it = post_acct.split(':');
            it.nth(3) == Some(pp) && it.next() == Some(pw)
        }
        None => true,
    };
    // #47 claw guard: a proven POSITIVE counterparty post leaf. Required
    // outright for kind 2/3 (B1/B2); for kind 0/1 it only gates whether a
    // collateral mismatch counts (see `col_ok` below).
    let cp_pos = matches!(acct_col(tree, leg.counterparty), Some(c) if c > 0);
    if leg.liq.is_some() && !cp_pos {
        return false;
    }
    // Position leg.
    let pos_leaf = tree.iter().find(|l| {
        l.starts_with("pos:") && {
            let o: Vec<&str> = l.split(':').collect();
            o.len() == 7 && o[1] == leg.acct_hex && o[2] == leg.market
        }
    });
    let (pos_ok, pos_bail) = if leg.exp_absent {
        if pos_leaf.is_some() {
            (false, false) // surviving leaf where the engine removed it
        } else if acct_pos_range(tree, leg.acct_hex, false).is_some() {
            // The AA's acct-wide arm has no final-tree after-max branch;
            // that shape falls through to the market-range check below.
            (true, false)
        } else {
            match mkt_pos_range(tree, leg.acct_hex, leg.market, leg.allow_last) {
                Some(_) => (true, false),
                None => (false, true),
            }
        }
    } else {
        match pos_leaf {
            Some(p) => {
                let o: Vec<&str> = p.split(':').collect();
                let ok = o[3].parse::<i64>().ok() == Some(leg.exp_qty)
                    && o[4]
                        .parse::<i64>()
                        .map(|e| (e - leg.exp_entry).abs() <= 1)
                        .unwrap_or(false)
                    && leg
                        .exp_bucket
                        .map(|b| {
                            o[6].parse::<i128>()
                                .map(|x| (x - b).abs() <= 1)
                                .unwrap_or(false)
                        })
                        .unwrap_or(true);
                (ok, false)
            }
            None => (false, true),
        }
    };
    // Collateral leg (+ the resting-order leg of a kind 0/1 taker).
    // `mid` = fill-stage collateral the engine's claw sees (before an
    // isolated taker's unrested escrow refund).
    let (expected, mid, ord_ok, ord_bail) = if let Some(liq) = &leg.liq {
        match liq.reward {
            // Liquidation target: fill-stage minus the keeper reward
            // seized from its own non-negative collateral.
            Some(reward) => {
                let kpay = if leg.exp_fill > 0 {
                    reward.min(leg.exp_fill)
                } else {
                    0
                };
                let e = leg.exp_fill - kpay;
                (e, e, true, true)
            }
            None => (leg.exp_fill, leg.exp_fill, true, true),
        }
    } else if let Some(tp) = &leg.taker_place {
        let still = if tp.rest { tp.tml } else { 0 };
        let key = format!("ord:{}:", tp.tord);
        let (ord_ok, ord_bail) = match tree.iter().find(|l| l.starts_with(&key)) {
            Some(l) => {
                let o: Vec<&str> = l.split(':').collect();
                let ok = tp.rest
                    && o.len() == 10
                    && o[2] == leg.market
                    && o[3] == tp.side
                    && o[4] == tp.price
                    && o[6].parse::<i128>().ok() == Some(tp.remaining)
                    && o[7] == leg.acct_hex
                    && o[8] == tp.iso
                    && o[9].parse::<i128>().ok() == Some(tp.tml);
                (ok, false)
            }
            None => {
                // The AA proves absence by straddle or before-min only.
                if range_straddle(tree, &key, &format!("ord:{};", tp.tord), false).is_some() {
                    (!tp.rest, false)
                } else {
                    (true, true)
                }
            }
        };
        // exp_fill already carries release + pnl - fee; the escrow
        // identity adds -(taker_post + still) + post_back.
        let e = leg.exp_fill - tp.tpost - still + tp.pback;
        (e, e - tp.tml + still, ord_ok, ord_bail)
    } else {
        (leg.exp_fill, leg.exp_fill, true, true)
    };
    // Negative fill-stage collateral: the claw's effect is unprovable from
    // these leaves — the AA bounces (no verdict) for that shape.
    if mid < 0 {
        return false;
    }
    // #47 claw guard: a mismatch counts only when no claw can have moved
    // this leg (positive counterparty; cross taker for a kind 0/1 maker).
    let col_ok = post_col == expected || !(cp_pos && leg.claw_checkable);
    (!pos_bail && !pos_ok) || !col_ok || !pin_ok || op_lie || (!ord_bail && !ord_ok)
}

fn fill_proof(
    batch: &Batch,
    k: usize,
    unit_hex: &str,
    pre_leaves: &[String],
    post_leaves: &[String],
    honest_fills: &[String],
) -> Option<BuiltProof> {
    // Reconstruct this unit's fills from the batch fills list (prefix match).
    let prefix = format!("f:{unit_hex}:");
    let unit_fills: Vec<&String> = batch
        .fills
        .iter()
        .filter(|f| f.starts_with(&prefix))
        .collect();
    if unit_fills.is_empty() {
        return None;
    }
    let unit_hexes: Vec<String> = batch
        .checkpoint
        .unit_ids
        .iter()
        .map(|id| hex::encode(id.0))
        .collect();
    // fills_root tree: fill descriptors + trailing length sentinel. Proof
    // indices over it match the raw array (the sentinel sits at the end).
    let fills_tree = minuend_settle::fills_root_elements(&batch.fills);

    // Ghost: maker ord leaf absent from pre leaves.
    for f in &unit_fills {
        let parts: Vec<&str> = f.split(':').collect();
        if parts.len() != 14 {
            continue;
        }
        let maker_hex = parts[4].to_string();
        let maker_order_hex = parts[6].to_string();
        let market = parts[7].to_string();
        let fill_price = parts[8].to_string();
        let fill_qty = parts[9].to_string();
        let fill_seq = parts[10].to_string();
        let opp_side = if parts[11] == "0" { "1" } else { "0" }.to_string();
        // Prefix-range ghost: fraud iff NO pre leaf carries this order id.
        // Any same-id leaf sits inside [$lo,$hi) and breaks every AA
        // straddle, so only emit then.
        let ord_prefix = format!("ord:{maker_order_hex}:");
        let ghost_hit = !pre_leaves.iter().any(|l| l.starts_with(&ord_prefix));
        if ghost_hit {
            let idx = index_of(&batch.fills, f)?;
            let mut data = serde_json::json!({
                "trace_root": batch.checkpoint.trace_root,
                "fills_root": batch.checkpoint.fills_root,
                "ops_root": batch.checkpoint.ops_root,
                "units_root": batch.checkpoint.units_root,
                "k": k,
                "fill": f,
                "fill_proof": proof_json(&fills_tree, idx),
                "units_proof": proof_json(&unit_hexes, k),
            });
            // Non-membership neighbors for the [$lo,$hi) range: reuse omit
            // geometry over the pre wit leaves with wit_count bound.
            let mut sorted = pre_leaves.to_vec();
            sorted.sort();
            let pos = sorted
                .iter()
                .position(|s| s.as_str() > ord_prefix.as_str())
                .unwrap_or(sorted.len());
            let obj = data.as_object_mut()?;
            obj.insert(
                "maker_ord".into(),
                format!(
                    "ord:{}:{}:{}:{}:{}:{}:{}:{}:{}",
                    maker_order_hex,
                    market,
                    opp_side,
                    fill_price,
                    fill_seq,
                    fill_qty,
                    maker_hex,
                    0,
                    0
                )
                .into(),
            );
            if pos > 0 && pos < sorted.len() {
                obj.insert("left".into(), sorted[pos - 1].clone().into());
                obj.insert("left_proof".into(), {
                    let p = obyte_merkle::proof(&sorted, pos - 1);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
                obj.insert("right".into(), sorted[pos].clone().into());
                obj.insert("right_proof".into(), {
                    let p = obyte_merkle::proof(&sorted, pos);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
            } else if !sorted.is_empty() {
                let i = if pos == 0 { 0 } else { sorted.len() - 1 };
                obj.insert("left".into(), sorted[i].clone().into());
                obj.insert("left_proof".into(), {
                    let p = obyte_merkle::proof(&sorted, i);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
            }
            return Some(BuiltProof {
                pred: "ghost".into(),
                fill_aa: false,
                data,
            });
        }
    }
    // Skip: another live order strictly better than the filled maker.
    // #37-9 / #47 B3: only the unit's FIRST fill (idx 0) — pre_wit is the
    // book matching started from, so its priority is checkable even in a
    // multi-fill unit; later fills may have lost their candidate to an
    // earlier same-unit fill. Owner gate (#47 B7, mirrors the AA): the
    // taker's own CROSS order is skipped by design (cancel-maker-continue);
    // the taker's own ESCROWED order on a Place fill (kind 0/1) would have
    // rejected the whole Place (SelfTrade::Reject), so crossing past it is
    // fraud. Liquidation fills (kind 2/3) keep the full exemption.
    for f in &unit_fills {
        let parts: Vec<&str> = f.split(':').collect();
        if parts.len() != 14 {
            continue;
        }
        if parts[2] != "0" {
            continue;
        }
        let taker_hex = parts[3].to_string();
        let maker_order_hex = parts[6].to_string();
        let market = parts[7].to_string();
        let price: i64 = match parts[8].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let side = parts[11];
        let place_fill = parts[12] == "0" || parts[12] == "1";
        let maker_ord = match pre_leaves.iter().find(|l| {
            l.starts_with("ord:") && {
                let o: Vec<&str> = l.split(':').collect();
                o.len() == 10 && o[1] == maker_order_hex && o[2] == market
            }
        }) {
            Some(m) => m.clone(),
            None => continue,
        };
        let mo: Vec<&str> = maker_ord.split(':').collect();
        let (mo_price, mo_seq): (i64, u64) = match (mo[4].parse(), mo[5].parse()) {
            (Ok(a), Ok(b)) => (a, b),
            _ => continue,
        };
        for cand in pre_leaves.iter().filter(|l| l.starts_with("ord:")) {
            let o: Vec<&str> = cand.split(':').collect();
            if o.len() != 10 || o[2] != market {
                continue;
            }
            if o[1] == maker_order_hex {
                continue;
            }
            if o[7] == taker_hex {
                let escrowed = o[9].parse::<i128>().map(|m| m > 0).unwrap_or(false);
                if !(escrowed && place_fill) {
                    continue;
                }
            }
            let (c_side, c_price, c_seq): (u8, i64, u64) =
                match (o[3].parse(), o[4].parse(), o[5].parse()) {
                    (Ok(a), Ok(b), Ok(c)) => (a, b, c),
                    _ => continue,
                };
            let c_rem: u64 = o[6].parse().unwrap_or(0);
            if c_rem == 0 {
                continue;
            }
            let better = if side == "0" {
                c_side == 1
                    && (c_price < mo_price || (c_price == mo_price && c_seq < mo_seq))
                    && c_price <= price
            } else if side == "1" {
                c_side == 0
                    && (c_price > mo_price || (c_price == mo_price && c_seq < mo_seq))
                    && c_price >= price
            } else {
                false
            };
            if better {
                let idx = index_of(&batch.fills, f)?;
                let mut data = serde_json::json!({
                    "trace_root": batch.checkpoint.trace_root,
                    "fills_root": batch.checkpoint.fills_root,
                    "ops_root": batch.checkpoint.ops_root,
                    "units_root": batch.checkpoint.units_root,
                    "k": k,
                    "fill": f,
                    "fill_proof": proof_json(&fills_tree, idx),
                    "units_proof": proof_json(&unit_hexes, k),
                    "maker_ord": maker_ord,
                    "better_ord": cand,
                });
                let pre_fields = pre_wit_fields(batch, k, pre_leaves);
                data.as_object_mut()?
                    .extend(pre_fields.as_object()?.clone());
                // Membership proofs for both orders in pre_wit.
                let mi = index_of(pre_leaves, &maker_ord)?;
                let bi = index_of(pre_leaves, cand)?;
                let obj = data.as_object_mut()?;
                obj.insert("maker_proof".into(), proof_json(pre_leaves, mi));
                obj.insert("better_proof".into(), proof_json(pre_leaves, bi));
                return Some(BuiltProof {
                    pred: "skip".into(),
                    fill_aa: false,
                    data,
                });
            }
        }
    }
    // fill_math: mirror the AA's collateral identity — kind fee/pnl,
    // isolated release, maker pro-rata refund, keeper seize, claw gates,
    // op binding — and emit only when the AA would verdict on the posted
    // legs while staying silent on the honest replay.
    //
    // The unit's op descriptor, as committed (the AA reads the posted
    // op). Kind 0/1 taker legs need a well-formed 10-part `p:` Place
    // (#47 A3); kind 2/3 legs need `L:{caller}:{target}:{market}` (#47 B1).
    let op_str = batch.ops.get(k)?.clone();
    let op_parts: Vec<&str> = op_str.split(':').collect();
    let op_place = op_parts.len() == 10
        && op_parts[0] == "p"
        && (op_parts[6] == "0" || op_parts[6] == "1")
        && op_parts[5].parse::<i128>().is_ok()
        && op_parts[7].parse::<i128>().is_ok();
    let op_liq = op_parts.len() == 4 && op_parts[0] == "L";
    for f in &unit_fills {
        let parts: Vec<&str> = f.split(':').collect();
        if parts.len() != 14 {
            continue;
        }
        // Single-fill completeness: idx 0 (a later idx means this unit has
        // other fills, so pre->post delta is bigger than one fill); the
        // right-neighbor arm is decided at gidx below.
        let in_unit_idx: usize = match parts[2].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if in_unit_idx != 0 {
            continue;
        }
        let gidx = match index_of(&batch.fills, f) {
            Some(i) => i,
            None => continue,
        };
        // Single-fill completeness mirror: the right neighbor outside this
        // unit's prefix. Over the sentinel tree this always exists — for a
        // trailing fill it is `n:{len}`, never `f:`-prefixed — so the AA's
        // right-neighbor conjunction alone decides.
        let right: &String = match fills_tree.get(gidx + 1) {
            Some(r) if !r.starts_with(&prefix) => r,
            _ => continue,
        };
        let kind: i64 = match parts[12].parse() {
            Ok(v) if (0..=3).contains(&v) => v,
            _ => continue,
        };
        let taker_hex = parts[3].to_string();
        let maker_hex = parts[4].to_string();
        let market = parts[7].to_string();
        let price: i64 = match parts[8].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let qty: u64 = match parts[9].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let taker_post: i128 = match parts[13].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let taker_side = parts[11];
        if taker_side != "0" && taker_side != "1" {
            continue;
        }
        let maker_side = if taker_side == "0" { "1" } else { "0" };
        // #47 B1/B2: kind 2/3 at idx 0 of a single-fill unit is judged only
        // on the Liquidate book path: taker == target, caller != maker.
        if kind >= 2
            && !(op_liq
                && op_parts[2] == taker_hex
                && op_parts[3] == market
                && op_parts[1] != maker_hex)
        {
            continue;
        }
        let pre_meta = match pre_leaves
            .iter()
            .find(|l| l.starts_with(&format!("meta:{market}:")))
        {
            Some(m) => m.clone(),
            None => continue,
        };
        let mparts: Vec<&str> = pre_meta.split(':').collect();
        if mparts.len() != 11 {
            continue;
        }
        let fee_bps: i128 = match mparts[5].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let keeper_bps: i128 = match mparts[6].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let usd: i128 = match mparts[9].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        // Price notional (engine notional_usd, i128 trunc chain): fee base
        // of kind 0/3, keeper base of kind 2/3. Funding markets (kind 1)
        // price the fee off the multiplier. Kind 2 (ADL) pays no fee.
        let t2 = i128::from(qty) * i128::from(price) / 100_000_000 * 1_000_000 / 100_000_000;
        let fee: i128 = if kind == 2 {
            0
        } else if kind == 1 {
            let fnot = i128::from(qty) * usd * 1_000_000 / 100_000_000;
            fnot * fee_bps / 10_000
        } else {
            t2.abs() * fee_bps / 10_000
        };
        let reward = t2.abs() * keeper_bps / 10_000;
        // Posted post legs: the commitments the AA checks proofs against.
        let posted_post: Vec<String> = batch
            .leaf_trace
            .get(k)
            .cloned()
            .unwrap_or_else(|| post_leaves.to_vec());
        let allow_last =
            k + 1 == batch.units.len() && posted_post.len() == batch.checkpoint.wit_count as usize;
        let sides = [
            ("taker", taker_hex.as_str(), taker_side),
            ("maker", maker_hex.as_str(), maker_side),
        ];
        for (who, acct_hex, side_acct) in sides {
            if acct_hex == "0000000000000000000000000000000000000000000000000000000000000000" {
                continue; // AA bails on the insurance account's own leaf
            }
            let who_taker = who == "taker";
            if who_taker && kind <= 1 && !op_place {
                continue; // AA bounces a kind 0/1 taker leg on a non-place op
            }
            let delta: i64 = if side_acct == "0" {
                qty as i64
            } else {
                -(qty as i64)
            };
            let pre_acct = match pre_leaves
                .iter()
                .find(|l| l.starts_with(&format!("acct:{acct_hex}:")))
            {
                Some(a) => a.clone(),
                None => continue,
            };
            let pre_parts: Vec<&str> = pre_acct.split(':').collect();
            if pre_parts.len() != 5 {
                continue;
            }
            let old_col: i128 = match pre_parts[2].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let pre_pos_opt = pre_leaves
                .iter()
                .find(|l| {
                    l.starts_with("pos:") && {
                        let o: Vec<&str> = l.split(':').collect();
                        o.len() == 7 && o[1] == acct_hex && o[2] == market
                    }
                })
                .cloned();
            let pos_absent = pre_pos_opt.is_none();
            let (old_qty, old_entry, iso, bucket): (i64, i64, bool, i128) = match &pre_pos_opt {
                None => (0, 0, false, 0),
                Some(p) => {
                    let o: Vec<&str> = p.split(':').collect();
                    match (o[3].parse(), o[4].parse(), o[6].parse()) {
                        (Ok(q), Ok(e), Ok(b)) => (q, e, o[5] == "1", b),
                        _ => continue,
                    }
                }
            };
            // #47 B1: an isolated liquidation TARGET may get STP escrow
            // refunds in-unit — the AA bounces that leg.
            if who_taker && kind >= 2 && iso {
                continue;
            }
            // The AA requires the maker's PRE ord leaf on every order-book
            // maker leg (#47: its margin mode decides the bucket check of a
            // maker with no prior position), except for ADL (kind 2: no
            // maker order, no escrow).
            let maker_ord = if !who_taker && kind != 2 {
                pre_leaves
                    .iter()
                    .find(|l| l.starts_with(&format!("ord:{}:", parts[6])))
                    .cloned()
            } else {
                None
            };
            if !who_taker && kind != 2 && maker_ord.is_none() {
                continue;
            }
            let mo_iso = maker_ord
                .as_ref()
                .map(|l| l.split(':').nth(8) == Some("1"))
                .unwrap_or(false);
            let mpost_any: i128 = match maker_ord.as_ref().map(|l| l.split(':').collect::<Vec<_>>())
            {
                Some(o) if o.len() == 10 => {
                    let ml: i128 = o[9].parse().unwrap_or(0);
                    let rem: i128 = o[6].parse().unwrap_or(0);
                    if i128::from(qty) >= rem {
                        ml
                    } else {
                        ml * i128::from(qty) / rem
                    }
                }
                _ => 0,
            };
            let post_any = if who_taker { taker_post } else { mpost_any };
            let tfee = if who_taker { fee } else { 0 };
            // Fill-stage collateral by kind: pre + release + pnl - taker fee
            // (+ maker pro-rata refund). Exact — the AA recomputes it.
            let abs_old = old_qty.unsigned_abs() as i128;
            let abs_delta = delta.unsigned_abs() as i128;
            let same = old_qty == 0 || (old_qty > 0 && delta > 0) || (old_qty < 0 && delta < 0);
            let (exp_qty, exp_entry, exp_fill, exp_absent, pback, exp_bucket) = if same {
                let eq = old_qty + delta;
                let ee = if old_qty == 0 {
                    price
                } else {
                    ((abs_old * i128::from(old_entry) + i128::from(qty) * i128::from(price))
                        / (abs_old + i128::from(qty))) as i64
                };
                let ec = if who_taker { old_col - tfee } else { old_col };
                // Same-sign fills always produce open qty: the post escrows
                // into the bucket, never back to collateral.
                (eq, ee, ec, false, 0, bucket + post_any)
            } else {
                let close = abs_old.min(abs_delta);
                // Isolated release: engine releases bucket*close/old (whole
                // bucket on full close) before PnL settles.
                let release = if iso {
                    if close == abs_old {
                        bucket
                    } else {
                        bucket * close / abs_old
                    }
                } else {
                    0
                };
                // kind 1 = funding rate cash (rate diff UNCLAMPED, matching
                // engine apply_fill); kind 0/2/3 = price-diff realize. Both
                // truncate toward zero at each division like Rust i128.
                let pnl: i128 = if kind == 1 {
                    let bpp = (price - 10_000_000_000_000) / 10_000;
                    let bpe = (old_entry - 10_000_000_000_000) / 10_000;
                    let sq: i128 = if old_qty > 0 { close } else { -close };
                    let x = sq * i128::from(bpp - bpe) * usd * 1_000_000;
                    let c1 = x / 100_000_000;
                    c1 / 10_000
                } else {
                    let signed: i128 = if old_qty > 0 {
                        price as i128 - old_entry as i128
                    } else {
                        old_entry as i128 - price as i128
                    };
                    let pr = signed * close * 1_000_000;
                    let q1 = pr / 100_000_000;
                    q1 / 100_000_000
                };
                let leftover = abs_old - close;
                let open = abs_delta - close;
                // Engine apply_fill: a taker post lands in the bucket iff
                // the fill produced open qty (flip), else returns to
                // collateral (reduce / full close).
                let pback: i128 = if leftover == 0 && open > 0 {
                    0
                } else {
                    taker_post
                };
                // Maker escrow returns only when the fill produces no new
                // open qty (flip fills escrow the post into the bucket).
                let mpost = if !who_taker && (leftover > 0 || open == 0) {
                    mpost_any
                } else {
                    0
                };
                let ec = if who_taker {
                    old_col + release + pnl - tfee
                } else {
                    old_col + release + pnl + mpost
                };
                let eb = if leftover == 0 {
                    post_any
                } else {
                    bucket - release
                };
                if leftover == 0 && open == 0 {
                    (0, 0, ec, true, pback, eb)
                } else {
                    let q = if leftover == 0 {
                        if delta > 0 {
                            open as i64
                        } else {
                            -(open as i64)
                        }
                    } else if old_qty > 0 {
                        leftover as i64
                    } else {
                        -(leftover as i64)
                    };
                    let e = if leftover == 0 { price } else { old_entry };
                    (q, e, ec, false, pback, eb)
                }
            };
            // #47 A3: the bucket is checked where its inflow is known —
            // an isolated taker Place (kind 0/1) or an isolated maker
            // pre position.
            let chk_b = if who_taker {
                kind <= 1 && op_parts.get(6) == Some(&"1")
            } else {
                iso || mo_iso
            };
            // #47 A3: kind 0/1 taker — bind the fill to its own Place op and
            // derive the resting escrow from typ/tif instead of F[5]'s leaf.
            let (taker_place, op_lie) = if who_taker && kind <= 1 {
                let oqty: i128 = op_parts[5].parse().unwrap_or(0);
                let margin: i128 = op_parts[7].parse().unwrap_or(0);
                let op_iso = op_parts[6] == "1";
                let q = i128::from(qty);
                let tpost_exp = if !op_iso {
                    0
                } else if q >= oqty {
                    margin
                } else {
                    margin * q / oqty
                };
                let op_ok = op_parts[1] == taker_hex
                    && op_parts[2] == market
                    && op_parts[3] == taker_side
                    && q <= oqty
                    && taker_post >= 0
                    && (taker_post - tpost_exp).abs() <= 1
                    && (op_iso || taker_post == 0);
                let rest = op_parts[9] == "0" && op_parts[8] == "0" && q < oqty;
                let tml = if op_iso { margin - taker_post } else { 0 };
                (
                    Some(TakerPlace {
                        tord: parts[5],
                        tpost: taker_post,
                        pback,
                        rest,
                        tml,
                        side: taker_side,
                        price: op_parts[4],
                        remaining: oqty - q,
                        iso: op_parts[6],
                    }),
                    !op_ok,
                )
            } else {
                (None, false)
            };
            let liq = if kind >= 2 {
                Some(LiqLeg {
                    reward: if who_taker { Some(reward) } else { None },
                })
            } else {
                None
            };
            let tord_hex = taker_place.as_ref().map(|t| t.tord.to_string());
            let leg = Leg {
                acct_hex,
                market: &market,
                exp_qty,
                exp_entry,
                exp_absent,
                exp_bucket: if chk_b { Some(exp_bucket) } else { None },
                exp_fill,
                taker_place,
                liq,
                allow_last,
                counterparty: if who_taker {
                    maker_hex.as_str()
                } else {
                    taker_hex.as_str()
                },
                claw_checkable: who_taker || kind >= 2 || op_parts.get(6) == Some(&"0"),
            };
            // AA verdict mirror: silent unless the honest replay passes
            // every leg and the committed legs fail one of them. A fill
            // string that contradicts its own op (`op_lie`) is fraud on
            // committed data alone, and so is any posted fill string that
            // the replay did not produce: the honest-replay gate is skipped
            // then because that tree was built from the TRUE fills.
            // The #37-17 pin compares the committed post leaf against the
            // PRE leaf's perp/W; the honest tree is checked with no pin.
            let fill_lie = op_lie || !honest_fills.iter().any(|h| h == *f);
            if !fill_lie && aa_fill_verdict(post_leaves, &leg, false, None) {
                continue;
            }
            if !aa_fill_verdict(
                &posted_post,
                &leg,
                op_lie,
                Some((pre_parts[3], pre_parts[4])),
            ) {
                continue;
            }
            let posted_acct = match posted_post
                .iter()
                .find(|l| l.starts_with(&format!("acct:{acct_hex}:")))
            {
                Some(a) => a.clone(),
                None => continue,
            };
            let posted_pos_opt = posted_post
                .iter()
                .find(|l| {
                    l.starts_with("pos:") && {
                        let o: Vec<&str> = l.split(':').collect();
                        o.len() == 7 && o[1] == acct_hex && o[2] == market
                    }
                })
                .cloned();
            let idx = index_of(&batch.fills, f)?;
            let mut data = serde_json::json!({
                "trace_root": batch.checkpoint.trace_root,
                "fills_root": batch.checkpoint.fills_root,
                "ops_root": batch.checkpoint.ops_root,
                "units_root": batch.checkpoint.units_root,
                "k": k,
                "fill": f,
                "fill_proof": proof_json(&fills_tree, idx),
                "units_proof": proof_json(&unit_hexes, k),
                "who": who,
                "pre_acct": pre_acct,
                "post_acct": posted_acct,
                "pre_meta": pre_meta,
                "pos_absent": pos_absent,
                "post_pos_absent": exp_absent,
            });
            let pre_fields = pre_wit_fields(batch, k, pre_leaves);
            let post_wit = batch.trace.get(k)?.clone();
            let post_proof = proof_json(&batch.trace, k);
            let pre_idx = index_of(pre_leaves, &pre_acct)?;
            let post_acct_idx = index_of(&posted_post, data["post_acct"].as_str()?)?;
            let meta_idx = index_of(pre_leaves, &pre_meta)?;
            data.as_object_mut()?
                .extend(pre_fields.as_object()?.clone());
            let obj = data.as_object_mut()?;
            // Right-neighbor arm: always present over the sentinel tree
            // (the trailing fill's neighbor is `n:{len}`).
            obj.insert("right".into(), right.clone().into());
            obj.insert("right_proof".into(), proof_json(&fills_tree, gidx + 1));
            // Op gate: every leg proves the unit op (Place or Liquidate).
            obj.insert("op".into(), op_str.clone().into());
            obj.insert("ops_proof".into(), proof_json(&batch.ops, k));
            // #47 claw guard: the counterparty's post collateral (required
            // for kind 2/3, needed for a kind 0/1 collateral mismatch).
            let cp = if who_taker { &maker_hex } else { &taker_hex };
            let key = format!("acct:{cp}:");
            match posted_post.iter().position(|l| l.starts_with(&key)) {
                Some(ci) => {
                    obj.insert("cp_acct".into(), posted_post[ci].clone().into());
                    obj.insert("cp_acct_proof".into(), proof_json(&posted_post, ci));
                }
                None if kind >= 2 => return None,
                None => {}
            }
            if let Some(tord) = &tord_hex {
                // Resting-order leg: the taker order's own post ord leaf, or
                // prefix non-membership over post_wit (straddle / before-min;
                // the AA has no after-max arm — it bails then).
                let key = format!("ord:{tord}:");
                match posted_post.iter().position(|l| l.starts_with(&key)) {
                    Some(li) => {
                        obj.insert("tord".into(), posted_post[li].clone().into());
                        obj.insert("tord_proof".into(), proof_json(&posted_post, li));
                    }
                    None => {
                        let mut sorted = posted_post.clone();
                        sorted.sort();
                        let pos = sorted
                            .iter()
                            .position(|s| s.as_str() > key.as_str())
                            .unwrap_or(sorted.len());
                        if pos > 0 && pos < sorted.len() {
                            obj.insert("oleft".into(), sorted[pos - 1].clone().into());
                            obj.insert("oleft_proof".into(), proof_json(&sorted, pos - 1));
                            obj.insert("oright".into(), sorted[pos].clone().into());
                            obj.insert("oright_proof".into(), proof_json(&sorted, pos));
                        } else if pos == 0 && !sorted.is_empty() {
                            obj.insert("oleft".into(), sorted[0].clone().into());
                            obj.insert("oleft_proof".into(), proof_json(&sorted, 0));
                        }
                    }
                }
            }
            obj.insert("post_wit".into(), post_wit.into());
            obj.insert("post_proof".into(), post_proof);
            obj.insert("pre_acct_proof".into(), {
                let p = obyte_merkle::proof(pre_leaves, pre_idx);
                serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
            });
            obj.insert("post_acct_proof".into(), {
                let p = obyte_merkle::proof(&posted_post, post_acct_idx);
                serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
            });
            obj.insert("pre_meta_proof".into(), {
                let p = obyte_merkle::proof(pre_leaves, meta_idx);
                serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
            });
            if let Some(pp) = &pre_pos_opt {
                let pi = index_of(pre_leaves, pp)?;
                obj.insert("pre_pos".into(), pp.clone().into());
                obj.insert("pre_pos_proof".into(), {
                    let p = obyte_merkle::proof(pre_leaves, pi);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
            } else {
                // Claimed-absent pre pos: prefix-range non-membership
                // neighbors over the SORTED pre leaves (AA checks the
                // [$plo,$phi) straddle). Note: proofs here are over the
                // sorted order; the AA only checks root/index/geometry.
                let mut sorted = pre_leaves.to_vec();
                sorted.sort();
                let plo = format!("pos:{acct_hex}:{market}:");
                let pos = sorted
                    .iter()
                    .position(|s| s.as_str() > plo.as_str())
                    .unwrap_or(sorted.len());
                if pos > 0 && pos < sorted.len() {
                    for (key, idx) in [("pleft", pos - 1), ("pright", pos)] {
                        obj.insert(format!("{key}_proof"), {
                            let p = obyte_merkle::proof(&sorted, idx);
                            serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                        });
                    }
                    obj.insert("pleft".into(), sorted[pos - 1].clone().into());
                    obj.insert("pright".into(), sorted[pos].clone().into());
                } else if !sorted.is_empty() {
                    let i = if pos == 0 { 0 } else { sorted.len() - 1 };
                    obj.insert("pleft".into(), sorted[i].clone().into());
                    obj.insert("pleft_proof".into(), {
                        let p = obyte_merkle::proof(&sorted, i);
                        serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                    });
                } else {
                    continue;
                }
            }
            if !exp_absent || posted_pos_opt.is_some() {
                if let Some(lp) = &posted_pos_opt {
                    let li = index_of(&posted_post, lp)?;
                    obj.insert("post_pos".into(), lp.clone().into());
                    obj.insert("post_pos_proof".into(), {
                        let p = obyte_merkle::proof(&posted_post, li);
                        serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                    });
                }
            }
            // Regime proofs: the acct-wide pos range empty on the posted
            // tree, or the market-range straddle, back a claimed-absent
            // post pos.
            if let Some((li, rj)) = acct_pos_range(&posted_post, acct_hex, false) {
                obj.insert("eleft".into(), posted_post[li].clone().into());
                obj.insert("eleft_proof".into(), {
                    let p = obyte_merkle::proof(&posted_post, li);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
                if let Some(rj) = rj {
                    obj.insert("eright".into(), posted_post[rj].clone().into());
                    obj.insert("eright_proof".into(), {
                        let p = obyte_merkle::proof(&posted_post, rj);
                        serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                    });
                }
            }
            if exp_absent && posted_pos_opt.is_none() {
                if let Some((li, rj)) = mkt_pos_range(&posted_post, acct_hex, &market, allow_last) {
                    obj.insert("post_pleft".into(), posted_post[li].clone().into());
                    obj.insert("post_pleft_proof".into(), {
                        let p = obyte_merkle::proof(&posted_post, li);
                        serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                    });
                    if let Some(rj) = rj {
                        obj.insert("post_pright".into(), posted_post[rj].clone().into());
                        obj.insert("post_pright_proof".into(), {
                            let p = obyte_merkle::proof(&posted_post, rj);
                            serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                        });
                    }
                }
            }
            if let Some(mo) = &maker_ord {
                let mi = index_of(pre_leaves, mo)?;
                obj.insert("maker_ord".into(), mo.clone().into());
                obj.insert("maker_ord_proof".into(), {
                    let p = obyte_merkle::proof(pre_leaves, mi);
                    serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
                });
            }
            return Some(BuiltProof {
                pred: "fill_math".into(),
                fill_aa: true,
                data,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use minuend_dag::{genesis_id, sign_unit, unit_id, Op};
    use minuend_types::{account_id_from_pubkey, AccountId};

    fn sk(n: u8) -> [u8; 32] {
        [n; 32]
    }
    fn acct_of(secret: &[u8; 32]) -> AccountId {
        let pk = SigningKey::from_bytes(secret).verifying_key().to_bytes();
        account_id_from_pubkey(&pk)
    }
    fn test_addr() -> String {
        "A".repeat(32)
    }

    #[test]
    fn deposit_mismatch_builds_proof() {
        let secret = sk(7);
        let acct = acct_of(&secret);
        let g = genesis_id();
        let aa = [9u8; 32];
        let u = sign_unit(
            vec![g],
            Op::Deposit {
                account: acct,
                addr: test_addr(),
                amount: 100,
                aa_unit: aa,
            },
            &secret,
        );
        let id = unit_id(&u);
        let mut eng = Engine::new();
        eng.state.deposits_allowed.insert((aa, false));
        eng.ingest(u).unwrap();
        let prev = minuend_state::ChainState::new();
        let mut eng2 = eng.clone();
        let mut batch = Batch::from_applied(&prev, &mut eng2, &[id]).expect("batch");
        // Tamper the posted post leaf: col 50 despite a +100 deposit (col 0
        // would be the "rejected deposit" shape, which is honest — #47).
        if let Some(leaves) = batch.leaf_trace.get_mut(0) {
            for l in leaves.iter_mut() {
                if l.starts_with(&format!("acct:{}:", hex::encode(acct.0))) {
                    let parts: Vec<&str> = l.split(':').collect();
                    *l = format!("acct:{}:50:{}:{}", parts[1], parts[3], parts[4]);
                }
            }
        }
        let mut replay = Engine::new();
        let proof = build_proof(&batch, &mut replay, &[], 0).expect("proof");
        assert_eq!(proof.pred, "deposit");
        assert!(!proof.fill_aa);
    }

    /// #47 (cross-PR): rejected units are committed like applied ones. An
    /// honestly REJECTED withdraw (insufficient balance — or, since #49,
    /// the spot reserve / gov-nonce rules) leaves the leaf unchanged; that
    /// must never become a withdraw proof (the AA bounces it too).
    #[test]
    fn rejected_withdraw_in_honest_batch_builds_no_proof() {
        let secret = sk(7);
        let acct = acct_of(&secret);
        let g = genesis_id();
        let aa = [9u8; 32];
        let dep = sign_unit(
            vec![g],
            Op::Deposit {
                account: acct,
                addr: test_addr(),
                amount: 100,
                aa_unit: aa,
            },
            &secret,
        );
        let d_id = unit_id(&dep);
        let wd = sign_unit(
            vec![d_id],
            Op::Withdraw {
                account: acct,
                amount: 1_000,
                nonce: 1,
            },
            &secret,
        );
        let w_id = unit_id(&wd);
        let mut eng = Engine::new();
        eng.state.deposits_allowed.insert((aa, false));
        eng.ingest(dep).unwrap();
        let evs = eng.ingest(wd).unwrap();
        assert!(evs
            .iter()
            .any(|e| matches!(e, minuend_exec::ExecEvent::Rejected { .. })));
        let prev = minuend_state::ChainState::new();
        let mut eng2 = eng.clone();
        let batch = Batch::from_applied(&prev, &mut eng2, &[d_id, w_id]).expect("batch");
        assert_eq!(batch.ops.len(), 2, "the rejected withdraw is committed");
        let mut replay = Engine::new();
        replay.state.deposits_allowed.insert((aa, false));
        assert!(build_proof(&batch, &mut replay, &[], 0).is_none());
    }

    #[test]
    fn omit_missing_forced_id_builds_proof() {
        // Batch with one honest deposit unit; the forced id is absent.
        let secret = sk(7);
        let acct = acct_of(&secret);
        let g = genesis_id();
        let aa = [9u8; 32];
        let u = sign_unit(
            vec![g],
            Op::Deposit {
                account: acct,
                addr: test_addr(),
                amount: 100,
                aa_unit: aa,
            },
            &secret,
        );
        let id = unit_id(&u);
        let mut eng = Engine::new();
        eng.state.deposits_allowed.insert((aa, false));
        eng.ingest(u).unwrap();
        let prev = minuend_state::ChainState::new();
        let mut eng2 = eng.clone();
        let batch = Batch::from_applied(&prev, &mut eng2, &[id]).expect("batch");
        let forced = hex::encode([0xabu8; 32]);
        let mut replay = Engine::new();
        let proof = build_proof(&batch, &mut replay, &[(forced.clone(), 0)], 999).expect("proof");
        assert_eq!(proof.pred, "omit");
        assert!(!proof.fill_aa);
        assert_eq!(
            proof.data.get("unit_id").and_then(|v| v.as_str()),
            Some(forced.as_str())
        );
    }

    #[test]
    fn fill_math_reduce_builds_proof() {
        use minuend_types::{
            OrderType, Side, TimeInForce, UnitId, BTC_USD, PRICE_SCALE, QTY_SCALE, USD_SCALE,
        };
        let alice = sk(1);
        let bob = sk(2);
        let alice_id = acct_of(&alice);
        let bob_id = acct_of(&bob);
        let fund = |eng: &mut Engine| {
            for id in [alice_id, bob_id] {
                eng.state
                    .account_mut(id)
                    .credit(10_000 * USD_SCALE as i128)
                    .unwrap();
            }
        };
        let mut eng = Engine::new();
        fund(&mut eng);
        let prev = eng.state.clone();
        let g = genesis_id();
        let px1 = 100_000 * PRICE_SCALE as i64;
        let px2 = 105_000 * PRICE_SCALE as i64;
        let q1 = QTY_SCALE;
        let q2 = QTY_SCALE / 2;
        let place = |parents: Vec<UnitId>,
                     secret: &[u8; 32],
                     account: AccountId,
                     side: Side,
                     price: i64,
                     qty: u64,
                     seq: u64| {
            sign_unit(
                parents,
                Op::Place {
                    account,
                    market: BTC_USD,
                    side,
                    typ: OrderType::Limit,
                    tif: TimeInForce::Gtc,
                    price,
                    qty,
                    client_seq: seq,
                    isolated: false,
                    margin: 0,
                },
                secret,
            )
        };
        // k=0: bob asks 1 @100k (rests). k=1: alice bids 1 @100k (fill1:
        // alice long 1 @100k). k=2: bob bids 0.5 @105k (rests). k=3: alice
        // asks 0.5 @105k (fill2, taker alice Ask) reducing the long and
        // realizing +2500 USD pnl into collateral.
        let ask1 = place(vec![g], &bob, bob_id, Side::Ask, px1, q1, 1);
        let id1 = unit_id(&ask1);
        eng.ingest(ask1).unwrap();
        let bid1 = place(vec![id1], &alice, alice_id, Side::Bid, px1, q1, 1);
        let id2 = unit_id(&bid1);
        eng.ingest(bid1).unwrap();
        let bid2 = place(vec![id2], &bob, bob_id, Side::Bid, px2, q2, 2);
        let id3 = unit_id(&bid2);
        eng.ingest(bid2).unwrap();
        let ask2 = place(vec![id3], &alice, alice_id, Side::Ask, px2, q2, 2);
        let id4 = unit_id(&ask2);
        eng.ingest(ask2).unwrap();
        let mut eng2 = eng.clone();
        let mut batch =
            Batch::from_applied(&prev, &mut eng2, &[id1, id2, id3, id4]).expect("batch");
        // Liar drops the taker fee from fill1's posted post col. fill1's
        // unit is chosen for the right-neighbor completeness arm; the
        // trailing fill2's arm is covered by
        // fill_math_trailing_fill_builds_last_arm_proof.
        let alice_hex = hex::encode(alice_id.0);
        if let Some(leaves) = batch.leaf_trace.get_mut(1) {
            for l in leaves.iter_mut() {
                if l.starts_with(&format!("acct:{alice_hex}:")) {
                    let p: Vec<&str> = l.split(':').collect();
                    let col: i128 = p[2].parse().unwrap();
                    *l = format!(
                        "acct:{}:{}:{}:{}",
                        p[1],
                        col - 2_500 * USD_SCALE as i128,
                        p[3],
                        p[4]
                    );
                }
            }
        }
        batch.trace[1] = obyte_merkle::root(&batch.leaf_trace[1]);
        batch.checkpoint.trace_root = obyte_merkle::root(&batch.trace);
        let mut replay = Engine::new();
        fund(&mut replay);
        let proof = build_proof(&batch, &mut replay, &[], 0).expect("proof");
        assert_eq!(proof.pred, "fill_math");
        assert!(proof.fill_aa);
        assert_eq!(
            proof.data.get("who").and_then(|v| v.as_str()),
            Some("taker")
        );
        assert!(
            proof.data.get("right").is_some(),
            "non-trailing fill keeps the right-neighbor arm"
        );
    }

    #[test]
    fn fill_math_trailing_fill_builds_last_arm_proof() {
        // Same 4-unit chain as fill_math_reduce_builds_proof, but the liar
        // tampers the TRAILING fill's unit (batch.fills' last element).
        // The watcher must still emit: single-fill completeness rides the
        // right-neighbor arm, whose neighbor for the trailing fill is the
        // fills_root length sentinel `n:{len}`.
        use minuend_types::{
            OrderType, Side, TimeInForce, UnitId, BTC_USD, PRICE_SCALE, QTY_SCALE, USD_SCALE,
        };
        let alice = sk(1);
        let bob = sk(2);
        let alice_id = acct_of(&alice);
        let bob_id = acct_of(&bob);
        let fund = |eng: &mut Engine| {
            for id in [alice_id, bob_id] {
                eng.state
                    .account_mut(id)
                    .credit(10_000 * USD_SCALE as i128)
                    .unwrap();
            }
        };
        let mut eng = Engine::new();
        fund(&mut eng);
        let prev = eng.state.clone();
        let g = genesis_id();
        let px1 = 100_000 * PRICE_SCALE as i64;
        let px2 = 105_000 * PRICE_SCALE as i64;
        let q1 = QTY_SCALE;
        let q2 = QTY_SCALE / 2;
        let place = |parents: Vec<UnitId>,
                     secret: &[u8; 32],
                     account: AccountId,
                     side: Side,
                     price: i64,
                     qty: u64,
                     seq: u64| {
            sign_unit(
                parents,
                Op::Place {
                    account,
                    market: BTC_USD,
                    side,
                    typ: OrderType::Limit,
                    tif: TimeInForce::Gtc,
                    price,
                    qty,
                    client_seq: seq,
                    isolated: false,
                    margin: 0,
                },
                secret,
            )
        };
        let ask1 = place(vec![g], &bob, bob_id, Side::Ask, px1, q1, 1);
        let id1 = unit_id(&ask1);
        eng.ingest(ask1).unwrap();
        let bid1 = place(vec![id1], &alice, alice_id, Side::Bid, px1, q1, 1);
        let id2 = unit_id(&bid1);
        eng.ingest(bid1).unwrap();
        let bid2 = place(vec![id2], &bob, bob_id, Side::Bid, px2, q2, 2);
        let id3 = unit_id(&bid2);
        eng.ingest(bid2).unwrap();
        let ask2 = place(vec![id3], &alice, alice_id, Side::Ask, px2, q2, 2);
        let id4 = unit_id(&ask2);
        eng.ingest(ask2).unwrap();
        let mut eng2 = eng.clone();
        let mut batch =
            Batch::from_applied(&prev, &mut eng2, &[id1, id2, id3, id4]).expect("batch");
        assert_eq!(batch.checkpoint.fill_count as usize, batch.fills.len());
        // Tamper fill2's unit (leaf_trace[3]): alice's realized +2500 pnl
        // disappears from her posted collateral.
        let alice_hex = hex::encode(alice_id.0);
        if let Some(leaves) = batch.leaf_trace.get_mut(3) {
            for l in leaves.iter_mut() {
                if l.starts_with(&format!("acct:{alice_hex}:")) {
                    let p: Vec<&str> = l.split(':').collect();
                    let col: i128 = p[2].parse().unwrap();
                    *l = format!(
                        "acct:{}:{}:{}:{}",
                        p[1],
                        col - 2_500 * USD_SCALE as i128,
                        p[3],
                        p[4]
                    );
                }
            }
        }
        batch.trace[3] = obyte_merkle::root(&batch.leaf_trace[3]);
        batch.checkpoint.trace_root = obyte_merkle::root(&batch.trace);
        let mut replay = Engine::new();
        fund(&mut replay);
        let proof = build_proof(&batch, &mut replay, &[], 0).expect("proof");
        assert_eq!(proof.pred, "fill_math");
        assert!(proof.fill_aa);
        let len = batch.fills.len();
        assert_eq!(
            proof.data.get("right").and_then(|v| v.as_str()),
            Some(format!("n:{len}").as_str()),
            "trailing fill's right neighbor is the length sentinel"
        );
        let rp = proof.data.get("right_proof").expect("right_proof");
        assert_eq!(
            rp.get("root").and_then(|v| v.as_str()),
            Some(batch.checkpoint.fills_root.as_str()),
            "sentinel proof verifies against the posted fills_root"
        );
        assert_eq!(
            rp.get("index").and_then(|v| v.as_u64()),
            Some(len as u64),
            "sentinel sits at index len"
        );
        assert!(
            proof.data.get("op").is_some(),
            "taker leg carries the unit op proof"
        );
    }

    #[test]
    fn fill_math_isolated_taker_emits_op_and_ord_proofs() {
        // Bob rests a cross ask; alice crosses it with an ISOLATED bid that
        // fully fills (her taker order leaves no post ord leaf). The liar
        // inflates alice's posted collateral by 1 unit. The payload must
        // carry the p: op proof (isolated flag) plus the taker-ord absence
        // straddle; as the batch's only fill its right neighbor is the
        // fills_root length sentinel.
        use minuend_types::{
            OrderType, Side, TimeInForce, BTC_USD, PRICE_SCALE, QTY_SCALE, USD_SCALE,
        };
        let alice = sk(1);
        let bob = sk(2);
        let alice_id = acct_of(&alice);
        let bob_id = acct_of(&bob);
        let fund = |eng: &mut Engine| {
            eng.state
                .account_mut(alice_id)
                .credit(10_000 * USD_SCALE as i128)
                .unwrap();
            eng.state
                .account_mut(bob_id)
                .credit(10_000 * USD_SCALE as i128)
                .unwrap();
        };
        let mut eng = Engine::new();
        fund(&mut eng);
        let prev = eng.state.clone();
        let g = genesis_id();
        let px = 100_000 * PRICE_SCALE as i64;
        let q = QTY_SCALE / 1000;
        let margin = 40 * USD_SCALE;
        let ask = sign_unit(
            vec![g],
            Op::Place {
                account: bob_id,
                market: BTC_USD,
                side: Side::Ask,
                typ: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: px,
                qty: q,
                client_seq: 1,
                isolated: false,
                margin: 0,
            },
            &bob,
        );
        let id1 = unit_id(&ask);
        eng.ingest(ask).unwrap();
        let bid = sign_unit(
            vec![id1],
            Op::Place {
                account: alice_id,
                market: BTC_USD,
                side: Side::Bid,
                typ: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: px,
                qty: q,
                client_seq: 1,
                isolated: true,
                margin,
            },
            &alice,
        );
        let id2 = unit_id(&bid);
        eng.ingest(bid).unwrap();
        let mut eng2 = eng.clone();
        let mut batch = Batch::from_applied(&prev, &mut eng2, &[id1, id2]).expect("batch");
        assert_eq!(batch.fills.len(), 1, "one fill, the batch's last element");
        assert_eq!(batch.checkpoint.fill_count, 1);
        // Liar: alice's posted collateral inflated by 1 USD unit.
        let alice_hex = hex::encode(alice_id.0);
        if let Some(leaves) = batch.leaf_trace.get_mut(1) {
            for l in leaves.iter_mut() {
                if l.starts_with(&format!("acct:{alice_hex}:")) {
                    let p: Vec<&str> = l.split(':').collect();
                    let col: i128 = p[2].parse().unwrap();
                    *l = format!("acct:{}:{}:{}:{}", p[1], col + 1, p[3], p[4]);
                }
            }
        }
        batch.trace[1] = obyte_merkle::root(&batch.leaf_trace[1]);
        batch.checkpoint.trace_root = obyte_merkle::root(&batch.trace);
        let mut replay = Engine::new();
        fund(&mut replay);
        let proof = build_proof(&batch, &mut replay, &[], 0).expect("proof");
        assert_eq!(proof.pred, "fill_math");
        assert!(proof.fill_aa);
        assert_eq!(
            proof.data.get("who").and_then(|v| v.as_str()),
            Some("taker")
        );
        let op = proof
            .data
            .get("op")
            .and_then(|v| v.as_str())
            .expect("op proof emitted");
        assert!(op.starts_with("p:"), "taker leg requires a Place op");
        assert_eq!(
            op.split(':').nth(6),
            Some("1"),
            "op carries the isolated flag"
        );
        assert!(proof.data.get("ops_proof").is_some());
        assert!(
            proof.data.get("tord").is_some()
                || (proof.data.get("oleft").is_some() && proof.data.get("oright").is_some()),
            "taker-ord membership or absence straddle is emitted"
        );
        assert_eq!(
            proof.data.get("right").and_then(|v| v.as_str()),
            Some(format!("n:{}", batch.fills.len()).as_str()),
            "sole batch fill's right neighbor is the length sentinel"
        );
        assert!(proof.data.get("right_proof").is_some());
    }
    #[test]
    fn honest_batch_builds_no_proof() {
        // Clean deposit batch, no inbox, untampered leaves: None.
        let secret = sk(7);
        let acct = acct_of(&secret);
        let g = genesis_id();
        let aa = [9u8; 32];
        let u = sign_unit(
            vec![g],
            Op::Deposit {
                account: acct,
                addr: test_addr(),
                amount: 100,
                aa_unit: aa,
            },
            &secret,
        );
        let id = unit_id(&u);
        let mut eng = Engine::new();
        eng.state.deposits_allowed.insert((aa, false));
        eng.ingest(u).unwrap();
        let prev = minuend_state::ChainState::new();
        let mut eng2 = eng.clone();
        let batch = Batch::from_applied(&prev, &mut eng2, &[id]).expect("batch");
        let mut replay = Engine::new();
        // Replay on a fresh engine at genesis prev root: the deposit
        // replays honestly, no divergence.
        replay.state.deposits_allowed.insert((aa, false));
        assert!(build_proof(&batch, &mut replay, &[], 0).is_none());
    }

    // ---- #47 helpers ----
    fn retrace(batch: &mut Batch, k: usize) {
        batch.leaf_trace[k].sort();
        batch.trace[k] = obyte_merkle::root(&batch.leaf_trace[k]);
        batch.checkpoint.trace_root = obyte_merkle::root(&batch.trace);
    }
    fn refill(batch: &mut Batch) {
        batch.checkpoint.fills_root =
            obyte_merkle::root(&minuend_settle::fills_root_elements(&batch.fills));
    }
    fn bump_col(batch: &mut Batch, k: usize, acct_hex: &str, by: i128) {
        for l in batch.leaf_trace[k].iter_mut() {
            if l.starts_with(&format!("acct:{acct_hex}:")) {
                let p: Vec<&str> = l.split(':').collect();
                let col: i128 = p[2].parse().unwrap();
                *l = format!("acct:{}:{}:{}:{}", p[1], col + by, p[3], p[4]);
            }
        }
        retrace(batch, k);
    }
    fn set_fill_field(batch: &mut Batch, i: usize, field: usize, v: &str) {
        let mut p: Vec<String> = batch.fills[i].split(':').map(String::from).collect();
        p[field] = v.to_string();
        batch.fills[i] = p.join(":");
        refill(batch);
    }

    /// Bob rests a cross ask of `ask_q`; alice crosses it with an ISOLATED
    /// Limit/Gtc bid of `bid_q` @ the same price (escrow `margin`).
    /// Returns (prev state, batch, alice hex, fund closure input ids).
    fn iso_taker_batch(ask_q: u64, bid_q: u64, margin: u64) -> (Batch, AccountId, AccountId) {
        use minuend_types::{OrderType, Side, TimeInForce, BTC_USD, PRICE_SCALE, USD_SCALE};
        let alice = sk(1);
        let bob = sk(2);
        let alice_id = acct_of(&alice);
        let bob_id = acct_of(&bob);
        let mut eng = Engine::new();
        for id in [alice_id, bob_id] {
            eng.state
                .account_mut(id)
                .credit(10_000 * USD_SCALE as i128)
                .unwrap();
        }
        let prev = eng.state.clone();
        let px = 100_000 * PRICE_SCALE as i64;
        let ask = sign_unit(
            vec![genesis_id()],
            Op::Place {
                account: bob_id,
                market: BTC_USD,
                side: Side::Ask,
                typ: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: px,
                qty: ask_q,
                client_seq: 1,
                isolated: false,
                margin: 0,
            },
            &bob,
        );
        let id1 = unit_id(&ask);
        eng.ingest(ask).unwrap();
        let bid = sign_unit(
            vec![id1],
            Op::Place {
                account: alice_id,
                market: BTC_USD,
                side: Side::Bid,
                typ: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: px,
                qty: bid_q,
                client_seq: 1,
                isolated: true,
                margin,
            },
            &alice,
        );
        let id2 = unit_id(&bid);
        eng.ingest(bid).unwrap();
        let mut eng2 = eng.clone();
        let batch = Batch::from_applied(&prev, &mut eng2, &[id1, id2]).expect("batch");
        (batch, alice_id, bob_id)
    }
    fn funded_replay(ids: &[AccountId]) -> Engine {
        let mut replay = Engine::new();
        for id in ids {
            replay
                .state
                .account_mut(*id)
                .credit(10_000 * minuend_types::USD_SCALE as i128)
                .unwrap();
        }
        replay
    }

    #[test]
    fn place_op_commits_order_type() {
        // #47 A3: p: ops carry tif AND typ (10 parts) so the AA can tell
        // whether an unfilled remainder rests.
        let (batch, _, _) = iso_taker_batch(
            minuend_types::QTY_SCALE / 1000,
            minuend_types::QTY_SCALE / 500,
            40 * minuend_types::USD_SCALE,
        );
        let op = &batch.ops[1];
        let p: Vec<&str> = op.split(':').collect();
        assert_eq!(p.len(), 10, "{op}");
        assert_eq!(p[8], "0", "tif Gtc");
        assert_eq!(p[9], "0", "typ Limit");
    }

    #[test]
    fn honest_isolated_partial_fill_that_rests_builds_no_proof() {
        // The remainder rests: `still` = margin - taker_post is derived
        // from the op (typ/tif), and the taker's post ord leaf matches.
        let q = minuend_types::QTY_SCALE / 1000;
        let (batch, a, b) = iso_taker_batch(q, 2 * q, 40 * minuend_types::USD_SCALE);
        assert_eq!(batch.fills.len(), 1);
        let mut replay = funded_replay(&[a, b]);
        assert!(build_proof(&batch, &mut replay, &[], 0).is_none());
    }

    #[test]
    fn honest_isolated_full_fill_builds_no_proof() {
        let q = minuend_types::QTY_SCALE / 1000;
        let (batch, a, b) = iso_taker_batch(q, q, 40 * minuend_types::USD_SCALE);
        let mut replay = funded_replay(&[a, b]);
        assert!(build_proof(&batch, &mut replay, &[], 0).is_none());
    }

    #[test]
    fn forged_taker_post_is_fill_math_fraud() {
        // #47 A3: the liar writes a NEGATIVE taker_post into the fill and
        // inflates alice's collateral by the same amount — the old identity
        // (which trusted F[13]) balanced; the op-bound one does not.
        let q = minuend_types::QTY_SCALE / 1000;
        let (mut batch, a, b) = iso_taker_batch(q, q, 40 * minuend_types::USD_SCALE);
        let honest_tpost: i128 = batch.fills[0].split(':').nth(13).unwrap().parse().unwrap();
        let forged = honest_tpost - 1_000_000_000;
        set_fill_field(&mut batch, 0, 13, &forged.to_string());
        let alice_hex = hex::encode(a.0);
        bump_col(&mut batch, 1, &alice_hex, honest_tpost - forged);
        let mut replay = funded_replay(&[a, b]);
        let proof = build_proof(&batch, &mut replay, &[], 0).expect("proof");
        assert_eq!(proof.pred, "fill_math");
        assert_eq!(proof.data["who"].as_str(), Some("taker"));
        assert!(proof.data.get("ops_proof").is_some());
    }

    #[test]
    fn fake_taker_order_id_on_resting_order_is_fraud() {
        // #47 A3: the remainder rests, but the liar points F[5] at a
        // non-existent order id and books the resting escrow back into
        // collateral (old identity: still = 0 behind the absence proof).
        let q = minuend_types::QTY_SCALE / 1000;
        let margin = 40 * minuend_types::USD_SCALE;
        let (mut batch, a, b) = iso_taker_batch(q, 2 * q, margin);
        let tpost: i128 = batch.fills[0].split(':').nth(13).unwrap().parse().unwrap();
        set_fill_field(&mut batch, 0, 5, &"ee".repeat(32));
        let alice_hex = hex::encode(a.0);
        bump_col(&mut batch, 1, &alice_hex, margin as i128 - tpost);
        let mut replay = funded_replay(&[a, b]);
        let proof = build_proof(&batch, &mut replay, &[], 0).expect("proof");
        assert_eq!(proof.pred, "fill_math");
        assert_eq!(proof.data["who"].as_str(), Some("taker"));
    }

    #[test]
    fn inflated_isolated_bucket_is_fraud() {
        // #47 A3: the pos leg now checks the post bucket (old_bucket +
        // taker_post on an open) — a padded bucket would later release
        // into collateral unchallenged.
        let q = minuend_types::QTY_SCALE / 1000;
        let (mut batch, a, b) = iso_taker_batch(q, q, 40 * minuend_types::USD_SCALE);
        let alice_hex = hex::encode(a.0);
        for l in batch.leaf_trace[1].iter_mut() {
            if l.starts_with(&format!("pos:{alice_hex}:")) {
                let mut p: Vec<String> = l.split(':').map(String::from).collect();
                let bk: i128 = p[6].parse().unwrap();
                p[6] = (bk + 5_000_000).to_string();
                *l = p.join(":");
            }
        }
        retrace(&mut batch, 1);
        let mut replay = funded_replay(&[a, b]);
        let proof = build_proof(&batch, &mut replay, &[], 0).expect("proof");
        assert_eq!(proof.pred, "fill_math");
    }

    #[test]
    fn gov_withdraw_fresh_account_with_fabricated_leaf_is_fraud() {
        // #47 B6: a PERP-only holder has no acct leaf, and gov ops never
        // create one — any posted leaf for it is fraud (whatever sign).
        let secret = sk(7);
        let acct = acct_of(&secret);
        let mut eng = Engine::new();
        eng.state.perp_balances.insert(acct, 1_000);
        eng.state.perp_supply = 1_000;
        let prev = eng.state.clone();
        let u = sign_unit(
            vec![genesis_id()],
            Op::GovWithdraw {
                account: acct,
                amount: 100,
                nonce: 1,
            },
            &secret,
        );
        let id = unit_id(&u);
        let mut replay = eng.clone();
        eng.ingest(u).unwrap();
        let mut eng2 = eng.clone();
        let mut batch = Batch::from_applied(&prev, &mut eng2, &[id]).expect("batch");
        let hexa = hex::encode(acct.0);
        assert!(
            !batch.leaf_trace[0]
                .iter()
                .any(|l| l.starts_with(&format!("acct:{hexa}:"))),
            "honest gov unit creates no acct leaf"
        );
        // Honest: nothing to prove.
        let mut r0 = replay.clone();
        assert!(build_proof(&batch, &mut r0, &[], 0).is_none());
        // Liar: fabricate the leaf with the AA's old "expected" perp.
        batch.leaf_trace[0].push(format!("acct:{hexa}:0:100:0"));
        retrace(&mut batch, 0);
        let proof = build_proof(&batch, &mut replay, &[], 0).expect("proof");
        assert_eq!(proof.pred, "withdraw");
        assert_eq!(proof.data["pre_absent"].as_bool(), Some(true));
    }

    /// k0 alice rests an ask @100k (isolated iff `alice_iso`), k1 bob rests
    /// an ask @101k, k2 alice bids 1 @101k (cross).
    fn self_trade_batch(alice_iso: bool) -> (Batch, Engine, [AccountId; 2], Vec<String>) {
        use minuend_types::{
            OrderType, Side, TimeInForce, BTC_USD, PRICE_SCALE, QTY_SCALE, USD_SCALE,
        };
        let alice = sk(1);
        let bob = sk(2);
        let ids = [acct_of(&alice), acct_of(&bob)];
        let mut eng = Engine::new();
        for id in ids {
            eng.state
                .account_mut(id)
                .credit(10_000 * USD_SCALE as i128)
                .unwrap();
        }
        let prev = eng.state.clone();
        let replay = eng.clone();
        let q = QTY_SCALE / 1000;
        let mk = |parents, secret: &[u8; 32], account, side, price, seq, iso: bool| {
            sign_unit(
                parents,
                Op::Place {
                    account,
                    market: BTC_USD,
                    side,
                    typ: OrderType::Limit,
                    tif: TimeInForce::Gtc,
                    price,
                    qty: q,
                    client_seq: seq,
                    isolated: iso,
                    margin: if iso { 40 * USD_SCALE } else { 0 },
                },
                secret,
            )
        };
        let p100 = 100_000 * PRICE_SCALE as i64;
        let p101 = 101_000 * PRICE_SCALE as i64;
        // alice's resting order is an ASK; a later alice BID on the same
        // market must share its mode, so the bid uses alice_iso too.
        let u0 = mk(
            vec![genesis_id()],
            &alice,
            ids[0],
            Side::Ask,
            p100,
            1,
            alice_iso,
        );
        let i0 = unit_id(&u0);
        eng.ingest(u0).unwrap();
        let u1 = mk(vec![i0], &bob, ids[1], Side::Ask, p101, 1, false);
        let i1 = unit_id(&u1);
        eng.ingest(u1).unwrap();
        let u2 = mk(vec![i1], &alice, ids[0], Side::Bid, p101, 2, alice_iso);
        let i2 = unit_id(&u2);
        eng.ingest(u2).unwrap();
        let mut eng2 = eng.clone();
        let batch = Batch::from_applied(&prev, &mut eng2, &[i0, i1, i2]).expect("batch");
        let hexes = vec![hex::encode(i2.0)];
        (batch, replay, ids, hexes)
    }

    #[test]
    fn skip_taker_own_cross_order_stays_exempt() {
        // Cross own maker: cancel-maker-continue, then alice fills bob.
        let (batch, mut replay, _, _) = self_trade_batch(false);
        assert_eq!(
            batch.fills.len(),
            1,
            "alice fills bob after cancelling her own ask"
        );
        assert!(build_proof(&batch, &mut replay, &[], 0).is_none());
    }

    #[test]
    fn skip_past_taker_own_escrowed_order_is_fraud() {
        // #47 B7: alice's own ESCROWED ask @100k rejects her Place
        // (SelfTrade::Reject) — honest batch has no fill at k2. The liar
        // fabricates "alice took bob @101k": crossing past her own escrowed
        // better order is provable skip fraud.
        let (mut batch, mut replay, ids, hexes) = self_trade_batch(true);
        assert!(
            batch.fills.is_empty(),
            "escrowed own maker rejects the place"
        );
        let bob_order = minuend_types::order_id(ids[1], minuend_types::BTC_USD, 1);
        let alice_order = minuend_types::order_id(ids[0], minuend_types::BTC_USD, 2);
        batch.fills.push(format!(
            "f:{}:0:{}:{}:{}:{}:{}:{}:{}:{}:0:0:0",
            hexes[0],
            hex::encode(ids[0].0),
            hex::encode(ids[1].0),
            hex::encode(alice_order.0),
            hex::encode(bob_order.0),
            minuend_types::BTC_USD.0,
            101_000 * minuend_types::PRICE_SCALE as i64,
            minuend_types::QTY_SCALE / 1000,
            3
        ));
        refill(&mut batch);
        let proof = build_proof(&batch, &mut replay, &[], 0).expect("proof");
        assert_eq!(proof.pred, "skip");
        let better = proof.data["better_ord"].as_str().unwrap();
        assert!(better.contains(&hex::encode(ids[0].0)), "alice's own order");
    }

    #[test]
    fn skip_on_first_fill_of_multi_fill_unit_builds_proof() {
        // #47 B3: carol @100k is better than bob @101k; alice sweeps both
        // (2 fills). The liar swaps fill idx 0's maker to bob — the first
        // fill of a multi-fill unit is now challengeable.
        use minuend_types::{
            OrderType, Side, TimeInForce, BTC_USD, PRICE_SCALE, QTY_SCALE, USD_SCALE,
        };
        let (alice, bob, carol) = (sk(1), sk(2), sk(3));
        let ids = [acct_of(&alice), acct_of(&bob), acct_of(&carol)];
        let mut eng = Engine::new();
        for id in ids {
            eng.state
                .account_mut(id)
                .credit(10_000 * USD_SCALE as i128)
                .unwrap();
        }
        let prev = eng.state.clone();
        let mut replay = eng.clone();
        let q = QTY_SCALE / 1000;
        let mk = |parents, secret: &[u8; 32], account, side, price, qty| {
            sign_unit(
                parents,
                Op::Place {
                    account,
                    market: BTC_USD,
                    side,
                    typ: OrderType::Limit,
                    tif: TimeInForce::Gtc,
                    price,
                    qty,
                    client_seq: 1,
                    isolated: false,
                    margin: 0,
                },
                secret,
            )
        };
        let p100 = 100_000 * PRICE_SCALE as i64;
        let p101 = 101_000 * PRICE_SCALE as i64;
        let u0 = mk(vec![genesis_id()], &bob, ids[1], Side::Ask, p101, q);
        let i0 = unit_id(&u0);
        eng.ingest(u0).unwrap();
        let u1 = mk(vec![i0], &carol, ids[2], Side::Ask, p100, q);
        let i1 = unit_id(&u1);
        eng.ingest(u1).unwrap();
        let u2 = mk(vec![i1], &alice, ids[0], Side::Bid, p101, 2 * q);
        let i2 = unit_id(&u2);
        eng.ingest(u2).unwrap();
        let mut eng2 = eng.clone();
        let mut batch = Batch::from_applied(&prev, &mut eng2, &[i0, i1, i2]).expect("batch");
        assert_eq!(batch.fills.len(), 2);
        // Honest: no proof.
        let mut r0 = replay.clone();
        assert!(build_proof(&batch, &mut r0, &[], 0).is_none());
        // Liar: idx 0 claims bob's worse order.
        let bob_order = minuend_types::order_id(ids[1], BTC_USD, 1);
        set_fill_field(&mut batch, 0, 4, &hex::encode(ids[1].0));
        set_fill_field(&mut batch, 0, 6, &hex::encode(bob_order.0));
        set_fill_field(&mut batch, 0, 8, &p101.to_string());
        let proof = build_proof(&batch, &mut replay, &[], 0).expect("proof");
        assert_eq!(proof.pred, "skip");
        assert_eq!(proof.data["fill"].as_str(), Some(batch.fills[0].as_str()));
    }

    fn liq_leg<'a>(acct: &'a str, cp: &'a str, taker: bool, exp_fill: i128) -> Leg<'a> {
        Leg {
            acct_hex: acct,
            market: "1",
            exp_qty: 0,
            exp_entry: 0,
            exp_absent: true,
            exp_bucket: None,
            exp_fill,
            taker_place: None,
            liq: Some(LiqLeg {
                reward: if taker { Some(30) } else { None },
            }),
            allow_last: false,
            counterparty: cp,
            claw_checkable: true,
        }
    }

    fn place_leg<'a>(acct: &'a str, cp: &'a str, exp_fill: i128, cross_taker: bool) -> Leg<'a> {
        Leg {
            acct_hex: acct,
            market: "1",
            exp_qty: 0,
            exp_entry: 0,
            exp_absent: true,
            exp_bucket: None,
            exp_fill,
            taker_place: None,
            liq: None,
            allow_last: false,
            counterparty: cp,
            claw_checkable: cross_taker,
        }
    }

    #[test]
    fn kind0_winner_leg_clawed_by_negative_counterparty_is_not_fraud() {
        // #47 (owner item "claw false-verdict in ordinary fills"): the
        // maker ended the fill negative and was clawed back to 0 from the
        // taker (fill-stage 1000 -> 600). The honest taker leaf 600 must
        // not be judged; with a provably positive counterparty the same
        // numbers ARE fraud (no claw can have happened).
        let a = "aa".repeat(32);
        let c = "cc".repeat(32);
        let tree = |acol: i128, ccol: i128| -> Vec<String> {
            let mut t = vec![
                format!("acct:{a}:{acol}:0:0"),
                format!("acct:{c}:{ccol}:0:0"),
            ];
            t.sort();
            t
        };
        let leg = place_leg(&a, &c, 1_000, true);
        assert!(!aa_fill_verdict(&tree(600, 0), &leg, false, None));
        assert!(!aa_fill_verdict(&tree(600, -5), &leg, false, None));
        assert!(aa_fill_verdict(&tree(600, 5), &leg, false, None));
        assert!(!aa_fill_verdict(&tree(1_000, 5), &leg, false, None));
        // Kind 0/1 maker leg against an ISOLATED taker Place: the taker's
        // unrested escrow refund lands after the claw, so a positive taker
        // leaf proves nothing — never a collateral verdict.
        let iso = place_leg(&a, &c, 1_000, false);
        assert!(!aa_fill_verdict(&tree(600, 5), &iso, false, None));
    }

    #[test]
    fn kind2_legs_bounce_without_positive_counterparty() {
        // #47 B1: a counterparty at <= 0 may mean the claw moved this leg's
        // collateral — the AA (and this mirror) must stay silent even when
        // the leg's own collateral differs from the fill-stage identity.
        let a = "aa".repeat(32);
        let c = "cc".repeat(32);
        let tree = |acol: i128, ccol: i128| -> Vec<String> {
            let mut t = vec![
                format!("acct:{a}:{acol}:0:0"),
                format!("acct:{c}:{ccol}:0:0"),
            ];
            t.sort();
            t
        };
        let maker = liq_leg(&a, &c, false, 1_000);
        // Claw shape: target at 0, maker paid 400 of the hole → 600.
        assert!(!aa_fill_verdict(&tree(600, 0), &maker, false, None));
        // Same numbers with a provably positive target: real fraud.
        assert!(aa_fill_verdict(&tree(600, 5), &maker, false, None));
        // Honest maker leg: exact fill-stage.
        assert!(!aa_fill_verdict(&tree(1_000, 5), &maker, false, None));
    }

    #[test]
    fn kind2_target_leg_models_keeper_seize() {
        // #47 B2: target post = fill-stage - min(reward, fill-stage).
        let a = "aa".repeat(32);
        let c = "cc".repeat(32);
        let mut t = vec![format!("acct:{a}:970:0:0"), format!("acct:{c}:5:0:0")];
        t.sort();
        let taker = liq_leg(&a, &c, true, 1_000);
        assert!(
            !aa_fill_verdict(&t, &taker, false, None),
            "honest keeper seize"
        );
        let mut t2 = vec![format!("acct:{a}:1000:0:0"), format!("acct:{c}:5:0:0")];
        t2.sort();
        assert!(
            aa_fill_verdict(&t2, &taker, false, None),
            "skipped keeper seize"
        );
        // Reward larger than the balance: seize stops at the balance.
        let small = liq_leg(&a, &c, true, 20);
        let mut t3 = vec![format!("acct:{a}:0:0:0"), format!("acct:{c}:5:0:0")];
        t3.sort();
        assert!(!aa_fill_verdict(&t3, &small, false, None));
    }
}
