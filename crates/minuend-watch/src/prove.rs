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
    /// #47 A2: true → post to the binding dispute AA (`--bind`: `wpin`,
    /// `adr`). Never set together with `fill_aa`.
    pub bind_aa: bool,
    /// Exact `trigger.data` supplement (merged with `height`/`pred` by the
    /// poster): `k`, `op`, proofs, leaves, roots the AA stale-checks.
    pub data: serde_json::Value,
}

impl BuiltProof {
    /// Which dispute AA takes this proof: `main`, `book` (round 2: P-ghost
    /// and P-skip moved to `minuend_dispute_book.aa`), `fill` or `bind`.
    pub fn target(&self) -> &'static str {
        if self.bind_aa {
            "bind"
        } else if self.fill_aa {
            "fill"
        } else if self.pred == "ghost"
            || self.pred == "skip"
            || self.pred == "mbind"
            || self.pred == "fsane"
        {
            "book"
        } else {
            "main"
        }
    }
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
    build_proof_with_vault(batch, replay, inbox, submit_ts, &VaultLedger::new())
}

/// The vault AA's deposit ledger as read from the hub for the anchors a
/// batch cites: key `dep_<anchor_b64>` / `depp_<anchor_b64>` →
/// `Some("payer:amount:account")` (recorded) or `None` (read, absent). A
/// key missing from the map is UNKNOWN (not read / hub error).
pub type VaultLedger = std::collections::HashMap<String, Option<String>>;

/// The vault ledger key the binding AA reads for a `d:`/`D:` op
/// (`d:{acct}:{amount}:{addr}:{anchor_b64}`), if the op has that shape.
pub fn vault_key_of_op(op: &str) -> Option<String> {
    let o: Vec<&str> = op.split(':').collect();
    match (o.first(), o.len()) {
        (Some(&"d"), 5) => Some(format!("dep_{}", o[4])),
        (Some(&"D"), 5) => Some(format!("depp_{}", o[4])),
        _ => None,
    }
}

/// [`build_proof`] with the vault deposit records the caller read from the
/// hub. R4-A-4: a P-adr proof that rests on the vault record (a new
/// binding whose anchor is unbacked / paid by someone else / for another
/// account / of the other asset kind) is built only when that record is
/// KNOWN — from `vault`, or from verified deposit evidence of that anchor
/// in the batch. An unknown record (e.g. an anchor the vault recorded but
/// the producer did not apply, so no evidence was stamped, and the hub was
/// not read) never yields a proof the AA might bounce.
pub fn build_proof_with_vault(
    batch: &Batch,
    replay: &mut Engine,
    inbox: &[(String, u64)],
    submit_ts: u64,
    vault: &VaultLedger,
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
    // R4-A-4: vault-record knowledge for P-adr, built once per batch.
    let vault_aa = minuend_settle::expected_vault();
    let backing = Backing {
        ledger: vault,
        evs: batch
            .unit_evidences
            .iter()
            .flatten()
            .filter(|e| {
                minuend_settle::deposit_verify::verify_evidence(
                    e,
                    &vault_aa,
                    &minuend_types::PERP_ASSET,
                )
                .is_ok()
            })
            .collect(),
    };
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
            if let Some(p) = deposit_proof(batch, k, &op, &pre_leaves, true, vault) {
                return Some(p);
            }
        } else if op.starts_with("w:") || op.starts_with("W:") {
            if let Some(p) = deposit_proof(batch, k, &op, &pre_leaves, false, vault) {
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
        // #47 A2: the two witness columns the vault pays against (W and
        // the adr: binding), pinned on EVERY unit by the binding dispute AA.
        if let Some(p) = binding_proof(batch, k, &op, &pre_leaves, &post_leaves, &backing) {
            return Some(p);
        }
        // Round 2: permanent leaves kept, binding mirror intact.
        if let Some(p) = keep_mirror_proof(batch, k, &pre_leaves, &post_leaves) {
            return Some(p);
        }
        // R4-A-3: positions and orders frozen across c:/d:/w:/D:/W: units.
        if let Some(p) = frame_proof(batch, k, &op, &pre_leaves, &post_leaves) {
            return Some(p);
        }
    }
    // R2-A-1: every unit transition replayed clean — the committed
    // wit_root must still be the trace's last element (P-tip).
    tip_proof(batch)
}

/// #47 A2 + round 2 mirror of `minuend_dispute_bind.aa` (P-wpin / P-adr)
/// for one posted post leaf: `None` = the AA accepts the transition
/// (bounces 'no fraud').
fn binding_violation(
    op: &str,
    pre: &[String],
    post_leaf: &str,
    backing: Option<&Backing>,
) -> Option<()> {
    let p: Vec<&str> = post_leaf.split(':').collect();
    let o: Vec<&str> = op.split(':').collect();
    if p.len() == 5 && p[0] == "acct" && p[1].len() == 64 {
        let key = format!("acct:{}:", p[1]);
        let pre_leaf = pre.iter().find(|l| l.starts_with(&key));
        let (w0, c0) = match pre_leaf {
            Some(l) => {
                let q: Vec<&str> = l.split(':').collect();
                (q.get(4)?.to_string(), q.get(2)?.to_string())
            }
            None => ("0".to_string(), "0".to_string()),
        };
        let own = o.len() == 4 && o[0] == "w" && o[1] == p[1];
        if !own {
            return if p[4] == w0 { None } else { Some(()) };
        }
        // R2-A-2: rejected => both columns unchanged; accepted => W += amt
        // AND collateral -= amt on an existing pre leaf (<= 15 digits).
        if p[4] == w0 && p[2] == c0 {
            return None;
        }
        let short = |s: &str| s.len() <= 15;
        let accepted = pre_leaf.is_some()
            && [o[2], p[2], p[4], c0.as_str(), w0.as_str()]
                .iter()
                .all(|v| short(v))
            && (|| {
                let amt: i128 = o[2].parse().ok()?;
                let w0n: i128 = w0.parse().ok()?;
                let c0n: i128 = c0.parse().ok()?;
                let w1: i128 = p[4].parse().ok()?;
                let c1: i128 = p[2].parse().ok()?;
                // R3-A-1: an accepted withdrawal never leaves col < 0.
                Some(amt > 0 && w1 == w0n + amt && c1 == c0n - amt && c1 >= 0)
            })()
            .unwrap_or(false);
        return if accepted { None } else { Some(()) };
    }
    if p.len() == 3 && p[0] == "adr" && p[2].len() == 64 {
        let key = format!("adr:{}:", p[1]);
        return match pre.iter().find(|l| l.starts_with(&key)) {
            Some(l) if l == post_leaf => None,
            Some(_) => Some(()),
            None => {
                // R2-A-8: the account must not already be bound.
                let bound = pre
                    .iter()
                    .any(|l| l.starts_with(&format!("adrx:{}:", p[2])));
                // R3-A-7: D: carries its anchor too (5 parts).
                let shape = (o.first() == Some(&"d") || o.first() == Some(&"D")) && o.len() == 5;
                // R4-A-4: the AA also requires the vault's dep_/depp_
                // record of the anchor, paid by this address for this
                // account. Judged only when the record is KNOWN (hub read
                // or verified batch evidence); unknown = no verdict here.
                let ok = !bound
                    && shape
                    && o[1] == p[2]
                    && o[3] == p[1]
                    && backing.is_none_or(|b| match b.record(o[0] == "D", o[4]) {
                        None => true,
                        Some(None) => false,
                        Some(Some((payer, account))) => {
                            payer == o[3] && account.eq_ignore_ascii_case(o[1])
                        }
                    });
                if ok {
                    None
                } else {
                    Some(())
                }
            }
        };
    }
    None
}

/// R4-A-4: what the watcher knows of the vault AA's deposit ledger for
/// one batch — the hub reads (`ledger`) and the batch's deposit evidences
/// that VERIFY against the vault (each one fully determines the vault's
/// record of its anchor: the vault writes `dep_` or `depp_`, never both).
pub(crate) struct Backing<'a> {
    pub(crate) ledger: &'a VaultLedger,
    pub(crate) evs: Vec<&'a minuend_settle::DepositEvidence>,
}

impl Backing<'_> {
    /// The vault record the binding AA reads for (`is_perp`, anchor):
    /// `Some(Some((payer, account_hex)))` recorded, `Some(None)` known
    /// absent, `None` unknown.
    fn record(&self, is_perp: bool, anchor_b64: &str) -> Option<Option<(String, String)>> {
        let key = format!("{}{anchor_b64}", if is_perp { "depp_" } else { "dep_" });
        if let Some(v) = self.ledger.get(&key) {
            return Some(v.as_ref().and_then(|r| {
                let q: Vec<&str> = r.split(':').collect();
                (q.len() == 3).then(|| (q[0].to_string(), q[2].to_string()))
            }));
        }
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(anchor_b64)
            .ok()?;
        let hex_anchor = hex::encode(raw);
        let ev = self
            .evs
            .iter()
            .find(|e| e.aa_unit.eq_ignore_ascii_case(&hex_anchor))?;
        if ev.is_perp == is_perp {
            Some(Some((ev.payer.clone(), ev.account.clone())))
        } else {
            Some(None)
        }
    }
}

/// Prefix non-membership of `key` in the sorted `leaves`, in the AA's two
/// shapes (adjacent straddle, before-min). Round 2: no after-max arm —
/// every witness tree ends with the `~:end` sentinel (R2-A-10).
fn prefix_absence(leaves: &[String], key: &str) -> Option<serde_json::Value> {
    let pos = leaves
        .iter()
        .position(|l| l.as_str() >= key)
        .unwrap_or(leaves.len());
    if leaves.get(pos).is_some_and(|l| l.starts_with(key)) {
        return None;
    }
    if pos > 0 && pos < leaves.len() {
        Some(serde_json::json!({
            "left": leaves[pos - 1], "left_proof": proof_json(leaves, pos - 1),
            "right": leaves[pos], "right_proof": proof_json(leaves, pos),
        }))
    } else if pos == 0 && !leaves.is_empty() {
        Some(serde_json::json!({"left": leaves[0], "left_proof": proof_json(leaves, 0)}))
    } else {
        None
    }
}

/// Exact non-membership of `leaf` in the sorted `leaves` (P-keep /
/// P-mirror / P-deposit marker shapes): adjacent straddle or before-min.
fn exact_absence(leaves: &[String], leaf: &str, l: &str, r: &str) -> Option<serde_json::Value> {
    if leaves.iter().any(|x| x == leaf) {
        return None;
    }
    let pos = leaves
        .iter()
        .position(|x| x.as_str() > leaf)
        .unwrap_or(leaves.len());
    if pos > 0 && pos < leaves.len() {
        let mut m = serde_json::Map::new();
        m.insert(l.into(), leaves[pos - 1].clone().into());
        m.insert(format!("{l}_proof"), proof_json(leaves, pos - 1));
        m.insert(r.into(), leaves[pos].clone().into());
        m.insert(format!("{r}_proof"), proof_json(leaves, pos));
        Some(serde_json::Value::Object(m))
    } else if pos == 0 && !leaves.is_empty() {
        let mut m = serde_json::Map::new();
        m.insert(l.into(), leaves[0].clone().into());
        m.insert(format!("{l}_proof"), proof_json(leaves, 0));
        Some(serde_json::Value::Object(m))
    } else {
        None
    }
}

/// Mirror leaf of a binding leaf: adr:{A}:{X} <-> adrx:{X}:{A}.
fn binding_mirror(leaf: &str) -> Option<String> {
    let q: Vec<&str> = leaf.split(':').collect();
    if q.len() != 3 {
        return None;
    }
    match q[0] {
        "adr" => Some(format!("adrx:{}:{}", q[2], q[1])),
        "adrx" => Some(format!("adr:{}:{}", q[2], q[1])),
        _ => None,
    }
}

/// Round 2 P-keep / P-mirror for unit `k` (binding dispute AA): a
/// permanent pre leaf (`adr:`/`adrx:`/`dep:`) missing from the POSTED post
/// tree, or a posted binding leaf without its mirror. Emitted only when
/// the honest replay's post tree does not break the same rule.
fn keep_mirror_proof(
    batch: &Batch,
    k: usize,
    pre_leaves: &[String],
    post_leaves: &[String],
) -> Option<BuiltProof> {
    let posted = batch.leaf_trace.get(k)?;
    let permanent =
        |l: &&String| l.starts_with("adr:") || l.starts_with("adrx:") || l.starts_with("dep:");
    // R3-A-6: an account leaf may change but its account never vanishes.
    let acct_key = |l: &str| -> Option<String> {
        let q: Vec<&str> = l.split(':').collect();
        (q.len() == 5 && q[0] == "acct" && q[1].len() == 64).then(|| format!("acct:{}:", q[1]))
    };
    let base = || {
        serde_json::json!({
            "trace_root": batch.checkpoint.trace_root,
            "k": k,
            "post_wit": batch.trace.get(k).cloned().unwrap_or_default(),
            "post_proof": proof_json(&batch.trace, k),
        })
    };
    // P-keep
    if let Some(lost) = pre_leaves
        .iter()
        .filter(permanent)
        .find(|l| !posted.contains(l) && post_leaves.contains(l))
    {
        let mut data = base();
        let obj = data.as_object_mut()?;
        obj.extend(pre_wit_fields(batch, k, pre_leaves).as_object()?.clone());
        obj.insert("leaf".into(), lost.clone().into());
        obj.insert(
            "leaf_proof".into(),
            proof_json(pre_leaves, index_of(pre_leaves, lost)?),
        );
        obj.extend(
            exact_absence(posted, lost, "left", "right")?
                .as_object()?
                .clone(),
        );
        return Some(BuiltProof {
            pred: "keep".into(),
            fill_aa: false,
            bind_aa: true,
            data,
        });
    }
    // R3-A-6 P-keep (acct:): a pre account with no posted post leaf while
    // the honest post tree still holds it.
    for l in pre_leaves.iter() {
        let Some(key) = acct_key(l) else { continue };
        if posted.iter().any(|p| p.starts_with(&key))
            || !post_leaves.iter().any(|p| p.starts_with(&key))
        {
            continue;
        }
        let mut data = base();
        let obj = data.as_object_mut()?;
        obj.extend(pre_wit_fields(batch, k, pre_leaves).as_object()?.clone());
        obj.insert("leaf".into(), l.clone().into());
        obj.insert(
            "leaf_proof".into(),
            proof_json(pre_leaves, index_of(pre_leaves, l)?),
        );
        obj.extend(prefix_absence(posted, &key)?.as_object()?.clone());
        return Some(BuiltProof {
            pred: "keep".into(),
            fill_aa: false,
            bind_aa: true,
            data,
        });
    }
    // P-mirror
    for l in posted.iter() {
        let Some(m) = binding_mirror(l) else { continue };
        if posted.contains(&m) {
            continue;
        }
        let honest_breaks = post_leaves
            .iter()
            .any(|h| binding_mirror(h).is_some_and(|hm| !post_leaves.contains(&hm)));
        if honest_breaks {
            return None;
        }
        let mut data = base();
        let obj = data.as_object_mut()?;
        obj.insert("leaf".into(), l.clone().into());
        obj.insert(
            "leaf_proof".into(),
            proof_json(posted, index_of(posted, l)?),
        );
        obj.extend(
            exact_absence(posted, &m, "left", "right")?
                .as_object()?
                .clone(),
        );
        return Some(BuiltProof {
            pred: "mirror".into(),
            fill_aa: false,
            bind_aa: true,
            data,
        });
    }
    None
}

/// R4-A-3 mirror of the binding AA's P-frame: at a unit whose op is
/// `c:`/`d:`/`w:`/`D:`/`W:` (well-formed), a `pos:`/`ord:` leaf of the PRE
/// tree missing from the POSTED post tree (except the order a `c:` of its
/// owner cancels), or a posted `pos:`/`ord:` leaf missing from the pre
/// tree. Emitted only when the honest replay's post tree agrees with the
/// pre tree on that leaf (the engine never moves them under these ops).
fn frame_proof(
    batch: &Batch,
    k: usize,
    op: &str,
    pre_leaves: &[String],
    post_leaves: &[String],
) -> Option<BuiltProof> {
    let o: Vec<&str> = op.split(':').collect();
    let t = *o.first()?;
    let shape = match t {
        "c" => o.len() == 3,
        "d" | "D" => o.len() == 5,
        "w" | "W" => o.len() == 4,
        _ => false,
    };
    if !shape {
        return None;
    }
    let posted = batch.leaf_trace.get(k)?;
    // R5-A-1: acct leaves of accounts other than the op's are frozen too
    // (the op account is op[2..66] for all five shapes).
    let op_acct = op.get(2..66);
    let framed = |l: &str| {
        let n = l.split(':').count();
        let foreign_acct = n == 5
            && l.starts_with("acct:")
            && l.as_bytes().get(69) == Some(&b':')
            && l.get(5..69) != op_acct;
        (l.starts_with("pos:") && n == 7) || (l.starts_with("ord:") && n == 10) || foreign_acct
    };
    let cancelled = |l: &str| {
        let q: Vec<&str> = l.split(':').collect();
        t == "c" && q[0] == "ord" && q.get(1) == o.get(2) && q.get(7) == o.get(1)
    };
    let base = |leaf: &str, ins: bool, src: &[String]| -> Option<serde_json::Value> {
        let mut data = serde_json::json!({
            "trace_root": batch.checkpoint.trace_root,
            "ops_root": batch.checkpoint.ops_root,
            "k": k,
            "op": op,
            "ops_proof": proof_json(&batch.ops, k),
            "post_wit": batch.trace.get(k)?.clone(),
            "post_proof": proof_json(&batch.trace, k),
            "leaf": leaf,
            "leaf_proof": proof_json(src, index_of(src, leaf)?),
            "ins": ins,
        });
        data.as_object_mut()?
            .extend(pre_wit_fields(batch, k, pre_leaves).as_object()?.clone());
        Some(data)
    };
    // Deletion / rewrite: a pre leaf the posted post tree dropped.
    for l in pre_leaves.iter() {
        if !framed(l) || cancelled(l) || posted.contains(l) || !post_leaves.contains(l) {
            continue;
        }
        let mut data = base(l, false, pre_leaves)?;
        data.as_object_mut()?.extend(
            exact_absence(posted, l, "left", "right")?
                .as_object()?
                .clone(),
        );
        return Some(BuiltProof {
            pred: "frame".into(),
            fill_aa: false,
            bind_aa: true,
            data,
        });
    }
    // Insertion / rewrite: a posted leaf the pre tree never held.
    let empty_pre = pre_leaves.len() == 1 && pre_leaves[0] == minuend_types::WIT_EMPTY_ELEMENT;
    for l in posted.iter() {
        if !framed(l) || pre_leaves.contains(l) || post_leaves.contains(l) {
            continue;
        }
        let mut data = base(l, true, posted)?;
        if !empty_pre {
            data.as_object_mut()?.extend(
                exact_absence(pre_leaves, l, "left", "right")?
                    .as_object()?
                    .clone(),
            );
        }
        return Some(BuiltProof {
            pred: "frame".into(),
            fill_aa: false,
            bind_aa: true,
            data,
        });
    }
    None
}

/// R5-A-2: the P-fsane shape rule on a fill string (mirrors the book AA's
/// `$bad`): not 14 fields, qty not a positive integer, price / taker_post
/// not integers, taker_post < 0, side not 0/1, kind not 0..3, or kind 2/3
/// with taker_post != 0.
fn fsane_shape_bad(parts: &[&str]) -> bool {
    if parts.len() != 14 {
        return true;
    }
    let int = |s: &str| oscript_num(s).filter(|x| x.fract() == 0.0);
    let Some(q) = int(parts[9]) else { return true };
    if q <= 0.0 || int(parts[8]).is_none() {
        return true;
    }
    let Some(tp) = int(parts[13]) else {
        return true;
    };
    if tp < 0.0 {
        return true;
    }
    if oscript_eq(parts[11], "0") != Some(true) && oscript_eq(parts[11], "1") != Some(true) {
        return true;
    }
    let Some(kd) = int(parts[12]).filter(|k| (0.0..=3.0).contains(k)) else {
        return true;
    };
    kd >= 2.0 && tp != 0.0
}

/// R5-A-2 P-fsane proof for one posted fill of unit `k` (see the book AA).
fn fsane_proof(
    batch: &Batch,
    k: usize,
    f: &str,
    pre_leaves: &[String],
    fills_tree: &[String],
    unit_hexes: &[String],
) -> Option<BuiltProof> {
    let parts: Vec<&str> = f.split(':').collect();
    let idx = index_of(&batch.fills, f)?;
    let mut data = serde_json::json!({
        "trace_root": batch.checkpoint.trace_root,
        "fills_root": batch.checkpoint.fills_root,
        "ops_root": batch.checkpoint.ops_root,
        "units_root": batch.checkpoint.units_root,
        "k": k,
        "fill": f,
        "fill_proof": proof_json(fills_tree, idx),
    });
    let built = |data: serde_json::Value| BuiltProof {
        pred: "fsane".into(),
        fill_aa: false,
        bind_aa: false,
        data,
    };
    if fsane_shape_bad(&parts) {
        if parts.len() == 14 {
            data.as_object_mut()?
                .insert("units_proof".into(), proof_json(unit_hexes, k));
        }
        return Some(built(data));
    }
    if unit_hexes.get(k).map(String::as_str) != Some(parts[1]) {
        return None;
    }
    data.as_object_mut()?
        .insert("units_proof".into(), proof_json(unit_hexes, k));
    data.as_object_mut()?
        .extend(pre_wit_fields(batch, k, pre_leaves).as_object()?.clone());
    let kind = parts[12];
    // Kind vs market (usd_per_unit != 0 = funding-rate market).
    if let Some(meta) = pre_leaves
        .iter()
        .find(|l| l.starts_with(&format!("meta:{}:", parts[7])))
    {
        let m: Vec<&str> = meta.split(':').collect();
        if let Some(usd) = m
            .get(9)
            .and_then(|v| v.parse::<i128>().ok())
            .filter(|_| m.len() == 11)
        {
            let fund = usd != 0;
            if (kind == "0" && fund) || (kind == "1" && !fund) || (kind == "3" && fund) {
                let mut d = data.clone();
                let o = d.as_object_mut()?;
                o.insert("pre_meta".into(), meta.clone().into());
                o.insert(
                    "pre_meta_proof".into(),
                    proof_json(pre_leaves, index_of(pre_leaves, meta)?),
                );
                return Some(built(d));
            }
        }
    }
    // Rejected direct Place: cross with margin != 0, or isolated with a
    // margin > 0 above the op account's pre collateral.
    let op = batch.ops.get(k)?;
    let o: Vec<&str> = op.split(':').collect();
    if o.len() == 10 && o[0] == "p" {
        if let Ok(margin) = o[7].parse::<i128>() {
            let mut d = data.clone();
            {
                let obj = d.as_object_mut()?;
                obj.insert("op".into(), op.clone().into());
                obj.insert("ops_proof".into(), proof_json(&batch.ops, k));
            }
            if o[6] == "0" && margin != 0 {
                return Some(built(d));
            }
            if o[6] == "1" && margin > 0 {
                let key = format!("acct:{}:", op.get(2..66)?);
                if let Some(acct) = pre_leaves.iter().find(|l| l.starts_with(&key)) {
                    let col = acct.split(':').nth(2).and_then(|c| c.parse::<i128>().ok());
                    if col.is_some_and(|c| margin > c) && acct.split(':').count() == 5 {
                        let obj = d.as_object_mut()?;
                        obj.insert("pre_acct".into(), acct.clone().into());
                        obj.insert(
                            "pre_acct_proof".into(),
                            proof_json(pre_leaves, index_of(pre_leaves, acct)?),
                        );
                        return Some(built(d));
                    }
                }
            }
        }
    }
    // Absent fill party.
    for (who, hexs) in [("taker", parts[3]), ("maker", parts[4])] {
        if hexs.bytes().all(|b| b.is_ascii_digit()) {
            continue; // Oscript would read it as a number
        }
        if let Some(abs) = prefix_absence(pre_leaves, &format!("acct:{hexs}:")) {
            let mut d = data.clone();
            let obj = d.as_object_mut()?;
            obj.insert("who".into(), who.into());
            obj.extend(abs.as_object()?.clone());
            return Some(built(d));
        }
    }
    None
}

/// R2-A-1 P-tip: the committed wit_root is not the trace's last element.
fn tip_proof(batch: &Batch) -> Option<BuiltProof> {
    let n = batch.checkpoint.unit_count as usize;
    let tip = batch.trace.get(n.checked_sub(1)?)?;
    if *tip == batch.checkpoint.wit_root {
        return None;
    }
    Some(BuiltProof {
        pred: "tip".into(),
        fill_aa: false,
        bind_aa: true,
        data: serde_json::json!({"tip": tip, "tip_proof": proof_json(&batch.trace, n - 1)}),
    })
}

/// #47 A2: P-wpin / P-adr proof for unit `k`, emitted only when the POSTED
/// post tree breaks the binding AA's rule and the honest replay does not
/// (a rule the honest engine itself broke would be a model bug — stay
/// silent rather than challenge an honest batch).
fn binding_proof(
    batch: &Batch,
    k: usize,
    op: &str,
    pre_leaves: &[String],
    post_leaves: &[String],
    backing: &Backing,
) -> Option<BuiltProof> {
    let posted_post = batch.leaf_trace.get(k)?;
    let liar = posted_post.iter().find(|l| {
        binding_violation(op, pre_leaves, l, Some(backing)).is_some()
            && !post_leaves.iter().any(|h| h == *l)
    })?;
    if post_leaves
        .iter()
        // The honest replay binds only on a credited, evidence-backed
        // deposit: judge its leaves without the offline backing lookup.
        .any(|l| binding_violation(op, pre_leaves, l, None).is_some())
    {
        return None;
    }
    let wpin = liar.starts_with("acct:");
    let key = if wpin {
        format!("acct:{}:", liar.split(':').nth(1)?)
    } else {
        format!("adr:{}:", liar.split(':').nth(1)?)
    };
    let mut data = serde_json::json!({
        "trace_root": batch.checkpoint.trace_root,
        "ops_root": batch.checkpoint.ops_root,
        "k": k,
        "op": op,
        "ops_proof": proof_json(&batch.ops, k),
        "post_wit": batch.trace.get(k)?.clone(),
        "post_proof": proof_json(&batch.trace, k),
        "post_leaf": liar,
        "post_leaf_proof": proof_json(posted_post, index_of(posted_post, liar)?),
    });
    let pre_fields = pre_wit_fields(batch, k, pre_leaves);
    let obj = data.as_object_mut()?;
    obj.extend(pre_fields.as_object()?.clone());
    match pre_leaves.iter().position(|l| l.starts_with(&key)) {
        Some(i) => {
            obj.insert("pre_leaf".into(), pre_leaves[i].clone().into());
            obj.insert("pre_leaf_proof".into(), proof_json(pre_leaves, i));
        }
        None => {
            let absent = prefix_absence(pre_leaves, &key)?;
            obj.extend(absent.as_object()?.clone());
            // R2-A-8: a new binding of an already-bound account.
            if !wpin {
                let xkey = format!("adrx:{}:", liar.split(':').nth(2)?);
                if let Some(i) = pre_leaves.iter().position(|l| l.starts_with(&xkey)) {
                    obj.insert("xleaf".into(), pre_leaves[i].clone().into());
                    obj.insert("xleaf_proof".into(), proof_json(pre_leaves, i));
                }
            }
        }
    }
    Some(BuiltProof {
        pred: if wpin { "wpin".into() } else { "adr".into() },
        fill_aa: false,
        bind_aa: true,
        data,
    })
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
    vault: &VaultLedger,
) -> Option<BuiltProof> {
    // Parse op: d:/D:{acct}:{amount}:{addr}:{aa_unit_b64} (round 2/3),
    // w:/W:{acct}:{amount}:{nonce}.
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
    // R4-A-6 (mirrors the AA): the PERP column is judged by arithmetic only
    // within 14 digits (engine PERP_SUPPLY_MAX < 1e14); a longer pre column
    // is not judged at all, a longer post column / amount only as unchanged.
    if is_gov && pre_hit.is_some() && pre_perp.to_string().len() > 14 {
        return None;
    }
    let pnum = !is_gov || (liar_perp.to_string().len() <= 14 && parts[2].len() <= 14);
    let liar_val_is_expected = pnum && liar_val == expected;
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
    // R3-A-1 (mirrors the AA): an ACCEPTED withdrawal never leaves the
    // moving column negative, and a pre-absent account can only have its
    // withdrawal REJECTED (col 0).
    let wd_ok = is_deposit || unchanged || (pre_hit.is_some() && liar_val >= 0);
    // R2-A-3 (mirrors the AA's credit arm): a credited collateral deposit
    // (R3-A-7: or PERP `D:` deposit) is also judged on its anchor marker
    // `dep:{aa_unit}` — already in the pre tree (re-credit) or missing from
    // the posted post tree — and (R3-A-4) on the binding
    // `adr:{addr}:{acct}`, which must be in the posted post tree. The
    // vault-ledger backing (dep_/depp_<unit> = payer:amount:account) is
    // on-chain state: the AA checks it on every deposit challenge, and
    // (R5 integration) this builder judges it only from a hub read in
    // `vault` ([`deposit_unbacked_by_ledger`]) — never from batch
    // evidence, because a PERP deposit the vault bounced at its
    // `pperp_total` cap still yields a verifying evidence.
    let credited = is_deposit
        && amount > 0
        && liar_val_is_expected
        && !unchanged
        && (!is_gov || (pre_hit.is_some() && col_ok));
    let mut dep_extra = serde_json::Map::new();
    if credited {
        if let Some(u) = parts.get(4) {
            let mk = format!("dep:{u}");
            if let Some(i) = index_of(pre_leaves, &mk) {
                dep_extra.insert("dep_pre_proof".into(), proof_json(pre_leaves, i));
            } else if let Some(a) = exact_absence(&posted_post, &mk, "dleft", "dright") {
                dep_extra.extend(a.as_object()?.clone());
            }
        }
        if dep_extra.is_empty() {
            if let Some(addr) = parts.get(3) {
                let ak = format!("adr:{addr}:{acct_hex}");
                if let Some(a) = exact_absence(&posted_post, &ak, "aleft", "aright") {
                    dep_extra.extend(a.as_object()?.clone());
                }
            }
        }
        if dep_extra.is_empty() && !deposit_unbacked_by_ledger(vault, is_gov, &parts) {
            return None; // credited, marker + binding fine, backing not known bad — honest leg
        }
    } else if !gov_fresh && (liar_val_is_expected || unchanged) && col_ok && wd_ok {
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
    obj.extend(dep_extra);
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
        bind_aa: false,
        data,
    })
}

/// R5 integration (vault `pperp_total` cap, R5-A-5): `true` only when the
/// hub-read vault ledger CERTAINLY fails the deposit AA's `$backed` test
/// for a credited `d:`/`D:` op `parts` = `[d|D, acct, amount, addr,
/// anchor_b64]`: record known absent, not `payer:amount:account`, payer !=
/// op address, account != op account (exact strings, like the AA), or
/// op amount > recorded amount (both <= 15 digits). Unknown record or an
/// uncertain number = `false` (no proof the AA might bounce). Batch
/// evidence is NOT consulted: a PERP deposit bounced at the vault's cap
/// leaves no `depp_` record although its joint still verifies.
fn deposit_unbacked_by_ledger(vault: &VaultLedger, is_gov: bool, parts: &[&str]) -> bool {
    if parts.len() != 5 {
        return false;
    }
    let key = format!("{}{}", if is_gov { "depp_" } else { "dep_" }, parts[4]);
    match vault.get(&key) {
        None => false,
        Some(None) => true,
        Some(Some(rec)) => {
            let r: Vec<&str> = rec.split(':').collect();
            if r.len() != 3 || r[0] != parts[3] || r[2] != parts[1] {
                return true;
            }
            let num = |s: &str| -> Option<u64> {
                (!s.is_empty() && s.len() <= 15 && s.bytes().all(|b| b.is_ascii_digit()))
                    .then(|| s.parse().ok())
                    .flatten()
            };
            matches!((num(parts[2]), num(r[1])), (Some(a), Some(b)) if a > b)
        }
    }
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
        bind_aa: false,
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
    /// R5-A-2: the AA compares the resting order's remaining to within
    /// floor(op qty / 1e12) (0 below 1e12); this mirror allows twice that.
    remaining_tol: i128,
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
    /// Some((expected post bucket, mirror tolerance)) when the AA checks it.
    exp_bucket: Option<(i128, i128)>,
    exp_fill: i128,
    taker_place: Option<TakerPlace<'a>>,
    liq: Option<LiqLeg>,
    allow_last: bool,
    /// The other fill party (claw guard: its proven post collateral must be
    /// > 0 before a collateral mismatch on THIS leg is fraud).
    counterparty: &'a str,
    /// R5-A-2 claw range: may a proven positive counterparty rule out a
    /// payment by THIS leg? False for a kind 0/1 maker leg whose taker
    /// Place is not a known cross one (an isolated taker's refund lands
    /// after the claw) and for a kind 2/3 leg whose keeper may be the
    /// maker (a keeper credit can lift a clawed maker above 0).
    claw_checkable: bool,
    /// R5-A-2: the AA's rounding tolerance, 6 + S / 1e12 over the proven
    /// magnitudes (exact here).
    tol: i128,
    /// R2-A-7: kind 1 — the collateral leg is never judged.
    col_skip: bool,
    /// R5-A-2: keeper reward a kind 2/3 maker that may be the keeper can
    /// additionally hold (0 otherwise).
    kx: i128,
    /// R5-A-2: a kind 0/1 taker under a non-`p:` descriptor (Reveal{Place}
    /// is `x:`): Some(max(pre collateral, 0)) — the cross identity is only a
    /// ceiling, fill-stage = ceiling - that floor, no lower bound.
    xt_floor: Option<i128>,
    /// R5-A-2: an ADL take larger than the leg's pre position (fraud).
    adl_over: bool,
    /// R4-A-5: price / entry / qty at or above 1e14 — the AA skips the
    /// position leg's numeric qty/entry compare (the leaf must still exist
    /// or be proven absent as expected).
    pos_big: bool,
}

/// R3-A-3: the fill AA checks the collateral identity to a tolerance of
/// FILL_TOL + S / 1e12 (ocore Oscript arithmetic keeps 15 significant
/// digits; R5-A-2 replaced the old 1e14 skip gates with that relative
/// slack). This mirror builds a proof only when the AA's verdict is certain
/// whatever its rounding: it widens every band by three AA tolerances.
const FILL_TOL: i128 = 6;
const FILL_MAX: i128 = 100_000_000_000_000;
const FILL_MARGIN: i128 = 16;
const FILL_LIM: i128 = FILL_MAX - FILL_MARGIN;
const FILL_REL: i128 = 1_000_000_000_000;

/// R5-A-6: how Oscript reads a numeric-looking `split()` field — ocore
/// `string_utils.toNumber` (`^[+-]?\d+(\.\d+)?([eE][+-]?\d+)?$`, then
/// parseFloat, finite only) into a 15-digit Decimal; anything else stays a
/// string (None).
fn oscript_num(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    let mut i = 0;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let digits = |i: &mut usize| {
        let st = *i;
        while *i < b.len() && b[*i].is_ascii_digit() {
            *i += 1;
        }
        *i > st
    };
    if !digits(&mut i) {
        return None;
    }
    if i < b.len() && b[i] == b'.' {
        i += 1;
        if !digits(&mut i) {
            return None;
        }
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        i += 1;
        if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
            i += 1;
        }
        if !digits(&mut i) {
            return None;
        }
    }
    if i != b.len() {
        return None;
    }
    let f: f64 = s.parse().ok()?;
    if !f.is_finite() {
        return None;
    }
    Some(if f == 0.0 { 0.0 } else { f })
}

/// R5-A-6: Oscript `a == b` on two `split()` fields, when certain: numbers
/// compare numerically (exact below 1e15), strings as strings, a number
/// never equals a string. None = 15-digit rounding could go either way.
fn oscript_eq(a: &str, b: &str) -> Option<bool> {
    match (oscript_num(a), oscript_num(b)) {
        (Some(x), Some(y)) => {
            let exact = x.abs() < 1e15 && y.abs() < 1e15 && x.fract() == 0.0 && y.fract() == 0.0;
            if x == y {
                Some(true)
            } else if exact || (x - y).abs() > 1e-12 * x.abs().max(y.abs()) {
                Some(false)
            } else {
                None
            }
        }
        (None, None) => Some(a == b),
        _ => Some(false),
    }
}

/// R5-A-3: the AA's `!is_integer(q) OR q <= 0 OR q > remaining` on a fill
/// qty field against an honest remaining, when certain.
fn oscript_qty_bad(q: &str, rem: &str) -> Option<bool> {
    let r = oscript_num(rem)?;
    let Some(x) = oscript_num(q) else {
        return Some(true); // a string: is_integer() is false
    };
    if x.fract() != 0.0 || x <= 0.0 {
        return Some(true);
    }
    if x.abs() < 1e15 && r.abs() < 1e15 {
        Some(x > r)
    } else if x > r * (1.0 + 1e-12) {
        Some(true)
    } else if x < r * (1.0 - 1e-12) {
        Some(false)
    } else {
        None
    }
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
    // #47 claw guard: a proven POSITIVE counterparty post leaf rules out a
    // payment by this leg (R5-A-2: a range bound, never a bounce).
    let cp_pos = matches!(acct_col(tree, leg.counterparty), Some(c) if c > 0);
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
        } else {
            // R5-A-2: the AA proves absence by the market-range straddle
            // only (the acct-wide arm was dropped for ops budget).
            match mkt_pos_range(tree, leg.acct_hex, leg.market, leg.allow_last) {
                Some(_) => (true, false),
                None => (false, true),
            }
        }
    } else {
        match pos_leaf {
            Some(p) => {
                let o: Vec<&str> = p.split(':').collect();
                let ok = (leg.pos_big
                    || (o[3].parse::<i64>().ok() == Some(leg.exp_qty)
                        && o[4]
                            .parse::<i64>()
                            .map(|e| (e - leg.exp_entry).abs() <= 1)
                            .unwrap_or(false)))
                    && leg
                        .exp_bucket
                        .map(|(b, btol)| {
                            o[6].parse::<i128>()
                                .map(|x| (x - b).abs() <= btol)
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
                    && o[6]
                        .parse::<i128>()
                        .is_ok_and(|r| (r - tp.remaining).abs() <= tp.remaining_tol)
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
    } else if let Some(floor) = leg.xt_floor {
        // x: taker: cross identity as the ceiling, fill-stage below it.
        (leg.exp_fill, leg.exp_fill - floor, true, true)
    } else {
        (leg.exp_fill, leg.exp_fill, true, true)
    };
    // R5-A-2 claw range (mirrors the AA): pays at most max(mid, 0) — none
    // when a positive counterparty rules the claw out — and receives at
    // most max(-mid, 0) (+ a keeper reward on a maybe-keeper maker). Every
    // band is widened by three AA tolerances so a verdict here is certain.
    let slack = 3 * leg.tol + 2;
    let d = post_col - expected;
    let lo = if leg.xt_floor.is_some() {
        i128::MIN
    } else if cp_pos && leg.claw_checkable {
        -slack
    } else {
        -(mid.max(0) + slack)
    };
    let hi = (-mid).max(0) + leg.kx + slack;
    let col_ok = leg.col_skip || (d >= lo && d <= hi);
    (!pos_bail && !pos_ok) || !col_ok || !pin_ok || op_lie || leg.adl_over || (!ord_bail && !ord_ok)
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
        // R2-A-6: ADL fills (kind 2) have no maker order (zero id) — the
        // AA bounces them; never build a ghost proof for one.
        if parts[12] == "2" || maker_order_hex.bytes().all(|b| b == b'0') {
            continue;
        }
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
                bind_aa: false,
                data,
            });
        }
    }
    // R4-A-1 P-mbind (book dispute AA): a book fill (kind 0/1/3, any idx)
    // must match its maker order's PRE leaf — owner, market, opposite side,
    // price — and fit its remaining qty. R5-A-3 / R5-A-6: mirrors the AA's
    // NUMERIC reading of split() fields (`1e13` equals `10000000000000`,
    // `1e30` / `-5` / `0` are bad quantities); built only when the AA's
    // outcome is certain. Gated on the fill not being a replay fill (an
    // honest fill always matches).
    for f in &unit_fills {
        if honest_fills.iter().any(|h| h == *f) {
            continue;
        }
        let parts: Vec<&str> = f.split(':').collect();
        if parts.len() != 14 || (parts[11] != "0" && parts[11] != "1") {
            continue;
        }
        if parts[12] == "2" || parts[6].bytes().all(|b| b == b'0') {
            continue;
        }
        let key = format!("ord:{}:", parts[6]);
        let Some(mo_leaf) = pre_leaves.iter().find(|l| l.starts_with(&key)) else {
            continue;
        };
        let mo: Vec<&str> = mo_leaf.split(':').collect();
        if mo.len() != 10 {
            continue;
        }
        let opp = if parts[11] == "0" { "1" } else { "0" };
        let eqs = [
            oscript_eq(mo[7], parts[4]),
            oscript_eq(mo[2], parts[7]),
            oscript_eq(mo[3], opp),
            oscript_eq(mo[4], parts[8]),
            oscript_qty_bad(parts[9], mo[6]).map(|b| !b),
        ];
        // Any uncertain comparison: stay silent; all bound: no fraud.
        if eqs.iter().any(|e| e.is_none()) || eqs.iter().all(|e| *e == Some(true)) {
            continue;
        }
        let idx = index_of(&batch.fills, f)?;
        let mut data = serde_json::json!({
            "trace_root": batch.checkpoint.trace_root,
            "fills_root": batch.checkpoint.fills_root,
            "units_root": batch.checkpoint.units_root,
            "k": k,
            "fill": f,
            "fill_proof": proof_json(&fills_tree, idx),
            "units_proof": proof_json(&unit_hexes, k),
            "maker_ord": mo_leaf,
            "maker_ord_proof": proof_json(pre_leaves, index_of(pre_leaves, mo_leaf)?),
        });
        data.as_object_mut()?
            .extend(pre_wit_fields(batch, k, pre_leaves).as_object()?.clone());
        return Some(BuiltProof {
            pred: "mbind".into(),
            fill_aa: false,
            bind_aa: false,
            data,
        });
    }
    // R5-A-2 P-fsane (book dispute AA): a posted fill the engine can never
    // emit — bad shape, kind vs market, a fill in a unit whose direct Place
    // is rejected before matching, or a fill party absent from the pre
    // tree. Only for fills the honest replay did not produce.
    for f in &unit_fills {
        if honest_fills.iter().any(|h| h == *f) {
            continue;
        }
        if let Some(p) = fsane_proof(batch, k, f, pre_leaves, &fills_tree, &unit_hexes) {
            return Some(p);
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
                    bind_aa: false,
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
        // R5-A-2: on a regular market every kind 2/3 fill is the book-path
        // Liquidate of its taker; the op only tells whether the keeper is
        // known to differ from the maker (`kc` = it may be the maker).
        let kc = kind >= 2 && !(op_liq && op_parts[1] != maker_hex);
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
        // usd_per_unit: != 0 marks a funding-rate market, where kind 2 is
        // the off-book ADL the AA bounces (R5-A-2).
        let usd: i128 = match mparts[9].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if kind >= 2 && usd != 0 {
            continue;
        }
        // Price notional (engine notional_usd, i128 trunc chain): fee base
        // of kind 0/3, keeper base of kind 2/3. Funding markets (kind 1)
        // price the fee off the multiplier. Kind 2 (ADL) pays no fee.
        let t2 = i128::from(qty) * i128::from(price) / 100_000_000 * 1_000_000 / 100_000_000;
        // R2-A-7 (mirrors the AA): kind 1 may settle the funding peg inside
        // the fill — its collateral leg is never judged, fee/PnL modelled 0.
        let fee: i128 = if kind == 2 || kind == 1 {
            0
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
        // Round 2: the AA has no after-max arm any more (`~:end` sentinel).
        let allow_last = false;
        let sides = [
            ("taker", taker_hex.as_str(), taker_side),
            ("maker", maker_hex.as_str(), maker_side),
        ];
        for (who, acct_hex, side_acct) in sides {
            if acct_hex == "0000000000000000000000000000000000000000000000000000000000000000" {
                continue; // AA bails on the insurance account's own leaf
            }
            let who_taker = who == "taker";
            // R5-A-2: a kind 0/1 taker under a non-`p:` descriptor (x:) gets
            // the position leg and a collateral ceiling only.
            let xt = who_taker && kind <= 1 && !op_place;
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
            // R5-A-2: the AA reads the maker's PRE ord leaf on every
            // order-book leg — a taker leg whenever supplied (always here)
            // and necessarily at price / qty >= 1e14 — except for ADL
            // (kind 2: no maker order, no escrow).
            let maker_ord = if kind != 2 {
                pre_leaves
                    .iter()
                    .find(|l| l.starts_with(&format!("ord:{}:", parts[6])))
                    .cloned()
            } else {
                None
            };
            // A taker leg may omit it only below 1e14 price / qty.
            if kind != 2
                && maker_ord.is_none()
                && (!who_taker
                    || i128::from(price).abs() >= FILL_MAX
                    || i128::from(qty) >= FILL_MAX)
            {
                continue;
            }
            // The AA bounces ('bad maker ord') a fill whose maker order is
            // not the maker's, or whose price / qty leave the order: those
            // lies are P-mbind's (R4-A-1 / R5-A-3).
            if let Some(l) = &maker_ord {
                let o: Vec<&str> = l.split(':').collect();
                if o.len() != 10
                    || o[7] != maker_hex
                    || oscript_eq(o[4], parts[8]) != Some(true)
                    || oscript_qty_bad(parts[9], o[6]) != Some(false)
                {
                    continue;
                }
            }
            let mo_iso = !who_taker
                && maker_ord
                    .as_ref()
                    .map(|l| l.split(':').nth(8) == Some("1"))
                    .unwrap_or(false);
            // R3-A-3: the AA's $mml (maker order margin_left; 0 otherwise).
            let mml: i128 = maker_ord
                .as_ref()
                .and_then(|l| l.split(':').nth(9).and_then(|v| v.parse().ok()))
                .unwrap_or(0);
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
            let mpost_any = if who_taker { 0 } else { mpost_any };
            let tfee = if who_taker { fee } else { 0 };
            // Fill-stage collateral by kind: pre + release + pnl - taker fee
            // (+ maker pro-rata refund). Exact — the AA recomputes it.
            let abs_old = old_qty.unsigned_abs() as i128;
            let abs_delta = delta.unsigned_abs() as i128;
            let same = old_qty == 0 || (old_qty > 0 && delta > 0) || (old_qty < 0 && delta < 0);
            let (exp_qty, exp_entry, exp_fill, exp_absent, pback, exp_bucket, pnl_v) = if same {
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
                (eq, ee, ec, false, 0, bucket + post_any, 0i128)
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
                    0
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
                    (0, 0, ec, true, pback, eb, pnl)
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
                    (q, e, ec, false, pback, eb, pnl)
                }
            };
            // #47 A3: the bucket is checked where its inflow is known —
            // an isolated taker Place (kind 0/1) or an isolated maker
            // pre position.
            // R5-A-2 (mirrors the AA): never skipped; the AA's tolerance is
            // 1 + (bucket + escrow share) / 1e12, doubled here (+2).
            let chk_b = if who_taker {
                kind <= 1 && !xt && op_parts.get(6) == Some(&"1")
            } else {
                iso || mo_iso
            };
            let btol = 4 + 2 * ((bucket + post_any).max(0) / FILL_REL);
            // #47 A3: kind 0/1 taker — bind the fill to its own Place op and
            // derive the resting escrow from typ/tif instead of F[5]'s leaf.
            let (taker_place, op_lie) = if who_taker && kind <= 1 && !xt {
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
                // R5-A-2: the AA's share tolerance is 1 + margin / 1e12
                // (no skip); a certain lie is beyond twice that (+2).
                let op_ok = op_parts[1] == taker_hex
                    && op_parts[2] == market
                    && op_parts[3] == taker_side
                    && q <= oqty
                    && taker_post >= 0
                    && (taker_post - tpost_exp).abs() <= 4 + 2 * (margin.max(0) / FILL_REL)
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
                        remaining_tol: 2 * (oqty.max(0) / FILL_REL),
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
            // R5-A-2: the AA's tolerance 6 + S / 1e12 over proven magnitudes
            // (old collateral, notional, pnl, bucket, maker margin_left, the
            // op margin of a `p:` taker, old entry notional).
            let sx: i128 = if who_taker && kind <= 1 && !xt {
                op_parts[7].parse::<i128>().unwrap_or(0).abs()
            } else {
                0
            };
            let s_mag = old_col.abs()
                + t2.abs()
                + pnl_v.abs()
                + bucket.abs()
                + mml.abs()
                + sx
                + abs_old * i128::from(old_entry).abs() / 10_000_000_000;
            let tol = FILL_TOL + s_mag / FILL_REL;
            let tord_hex = taker_place.as_ref().map(|t| t.tord.to_string());
            let leg = Leg {
                acct_hex,
                market: &market,
                exp_qty,
                exp_entry,
                exp_absent,
                exp_bucket: if chk_b {
                    Some((exp_bucket, btol))
                } else {
                    None
                },
                exp_fill,
                taker_place,
                liq,
                allow_last,
                counterparty: if who_taker {
                    maker_hex.as_str()
                } else {
                    taker_hex.as_str()
                },
                claw_checkable: !kc
                    && (who_taker
                        || kind >= 2
                        || (op_parts.len() == 10 && op_parts.get(6) == Some(&"0"))),
                tol,
                // R2-A-7: never for kind 1 (funding peg may move collateral).
                col_skip: kind == 1,
                kx: if !who_taker && kc { reward } else { 0 },
                xt_floor: if xt { Some(old_col.max(0)) } else { None },
                adl_over: kind == 2 && i128::from(qty) > abs_old,
                // R5-A-4: magnitudes (negative prices round the same).
                pos_big: i128::from(price).abs() >= FILL_LIM
                    || i128::from(old_entry).abs() >= FILL_LIM
                    || abs_old >= FILL_LIM
                    || i128::from(qty) >= FILL_LIM,
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
            // #47 claw guard: the counterparty's post collateral (tightens
            // the claw range's lower bound when positive).
            let cp = if who_taker { &maker_hex } else { &taker_hex };
            let key = format!("acct:{cp}:");
            if let Some(ci) = posted_post.iter().position(|l| l.starts_with(&key)) {
                obj.insert("cp_acct".into(), posted_post[ci].clone().into());
                obj.insert("cp_acct_proof".into(), proof_json(&posted_post, ci));
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
            // The market-range straddle backs a claimed-absent post pos
            // (R5-A-2: the AA's acct-wide arm is gone).
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
                bind_aa: false,
                data,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_backing(ledger: &VaultLedger) -> Backing<'_> {
        Backing {
            ledger,
            evs: Vec::new(),
        }
    }
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

    /// R5 integration (vault `pperp_total` cap): a credited deposit whose
    /// marker and binding are fine is still fraud when the hub-read vault
    /// ledger shows no backing record (e.g. a PERP deposit the vault
    /// bounced at its cap: the joint still verifies as evidence). Unknown
    /// record = silent; a matching record = silent.
    #[test]
    fn r5_credited_deposit_unbacked_by_vault_ledger_builds_proof() {
        let secret = sk(7);
        let acct = acct_of(&secret);
        let aa = [9u8; 32];
        let u = sign_unit(
            vec![genesis_id()],
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
        let batch = Batch::from_applied(&prev, &mut eng, &[id]).expect("batch");
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(aa);
        let key = format!("dep_{b64}");
        let a = hex::encode(acct.0);
        let run = |ledger: &VaultLedger| {
            let mut replay = Engine::new();
            replay.state.deposits_allowed.insert((aa, false));
            build_proof_with_vault(&batch, &mut replay, &[], 0, ledger)
        };
        // Unknown record: honest as far as the watcher knows.
        assert!(run(&VaultLedger::new()).is_none());
        // Matching record (amount >= op amount): honest.
        let mut l = VaultLedger::new();
        l.insert(key.clone(), Some(format!("{}:100:{a}", test_addr())));
        assert!(run(&l).is_none());
        l.insert(key.clone(), Some(format!("{}:250:{a}", test_addr())));
        assert!(run(&l).is_none());
        // Known absent (cap-bounced / never paid): P-deposit.
        l.insert(key.clone(), None);
        let p = run(&l).expect("unbacked credit");
        assert_eq!(p.pred, "deposit");
        assert!(p.data.get("dleft").is_none() && p.data.get("aleft").is_none());
        // Record for another payer / account / a smaller amount: P-deposit.
        for rec in [
            format!("{}:100:{a}", "Z".repeat(32)),
            format!("{}:100:{}", test_addr(), "ab".repeat(32)),
            format!("{}:99:{a}", test_addr()),
        ] {
            l.insert(key.clone(), Some(rec.clone()));
            assert_eq!(run(&l).expect(&rec).pred, "deposit", "{rec}");
        }
        // Uncertain number in the record: silent.
        l.insert(key.clone(), Some(format!("{}:1e3:{a}", test_addr())));
        assert!(run(&l).is_none());
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

    /// R3-A-1: the honestly REJECTED overdraft (balance 100, withdraw 1000)
    /// posted as ACCEPTED — W += 1000, collateral -900 — must be a proof
    /// (pre-fix both the withdraw and the wpin mirrors accepted it).
    #[test]
    fn overdraft_withdraw_posted_as_accepted_builds_proof() {
        let secret = sk(7);
        let acct = acct_of(&secret);
        let aa = [9u8; 32];
        let dep = sign_unit(
            vec![genesis_id()],
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
        eng.ingest(wd).unwrap();
        let prev = minuend_state::ChainState::new();
        let mut eng2 = eng.clone();
        let mut batch = Batch::from_applied(&prev, &mut eng2, &[d_id, w_id]).expect("batch");
        let key = format!("acct:{}:", hex::encode(acct.0));
        for l in batch.leaf_trace[1].iter_mut() {
            if l.starts_with(&key) {
                *l = format!("acct:{}:-900:0:1000", hex::encode(acct.0));
            }
        }
        batch.leaf_trace[1].sort();
        batch.trace[1] = obyte_merkle::root(&batch.leaf_trace[1]);
        batch.checkpoint.trace_root = obyte_merkle::root(&batch.trace);
        batch.checkpoint.wit_root = batch.trace[1].clone();
        let mut replay = Engine::new();
        replay.state.deposits_allowed.insert((aa, false));
        let proof = build_proof(&batch, &mut replay, &[], 0).expect("proof");
        assert_eq!(proof.pred, "withdraw");
        // The binding AA mirror rejects the same leaf on its own.
        let pre = vec![format!("acct:{}:100:0:0", hex::encode(acct.0))];
        assert!(binding_violation(
            &format!("w:{}:1000:1", hex::encode(acct.0)),
            &pre,
            &format!("acct:{}:-900:0:1000", hex::encode(acct.0)),
            Some(&no_backing(&VaultLedger::new()))
        )
        .is_some());
        assert!(binding_violation(
            &format!("w:{}:100:1", hex::encode(acct.0)),
            &pre,
            &format!("acct:{}:0:0:100", hex::encode(acct.0)),
            Some(&no_backing(&VaultLedger::new()))
        )
        .is_none());
    }

    /// R3-A-6: an account leaf vanishing from the posted post tree is a
    /// P-keep proof over the account's prefix range.
    #[test]
    fn dropped_account_leaf_builds_keep_proof() {
        let (mut batch, acct, aa) = honest_deposit_batch();
        // A second (non-deposit) unit would be ideal; dropping the account
        // in the deposit unit's own post tree is caught by P-deposit first,
        // so judge keep_mirror_proof directly on a synthetic pre/post pair.
        let key = format!("acct:{}:", hex::encode(acct.0));
        let pre: Vec<String> = batch.leaf_trace[0].clone();
        let honest_post = pre.clone();
        let mut posted = pre.clone();
        posted.retain(|l| !l.starts_with(&key));
        batch.leaf_trace[0] = posted;
        let _ = aa;
        let p = keep_mirror_proof(&batch, 0, &pre, &honest_post).expect("keep proof");
        assert_eq!(p.pred, "keep");
        assert!(p.data["leaf"].as_str().unwrap().starts_with(&key));
        assert!(p.data.get("left").is_some());
        // Honest (account kept) → nothing.
        batch.leaf_trace[0] = pre.clone();
        assert!(keep_mirror_proof(&batch, 0, &pre, &honest_post).is_none());
    }

    fn honest_deposit_batch() -> (Batch, AccountId, [u8; 32]) {
        let secret = sk(7);
        let acct = acct_of(&secret);
        let aa = [9u8; 32];
        let u = sign_unit(
            vec![genesis_id()],
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
        let batch = Batch::from_applied(&prev, &mut eng, &[id]).expect("batch");
        (batch, acct, aa)
    }

    /// #47 A2: W moved without the account's own withdraw → P-wpin on the
    /// binding dispute AA (the deposit leg itself is honest).
    #[test]
    fn forged_withdrawn_builds_wpin_proof() {
        let (mut batch, acct, aa) = honest_deposit_batch();
        let mut replay = Engine::new();
        replay.state.deposits_allowed.insert((aa, false));
        assert!(build_proof(&batch, &mut replay.clone(), &[], 0).is_none());
        for l in batch.leaf_trace[0].iter_mut() {
            if l.starts_with(&format!("acct:{}:", hex::encode(acct.0))) {
                *l = format!("acct:{}:100:0:777", hex::encode(acct.0));
            }
        }
        let proof = build_proof(&batch, &mut replay, &[], 0).expect("proof");
        assert_eq!(proof.pred, "wpin");
        assert_eq!(proof.target(), "bind");
        assert!(
            proof.data.get("left").is_some(),
            "fresh account: pre absence"
        );
    }

    /// R2-A-1: every transition clean but the committed wit_root is not
    /// the trace tip → P-tip on the binding dispute AA.
    #[test]
    fn r2_forged_wit_root_builds_tip_proof() {
        let (mut batch, _acct, aa) = honest_deposit_batch();
        let mut replay = Engine::new();
        replay.state.deposits_allowed.insert((aa, false));
        assert!(build_proof(&batch, &mut replay.clone(), &[], 0).is_none());
        batch.checkpoint.wit_root = obyte_merkle::hash("forged-tree");
        let p = build_proof(&batch, &mut replay, &[], 0).expect("tip proof");
        assert_eq!(p.pred, "tip");
        assert_eq!(p.target(), "bind");
        assert_eq!(p.data["tip"], serde_json::json!(batch.trace[0]));
        assert_eq!(p.data["tip_proof"]["index"], serde_json::json!(0));
    }

    /// R2-A-2 / R2-A-8 mirror of the binding AA: W and collateral are
    /// judged jointly; a second binding of a bound account is refused.
    #[test]
    fn r2_binding_violation_is_joint() {
        let a = "aa".repeat(32);
        let pre = vec![format!("acct:{a}:1000:0:0")];
        let op = format!("w:{a}:100:1");
        let empty = VaultLedger::new();
        let nb = no_backing(&empty);
        let v = |leaf: String| binding_violation(&op, &pre, &leaf, Some(&nb));
        assert!(v(format!("acct:{a}:900:0:100")).is_none(), "accepted");
        assert!(v(format!("acct:{a}:1000:0:0")).is_none(), "rejected");
        assert!(
            v(format!("acct:{a}:1000:0:100")).is_some(),
            "W without debit"
        );
        assert!(v(format!("acct:{a}:900:0:0")).is_some(), "debit without W");
        let f = "99".repeat(32);
        assert!(
            binding_violation(
                &format!("w:{f}:100:1"),
                &pre,
                &format!("acct:{f}:0:0:100"),
                Some(&nb)
            )
            .is_some(),
            "W minted on a rejected (fresh) withdraw"
        );
        let addr = "Q".repeat(32);
        let d = format!("d:{a}:5:{addr}:{}", "A".repeat(44));
        let ev = |is_perp: bool, payer: &str, account: &str| minuend_settle::DepositEvidence {
            aa_unit: "00".repeat(32),
            is_perp,
            amount: "5".into(),
            vault_address: String::new(),
            payer: payer.into(),
            account: account.into(),
            joint: serde_json::Value::Null,
        };
        // anchor "A"*43 + "=" is 32 zero bytes.
        let d = d.replace(&"A".repeat(44), &format!("{}=", "A".repeat(43)));
        let bk = |ledger: &VaultLedger, evs: &[minuend_settle::DepositEvidence]| {
            binding_violation(
                &d,
                &[],
                &format!("adr:{addr}:{a}"),
                Some(&Backing {
                    ledger,
                    evs: evs.iter().collect(),
                }),
            )
        };
        let good = [ev(false, &addr, &a)];
        let bound = vec![format!("adrx:{a}:{}", "R".repeat(32))];
        let good_b = Backing {
            ledger: &empty,
            evs: good.iter().collect(),
        };
        assert!(binding_violation(&d, &bound, &format!("adr:{addr}:{a}"), Some(&good_b)).is_some());
        assert!(bk(&empty, &good).is_none());
        // R4-A-4: the vault record is UNKNOWN (no verified evidence for the
        // anchor, hub not read) → no verdict, no proof the AA might bounce.
        assert!(bk(&empty, &[]).is_none());
        // Known absent (hub read: no dep_ record) → fraud.
        let key = vault_key_of_op(&d).unwrap();
        let absent: VaultLedger = [(key.clone(), None)].into_iter().collect();
        assert!(bk(&absent, &[]).is_some());
        // Hub record names another payer / another account → fraud; the
        // exact record → accepted.
        let other = "bb".repeat(32);
        let rec = |r: String| -> VaultLedger { [(key.clone(), Some(r))].into_iter().collect() };
        assert!(bk(&rec(format!("{}:5:{a}", "P".repeat(32))), &[]).is_some());
        assert!(bk(&rec(format!("{addr}:5:{other}")), &[]).is_some());
        assert!(bk(&rec(format!("{addr}:5:{a}")), &[]).is_none());
        // Verified evidence for that anchor: other account → fraud; other
        // asset kind → the vault wrote only depp_, so dep_ is absent → fraud.
        assert!(bk(&empty, &[ev(false, &addr, &other)]).is_some());
        assert!(bk(&empty, &[ev(true, &addr, &a)]).is_some());
        // round-2 d: carries the anchor: the old 4-part shape is refused
        let d4 = format!("d:{a}:5:{addr}");
        assert!(binding_violation(&d4, &[], &format!("adr:{addr}:{a}"), Some(&good_b)).is_some());
    }

    /// R2-A-8: a posted binding without its adrx: mirror → P-mirror.
    #[test]
    fn r2_dropped_binding_mirror_builds_mirror_proof() {
        let (mut batch, acct, aa) = honest_deposit_batch();
        let x = format!("adrx:{}:{}", hex::encode(acct.0), test_addr());
        assert!(batch.leaf_trace[0].contains(&x), "engine writes adrx:");
        assert!(
            batch.leaf_trace[0].iter().any(|l| l.starts_with("dep:")),
            "engine writes the consumed-deposit marker"
        );
        assert_eq!(
            batch.leaf_trace[0].last().map(String::as_str),
            Some("~:end")
        );
        batch.leaf_trace[0].retain(|l| *l != x);
        retrace(&mut batch, 0);
        batch.checkpoint.wit_root = batch.trace[0].clone();
        let mut replay = Engine::new();
        replay.state.deposits_allowed.insert((aa, false));
        let p = build_proof(&batch, &mut replay, &[], 0).expect("mirror proof");
        assert_eq!(p.pred, "mirror");
        assert!(p.data.get("left").is_some() && p.data.get("right").is_some());
    }

    /// #47 A2: an address binding re-pointed to another account → P-adr.
    #[test]
    fn forged_address_binding_builds_adr_proof() {
        let (mut batch, acct, aa) = honest_deposit_batch();
        let adr = format!("adr:{}:{}", test_addr(), hex::encode(acct.0));
        assert!(
            batch.leaf_trace[0].contains(&adr),
            "deposit binds the address in the witness tree"
        );
        for l in batch.leaf_trace[0].iter_mut() {
            if *l == adr {
                *l = format!("adr:{}:{}", test_addr(), "ee".repeat(32));
            }
        }
        let mut replay = Engine::new();
        replay.state.deposits_allowed.insert((aa, false));
        let proof = build_proof(&batch, &mut replay, &[], 0).expect("proof");
        // R3-A-4: the credited deposit's own binding adr:{addr}:{acct} is
        // missing from the posted post tree — P-deposit fires first (the
        // re-pointed leaf would also fail P-adr).
        assert_eq!(proof.pred, "deposit");
        assert!(proof.data.get("aleft").is_some());
        assert!(!proof.bind_aa && !proof.fill_aa);
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
        // inflates alice's posted collateral by 1000 units (R3-A-3: a
        // +-FILL_TOL rounding band is never a verdict, and the mirror needs
        // > 2*FILL_TOL to be certain). The payload must
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
        let alice_hex = hex::encode(alice_id.0);
        let bump = |batch: &mut Batch, by: i128| {
            if let Some(leaves) = batch.leaf_trace.get_mut(1) {
                for l in leaves.iter_mut() {
                    if l.starts_with(&format!("acct:{alice_hex}:")) {
                        let p: Vec<&str> = l.split(':').collect();
                        let col: i128 = p[2].parse().unwrap();
                        *l = format!("acct:{}:{}:{}:{}", p[1], col + by, p[3], p[4]);
                    }
                }
            }
            batch.trace[1] = obyte_merkle::root(&batch.leaf_trace[1]);
            batch.checkpoint.trace_root = obyte_merkle::root(&batch.trace);
            batch.checkpoint.wit_root = batch.trace[1].clone();
        };
        // R3-A-3: inside the rounding band (+1 .. +2*FILL_TOL) — the AA may
        // read it as its own rounding, so the mirror stays silent.
        let mut near = batch.clone();
        bump(&mut near, 2 * FILL_TOL);
        let mut replay = Engine::new();
        fund(&mut replay);
        assert!(
            build_proof(&near, &mut replay, &[], 0).is_none(),
            "a sub-tolerance collateral drift is never a certain verdict"
        );
        // Liar: alice's posted collateral inflated by 1000 units.
        bump(&mut batch, 1_000);
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
        // #47 A3: the liar writes a wrong taker_post into the fill and moves
        // alice's collateral by the same amount — the old identity (which
        // trusted F[13]) balanced; the op-bound one does not. (R5-A-2: a
        // NEGATIVE taker_post is now P-fsane's shape lie, so the forged
        // share here is an inflated positive one.)
        let q = minuend_types::QTY_SCALE / 1000;
        let (mut batch, a, b) = iso_taker_batch(q, q, 40 * minuend_types::USD_SCALE);
        let honest_tpost: i128 = batch.fills[0].split(':').nth(13).unwrap().parse().unwrap();
        let forged = honest_tpost + 1_000_000_000;
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
            tol: FILL_TOL,
            col_skip: false,
            kx: 0,
            xt_floor: None,
            adl_over: false,
            pos_big: false,
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
            tol: FILL_TOL,
            col_skip: false,
            kx: 0,
            xt_floor: None,
            adl_over: false,
            pos_big: false,
        }
    }

    /// R4-A-1: a fill that disagrees with its maker order's PRE leaf
    /// (price, owner, qty beyond remaining, same side) → P-mbind proof for
    /// the book dispute AA; the honest fill builds nothing.
    #[test]
    fn r4a1_fill_off_its_maker_order_builds_mbind_proof() {
        let q = minuend_types::QTY_SCALE / 1000;
        let (honest, a, b) = iso_taker_batch(q, q, 40 * minuend_types::USD_SCALE);
        let mut r0 = funded_replay(&[a, b]);
        assert!(build_proof(&honest, &mut r0, &[], 0).is_none());
        let px: i64 = honest.fills[0].split(':').nth(8).unwrap().parse().unwrap();
        let cases: Vec<(usize, String)> = vec![
            (8, (px * 10).to_string()), // price != maker price
            (4, hex::encode(a.0)),      // maker != order owner
            (9, (2 * q).to_string()),   // qty > remaining
            (11, "1".to_string()),      // taker on the maker's side
        ];
        for (field, v) in cases {
            let mut batch = honest.clone();
            set_fill_field(&mut batch, 0, field, &v);
            let mut replay = funded_replay(&[a, b]);
            let proof = build_proof(&batch, &mut replay, &[], 0)
                .unwrap_or_else(|| panic!("field {field}: no proof"));
            assert_eq!(proof.pred, "mbind", "field {field}");
            assert_eq!(proof.target(), "book");
            assert!(proof.data["maker_ord"]
                .as_str()
                .unwrap()
                .starts_with(&format!(
                    "ord:{}:",
                    batch.fills[0].split(':').nth(6).unwrap()
                )));
            assert!(proof.data.get("maker_ord_proof").is_some());
            assert!(proof.data.get("units_proof").is_some());
        }
    }

    /// R5-A-3 / R5-A-6: P-mbind compares numerically, like the AA reads
    /// split() fields — `1e30`, a negative and a zero qty are fraud; a
    /// price written `1e13` that equals the maker's `10000000000000` is not
    /// a P-mbind lie (the AA would bounce it).
    #[test]
    fn r5a3_mbind_numeric_qty_and_price() {
        let q = minuend_types::QTY_SCALE / 1000;
        let (honest, a, b) = iso_taker_batch(q, q, 40 * minuend_types::USD_SCALE);
        for v in ["1e30", "1e21", "-50000000", "0"] {
            let mut batch = honest.clone();
            set_fill_field(&mut batch, 0, 9, v);
            let mut replay = funded_replay(&[a, b]);
            let proof = build_proof(&batch, &mut replay, &[], 0)
                .unwrap_or_else(|| panic!("qty {v}: no proof"));
            assert_eq!(proof.pred, "mbind", "qty {v}");
        }
        let px: i64 = honest.fills[0].split(':').nth(8).unwrap().parse().unwrap();
        assert_eq!(px, 10_000_000_000_000, "test assumes px = 1e13");
        let mut batch = honest.clone();
        set_fill_field(&mut batch, 0, 8, "1e13");
        let mut replay = funded_replay(&[a, b]);
        if let Some(p) = build_proof(&batch, &mut replay, &[], 0) {
            assert_ne!(p.pred, "mbind", "numerically equal price is not P-mbind");
        }
        assert_eq!(oscript_eq("1e13", "10000000000000"), Some(true));
        assert_eq!(oscript_eq("007", "7"), Some(true));
        assert_eq!(oscript_eq("abc", "abc"), Some(true));
        assert_eq!(oscript_eq("abc", "0"), Some(false));
        assert_eq!(oscript_qty_bad("1e30", "100000"), Some(true));
        assert_eq!(oscript_qty_bad("100000", "100000"), Some(false));
        assert_eq!(oscript_qty_bad("1.5", "100000"), Some(true));
    }

    /// R5-A-2 P-fsane: kind 2/3 with taker_post != 0, a kind 0 fill tagged
    /// kind 1 on a regular market, and a fill under a Place whose isolated
    /// margin exceeds the pre collateral are fraud on proven values alone.
    #[test]
    fn r5a2_fsane_rules() {
        let q = minuend_types::QTY_SCALE / 1000;
        let (honest, a, b) = iso_taker_batch(q, q, 40 * minuend_types::USD_SCALE);
        // kind 1 on BTC_USD (usd_per_unit 0).
        let mut batch = honest.clone();
        set_fill_field(&mut batch, 0, 12, "1");
        let mut replay = funded_replay(&[a, b]);
        let p = build_proof(&batch, &mut replay, &[], 0).expect("fsane kind proof");
        assert_eq!(p.pred, "fsane");
        assert_eq!(p.target(), "book");
        assert!(p.data.get("pre_meta").is_some());
        // kind 3 with a non-zero taker_post.
        let mut batch = honest.clone();
        set_fill_field(&mut batch, 0, 12, "3");
        set_fill_field(&mut batch, 0, 13, "5");
        let mut replay = funded_replay(&[a, b]);
        let p = build_proof(&batch, &mut replay, &[], 0).expect("fsane shape proof");
        assert_eq!(p.pred, "fsane");
        assert!(p.data.get("pre_meta").is_none());
        // Shape helper.
        let f = "f:u:0:t:m:to:mo:1:5:7:1:0:0:0";
        let parts: Vec<&str> = f.split(':').collect();
        assert!(!fsane_shape_bad(&parts));
        for (i, v) in [
            (9, "0"),
            (9, "1.5"),
            (8, "x"),
            (13, "-1"),
            (11, "2"),
            (12, "4"),
        ] {
            let mut p2 = parts.clone();
            p2[i] = v;
            assert!(fsane_shape_bad(&p2), "field {i} = {v}");
        }
        // Isolated Place with margin > pre collateral (alice had 10 000 USD;
        // rewrite the op's margin to 20 000 USD, fill untouched).
        let mut batch = honest.clone();
        let k = batch
            .ops
            .iter()
            .position(|o| o.starts_with("p:") && o.split(':').nth(6) == Some("1"))
            .expect("iso place op");
        let mut o: Vec<String> = batch.ops[k].split(':').map(String::from).collect();
        o[7] = (20_000 * minuend_types::USD_SCALE).to_string();
        batch.ops[k] = o.join(":");
        batch.checkpoint.ops_root = obyte_merkle::root(&batch.ops);
        let pre = batch.leaf_trace[k - 1].clone();
        let unit_hexes: Vec<String> = batch
            .checkpoint
            .unit_ids
            .iter()
            .map(|id| hex::encode(id.0))
            .collect();
        let tree = minuend_settle::fills_root_elements(&batch.fills);
        let f0 = batch.fills[0].clone();
        let p = fsane_proof(&batch, k, &f0, &pre, &tree, &unit_hexes).expect("fsane op proof");
        assert!(p.data.get("pre_acct").is_some());
        assert!(p.data.get("op").is_some());
    }

    /// Alice rests an isolated bid that bob's ask partly fills, then
    /// cancels the rest (unit 2, a `c:` unit) — three units, honest.
    fn cancel_batch() -> (Batch, AccountId, AccountId, String) {
        use minuend_types::{OrderType, Side, TimeInForce, BTC_USD, PRICE_SCALE, USD_SCALE};
        let alice = sk(1);
        let bob = sk(2);
        let (alice_id, bob_id) = (acct_of(&alice), acct_of(&bob));
        let mut eng = Engine::new();
        for id in [alice_id, bob_id] {
            eng.state
                .account_mut(id)
                .credit(10_000 * USD_SCALE as i128)
                .unwrap();
        }
        let prev = eng.state.clone();
        let px = 100_000 * PRICE_SCALE as i64;
        let q = minuend_types::QTY_SCALE / 1000;
        let place = |parents, acct, side, qty, iso, margin, secret: &[u8; 32]| {
            sign_unit(
                parents,
                Op::Place {
                    account: acct,
                    market: BTC_USD,
                    side,
                    typ: OrderType::Limit,
                    tif: TimeInForce::Gtc,
                    price: px,
                    qty,
                    client_seq: 1,
                    isolated: iso,
                    margin,
                },
                secret,
            )
        };
        let u0 = place(vec![genesis_id()], bob_id, Side::Ask, q, false, 0, &bob);
        let i0 = unit_id(&u0);
        eng.ingest(u0).unwrap();
        let u1 = place(
            vec![i0],
            alice_id,
            Side::Bid,
            2 * q,
            true,
            40 * USD_SCALE,
            &alice,
        );
        let i1 = unit_id(&u1);
        eng.ingest(u1).unwrap();
        let oid = minuend_types::order_id(alice_id, BTC_USD, 1);
        let u2 = sign_unit(
            vec![i1],
            Op::Cancel {
                account: alice_id,
                order_id: oid,
            },
            &alice,
        );
        let i2 = unit_id(&u2);
        eng.ingest(u2).unwrap();
        let mut eng2 = eng.clone();
        let batch = Batch::from_applied(&prev, &mut eng2, &[i0, i1, i2]).expect("batch");
        (batch, alice_id, bob_id, hex::encode(oid.0))
    }

    /// R4-A-3: under a `c:` unit, a rewritten position (entry inflated),
    /// an inserted order leaf, or a dropped position → P-frame proof on the
    /// bind AA; the honest cancel (its own order removed) builds nothing.
    #[test]
    fn r4a3_frame_change_in_cancel_unit_builds_frame_proof() {
        let (honest, a, b, oid) = cancel_batch();
        assert!(honest.ops[2].starts_with("c:"), "{}", honest.ops[2]);
        let alice_hex = hex::encode(a.0);
        assert!(
            honest.leaf_trace[1]
                .iter()
                .any(|l| l.starts_with(&format!("ord:{oid}:"))),
            "the remainder rests before the cancel"
        );
        assert!(
            !honest.leaf_trace[2]
                .iter()
                .any(|l| l.starts_with(&format!("ord:{oid}:"))),
            "the cancel removes it"
        );
        let mut r0 = funded_replay(&[a, b]);
        assert!(build_proof(&honest, &mut r0, &[], 0).is_none());
        // (a) entry rewritten → the pre leaf is gone (deletion arm).
        let mut batch = honest.clone();
        for l in batch.leaf_trace[2].iter_mut() {
            if l.starts_with(&format!("pos:{alice_hex}:")) {
                let mut p: Vec<String> = l.split(':').map(String::from).collect();
                let e: i64 = p[4].parse().unwrap();
                p[4] = (e * 100).to_string();
                *l = p.join(":");
            }
        }
        retrace(&mut batch, 2);
        batch.checkpoint.wit_root = batch.trace[2].clone();
        let mut replay = funded_replay(&[a, b]);
        let p = build_proof(&batch, &mut replay, &[], 0).expect("frame proof");
        assert_eq!(p.pred, "frame");
        assert_eq!(p.target(), "bind");
        assert_eq!(p.data["ins"], serde_json::json!(false));
        assert!(p.data["leaf"].as_str().unwrap().starts_with("pos:"));
        assert!(p.data.get("left").is_some());
        // (b) a fake order of bob's inserted (insertion arm).
        let mut batch = honest.clone();
        let fake = format!("ord:{}:1:0:1:9:5:{}:0:0", "ab".repeat(32), hex::encode(b.0));
        batch.leaf_trace[2].push(fake.clone());
        retrace(&mut batch, 2);
        batch.checkpoint.wit_root = batch.trace[2].clone();
        let mut replay = funded_replay(&[a, b]);
        let p = build_proof(&batch, &mut replay, &[], 0).expect("frame ins proof");
        assert_eq!(p.pred, "frame");
        assert_eq!(p.data["ins"], serde_json::json!(true));
        assert_eq!(p.data["leaf"].as_str(), Some(fake.as_str()));
        // (c) the position dropped outright.
        let mut batch = honest.clone();
        batch.leaf_trace[2].retain(|l| !l.starts_with(&format!("pos:{alice_hex}:")));
        retrace(&mut batch, 2);
        batch.checkpoint.wit_root = batch.trace[2].clone();
        let mut replay = funded_replay(&[a, b]);
        let p = build_proof(&batch, &mut replay, &[], 0).expect("frame drop proof");
        assert_eq!(p.pred, "frame");
        assert_eq!(p.data["ins"], serde_json::json!(false));
    }

    /// R5-A-1: a foreign account's acct leaf rewritten (or dropped, or a
    /// fake one inserted) in a c: unit is P-frame fraud; the cancelling
    /// account's own leaf is not framed.
    #[test]
    fn r5a1_foreign_acct_change_in_cancel_unit_builds_frame_proof() {
        let (honest, a, b, _oid) = cancel_batch();
        assert!(honest.ops[2].starts_with("c:"), "{}", honest.ops[2]);
        let canceller = honest.ops[2][2..66].to_string();
        let other = if canceller == hex::encode(a.0) {
            hex::encode(b.0)
        } else {
            hex::encode(a.0)
        };
        // (a) the other account's collateral zeroed (rewrite).
        let mut batch = honest.clone();
        let mut hit = false;
        for l in batch.leaf_trace[2].iter_mut() {
            if l.starts_with(&format!("acct:{other}:")) {
                let mut p: Vec<String> = l.split(':').map(String::from).collect();
                p[2] = "0".into();
                *l = p.join(":");
                hit = true;
            }
        }
        assert!(hit, "other account has an acct leaf");
        retrace(&mut batch, 2);
        batch.checkpoint.wit_root = batch.trace[2].clone();
        let mut replay = funded_replay(&[a, b]);
        let p = build_proof(&batch, &mut replay, &[], 0).expect("frame acct proof");
        assert_eq!(p.pred, "frame");
        assert!(p.data["leaf"]
            .as_str()
            .unwrap()
            .starts_with(&format!("acct:{other}:")));
        // (b) a fake acct leaf inserted.
        let mut batch = honest.clone();
        let fake = format!("acct:{}:777:0:0", "ab".repeat(32));
        batch.leaf_trace[2].push(fake.clone());
        batch.leaf_trace[2].sort();
        retrace(&mut batch, 2);
        batch.checkpoint.wit_root = batch.trace[2].clone();
        let mut replay = funded_replay(&[a, b]);
        let p = build_proof(&batch, &mut replay, &[], 0).expect("frame acct ins proof");
        assert_eq!(p.pred, "frame");
        assert_eq!(p.data["ins"], serde_json::json!(true));
        assert_eq!(p.data["leaf"].as_str(), Some(fake.as_str()));
        // (c) the frame closure itself never frames the op account.
        let pre = &honest.leaf_trace[1];
        let post = &honest.leaf_trace[2];
        assert!(frame_proof(&honest, 2, &honest.ops[2], pre, post).is_none());
    }

    /// R4-A-5: the size/near-zero gate silences only the collateral leg —
    /// a surviving position where the engine closed it is still fraud.
    #[test]
    fn r4a5_size_gate_keeps_position_leg() {
        let a = "aa".repeat(32);
        let c = "cc".repeat(32);
        let mut leg = place_leg(&a, &c, 1_000, true);
        leg.col_skip = true;
        let mut t = vec![
            format!("acct:{a}:600:0:0"),
            format!("acct:{c}:5:0:0"),
            format!("pos:{a}:1:5:100:0:0"),
        ];
        t.sort();
        assert!(
            aa_fill_verdict(&t, &leg, false, None),
            "position lie judged"
        );
        t.retain(|l| !l.starts_with("pos:"));
        assert!(
            !aa_fill_verdict(&t, &leg, false, None),
            "collateral skipped"
        );
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
        // R5-A-2: a claw can lift a leg at most to 0 from a NEGATIVE fill
        // stage; a positive fill stage can never receive — minting above
        // the identity is fraud whatever the counterparty shows.
        assert!(aa_fill_verdict(&tree(1_500, 0), &leg, false, None));
        assert!(aa_fill_verdict(&tree(1_500, -5), &iso, false, None));
        // Negative fill stage (-300): honest post anywhere in [-300, 0].
        let neg = place_leg(&a, &c, -300, true);
        assert!(!aa_fill_verdict(&tree(0, 5), &neg, false, None));
        assert!(!aa_fill_verdict(&tree(-300, 5), &neg, false, None));
        assert!(aa_fill_verdict(
            &tree(1_000_000_000_000, 5),
            &neg,
            false,
            None
        ));
        // x: taker: ceiling max(cross identity, pre floor), no lower bound.
        let mut xt = place_leg(&a, &c, 100, true);
        xt.xt_floor = Some(400);
        assert!(!aa_fill_verdict(&tree(400, 5), &xt, false, None));
        assert!(!aa_fill_verdict(&tree(-9_000, 5), &xt, false, None));
        assert!(aa_fill_verdict(&tree(5_000, 5), &xt, false, None));
    }

    #[test]
    fn kind2_legs_judged_as_claw_range() {
        // #47 B1: a counterparty at <= 0 may mean the claw moved this leg's
        // collateral (a payment of at most its fill stage) — silent then.
        // R5-A-2: no longer a bounce: a post ABOVE the identity is fraud.
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
        // R5-A-2: minted above the identity with the counterparty at 0.
        assert!(aa_fill_verdict(&tree(5_000, 0), &maker, false, None));
        // A maker that may be the keeper holds up to the reward on top.
        let mut keeper = liq_leg(&a, &c, false, 1_000);
        keeper.kx = 30;
        keeper.claw_checkable = false;
        assert!(!aa_fill_verdict(&tree(1_030, 5), &keeper, false, None));
        assert!(aa_fill_verdict(&tree(1_100, 5), &keeper, false, None));
        // An ADL take past the pre position is fraud on its own.
        let mut over = liq_leg(&a, &c, false, 1_000);
        over.adl_over = true;
        assert!(aa_fill_verdict(&tree(1_000, 5), &over, false, None));
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
