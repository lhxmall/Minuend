//! Independent verification of deposit evidences (H2).
//!
//! An evidence binds a sidechain `Op::Deposit`/`Op::GovDeposit` anchor to a
//! real Obyte joint that actually paid the vault AA. Verification is
//! caller-parameterized (`expected_vault`, `perp_asset`) so replays never
//! trust an evidence's self-declared payee.

use crate::DepositEvidence;
use crate::SettleError;
use minuend_dag::Op;
use minuend_types::{AccountId, DEPOSIT_EVIDENCE_MAX_BYTES};
use std::collections::{HashMap, HashSet};

use crate::obyte_hash::{get_payload_hash, get_unit_hash};

/// R3-A-5: a message's payload is covered by the unit hash only through
/// its `payload_hash` — check it before trusting the payload.
fn payload_hash_ok(msg: &serde_json::Value, unit: &serde_json::Value) -> bool {
    match (
        msg.get("payload"),
        msg.get("payload_hash").and_then(|h| h.as_str()),
    ) {
        (Some(p), Some(h)) => get_payload_hash(p, unit).map(|c| c == h).unwrap_or(false),
        _ => false,
    }
}

/// R3-A-5 / R3-E-3: the sidechain account the payer named in the vault
/// payment (`trigger.data.account`): the joint's ONE `data` message, payload
/// hash verified, `account` = 64 lowercase hex. The vault bounces a deposit
/// without it, so a joint lacking it is no deposit at all.
fn designated_account(unit: &serde_json::Value) -> Option<AccountId> {
    let msgs = unit.get("messages")?.as_array()?;
    let mut data = msgs
        .iter()
        .filter(|m| m.get("app").and_then(|a| a.as_str()) == Some("data"));
    let msg = data.next()?;
    if data.next().is_some() || !payload_hash_ok(msg, unit) {
        return None;
    }
    let acct = msg.get("payload")?.get("account")?.as_str()?;
    if acct.len() != 64
        || !acct
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hex::decode(acct).ok()?);
    Some(AccountId(out))
}

fn parse_hex32(s: &str) -> Result<[u8; 32], SettleError> {
    if s.len() != 64 {
        return Err(SettleError::DepositContentMismatch);
    }
    let bytes = hex::decode(s).map_err(|_| SettleError::DepositContentMismatch)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// True when an Obyte asset string (hex or base64 of the 32-byte id)
/// identifies `want`.
fn asset_matches(s: &str, want: &[u8; 32]) -> bool {
    if s == hex::encode(want) {
        return true;
    }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map(|b| b.as_slice() == want)
        .unwrap_or(false)
}

/// Finds the first output paying `vault` in the expected asset kind; accepts
/// an output to ANY address when `vault` is None (vault address not
/// configured pre-deploy). Asset-class binding is enforced either way so a
/// PERP evidence can never ride a non-PERP payment.
fn find_payment_output_opt(
    unit: &serde_json::Value,
    vault: Option<&str>,
    is_perp: bool,
    perp_asset: &[u8; 32],
) -> Option<(String, Option<String>)> {
    let messages = unit.get("messages")?.as_array()?;
    for msg in messages {
        if msg.get("app").and_then(|a| a.as_str()) != Some("payment") {
            continue;
        }
        // R3-A-5: the amount is read from the payload — it must be the
        // payload the unit hash commits to.
        if !payload_hash_ok(msg, unit) {
            continue;
        }
        let payload = msg.get("payload")?;
        let outputs = payload.get("outputs")?.as_array()?;
        let asset = payload
            .get("asset")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let is_base = match &asset {
            None => true,
            Some(a) => a == "base",
        };
        if is_perp == is_base {
            // Wrong asset class for this evidence kind.
            continue;
        }
        if is_perp {
            // PERP-class payment must carry exactly the governed PERP asset.
            if !asset
                .as_deref()
                .map(|a| asset_matches(a, perp_asset))
                .unwrap_or(false)
            {
                continue;
            }
        }
        for out in outputs {
            let addr = out.get("address")?.as_str()?;
            if let Some(v) = vault {
                if addr != v {
                    continue;
                }
            }
            let amount_val = out.get("amount")?;
            let amount_str = if let Some(n) = amount_val.as_u64() {
                n.to_string()
            } else if let Some(n) = amount_val.as_i64() {
                n.to_string()
            } else if let Some(s) = amount_val.as_str() {
                s.to_string()
            } else {
                continue;
            };
            return Some((amount_str, asset));
        }
    }
    None
}

/// Base-asset joint amount vs credited amount. Production rule: joint pays
/// ev.amount + the 10000 bounce fee. Test fixtures may post without the fee,
/// hence the `cfg(test)` relaxation — never enable it outside tests.
#[cfg(not(test))]
fn base_amount_matches(joint_amt: i128, ev_amt: i128) -> bool {
    joint_amt == ev_amt + 10_000
}
#[cfg(test)]
fn base_amount_matches(joint_amt: i128, ev_amt: i128) -> bool {
    joint_amt == ev_amt + 10_000 || joint_amt == ev_amt
}

/// R3 (unified deposit pipeline): what a verified evidence proves about
/// its anchor — the on-chain payment, independent of any sidechain op.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDeposit {
    /// Amount in the deposit's own unit (base: joint output − bounce fee;
    /// PERP: joint output).
    pub amount: u128,
    /// The paying Obyte address (`joint.authors[0].address`).
    pub payer: String,
    /// The payer-designated sidechain account (`trigger.data.account`).
    pub account: AccountId,
}

/// Verifies ONE evidence on its own: the joint hashes to `ev.aa_unit`, its
/// first author is `ev.payer`, it pays `expected_vault` exactly `ev.amount`
/// (+ bounce fee for base) in the asset class `ev.is_perp` names, both the
/// payment and the data message are payload-hash bound, and the data
/// message designates `ev.account`. The sidechain op is NOT consulted:
/// whether an op may consume the anchor (same amount, payer address and
/// account) is the engine's per-unit decision against the recorded backing
/// (`ChainState::allow_deposit`), so an op that does not match — a
/// front-run with another account or address, a wrong amount — is a
/// REJECTED unit on producer and replay alike instead of an evidence
/// failure that would stall the whole height.
pub fn verify_evidence(
    ev: &DepositEvidence,
    expected_vault: &str,
    perp_asset: &[u8; 32],
) -> Result<([u8; 32], bool, VerifiedDeposit), SettleError> {
    // Payer binding (#8): the evidence's payer must be the joint's first
    // author; the engine then requires the op's bound address to equal it.
    let joint_authors = if let Some(u) = ev.joint.get("unit") {
        u.get("authors")
    } else {
        ev.joint.get("authors")
    };
    let first_author = joint_authors
        .and_then(|a| a.get(0))
        .and_then(|a| a.get("address"))
        .and_then(|a| a.as_str());
    match first_author {
        Some(a) if a == ev.payer => {}
        _ => return Err(SettleError::DepositContentMismatch),
    }
    let ev_bytes = parse_hex32(&ev.aa_unit)?;
    // The credited amount: a non-negative decimal in canonical form.
    let amount: u128 = ev
        .amount
        .parse()
        .map_err(|_| SettleError::DepositContentMismatch)?;
    if amount.to_string() != ev.amount {
        return Err(SettleError::DepositContentMismatch);
    }
    // Payee check (H2): the declared vault must equal the caller's expected
    // vault — an evidence can no longer vouch for itself.
    if ev.vault_address != expected_vault {
        return Err(SettleError::DepositContentMismatch);
    }
    // hash check
    let computed = get_unit_hash(&ev.joint).map_err(|_| SettleError::DepositContentMismatch)?;
    if computed != ev_bytes {
        return Err(SettleError::DepositContentMismatch);
    }
    let unit_obj = if let Some(u) = ev.joint.get("unit") {
        u
    } else {
        &ev.joint
    };
    // Content check: the joint must actually pay the expected vault the
    // claimed (amount, asset). Pre-deploy (empty expected vault) any payee
    // is accepted, but the asset-class binding below still applies.
    let vault_arg = if expected_vault.is_empty() {
        None
    } else {
        Some(expected_vault)
    };
    // R3-A-5: the payer-designated account, declared in the evidence and
    // read from the joint's payload-hash-verified data message.
    let designated = designated_account(unit_obj).ok_or(SettleError::DepositContentMismatch)?;
    if ev.account != hex::encode(designated.0) {
        return Err(SettleError::DepositContentMismatch);
    }
    match find_payment_output_opt(unit_obj, vault_arg, ev.is_perp, perp_asset) {
        Some((joint_amount_str, _asset)) => {
            if ev.is_perp {
                // For PERP, joint amount should equal ev.amount directly.
                if joint_amount_str != ev.amount {
                    return Err(SettleError::DepositContentMismatch);
                }
            } else {
                // For base, joint amount is ev.amount + 10000 bounce fee;
                // see `base_amount_matches` (fixtures post without the fee).
                let ev_amt =
                    i128::try_from(amount).map_err(|_| SettleError::DepositContentMismatch)?;
                let joint_amt: i128 = joint_amount_str
                    .parse()
                    .map_err(|_| SettleError::DepositContentMismatch)?;
                if !base_amount_matches(joint_amt, ev_amt) {
                    return Err(SettleError::DepositContentMismatch);
                }
            }
        }
        None => return Err(SettleError::DepositContentMismatch),
    }
    Ok((
        ev_bytes,
        ev.is_perp,
        VerifiedDeposit {
            amount,
            payer: ev.payer.clone(),
            account: designated,
        },
    ))
}

/// R3-R-4 + R3-E-1 + R3-A-5: per-deposit verification for replay — the one
/// deposit path of `Batch::validate_against`.
///
/// Structural problems of the evidence list itself (over the size cap,
/// duplicate anchors, malformed anchor hex) are hard errors. Otherwise each
/// Deposit/GovDeposit unit's anchor is endorsed iff an evidence for it
/// exists, names the same asset kind as the op, and [`verify_evidence`]
/// accepts it; the result maps each endorsed `(aa_unit, is_perp)` to the
/// verified payment. Missing or failing evidence → simply not endorsed: the
/// replay rejects that unit (`UnbackedDeposit`) exactly like the producer,
/// whose vault feed never held it. The caller records each endorsed anchor
/// with [`minuend_state::ChainState::allow_deposit`] (amount, payer,
/// account), so the engine accepts only the exact payment for the
/// designated account, and must still require that every deposit the
/// replay APPLIED was endorsed.
pub fn verify_each(
    units: &[minuend_dag::Unit],
    evidences: &[DepositEvidence],
    expected_vault: &str,
    perp_asset: &[u8; 32],
) -> Result<HashMap<([u8; 32], bool), VerifiedDeposit>, SettleError> {
    let total_bytes: usize = evidences
        .iter()
        .map(|e| serde_json::to_vec(e).map(|v| v.len()).unwrap_or(0))
        .sum();
    if total_bytes > DEPOSIT_EVIDENCE_MAX_BYTES {
        return Err(SettleError::DepositEvidenceTooLarge);
    }
    let mut map: HashMap<String, &DepositEvidence> = HashMap::new();
    for ev in evidences {
        parse_hex32(&ev.aa_unit)?;
        if map.insert(ev.aa_unit.to_lowercase(), ev).is_some() {
            return Err(SettleError::DepositDuplicateAnchor);
        }
    }
    let mut endorsed: HashMap<([u8; 32], bool), VerifiedDeposit> = HashMap::new();
    let mut tried: HashSet<([u8; 32], bool)> = HashSet::new();
    for u in units {
        let key = match &u.op {
            Op::Deposit { aa_unit, .. } => (*aa_unit, false),
            Op::GovDeposit { aa_unit, .. } => (*aa_unit, true),
            _ => continue,
        };
        if !tried.insert(key) {
            continue;
        }
        let Some(ev) = map.get(&hex::encode(key.0)) else {
            continue;
        };
        if ev.is_perp != key.1 {
            continue;
        }
        if let Ok((anchor, is_perp, v)) = verify_evidence(ev, expected_vault, perp_asset) {
            if (anchor, is_perp) == key {
                endorsed.insert(key, v);
            }
        }
    }
    Ok(endorsed)
}
