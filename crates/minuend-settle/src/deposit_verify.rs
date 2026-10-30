//! Independent verification of deposit evidences (H2).
//!
//! An evidence binds a sidechain `Op::Deposit`/`Op::GovDeposit` anchor to a
//! real Obyte joint that actually paid the vault AA. Verification is
//! caller-parameterized (`expected_vault`, `perp_asset`) so replays never
//! trust an evidence's self-declared payee.
//!
//! R4 (R4-E-2 / R4-R-3 / R4-A-2 / R4-A-7): the acceptance rule mirrors how
//! the vault AA (`obyte-local/agents/minuend_vault.aa`) and ocore
//! (`aa_composer.js` `getTrigger`, `formula/evaluation.js`) turn the joint
//! into a `dep_<unit>` / `depp_<unit>` record:
//!
//! * `trigger.address` = first author; `trigger.data` = the FIRST `data`
//!   message's payload; `trigger.output[[asset=X]]` = the SUM of every
//!   output to the vault in asset X over all payment messages;
//! * a primary trigger carrying less than the 10000-byte bounce fee, or a
//!   unit with `max_aa_responses: 0`, bounces;
//! * the case order decides the kind: an Oscript-truthy `data.deposit` is a
//!   BASE deposit (even if `deposit_perp` is also set), else an
//!   Oscript-truthy `data.deposit_perp` is a PERP deposit, else no deposit;
//! * `data.account` must be a 64-char lowercase-hex STRING that Oscript does
//!   not convert to a number;
//! * BASE amount = base sum − 10000 and must be > 0; PERP amount = sum of the
//!   governed PERP asset and must be > 0.
//!
//! The evidence must declare exactly what this derivation yields. The
//! producer admits an anchor only when this check AND the vault record
//! agree ([`admit_deposit`]); see `work/r4-dep-format.md` / PROTOCOL.

use crate::DepositEvidence;
use crate::SettleError;
use minuend_types::{AccountId, DEPOSIT_EVIDENCE_MAX_BYTES};
use std::collections::BTreeMap;

use crate::obyte_hash::{get_payload_hash, get_unit_hash};

/// R4-R-2 / R5-E-1: largest single evidence a WATCHER accepts
/// (serde-serialized JSON). A larger stamped evidence endorses nothing
/// (per-unit rejection). This is the verify limit, not the producer's:
/// the producer admits only up to [`DEPOSIT_EVIDENCE_ADMIT_UNIT_MAX_BYTES`].
pub const DEPOSIT_EVIDENCE_UNIT_MAX_BYTES: usize = 256 * 1024;
/// Total evidence of one batch (all stamped frames) a WATCHER accepts.
/// Only APPLIED deposits carry evidence, so this is under the producer's
/// control (R5-E-1: it enforces the smaller
/// [`DEPOSIT_EVIDENCE_ADMIT_BATCH_MAX_BYTES`] BEFORE applying a deposit,
/// see [`DepositEvidenceBudget`]).
pub const DEPOSIT_EVIDENCE_BATCH_MAX_BYTES: usize = DEPOSIT_EVIDENCE_MAX_BYTES;
/// R5-E-1 / R5-R-1: the producer's admission limit for ONE evidence
/// ([`admit_deposit`] refuses anything larger). Three tiers, strictly
/// ordered so that whatever the producer admits the poster can post and
/// every watcher accepts, even if `JSON.stringify` and `serde_json` measure
/// a joint a few bytes apart:
/// admit (240 KiB) < post (`post_batch.js`, 248 KiB) < verify (256 KiB).
pub const DEPOSIT_EVIDENCE_ADMIT_UNIT_MAX_BYTES: usize = 240 * 1024;
/// R5-E-1: the limit `obyte-local/deposit_evidence.js` posts up to (one
/// evidence). Mirrored there as `DEPOSIT_EVIDENCE_POST_UNIT_MAX_BYTES`.
pub const DEPOSIT_EVIDENCE_POST_UNIT_MAX_BYTES: usize = 248 * 1024;
/// R5-E-1: the producer's running per-batch admission limit: the evidence
/// of all deposits APPLIED since the last cut. Enforced before a deposit
/// is applied ([`DepositEvidenceBudget::try_reserve`]), never after the cut.
pub const DEPOSIT_EVIDENCE_ADMIT_BATCH_MAX_BYTES: usize = 960 * 1024;
/// R5-E-1: the batch total `deposit_evidence.js` posts up to. Mirrored
/// there as `DEPOSIT_EVIDENCE_POST_BATCH_MAX_BYTES`.
pub const DEPOSIT_EVIDENCE_POST_BATCH_MAX_BYTES: usize = 992 * 1024;

const _: () = {
    assert!(DEPOSIT_EVIDENCE_ADMIT_UNIT_MAX_BYTES < DEPOSIT_EVIDENCE_POST_UNIT_MAX_BYTES);
    assert!(DEPOSIT_EVIDENCE_POST_UNIT_MAX_BYTES < DEPOSIT_EVIDENCE_UNIT_MAX_BYTES);
    assert!(DEPOSIT_EVIDENCE_ADMIT_BATCH_MAX_BYTES < DEPOSIT_EVIDENCE_POST_BATCH_MAX_BYTES);
    assert!(DEPOSIT_EVIDENCE_POST_BATCH_MAX_BYTES < DEPOSIT_EVIDENCE_BATCH_MAX_BYTES);
    // An empty batch always has room for one admissible deposit.
    assert!(DEPOSIT_EVIDENCE_ADMIT_UNIT_MAX_BYTES <= DEPOSIT_EVIDENCE_ADMIT_BATCH_MAX_BYTES);
};
/// The vault's `bounce_fees.base` (ocore `MIN_BYTES_BOUNCE_FEE`).
pub const VAULT_BOUNCE_FEE: u128 = 10_000;
/// ocore `constants.MAX_AA_STRING_LENGTH`.
const MAX_AA_STRING_LENGTH: usize = 4096;

/// Serialized size of one evidence (the measure both caps use).
pub fn evidence_len(ev: &DepositEvidence) -> usize {
    serde_json::to_vec(ev)
        .map(|v| v.len())
        .unwrap_or(usize::MAX)
}

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

/// ocore `string_utils.toNumber` (post-aa2, unlimited precision): `Some(f)`
/// when Oscript converts the string to a number.
fn oscript_to_number(s: &str) -> Option<f64> {
    // /^[+-]?(\d+(\.\d+)?)([eE][+-]?(\d+))?$/
    let b = s.as_bytes();
    let mut i = 0;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let m_start = i;
    let int_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == int_start {
        return None;
    }
    if i < b.len() && b[i] == b'.' {
        let fs = i + 1;
        let mut j = fs;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j == fs {
            return None;
        }
        i = j;
    }
    let mantissa = &s[m_start..i];
    let mut abs_exp: Option<&str> = None;
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        let mut j = i + 1;
        if j < b.len() && (b[j] == b'+' || b[j] == b'-') {
            j += 1;
        }
        let es = j;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j == es {
            return None;
        }
        abs_exp = Some(&s[es..j]);
        i = j;
    }
    if i != b.len() {
        return None;
    }
    let f: f64 = s.parse().ok()?;
    if !f.is_finite() {
        return None;
    }
    // `f === 0 && mantissa > 0 && abs_exp > 0`: underflow (e.g. 1.23e-700).
    let mant_pos = mantissa.parse::<f64>().map(|m| m > 0.0).unwrap_or(false);
    let exp_pos = abs_exp
        .and_then(|e| e.parse::<f64>().ok())
        .map(|e| e > 0.0)
        .unwrap_or(false);
    if f == 0.0 && mant_pos && exp_pos {
        return None;
    }
    Some(if f == 0.0 { 0.0 } else { f })
}

/// Oscript truthiness of `trigger.data.<key>` used as a case `if`:
/// `Ok(false)` for a missing key; `Err(())` where ocore raises (the AA then
/// bounces): `null`, or a string longer than `MAX_AA_STRING_LENGTH`.
fn oscript_truthy(v: Option<&serde_json::Value>) -> Result<bool, ()> {
    use serde_json::Value;
    match v {
        None => Ok(false),
        Some(Value::Null) => Err(()),
        Some(Value::Bool(b)) => Ok(*b),
        Some(Value::Number(n)) => Ok(n.as_f64().map(|f| f != 0.0).unwrap_or(true)),
        Some(Value::String(s)) => {
            if s.encode_utf16().count() > MAX_AA_STRING_LENGTH {
                return Err(());
            }
            match oscript_to_number(s) {
                Some(f) => Ok(f != 0.0),
                None => Ok(!s.is_empty()),
            }
        }
        Some(Value::Array(_)) | Some(Value::Object(_)) => Ok(true),
    }
}

/// The vault's account rule: a STRING (after Oscript's numeric conversion)
/// of exactly 64 lowercase hex chars.
fn vault_account(v: Option<&serde_json::Value>) -> Option<AccountId> {
    let s = v?.as_str()?;
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    if oscript_to_number(s).is_some() {
        // e.g. an all-digit id: Oscript reads a number, `typeof != 'string'`
        // → the vault bounces 'bad account'.
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hex::decode(s).ok()?);
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

/// What the vault records for a joint: `(is_perp, amount, payer, account)`,
/// or `None` when the vault would not record a deposit for it (no trigger,
/// bounce, other case). `Err` = the joint itself is malformed / forged
/// (payload not bound by its hash).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultDeposit {
    pub is_perp: bool,
    pub amount: u128,
    pub payer: String,
    pub account: AccountId,
}

/// R4-E-2 / R4-R-3: derive the vault's deposit record from a joint exactly
/// like ocore + the vault AA (module docs). `vault` must be non-empty.
pub fn vault_deposit_of(
    joint: &serde_json::Value,
    vault: &str,
    perp_asset: &[u8; 32],
) -> Result<Option<VaultDeposit>, SettleError> {
    if vault.is_empty() {
        return Err(SettleError::DepositContentMismatch);
    }
    let unit = joint.get("unit").unwrap_or(joint);
    let payer = unit
        .get("authors")
        .and_then(|a| a.get(0))
        .and_then(|a| a.get("address"))
        .and_then(|a| a.as_str())
        .ok_or(SettleError::DepositContentMismatch)?
        .to_string();
    if let Some(m) = unit.get("max_aa_responses") {
        if m.as_u64() == Some(0) {
            return Ok(None);
        }
    }
    let msgs = unit
        .get("messages")
        .and_then(|m| m.as_array())
        .ok_or(SettleError::DepositContentMismatch)?;
    let mut data: Option<&serde_json::Value> = None;
    // asset string -> summed amount paid to the vault.
    let mut outputs: BTreeMap<String, u128> = BTreeMap::new();
    for msg in msgs {
        match msg.get("app").and_then(|a| a.as_str()) {
            Some("data") if data.is_none() => {
                // ocore uses the FIRST data message, payload included as is;
                // we only trust it when its hash binds it to the unit.
                if !payload_hash_ok(msg, unit) {
                    return Err(SettleError::DepositContentMismatch);
                }
                data = msg.get("payload");
            }
            Some("payment") => {
                let Some(payload) = msg.get("payload") else {
                    continue; // private payment: getTrigger skips it too
                };
                let outs = payload
                    .get("outputs")
                    .and_then(|o| o.as_array())
                    .ok_or(SettleError::DepositContentMismatch)?;
                let pays_vault = outs
                    .iter()
                    .any(|o| o.get("address").and_then(|a| a.as_str()) == Some(vault));
                if !pays_vault {
                    continue;
                }
                if !payload_hash_ok(msg, unit) {
                    return Err(SettleError::DepositContentMismatch);
                }
                let asset = match payload.get("asset") {
                    None => "base".to_string(),
                    Some(a) => a
                        .as_str()
                        .ok_or(SettleError::DepositContentMismatch)?
                        .to_string(),
                };
                for o in outs {
                    if o.get("address").and_then(|a| a.as_str()) != Some(vault) {
                        continue;
                    }
                    let amt = o
                        .get("amount")
                        .and_then(|a| a.as_u64())
                        .ok_or(SettleError::DepositContentMismatch)?;
                    let e = outputs.entry(asset.clone()).or_insert(0);
                    *e = e.saturating_add(u128::from(amt));
                }
            }
            _ => {}
        }
    }
    if outputs.is_empty() {
        return Ok(None); // not a trigger of the vault
    }
    let base_sum = outputs.get("base").copied().unwrap_or(0);
    if base_sum < VAULT_BOUNCE_FEE {
        return Ok(None); // 'received bytes are not enough to cover bounce fees'
    }
    // `trigger.data` is false for a missing / non-object / empty payload.
    let Some(data) = data.and_then(|d| d.as_object()).filter(|o| !o.is_empty()) else {
        return Ok(None);
    };
    let is_perp = match oscript_truthy(data.get("deposit")) {
        Err(()) => return Ok(None),
        Ok(true) => false,
        Ok(false) => match oscript_truthy(data.get("deposit_perp")) {
            Ok(true) => true,
            _ => return Ok(None),
        },
    };
    let Some(account) = vault_account(data.get("account")) else {
        return Ok(None);
    };
    let amount = if is_perp {
        let sum: u128 = outputs
            .iter()
            .filter(|(a, _)| a.as_str() != "base" && asset_matches(a, perp_asset))
            .map(|(_, v)| *v)
            .fold(0u128, |a, b| a.saturating_add(b));
        if sum == 0 {
            return Ok(None); // 'bad deposit'
        }
        sum
    } else {
        let a = base_sum - VAULT_BOUNCE_FEE;
        if a == 0 {
            return Ok(None); // 'deposit too small'
        }
        a
    };
    Ok(Some(VaultDeposit {
        is_perp,
        amount,
        payer,
        account,
    }))
}

/// R3 (unified deposit pipeline): what a verified evidence proves about
/// its anchor — the on-chain payment, independent of any sidechain op.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDeposit {
    /// Amount in the deposit's own unit (base: vault outputs − bounce fee;
    /// PERP: PERP outputs to the vault).
    pub amount: u128,
    /// The paying Obyte address (`joint.authors[0].address`).
    pub payer: String,
    /// The payer-designated sidechain account (`trigger.data.account`).
    pub account: AccountId,
}

/// Verifies ONE evidence on its own: size within
/// [`DEPOSIT_EVIDENCE_UNIT_MAX_BYTES`], the joint hashes to `ev.aa_unit`,
/// and the vault record the joint produces ([`vault_deposit_of`]) is a
/// deposit of exactly `ev.is_perp`, `ev.amount`, `ev.payer`, `ev.account`
/// to `ev.vault_address == expected_vault`. The sidechain op is NOT
/// consulted: whether an op may consume the anchor is the engine's per-unit
/// decision against the recorded backing.
pub fn verify_evidence(
    ev: &DepositEvidence,
    expected_vault: &str,
    perp_asset: &[u8; 32],
) -> Result<([u8; 32], bool, VerifiedDeposit), SettleError> {
    if evidence_len(ev) > DEPOSIT_EVIDENCE_UNIT_MAX_BYTES {
        return Err(SettleError::DepositEvidenceTooLarge);
    }
    if expected_vault.is_empty() || ev.vault_address != expected_vault {
        return Err(SettleError::DepositContentMismatch);
    }
    let ev_bytes = parse_hex32(&ev.aa_unit)?;
    let amount: u128 = ev
        .amount
        .parse()
        .map_err(|_| SettleError::DepositContentMismatch)?;
    if amount.to_string() != ev.amount {
        return Err(SettleError::DepositContentMismatch);
    }
    let computed = get_unit_hash(&ev.joint).map_err(|_| SettleError::DepositContentMismatch)?;
    if computed != ev_bytes {
        return Err(SettleError::DepositContentMismatch);
    }
    let rec = vault_deposit_of(&ev.joint, expected_vault, perp_asset)?
        .ok_or(SettleError::DepositContentMismatch)?;
    if rec.is_perp != ev.is_perp {
        return Err(SettleError::DepositKindMismatch);
    }
    if rec.amount != amount || rec.payer != ev.payer || hex::encode(rec.account.0) != ev.account {
        return Err(SettleError::DepositContentMismatch);
    }
    Ok((
        ev_bytes,
        ev.is_perp,
        VerifiedDeposit {
            amount,
            payer: rec.payer,
            account: rec.account,
        },
    ))
}

/// R4-E-1 / R4-E-4: the per-unit check the replay applies to the evidence
/// stamped on ONE Deposit/GovDeposit frame: the evidence verifies and names
/// exactly that unit's `(anchor, kind)`.
pub fn verify_unit_evidence(
    ev: &DepositEvidence,
    anchor: [u8; 32],
    is_perp: bool,
    expected_vault: &str,
    perp_asset: &[u8; 32],
) -> Result<VerifiedDeposit, SettleError> {
    let (a, k, v) = verify_evidence(ev, expected_vault, perp_asset)?;
    if a != anchor {
        return Err(SettleError::DepositAnchorMissing);
    }
    if k != is_perp {
        return Err(SettleError::DepositKindMismatch);
    }
    Ok(v)
}

/// R4-E-4 producer rule: admit an anchor (`ChainState::allow_deposit`) only
/// when the evidence built from its joint verifies AND agrees field by field
/// with the vault's on-chain record `'{payer}:{amount}:{account}'`
/// (`dep_<unit>` for base, `depp_<unit>` for PERP — pass the one matching
/// `ev.is_perp`). A producer following this rule and stamping the evidence
/// on exactly the deposit units it applied is replayed identically by every
/// watcher, whenever it learned of the vault record.
///
/// R5-E-1 / R5-R-1: the evidence must also be at most
/// [`DEPOSIT_EVIDENCE_ADMIT_UNIT_MAX_BYTES`] (below the poster's and the
/// watchers' limits), else [`SettleError::DepositEvidenceTooLarge`]: an
/// anchor the producer admits is always postable. Use
/// [`DepositEvidenceBudget`] to also keep the batch total within budget.
pub fn admit_deposit(
    ev: &DepositEvidence,
    expected_vault: &str,
    perp_asset: &[u8; 32],
    vault_record: &str,
) -> Result<([u8; 32], bool, VerifiedDeposit), SettleError> {
    if evidence_len(ev) > DEPOSIT_EVIDENCE_ADMIT_UNIT_MAX_BYTES {
        return Err(SettleError::DepositEvidenceTooLarge);
    }
    let out = verify_evidence(ev, expected_vault, perp_asset)?;
    let parts: Vec<&str> = vault_record.split(':').collect();
    if parts.len() != 3
        || parts[0] != out.2.payer
        || parts[1] != out.2.amount.to_string()
        || parts[2] != hex::encode(out.2.account.0)
    {
        return Err(SettleError::DepositContentMismatch);
    }
    Ok(out)
}

/// R5-E-1 / R5-R-1: the producer's running deposit-evidence budget for the
/// batch being built. The evidence size is known at admission
/// ([`DepositEvidenceBudget::admit`] = [`admit_deposit`] + remember the
/// size); the batch total is checked BEFORE a deposit unit is ingested
/// ([`DepositEvidenceBudget::try_reserve`] /
/// [`ingest_within_budget`]), so a batch can never be cut with more
/// evidence than [`DEPOSIT_EVIDENCE_ADMIT_BATCH_MAX_BYTES`] (the old rule —
/// "cut the batch earlier" once `post_batch.js` refused — came after the
/// irreversible cut). A deposit that does not fit is not ingested in this
/// batch: the producer keeps the unit and ingests it after the next cut
/// (its anchor stays admitted).
///
/// Producer loop: `admit` each vault record (then `allow_deposit` with the
/// returned backing), `ingest_within_budget` each unit (`Ok(None)` =
/// deferred to the next batch), and `on_batch_cut` right after
/// `Batch::from_applied`. Not part of any root; producer-local.
#[derive(Clone, Debug, Default)]
pub struct DepositEvidenceBudget {
    /// Evidence size of every admitted, not yet consumed anchor.
    admitted: BTreeMap<([u8; 32], bool), usize>,
    /// Evidence bytes of the deposits applied (reserved) since the last cut.
    used: usize,
    /// Anchors reserved in the current batch.
    reserved: BTreeMap<([u8; 32], bool), usize>,
}

impl DepositEvidenceBudget {
    pub fn new() -> Self {
        Self::default()
    }
    /// [`admit_deposit`], remembering the evidence size of the anchor.
    pub fn admit(
        &mut self,
        ev: &DepositEvidence,
        expected_vault: &str,
        perp_asset: &[u8; 32],
        vault_record: &str,
    ) -> Result<([u8; 32], bool, VerifiedDeposit), SettleError> {
        let out = admit_deposit(ev, expected_vault, perp_asset, vault_record)?;
        self.admitted.insert((out.0, out.1), evidence_len(ev));
        Ok(out)
    }
    /// Evidence bytes reserved by the deposits applied since the last cut.
    pub fn used(&self) -> usize {
        self.used
    }
    /// Bytes still available in the current batch.
    pub fn remaining(&self) -> usize {
        DEPOSIT_EVIDENCE_ADMIT_BATCH_MAX_BYTES.saturating_sub(self.used)
    }
    /// Evidence size of the anchor an op consumes, if admitted here.
    pub fn evidence_len_of(&self, op: &minuend_dag::Op) -> Option<usize> {
        crate::deposit_key(op).and_then(|k| self.admitted.get(&k).copied())
    }
    /// Reserve the evidence of a deposit op before ingesting it. Ops that
    /// are not deposits, or whose anchor was not admitted through this
    /// budget (they cannot be applied with evidence anyway), reserve
    /// nothing. `Err(DepositEvidenceBudget)` = it would push the batch
    /// over [`DEPOSIT_EVIDENCE_ADMIT_BATCH_MAX_BYTES`]: defer the unit.
    pub fn try_reserve(&mut self, op: &minuend_dag::Op) -> Result<(), SettleError> {
        let Some(key) = crate::deposit_key(op) else {
            return Ok(());
        };
        let Some(len) = self.admitted.get(&key).copied() else {
            return Ok(());
        };
        if self.reserved.contains_key(&key) {
            // A second unit citing the same anchor in this batch is a
            // duplicate the engine rejects: nothing more to reserve.
            return Ok(());
        }
        let total = self.used.saturating_add(len);
        if total > DEPOSIT_EVIDENCE_ADMIT_BATCH_MAX_BYTES {
            return Err(SettleError::DepositEvidenceBudget);
        }
        self.used = total;
        self.reserved.insert(key, len);
        Ok(())
    }
    /// Give back a reservation whose unit was not applied.
    pub fn release(&mut self, op: &minuend_dag::Op) {
        if let Some(key) = crate::deposit_key(op) {
            if let Some(len) = self.reserved.remove(&key) {
                self.used = self.used.saturating_sub(len);
            }
        }
    }
    /// Call right after `Batch::from_applied`: consumed anchors leave the
    /// budget and the running total restarts at 0.
    pub fn on_batch_cut(&mut self) {
        for k in std::mem::take(&mut self.reserved).into_keys() {
            self.admitted.remove(&k);
        }
        self.used = 0;
    }
}

/// R5-E-1: ingest one unit under the producer's evidence budget.
/// `Ok(None)` = a deposit whose evidence does not fit the current batch:
/// NOT ingested (engine untouched); re-submit it after the next cut.
/// `Ok(Some(events))` = ingested; a deposit that was not applied gives its
/// reservation back.
pub fn ingest_within_budget(
    engine: &mut minuend_exec::Engine,
    budget: &mut DepositEvidenceBudget,
    unit: minuend_dag::Unit,
) -> Result<Option<Vec<minuend_exec::ExecEvent>>, minuend_exec::ExecError> {
    if budget.try_reserve(&unit.op).is_err() {
        return Ok(None);
    }
    let op = unit.op.clone();
    let uid = minuend_dag::unit_id(&unit);
    match engine.ingest(unit) {
        Ok(events) => {
            let applied = events.iter().any(|e| {
                matches!(e, minuend_exec::ExecEvent::Applied { unit, .. } if *unit == uid)
            });
            if !applied {
                budget.release(&op);
            }
            Ok(Some(events))
        }
        Err(e) => {
            budget.release(&op);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn oscript_numbers() {
        assert_eq!(oscript_to_number("0"), Some(0.0));
        assert_eq!(oscript_to_number("-0"), Some(0.0));
        assert_eq!(oscript_to_number("1.5e3"), Some(1500.0));
        assert_eq!(oscript_to_number("1e-700"), None);
        assert_eq!(oscript_to_number("0e-700"), Some(0.0));
        assert_eq!(oscript_to_number("1e400"), None);
        assert_eq!(oscript_to_number("1."), None);
        assert_eq!(oscript_to_number(".5"), None);
        assert_eq!(oscript_to_number("abc"), None);
        assert_eq!(oscript_to_number(""), None);
        assert_eq!(oscript_to_number("0x10"), None);
    }

    #[test]
    fn oscript_truthiness() {
        assert_eq!(oscript_truthy(None), Ok(false));
        assert_eq!(oscript_truthy(Some(&json!(1))), Ok(true));
        assert_eq!(oscript_truthy(Some(&json!(0))), Ok(false));
        assert_eq!(oscript_truthy(Some(&json!(0.0))), Ok(false));
        assert_eq!(oscript_truthy(Some(&json!("0"))), Ok(false));
        assert_eq!(oscript_truthy(Some(&json!("0.00"))), Ok(false));
        assert_eq!(oscript_truthy(Some(&json!(""))), Ok(false));
        assert_eq!(oscript_truthy(Some(&json!("x"))), Ok(true));
        assert_eq!(oscript_truthy(Some(&json!(false))), Ok(false));
        assert_eq!(oscript_truthy(Some(&json!({}))), Ok(true));
        assert_eq!(oscript_truthy(Some(&json!([]))), Ok(true));
        assert_eq!(oscript_truthy(Some(&json!(null))), Err(()));
        assert_eq!(oscript_truthy(Some(&json!("y".repeat(4097)))), Err(()));
    }

    #[test]
    fn vault_account_rules() {
        assert!(vault_account(Some(&json!("ab".repeat(32)))).is_some());
        assert!(vault_account(Some(&json!("AB".repeat(32)))).is_none());
        // all digits: Oscript converts to a number → vault bounces.
        assert!(vault_account(Some(&json!("12".repeat(32)))).is_none());
        assert!(vault_account(Some(&json!(5))).is_none());
    }
}
