//! Independent MINUEND vault-AA watcher.
//!
//! Contract (read-only except detection): reads `da_unit_<h>` from a live
//! Obyte hub, verifies the unit↔data binding, and replays the posted batch
//! through [`minuend_settle::Batch::validate_against`]. Any height whose replay
//! fails is a mismatch that a watcher-owned wallet would challenge on-chain.
//!
//! This crate NEVER writes `submit`/`lock`/`finalize`. The `challenge` is the
//! only AA transaction a watcher may emit, and it is issued by the binary
//! (whose signing backend is the operator's separate deployment concern —
//! see the watcher limitation footnote in the workspace README).
//!
//! The core [`HubClient`] is abstracted so the replay/verify logic is fully
//! unit-testable without a live hub; the binary supplies an HTTP client.

pub mod prove;
use minuend_exec::Engine;
use minuend_settle::{Batch, SettleError};

/// Challenge bond gross attached to a `challenge` trigger.
/// mirrors minuend_types::CHALLENGE_BOND_NET + BOUNCE_FEE_BASE
pub const CHALLENGE_BOND_GROSS: u64 = 1_000_000_010_000;
/// Default poll interval in seconds.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 30;

/// Watcher configuration.
#[derive(Clone, Debug)]
pub struct WatchConfig {
    /// Obyte rollup AA address to watch.
    pub rollup_address: String,
    /// Obyte vault AA address (deposit evidence payee).
    pub vault_address: String,
    /// Optional dispute AA address (challenge posting target).
    pub dispute_address: Option<String>,
    /// Hub JSON-RPC base URL (e.g. `http://127.0.0.1:6611`).
    pub hub_url: Option<String>,
    pub poll_interval_secs: u64,
    pub challenge_bond_gross: u64,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            rollup_address: String::new(),
            vault_address: String::new(),
            dispute_address: None,
            hub_url: None,
            poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
            challenge_bond_gross: CHALLENGE_BOND_GROSS,
        }
    }
}

/// A batch's data-availability unit as observed on-chain.
#[derive(Clone, Debug)]
pub struct DaUnit {
    /// Batch height.
    pub height: u64,
    /// The Obyte unit hash recorded in `da_unit_<h>`.
    pub unit_hash: String,
    /// The temp_data payload `data` (the batch JSON) carried by that unit.
    pub data: serde_json::Value,
    /// The raw Obyte joint fetched for `unit_hash` (for binding re-hash).
    pub joint: serde_json::Value,
}

/// Errors surfaced by the watcher core.
#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("hub unavailable: {0}")]
    HubUnavailable(String),
    #[error("no da_unit at height {0}")]
    DaMissing(u64),
    #[error("binding mismatch: {0}")]
    BindingMismatch(String),
    #[error("settle: {0}")]
    Settle(#[from] SettleError),
    #[error("challenge rejected: {0}")]
    AaChallengeFailed(String),
}

/// Abstraction over the Obyte hub. Tests provide a mock; the binary provides
/// an HTTP-backed implementation (`HttpHubClient`).
pub trait HubClient {
    /// Read a single AA state variable. `Ok(Some(value))` when set,
    /// `Ok(None)` when the var is absent, `Err` on transport failure.
    fn get_aa_state_var(
        &self,
        address: &str,
        key: &str,
    ) -> Result<Option<serde_json::Value>, String>;
    /// Fetch a unit/joint by its hash as the hub returns it.
    fn get_joint(&self, unit_hash: &str) -> Result<serde_json::Value, String>;
}

/// Fetch the `da_unit_<height>` package from the hub, verifying the recorded
/// unit hash actually corresponds to the joint that carries the temp_data.
///
/// Returns `Ok(None)` when the height has no `da_unit_<h>` (never submitted,
/// or cleared by a failed-finalize sweep). Transport failures are
/// [`WatchError::HubUnavailable`] so the caller backs off rather than
/// mis-challenging.
pub fn fetch_da_unit<H: HubClient>(
    hub: &H,
    vault: &str,
    height: u64,
) -> Result<Option<DaUnit>, WatchError> {
    let key = format!("da_unit_{height}");
    let val = hub
        .get_aa_state_var(vault, &key)
        .map_err(WatchError::HubUnavailable)?;
    let unit_hash = match val {
        Some(v) => v
            .as_str()
            .ok_or_else(|| WatchError::HubUnavailable("da_unit var not a string".into()))?
            .to_string(),
        None => return Ok(None),
    };
    let joint = hub
        .get_joint(&unit_hash)
        .map_err(WatchError::HubUnavailable)?;
    let data = extract_temp_data(&joint).ok_or_else(|| {
        WatchError::BindingMismatch("joint has no inline temp_data payload".into())
    })?;
    Ok(Some(DaUnit {
        height,
        unit_hash,
        data,
        joint,
    }))
}

/// Verify the DA binding: the Obyte unit whose hash the AA recorded in
/// `da_unit_<h>` must be exactly the joint we fetched (`get_unit_hash`).
/// `validate_against` separately proves the root points at this data package.
pub fn verify_da_binding(da: &DaUnit) -> Result<(), WatchError> {
    let recomputed = obyte_hash::get_unit_hash(&da.joint).map_err(WatchError::BindingMismatch)?;
    let recomputed_hex = hex::encode(recomputed);
    if recomputed_hex != da.unit_hash {
        return Err(WatchError::BindingMismatch(format!(
            "recorded unit_hash {} != recomputed {}",
            da.unit_hash, recomputed_hex
        )));
    }
    Ok(())
}
/// Assemble a multi-package header: fetch each `packages` hash via
/// `get_joint`, require its `package_blob` string (base64(gzip(bytes))),
/// gunzip, and concatenate the package bytes **unchanged**. The result must
/// hash (hex sha256) to the header's `data_root`; it is returned as-is and is
/// exactly the byte string the frame parser reads (B11, #47: no parse-only
/// LF insertion / duplicate-LF removal any more, so the bytes that are parsed
/// are the bytes `data_root` commits to).
/// Transport errors map to `HubUnavailable` (caller backs off); bad content
/// (bad base64, invalid gzip, root mismatch) maps to `BindingMismatch`.
/// No retries here — the poll loop owns backoff.
pub fn assemble_frames<H: HubClient>(
    hub: &H,
    data: &serde_json::Value,
) -> Result<Vec<u8>, WatchError> {
    let hashes = data
        .get("packages")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            WatchError::BindingMismatch("header has neither frames_blob nor packages".into())
        })?;
    let want = data
        .get("data_root")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WatchError::BindingMismatch("packages header missing data_root".into()))?;
    use base64::Engine as _;
    // R2-R-2: bound the work before any fetch/decompression. A package can
    // never hold less than one frame, so a header listing more packages
    // than units (or than a batch may carry) is malformed.
    let max_pkgs = header_unit_count(data)
        .unwrap_or(MAX_PACKAGES as u64)
        .min(MAX_PACKAGES as u64) as usize;
    if hashes.len() > max_pkgs.max(1) {
        return Err(WatchError::BindingMismatch(format!(
            "header lists {} packages (max {})",
            hashes.len(),
            max_pkgs.max(1)
        )));
    }
    let mut concat: Vec<u8> = Vec::new();
    for h in hashes {
        let s = h
            .as_str()
            .ok_or_else(|| WatchError::BindingMismatch("package hash not a string".into()))?;
        let joint = hub.get_joint(s).map_err(WatchError::HubUnavailable)?;
        let payload = extract_temp_data(&joint)
            .ok_or_else(|| WatchError::BindingMismatch("package joint has no temp_data".into()))?;
        let b64 = payload
            .get("package_blob")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                WatchError::BindingMismatch("package joint missing package_blob".into())
            })?;
        let gz = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| WatchError::BindingMismatch("package_blob not base64".into()))?;
        let budget = MAX_COMMITTED_RAW_BYTES.saturating_sub(concat.len());
        let raw = gunzip_bounded(&gz, MAX_PACKAGE_RAW_BYTES.min(budget))?;
        concat.extend_from_slice(&raw);
    }
    check_data_root(&concat, want)?;
    Ok(concat)
}

fn check_data_root(raw: &[u8], want: &str) -> Result<(), WatchError> {
    use sha2::{Digest, Sha256};
    let got = hex::encode(Sha256::digest(raw));
    if got != want {
        return Err(WatchError::BindingMismatch(format!(
            "data_root mismatch: want {want} got {got}"
        )));
    }
    Ok(())
}

/// Header shape check shared by every decode path (B11, #47). A header must
/// carry exactly one frame source: an inline `frames_blob` OR a `packages`
/// list. Carrying both used to skip the inline `data_root` check (the check
/// was keyed on "no `packages`"), so that combination is now refused.
fn check_header_shape(data: &serde_json::Value) -> Result<(), WatchError> {
    if data.get("units").is_some() {
        return Err(WatchError::BindingMismatch(
            "legacy units-array header is not accepted".into(),
        ));
    }
    match (
        data.get("frames_blob").is_some(),
        data.get("packages").is_some(),
    ) {
        (true, true) => Err(WatchError::BindingMismatch(
            "header carries both frames_blob and packages".into(),
        )),
        (false, false) => Err(WatchError::BindingMismatch(
            "header has neither frames_blob nor packages".into(),
        )),
        _ => Ok(()),
    }
}

/// Exact committed bytes of a single-package (inline `frames_blob`) header,
/// verified against the mandatory `data_root`.
pub fn inline_frame_bytes(data: &serde_json::Value) -> Result<Vec<u8>, WatchError> {
    check_header_shape(data)?;
    let blob = data
        .get("frames_blob")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WatchError::BindingMismatch("frames_blob missing".into()))?;
    let want = data
        .get("data_root")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            WatchError::BindingMismatch("frames_blob header missing data_root".into())
        })?;
    use base64::Engine as _;
    let gz = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .map_err(|_| WatchError::BindingMismatch("frames_blob not base64(gzip)".into()))?;
    // R2-R-2/R2-R-15: bounded, single-member decode (was unbounded).
    let raw = gunzip_bounded(&gz, MAX_PACKAGE_RAW_BYTES)?;
    check_data_root(&raw, want)?;
    Ok(raw)
}

/// The exact byte string a header's `data_root` commits to, from whichever
/// source the header names (inline blob or package joints). Every returned
/// byte string has been checked against `data_root`.
pub fn committed_frame_bytes<H: HubClient>(
    hub: &H,
    data: &serde_json::Value,
) -> Result<Vec<u8>, WatchError> {
    check_header_shape(data)?;
    if data.get("packages").is_some() {
        assemble_frames(hub, data)
    } else {
        inline_frame_bytes(data)
    }
}

/// Strict frame split over the committed bytes (B11, #47): valid UTF-8,
/// frames separated by exactly one LF, no empty frame (so no leading,
/// trailing or doubled LF) and no CR anywhere. Anything else is rejected
/// instead of being normalised, so every implementation reaches the same
/// verdict on the same committed bytes. A frame may span a package boundary:
/// only the concatenation matters.
pub fn parse_committed_frames(raw: &[u8]) -> Result<Vec<String>, SettleError> {
    let text = std::str::from_utf8(raw).map_err(|_| SettleError::RootMismatch)?;
    if text.is_empty() || text.contains('\r') {
        return Err(SettleError::RootMismatch);
    }
    let frames: Vec<String> = text.split('\n').map(str::to_string).collect();
    if frames.iter().any(|f| f.is_empty()) {
        return Err(SettleError::RootMismatch);
    }
    Ok(frames)
}

/// Rebuild a [`Batch`] from a header plus the exact committed frame bytes
/// returned by [`committed_frame_bytes`].
pub fn batch_from_committed(data: &serde_json::Value, raw: &[u8]) -> Result<Batch, SettleError> {
    if data.get("units").is_some() {
        return Err(SettleError::RootMismatch);
    }
    // R2-R-2/R2-R-5: frame count must equal the header's unit_count (and a
    // batch's legal maximum) BEFORE the bytes are split and parsed.
    let n_frames = raw.iter().filter(|b| **b == b'\n').count() as u64 + 1;
    match header_unit_count(data) {
        Some(n) if n == n_frames && n <= minuend_types::BATCH_MAX_UNITS as u64 => {}
        _ => return Err(SettleError::RootMismatch),
    }
    let frames = parse_committed_frames(raw)?;
    minuend_settle::batch_from_frames(data, &frames)
}

/// Replay a posted batch against the running engine and assert it reproduces
/// the committed roots. On success the engine is advanced to the batch's
/// state (so the caller can replay `h+1` with `engine.state.state_root()` as
/// its prev root). Any failure is a real root mismatch. Inline headers only;
/// multi-package callers use [`committed_frame_bytes`] +
/// [`batch_from_committed`] and call `validate_against` directly.
pub fn replay_and_check(
    da: &DaUnit,
    prev_root: [u8; 32],
    engine: &mut Engine,
) -> Result<(), SettleError> {
    let batch = batch_from_data(&da.data)?;
    batch.validate_against(prev_root, engine)
}

/// R2-R-2 / R3-R-1: largest decompressed size accepted for ONE package (or
/// an inline `frames_blob`), and for all packages of one height together.
/// These are the producer's own limits (`minuend_settle` cuts packages on
/// raw size and refuses to export a batch above the per-height cap;
/// `obyte-local/batch_frames.js` enforces the same values before posting),
/// so an honest batch is never refused for size while a gzip bomb is still
/// cut off early.
pub use minuend_settle::{MAX_COMMITTED_RAW_BYTES, MAX_PACKAGE_RAW_BYTES};
/// R2-R-2: a header can list at most one package per unit, and a batch
/// carries at most `BATCH_MAX_UNITS` units.
pub const MAX_PACKAGES: usize = minuend_types::BATCH_MAX_UNITS as usize;

fn header_unit_count(data: &serde_json::Value) -> Option<u64> {
    data.get("unit_count").and_then(|v| v.as_u64())
}

/// Unbounded legacy helper kept for API compatibility; now bounded by
/// [`MAX_PACKAGE_RAW_BYTES`] and single-member (see [`gunzip_bounded`]).
pub fn gunzip_blob(gz: &[u8]) -> Result<Vec<u8>, WatchError> {
    gunzip_bounded(gz, MAX_PACKAGE_RAW_BYTES)
}

/// R2-R-2 / R2-R-15: decompress exactly ONE gzip member, refusing output
/// beyond `cap` bytes (gzip bomb) and any byte after the member (a second
/// member or trailing garbage). Node's `gunzipSync` would decode a
/// concatenated `gzip(A)||gzip(B)` as `A||B` while flate2's `GzDecoder`
/// yields only `A`; rejecting the shape makes every implementation reach
/// the same verdict on the same committed bytes.
pub fn gunzip_bounded(gz: &[u8], cap: usize) -> Result<Vec<u8>, WatchError> {
    use flate2::bufread::GzDecoder;
    use std::io::Read;
    let mut dec = GzDecoder::new(gz);
    let mut out = Vec::new();
    (&mut dec)
        .take(cap as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| WatchError::BindingMismatch("package_blob not gzip".into()))?;
    if out.len() > cap {
        return Err(WatchError::BindingMismatch(format!(
            "package decompresses beyond the {cap}-byte cap"
        )));
    }
    if !dec.into_inner().is_empty() {
        return Err(WatchError::BindingMismatch(
            "package_blob has bytes after the gzip member (multi-member gzip is not accepted)"
                .into(),
        ));
    }
    Ok(out)
}

/// Rebuild a [`Batch`] from a single-package temp_data header (scalars plus
/// inline `frames_blob` = base64(gzip(frames))). `data_root` is mandatory
/// and always checked over the exact gunzipped bytes; a header that also
/// (or only) lists `packages` is rejected here — multi-package data goes
/// through [`committed_frame_bytes`]. Legacy `units`-array headers are
/// rejected.
pub fn batch_from_data(data: &serde_json::Value) -> Result<Batch, SettleError> {
    let raw = inline_frame_bytes(data).map_err(|_| SettleError::RootMismatch)?;
    batch_from_committed(data, &raw)
}

/// Locate the inline `temp_data` payload inside a hub-returned joint. The
/// joint shape varies (top-level `messages` vs nested under `unit.messages`),
/// so both are probed.
fn extract_temp_data(joint: &serde_json::Value) -> Option<serde_json::Value> {
    let messages = joint
        .get("messages")
        .or_else(|| joint.get("unit").and_then(|u| u.get("messages")))?;
    let arr = messages.as_array()?;
    for m in arr {
        if m.get("app").and_then(|a| a.as_str()) == Some("temp_data") {
            if let Some(data) = m.pointer("/payload/data") {
                return Some(data.clone());
            }
        }
    }
    None
}

/// R2-R-1: the per-height fields the rollup AA stores from the submit
/// unit's `data` message (`trigger.data.<key>` -> state var `<prefix><h>`).
/// The vault pays from these roots, so the DA header the watcher replays
/// must carry exactly the same values.
pub const COMMITTED_ROOT_FIELDS: &[(&str, &str)] = &[
    ("state_root", "state_root_"),
    ("aa_root", "aa_root_"),
    ("aa_forest", "aa_forest_"),
    ("prev_state_hash", "prev_"),
    ("wit_root", "wit_root_"),
    ("trace_root", "trace_root_"),
    ("units_root", "units_root_"),
    ("units_set_root", "units_set_root_"),
    ("ops_root", "ops_root_"),
    ("fills_root", "fills_root_"),
    ("unit_count", "unit_count_"),
    ("wit_count", "wit_count_"),
    ("fill_count", "fill_count_"),
];

/// R2-R-1: per-height fields the DA-binding rollup AA (fix/47-r2-aa, see
/// `work/r2-da-binding.md`) additionally stores. Compared whenever the AA
/// has them; a rollup without them (pre-binding deployment) still gets the
/// full field-by-field comparison above.
pub const BINDING_ROOT_FIELDS: &[(&str, &str)] = &[
    ("da_bind", "da_bind_"),
    ("data_root", "data_root_"),
    ("counts_root", "counts_root_"),
];

/// Domain tag of the DA binding hash.
pub const DA_BIND_DOMAIN: &str = "minuend-da-v1";

/// R2-R-1: `da_bind` = hex(sha256(join('|', [domain, chain_id, height,
/// prev_state_hash, state_root, aa_root, wit_root, trace_root, units_root,
/// units_set_root, ops_root, fills_root, counts_root, unit_count,
/// wit_count, fill_count, assertion_version, data_root]))), integers in
/// plain decimal, strings verbatim — recomputed here from the DA header.
/// `None` when the header lacks a field.
pub fn da_bind_from_header(header: &serde_json::Value) -> Option<String> {
    use sha2::{Digest, Sha256};
    const KEYS: [&str; 17] = [
        "chain_id",
        "height",
        "prev_state_hash",
        "state_root",
        "aa_root",
        "wit_root",
        "trace_root",
        "units_root",
        "units_set_root",
        "ops_root",
        "fills_root",
        "counts_root",
        "unit_count",
        "wit_count",
        "fill_count",
        "assertion_version",
        "data_root",
    ];
    let mut parts = vec![DA_BIND_DOMAIN.to_string()];
    for k in KEYS {
        parts.push(header.get(k).and_then(canon)?);
    }
    Some(hex::encode(Sha256::digest(parts.join("|").as_bytes())))
}

/// R2-R-1: fields the AA gates on (or that ride the submit for indexers)
/// but does not store per height; compared against the submit `data`
/// message only. `counts_root`/`validity_proof_hash`/`perp_burned` are
/// compared when the submit carries them.
const SUBMIT_ONLY_FIELDS: &[&str] = &["chain_id", "height", "assertion_version"];
const SUBMIT_OPTIONAL_FIELDS: &[&str] = &[
    "counts_root",
    "validity_proof_hash",
    "perp_burned",
    "da_bind",
    "data_root",
];

/// Canonical text of a scalar JSON value for cross-source comparison
/// (hub state vars may come back as numbers or strings).
fn canon(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Some(u.to_string())
            } else if let Some(i) = n.as_i64() {
                Some(i.to_string())
            } else {
                n.as_f64().map(|f| {
                    if f.fract() == 0.0 && f.abs() < 9.0e15 {
                        format!("{}", f as i64)
                    } else {
                        f.to_string()
                    }
                })
            }
        }
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// The header's value for a committed field (`aa_forest` is the
/// concatenation of `aa_shard_roots`, exactly as the poster builds it).
fn header_field(header: &serde_json::Value, key: &str) -> Option<String> {
    if key == "aa_forest" {
        if let Some(f) = header.get("aa_forest").and_then(canon) {
            return Some(f);
        }
        let roots = header.get("aa_shard_roots")?.as_array()?;
        let mut out = String::new();
        for r in roots {
            out.push_str(r.as_str()?);
        }
        return Some(out);
    }
    header.get(key).and_then(canon)
}

fn compare_field(
    out: &mut Vec<String>,
    source: &str,
    key: &str,
    header: Option<String>,
    onchain: Option<String>,
) {
    if header.is_none() || header != onchain {
        out.push(format!(
            "{source} {key}={} but DA header {key}={}",
            onchain.as_deref().unwrap_or("<absent>"),
            header.as_deref().unwrap_or("<absent>")
        ));
    }
}

/// R2-R-1: the submit trigger's `data` message inside the (hash-verified)
/// DA joint — the exact `trigger.data` the rollup AA stored.
pub fn extract_submit_data(joint: &serde_json::Value) -> Option<serde_json::Value> {
    let messages = joint
        .get("messages")
        .or_else(|| joint.get("unit").and_then(|u| u.get("messages")))?;
    for m in messages.as_array()? {
        if m.get("app").and_then(|a| a.as_str()) == Some("data") {
            if let Some(p) = m.get("payload") {
                if p.get("submit").is_some() {
                    return Some(p.clone());
                }
            }
        }
    }
    None
}

/// R2-R-1: compare every committed field of the submit `data` message
/// (`trigger.data`) with the DA header the watcher replays. Returns the
/// list of mismatches (empty = bound). The replay proves the HEADER honest;
/// only this comparison carries that verdict over to the roots the AA
/// stored and the vault pays from.
pub fn check_header_against_submit(
    header: &serde_json::Value,
    submit: &serde_json::Value,
    height: u64,
) -> Vec<String> {
    let mut out = Vec::new();
    for (key, _) in COMMITTED_ROOT_FIELDS {
        compare_field(
            &mut out,
            "submit data",
            key,
            header_field(header, key),
            submit.get(*key).and_then(canon),
        );
    }
    for key in SUBMIT_ONLY_FIELDS {
        compare_field(
            &mut out,
            "submit data",
            key,
            header_field(header, key),
            submit.get(*key).and_then(canon),
        );
    }
    for key in SUBMIT_OPTIONAL_FIELDS {
        if let Some(v) = submit.get(*key) {
            compare_field(
                &mut out,
                "submit data",
                key,
                header_field(header, key),
                canon(v),
            );
        }
    }
    if header.get("height").and_then(|v| v.as_u64()) != Some(height) {
        out.push(format!(
            "DA header height {:?} is not the watched height {height}",
            header.get("height")
        ));
    }
    out
}

/// R2-R-1: read the roots the rollup AA actually stored for `height`.
pub fn read_committed_state<H: HubClient>(
    hub: &H,
    rollup: &str,
    height: u64,
) -> Result<std::collections::BTreeMap<String, serde_json::Value>, WatchError> {
    let mut out = std::collections::BTreeMap::new();
    for (key, prefix) in COMMITTED_ROOT_FIELDS
        .iter()
        .chain(BINDING_ROOT_FIELDS)
        .chain(&[("da_hash", "da_hash_")])
    {
        let v = hub
            .get_aa_state_var(rollup, &format!("{prefix}{height}"))
            .map_err(WatchError::HubUnavailable)?;
        if let Some(v) = v {
            out.insert(key.to_string(), v);
        }
    }
    Ok(out)
}

/// R2-R-1: compare the AA's stored per-height roots with the DA header.
pub fn check_header_against_state(
    header: &serde_json::Value,
    state: &std::collections::BTreeMap<String, serde_json::Value>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (key, prefix) in COMMITTED_ROOT_FIELDS {
        compare_field(
            &mut out,
            &format!("AA state {prefix}<h>:"),
            key,
            header_field(header, key),
            state.get(*key).and_then(canon),
        );
    }
    // Binding AA: every binding var it stores must match the header too.
    for (key, prefix) in BINDING_ROOT_FIELDS {
        if let Some(v) = state.get(*key) {
            compare_field(
                &mut out,
                &format!("AA state {prefix}<h>:"),
                key,
                header_field(header, key),
                canon(v),
            );
        }
    }
    let bound = state.contains_key("da_bind") || header.get("da_bind").is_some();
    if bound {
        for (key, prefix) in BINDING_ROOT_FIELDS {
            if !state.contains_key(*key) {
                out.push(format!(
                    "AA state {prefix}<h> missing (binding AA expected)"
                ));
            }
        }
        // The header's own da_bind must be the hash of its own fields.
        match (da_bind_from_header(header), header_field(header, "da_bind")) {
            (Some(re), Some(hd)) if re == hd => {}
            (re, hd) => out.push(format!(
                "DA header da_bind={} but recomputed from its fields={}",
                hd.as_deref().unwrap_or("<absent>"),
                re.as_deref().unwrap_or("<incomplete header>")
            )),
        }
    }
    out
}

/// R2-R-1: the DA joint must carry exactly one `temp_data` message, and its
/// data hash must be the one the binding AA stored (`da_hash_<h>`, base64)
/// and must hash the header we decoded.
pub fn check_temp_data_hash(
    joint: &serde_json::Value,
    header: &serde_json::Value,
    stored_da_hash: Option<&serde_json::Value>,
) -> Vec<String> {
    use base64::Engine as _;
    let mut out = Vec::new();
    let msgs: Vec<&serde_json::Value> = joint
        .get("messages")
        .or_else(|| joint.get("unit").and_then(|u| u.get("messages")))
        .and_then(|m| m.as_array())
        .map(|a| {
            a.iter()
                .filter(|m| m.get("app").and_then(|x| x.as_str()) == Some("temp_data"))
                .collect()
        })
        .unwrap_or_default();
    if msgs.len() != 1 {
        out.push(format!(
            "DA unit carries {} temp_data messages (exactly one required)",
            msgs.len()
        ));
        return out;
    }
    let Some(stored) = stored_da_hash else {
        return out; // pre-binding rollup: nothing stored to compare
    };
    let stored = canon(stored).unwrap_or_default();
    let carried = msgs[0]
        .pointer("/payload/data_hash")
        .and_then(canon)
        .unwrap_or_default();
    if carried != stored {
        out.push(format!(
            "AA state da_hash_<h>={stored} but temp_data payload.data_hash={carried}"
        ));
    }
    // ocore carries base64; accept the hex spelling too.
    let recomputed = std::panic::catch_unwind(|| obyte_hash::get_data_hash(header)).ok();
    let matches = recomputed.is_some_and(|h| {
        base64::engine::general_purpose::STANDARD.encode(h) == stored || hex::encode(h) == stored
    });
    if !matches {
        out.push(format!(
            "AA state da_hash_<h>={stored} but the DA header hashes to {}",
            recomputed
                .map(|h| base64::engine::general_purpose::STANDARD.encode(h))
                .unwrap_or_else(|| "<unhashable>".into())
        ));
    }
    out
}

/// R2-R-1: full binding check for a DA unit whose unit hash has already
/// been verified ([`verify_da_binding`]): the header must equal the submit
/// `data` message of the same unit AND the roots stored in the rollup AA.
/// `Err` carries a human-readable mismatch list; a hub transport failure is
/// `Ok(None)`-equivalent for the caller (`HubUnavailable`).
pub fn check_committed_roots<H: HubClient>(
    hub: &H,
    rollup: &str,
    da: &DaUnit,
) -> Result<(), WatchError> {
    let submit = extract_submit_data(&da.joint).ok_or_else(|| {
        WatchError::BindingMismatch("DA unit carries no submit data message".into())
    })?;
    let mut problems = check_header_against_submit(&da.data, &submit, da.height);
    let state = read_committed_state(hub, rollup, da.height)?;
    problems.extend(check_header_against_state(&da.data, &state));
    problems.extend(check_temp_data_hash(
        &da.joint,
        &da.data,
        state.get("da_hash"),
    ));
    if problems.is_empty() {
        Ok(())
    } else {
        Err(WatchError::BindingMismatch(format!(
            "ASSERTION/DA MISMATCH: {}",
            problems.join("; ")
        )))
    }
}

/// R2-R-9: load the watcher's replay checkpoint (newest snapshot in `dir`)
/// as a replay engine: the replayed state plus the DAG anchors it needs to
/// link the next batch's parents. `Ok(None)` = no checkpoint (genesis).
/// The engine stays ephemeral (`store_dir = None`): the watcher never
/// writes the producer's gov-nonce WAL.
///
/// R3-R-7: when `dir` holds checkpoint files but NONE of them can be loaded
/// (a format-version bump, corruption) this is an error, never a silent
/// restart from genesis: the watcher would otherwise sit on h=1 (whose DA
/// is long purged) with only a generic stall alert.
pub fn load_checkpoint(dir: &std::path::Path) -> std::io::Result<Option<Engine>> {
    match minuend_state::persist::load_latest_with_anchors(dir)? {
        Some(loaded) => Ok(Some(engine_from_snapshot(loaded))),
        None => {
            let heights = minuend_state::persist::snapshot_heights(dir)?;
            if heights.is_empty() {
                Ok(None)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "{} holds {} checkpoint file(s) (newest h={}) but none can be loaded \
                         (snapshot format v{} expected, or corrupt): refusing to restart from \
                         genesis silently. Import a trusted chainstate.<h>.snap of the current \
                         format into the state dir, or move the unreadable files away to \
                         replay from genesis on purpose",
                        dir.display(),
                        heights.len(),
                        heights[0],
                        minuend_state::persist::SNAPSHOT_FORMAT_VERSION
                    ),
                ))
            }
        }
    }
}

fn engine_from_snapshot(loaded: minuend_state::persist::LoadedSnapshot) -> Engine {
    let (_, state, anchors) = loaded;
    let mut engine = Engine::new();
    engine.state = state;
    for a in anchors {
        let id = minuend_types::UnitId(a);
        engine.dag.mark_ancestor_known(id);
        engine.recent_units.push_back(id);
    }
    engine
}

/// R3-R-2: the checkpoint of exactly `height` (`Ok(None)` if absent).
pub fn load_checkpoint_at(dir: &std::path::Path, height: u64) -> std::io::Result<Option<Engine>> {
    Ok(minuend_state::persist::load_snapshot_at(dir, height)?.map(engine_from_snapshot))
}

/// R2-R-9: persist the engine after a height replayed cleanly. Only
/// replay-verified heights are ever checkpointed.
pub fn save_checkpoint(
    dir: &std::path::Path,
    engine: &Engine,
) -> std::io::Result<std::path::PathBuf> {
    save_checkpoint_retaining(dir, engine, u64::MAX)
}

/// R3-R-2: persist the engine and keep every checkpoint at or above
/// `retain_from` (the chain's `last_finalized`): an accepted height can
/// still be judged fraudulent (by another challenger, e.g. P-omit) and be
/// re-submitted until it finalizes, and the watcher must then rewind to
/// the height below it.
pub fn save_checkpoint_retaining(
    dir: &std::path::Path,
    engine: &Engine,
    retain_from: u64,
) -> std::io::Result<std::path::PathBuf> {
    let anchors: Vec<[u8; 32]> = engine.recent_units.iter().map(|u| u.0).collect();
    minuend_state::persist::save_snapshot_retaining(dir, &engine.state, &anchors, retain_from)
}

/// R3-R-2: what the rollup AA says right now about the heights the watcher
/// already accepted.
#[derive(Clone, Debug, Default)]
pub struct ChainView {
    pub last_submitted: u64,
    pub last_finalized: u64,
    /// `frozen_<last_submitted>`; 2 = judged fraudulent, awaiting re-submit.
    pub frozen_at_last_submitted: u64,
    /// Current `da_unit_<h>` for the accepted, not yet final heights
    /// (`None` = no longer set).
    pub da_units: std::collections::BTreeMap<u64, Option<String>>,
}

/// R3-R-2: the height the watcher must rewind its engine to, if any. The
/// replay already accepted heights `..=processed_upto`, recording the
/// `da_unit` it replayed for each in `accepted`. A height is dead when the
/// AA rolled `last_submitted` below it (a verdict lands `last_submitted` on
/// the failed height with `frozen = 2`; everything above is overwritten by
/// later submits) or when its `da_unit_<h>` now names another unit (it was
/// re-submitted). Returns `Some(t)` with `t < processed_upto` when heights
/// `t+1..=processed_upto` must be replayed again from the checkpoint at
/// `t`.
pub fn rewind_target(
    processed_upto: u64,
    accepted: &std::collections::BTreeMap<u64, String>,
    view: &ChainView,
) -> Option<u64> {
    let live_top = if view.frozen_at_last_submitted == 2 {
        view.last_submitted.saturating_sub(1)
    } else {
        view.last_submitted
    };
    let mut target = processed_upto.min(live_top);
    for (h, cur) in &view.da_units {
        if *h > target {
            break;
        }
        // R4-R-4: an empty / missing `da_unit_<h>` is "unknown" (a hub
        // hiccup), never "re-submitted": a verdict does not clear it and a
        // re-submission overwrites it with the new unit.
        let Some(cur) = cur.as_deref().filter(|c| !c.is_empty()) else {
            continue;
        };
        if let Some(seen) = accepted.get(h) {
            if cur != seen.as_str() {
                target = h.saturating_sub(1);
                break;
            }
        }
    }
    // R4-R-4: the AA can never invalidate a finalized height, so a view
    // that points below `last_finalized` is wrong; never rewind below it
    // on these readings. (A finalized height replaced before we looked is
    // caught by the root comparison, R4-R-6, which verifies the target
    // checkpoint against the chain first.)
    let target = target.max(view.last_finalized);
    (target < processed_upto).then_some(target)
}

/// R4-R-4: sanity-check one round's `last_submitted` / `last_finalized`
/// readings before anything acts on them. `None` = the var was missing,
/// empty or not a number. `known_lf` is the highest `last_finalized` seen
/// so far (finalization never goes backwards); `processed_upto` the last
/// replay-verified height. Returns the readings to use, or `Err(reason)`
/// when the round must be skipped (no rewind, no deletion).
pub fn sane_chain_readings(
    last_submitted: Option<u64>,
    last_finalized: Option<u64>,
    known_lf: u64,
    processed_upto: u64,
) -> Result<(u64, u64), String> {
    let ls = match last_submitted {
        Some(v) => v,
        None if processed_upto == 0 && known_lf == 0 => 0,
        None => {
            return Err(format!(
                "hub returned no last_submitted although h={processed_upto} was already \
                 verified: treating the reading as unknown"
            ))
        }
    };
    // `last_finalized` is legitimately absent before the first finalization.
    let lf = match last_finalized {
        Some(v) => v,
        None if known_lf == 0 => 0,
        None => {
            return Err(format!(
                "hub returned no last_finalized although h={known_lf} already finalized"
            ))
        }
    };
    if ls == 0 && (processed_upto > 0 || known_lf > 0) {
        return Err(format!(
            "hub reports last_submitted=0 although h={} was already verified/finalized",
            processed_upto.max(known_lf)
        ));
    }
    if lf < known_lf {
        return Err(format!(
            "hub reports last_finalized={lf} below the already seen {known_lf}"
        ));
    }
    if ls < lf {
        return Err(format!(
            "hub reports last_submitted={ls} below last_finalized={lf}"
        ));
    }
    Ok((ls, lf))
}

/// R5-R-4: is a `last_submitted` reading below the last replay-verified
/// height self-contradictory? The rollup AA lowers `last_submitted` only by
/// a verdict, which sets `frozen_<ls> = 2`; a re-submission of the judged
/// height clears the marker but writes a NEW `da_unit_<ls>`. So
/// `ls < processed_upto` with `frozen_<ls> != 2` is genuine only when
/// `da_unit_<ls>` now names another unit than the one we replayed; with
/// the very unit we accepted it is a stale / lagging hub and the round
/// must be skipped (no rewind, no `dead/` move, no re-replay). `ls == lf`
/// below our tip can never be genuine (a final height is not judged).
/// When we hold no record of `ls` (not accepted, e.g. right after a
/// restart) and `ls > lf`, the reading is not provably wrong: `false`.
pub fn regressed_tip_contradictory(
    last_submitted: u64,
    last_finalized: u64,
    processed_upto: u64,
    frozen_at_ls: u64,
    da_unit_at_ls: Option<&str>,
    accepted_at_ls: Option<&str>,
) -> bool {
    if last_submitted >= processed_upto || frozen_at_ls == 2 {
        return false;
    }
    if last_submitted <= last_finalized {
        return true;
    }
    match (da_unit_at_ls.filter(|d| !d.is_empty()), accepted_at_ls) {
        (Some(cur), Some(seen)) => cur == seen,
        // An empty / missing da_unit next to a known acceptance: unknown,
        // never "re-submitted" (R4-R-4) — skip the round.
        (None, Some(_)) => true,
        (_, None) => false,
    }
}

/// R4-R-6: whether the chain's `state_root_<h>` contradicts the engine's
/// root at `h`. Only a present, non-empty string root counts; a missing
/// value or a non-string (a verdict writes `0`) is "unknown", not a
/// divergence.
pub fn root_diverged(engine_root_hex: &str, chain_root: Option<&serde_json::Value>) -> bool {
    match chain_root.and_then(|v| v.as_str()) {
        Some(c) if !c.is_empty() => c != engine_root_hex,
        _ => false,
    }
}

/// R4-R-6: the newest checkpoint height below `below` whose own state
/// root (`mine(h)`, `None` = unreadable) equals the chain's
/// `state_root_<h>` (`chain(h)`). A hub error aborts the search (the
/// caller changes nothing). `Ok(None)` = no checkpoint matches.
pub fn pick_root_verified_checkpoint<M, C>(
    heights_newest_first: &[u64],
    below: u64,
    mut mine: M,
    mut chain: C,
) -> Result<Option<u64>, String>
where
    M: FnMut(u64) -> Option<String>,
    C: FnMut(u64) -> Result<Option<serde_json::Value>, String>,
{
    for &h in heights_newest_first.iter().filter(|h| **h < below) {
        let Some(root) = mine(h) else {
            continue;
        };
        let onchain = chain(h)?;
        if onchain.as_ref().and_then(|v| v.as_str()) == Some(root.as_str()) {
            return Ok(Some(h));
        }
    }
    Ok(None)
}

/// R4-R-8: the replay must not re-check `h` when it is the chain tip
/// `last_submitted` and that tip was judged fraudulent (`frozen = 2`): it
/// is awaiting re-submission, its `state_root` is zeroed while `da_unit`
/// still names the judged unit, so checking it only yields a false
/// BINDING MISMATCH and a false stall.
pub fn tip_awaiting_resubmission(h: u64, last_submitted: u64, frozen_at_tip: u64) -> bool {
    h == last_submitted && frozen_at_tip == 2
}

/// R4-R-7: name of the owner marker written into a temp checkpoint dir
/// (informational since R5-R-7: liveness is the lock below, not the pid).
pub const TEMP_DIR_OWNER_FILE: &str = "owner.pid";
/// R5-R-7: lock file a running temp-dir watcher holds an exclusive
/// `flock` on for its whole lifetime.
pub const TEMP_DIR_LOCK_FILE: &str = "owner.lock";

#[cfg(unix)]
mod flock_sys {
    use std::os::raw::c_int;
    pub const LOCK_EX: c_int = 2;
    pub const LOCK_NB: c_int = 4;
    extern "C" {
        pub fn flock(fd: c_int, operation: c_int) -> c_int;
    }
}

/// R5-R-7: try to take an exclusive, non-blocking `flock` on `f`.
/// `Ok(true)` = locked (released when `f` is closed), `Ok(false)` = held by
/// another open file description (a live owner, whatever its PID
/// namespace), `Err` = locking unsupported. `flock` locks belong to the
/// open file, so this also works across containers sharing `/tmp`.
#[cfg(unix)]
pub fn try_flock_exclusive(f: &std::fs::File) -> std::io::Result<bool> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: `flock(2)` on a valid, owned descriptor; no memory involved.
    let rc = unsafe { flock_sys::flock(f.as_raw_fd(), flock_sys::LOCK_EX | flock_sys::LOCK_NB) };
    if rc == 0 {
        return Ok(true);
    }
    let e = std::io::Error::last_os_error();
    if e.kind() == std::io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(e)
    }
}

/// R5-R-7: the lock a temp-dir watcher holds on its own checkpoint dir.
/// Dropping it (process exit, including a kill) releases the lock.
#[derive(Debug)]
pub struct TempDirLock {
    _file: std::fs::File,
}

/// R5-R-7: create `dir/`[`TEMP_DIR_LOCK_FILE`] (fresh, 0600) and lock it.
/// Fails if the file already exists or the lock cannot be taken.
#[cfg(unix)]
pub fn lock_temp_dir(dir: &std::path::Path) -> std::io::Result<TempDirLock> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join(TEMP_DIR_LOCK_FILE))?;
    if !try_flock_exclusive(&f)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "temp dir lock is held by another process",
        ));
    }
    Ok(TempDirLock { _file: f })
}

#[cfg(not(unix))]
pub fn lock_temp_dir(dir: &std::path::Path) -> std::io::Result<TempDirLock> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(dir.join(TEMP_DIR_LOCK_FILE))?;
    Ok(TempDirLock { _file: f })
}

/// R4-R-7: remove the checkpoints (live, dead-branch and half-written ones)
/// from a throw-away checkpoint dir; proofs and other files are kept (a
/// background challenge poster may still read them). The dir itself is
/// removed when nothing else is left in it.
pub fn clear_temp_checkpoints(dir: &std::path::Path) {
    use minuend_state::persist::{DEAD_SNAPSHOT_DIR, SNAPSHOT_PREFIX};
    let _ = std::fs::remove_dir_all(dir.join(DEAD_SNAPSHOT_DIR));
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let is_file = e.file_type().map(|t| t.is_file()).unwrap_or(false);
            if is_file
                && (name.starts_with(SNAPSHOT_PREFIX)
                    || name == TEMP_DIR_OWNER_FILE
                    || name == TEMP_DIR_LOCK_FILE)
            {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    // Fails (and keeps the dir) when proofs are still in it.
    let _ = std::fs::remove_dir(dir.join("proofs"));
    let _ = std::fs::remove_dir(dir);
}

/// R4-R-7 / R5-R-7: clear the checkpoints left in OUR earlier temp dirs
/// (same `prefix-…` name next to `own`, a real directory owned by the same
/// user) whose owner is gone. Liveness is the owner's exclusive `flock` on
/// [`TEMP_DIR_LOCK_FILE`]: a dir is swept only when WE can take that lock
/// (then no process anywhere holds it — PID namespaces do not matter, the
/// old `/proc/<pid>` check wiped live watchers of other containers). A dir
/// without a lock file (an older watcher version, or one still starting)
/// is left alone. Unix only; a no-op elsewhere. Returns the dirs cleared.
pub fn sweep_stale_temp_dirs(prefix: &str, own: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut cleared = Vec::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(own_meta) = std::fs::metadata(own) else {
            return cleared;
        };
        let base = own
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(std::env::temp_dir);
        let Ok(entries) = std::fs::read_dir(&base) else {
            return cleared;
        };
        let want = format!("{prefix}-");
        for e in entries.flatten() {
            let path = e.path();
            if path == own || !e.file_name().to_string_lossy().starts_with(&want) {
                continue;
            }
            // symlink_metadata: never follow a planted symlink.
            let Ok(m) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if !m.is_dir() || m.uid() != own_meta.uid() {
                continue;
            }
            let lock_path = path.join(TEMP_DIR_LOCK_FILE);
            match std::fs::symlink_metadata(&lock_path) {
                Ok(lm) if lm.is_file() && lm.uid() == own_meta.uid() => {}
                _ => continue,
            }
            let Ok(f) = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&lock_path)
            else {
                continue;
            };
            if !matches!(try_flock_exclusive(&f), Ok(true)) {
                continue; // a live owner holds it (or locking failed)
            }
            clear_temp_checkpoints(&path);
            drop(f);
            cleared.push(path);
        }
    }
    #[cfg(not(unix))]
    let _ = (prefix, own);
    cleared
}

/// R5-R-2: most vault-ledger reads the watcher makes for ONE height per
/// round (each is one hub round trip).
pub const MAX_VAULT_READS_PER_HEIGHT: usize = 64;
/// R5-R-2: wall-clock budget for one height's vault reads per round.
pub const VAULT_READ_BUDGET_SECS: u64 = 60;
/// R5-R-2: reads stop this long before the challenge-posting deadline so
/// the proof can still be built and posted.
pub const VAULT_READ_DEADLINE_RESERVE_SECS: u64 = 300;

/// R5-R-2: per-round cache of vault ledger reads, failures included
/// (`Err(())` = the read failed this round; it is not retried until the
/// next round). Create a fresh one each poll round.
pub type VaultReadCache = std::collections::HashMap<String, Result<Option<String>, ()>>;

/// R5-R-2: the vault ledger keys (`dep_`/`depp_<anchor_b64>`) a P-adr
/// proof of `batch` could actually need, i.e. the records the binding
/// predicate consults (`binding_violation` in prove.rs) — and nothing else:
///
/// * only units whose posted op string `ops[k]` is exactly the op of the
///   unit itself (`ops_element(unit_k)`), so the key is derived from the
///   unit's real op, never from operator-chosen `"o"` text;
/// * only `d:`/`D:` ops whose POSTED post tree (`leaf_trace[k]`) carries
///   the new binding `adr:{addr}:{acct}` of that very op (the only leaf
///   for which the record is consulted);
/// * not when a verified deposit evidence in the batch already
///   determines the record of that anchor.
///
/// R5 integration (vault `pperp_total` cap, R5-A-5): a verified PERP
/// evidence no longer determines the `depp_` record — the vault bounces a
/// deposit that would push its recorded PERP total past the cap, and the
/// joint of a bounced deposit still verifies. So a `D:` op whose anchor
/// carries a verified PERP evidence (the operator claims it applied it)
/// always needs the read — for P-adr and for the P-deposit backing arm
/// (`prove::deposit_unbacked_by_ledger`). Only the operator stamps
/// evidence, so this cannot be inflated by outsiders.
///
/// Deduplicated, in batch order.
pub fn vault_keys_needed(batch: &Batch) -> Vec<String> {
    let vault = minuend_settle::expected_vault();
    vault_keys_needed_with(batch, &|e| {
        minuend_settle::deposit_verify::verify_evidence(e, &vault, &minuend_types::PERP_ASSET)
            .is_ok()
    })
}

/// [`vault_keys_needed`] with the evidence check injected (`verified`).
fn vault_keys_needed_with(
    batch: &Batch,
    verified: &dyn Fn(&minuend_settle::DepositEvidence) -> bool,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (k, unit) in batch.units.iter().enumerate() {
        let (Some(op_str), Some(id)) = (batch.ops.get(k), batch.checkpoint.unit_ids.get(k)) else {
            continue;
        };
        if minuend_settle::deposit_key(&unit.op).is_none() {
            continue;
        }
        if *op_str != minuend_settle::ops_element(&hex::encode(id.0), &unit.op) {
            continue;
        }
        let Some(key) = prove::vault_key_of_op(op_str) else {
            continue;
        };
        let o: Vec<&str> = op_str.split(':').collect();
        if o.len() != 5 {
            continue;
        }
        let binding = format!("adr:{}:{}", o[3], o[1]);
        let binds = batch
            .leaf_trace
            .get(k)
            .is_some_and(|ls| ls.contains(&binding));
        let anchor_hex = minuend_settle::deposit_key(&unit.op)
            .map(|(a, _)| hex::encode(a))
            .unwrap_or_default();
        let is_gov = o[0] == "D";
        let evs: Vec<&minuend_settle::DepositEvidence> = batch
            .unit_evidences
            .iter()
            .flatten()
            .filter(|e| e.aa_unit.eq_ignore_ascii_case(&anchor_hex) && verified(e))
            .collect();
        // A verified PERP evidence cited by a `D:` op leaves the `depp_`
        // record open (cap bounce); any other verified evidence decides it.
        let perp_open = is_gov && evs.iter().any(|e| e.is_perp);
        let covered = !perp_open && !evs.is_empty();
        if !(binds || perp_open) || covered || out.contains(&key) {
            continue;
        }
        out.push(key);
    }
    out
}

/// R5-R-2: read the vault records for `keys` with hard bounds: at most
/// `max_reads` hub reads, none after `deadline` (unix seconds, `now()` is
/// the clock), and every outcome — failures too — cached in `cache` for
/// the rest of the round. Keys not read (budget, deadline, failure) stay
/// UNKNOWN (absent from the returned ledger), which only makes the proof
/// builder stay silent on the backing condition.
pub fn read_vault_ledger_bounded<H: HubClient>(
    hub: &H,
    vault: &str,
    keys: &[String],
    cache: &mut VaultReadCache,
    max_reads: usize,
    deadline: u64,
    now: &mut dyn FnMut() -> u64,
) -> prove::VaultLedger {
    let mut ledger = prove::VaultLedger::new();
    if vault.is_empty() {
        return ledger;
    }
    let mut reads = 0usize;
    for key in keys {
        let got = match cache.get(key) {
            Some(r) => r.clone(),
            None => {
                if reads >= max_reads || now() >= deadline {
                    continue;
                }
                reads += 1;
                let r = match hub.get_aa_state_var(vault, key) {
                    Ok(None) => Ok(None),
                    Ok(Some(v)) => v.as_str().map(|r| Some(r.to_string())).ok_or(()),
                    Err(_) => Err(()),
                };
                cache.insert(key.clone(), r.clone());
                r
            }
        };
        if let Ok(v) = got {
            ledger.insert(key.clone(), v);
        }
    }
    ledger
}

/// R3-R-6: create a fresh directory only the current user can enter, with
/// an unpredictable name, failing (never reusing) if the path exists. Used
/// for proofs (and in-run checkpoints) when no `--state-dir` is given, so a
/// local user cannot pre-create the directory and make every proof write
/// fail.
pub fn create_private_temp_dir(prefix: &str) -> std::io::Result<std::path::PathBuf> {
    use sha2::{Digest, Sha256};
    let base = std::env::temp_dir();
    for attempt in 0u32..16 {
        let mut seed = Vec::new();
        #[cfg(unix)]
        {
            use std::io::Read;
            if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
                let mut buf = [0u8; 32];
                if f.read_exact(&mut buf).is_ok() {
                    seed.extend_from_slice(&buf);
                }
            }
        }
        seed.extend_from_slice(&std::process::id().to_le_bytes());
        seed.extend_from_slice(&attempt.to_le_bytes());
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        seed.extend_from_slice(&nanos.to_le_bytes());
        let tag = hex::encode(&Sha256::digest(seed.as_slice())[..16]);
        let path = base.join(format!("{prefix}-{tag}"));
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        match b.create(&path) {
            Ok(()) => {
                // mkdir never follows a final symlink and fails on any
                // existing entry, so this directory is ours; pin the mode
                // regardless of the umask.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
                }
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not create a fresh private temp dir",
    ))
}

/// R2-R-9: first height to replay, from the `--from-height` flag and the
/// loaded checkpoint height. The engine cannot skip heights, so a start
/// above `checkpoint + 1` (or above 1 with no checkpoint) is refused up
/// front instead of producing a `PrevMismatch` stall on every height.
pub fn resolve_start_height(
    from_flag: Option<u64>,
    checkpoint: Option<u64>,
) -> Result<u64, String> {
    let next = checkpoint.map(|h| h + 1).unwrap_or(1);
    match from_flag {
        None => Ok(next),
        Some(f) if f <= next => Ok(next.max(f.max(1))),
        Some(f) => Err(match checkpoint {
            Some(h) => format!(
                "--from-height {f} is above the checkpoint (h={h}): the replay cannot skip \
                 heights; start at {next} or import a trusted chainstate.{}.snap into --state-dir",
                f - 1
            ),
            None => format!(
                "--from-height {f} needs the replayed state at height {}: pass --state-dir \
                 containing a trusted chainstate.{}.snap (no checkpoint found)",
                f - 1,
                f - 1
            ),
        }),
    }
}

/// R2-R-12: create (or reuse) a directory only the current user can enter.
pub fn ensure_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "proof dir is not a directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// R2-R-12: write a proof file that cannot be pre-planted or redirected:
/// a fresh name inside a private directory, created with `create_new`
/// (never follows or truncates an existing file / symlink) and mode 0600.
pub fn write_private_proof(
    dir: &std::path::Path,
    height: u64,
    pred: &str,
    data: &serde_json::Value,
) -> std::io::Result<std::path::PathBuf> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    ensure_private_dir(dir)?;
    let safe_pred: String = pred
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = dir.join(format!(
        "minuend-proof-{height}-{safe_pred}-{}-{nanos}-{}.json",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&path)?;
    f.write_all(serde_json::to_string(data).unwrap_or_default().as_bytes())?;
    f.sync_all()?;
    Ok(path)
}

pub use minuend_settle::obyte_hash;

#[cfg(test)]
mod tests {
    use super::*;

    // A tiny mock hub serving a fixed set of state vars + joints.
    struct MockHub {
        vars: std::collections::HashMap<String, serde_json::Value>,
        joints: std::collections::HashMap<String, serde_json::Value>,
    }

    impl HubClient for MockHub {
        fn get_aa_state_var(
            &self,
            _addr: &str,
            key: &str,
        ) -> Result<Option<serde_json::Value>, String> {
            Ok(self.vars.get(key).cloned())
        }
        fn get_joint(&self, unit_hash: &str) -> Result<serde_json::Value, String> {
            self.joints
                .get(unit_hash)
                .cloned()
                .ok_or_else(|| format!("404: no joint {unit_hash}"))
        }
    }

    // Build the on-chain temp_data message shape used by post_batch.js.
    fn temp_data_msg(data: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "app": "temp_data",
            "payload_location": "inline",
            "payload": {
                "data_length": 0,
                "data_hash": "x",
                "data": data.clone(),
            }
        })
    }

    // Encode a minimal joint wrapping a temp_data message. The exact unit hash
    // is not meaningful here; tests override the recorded hash to flip binding.
    fn joint_with(data: &serde_json::Value, unit_hash: &str) -> serde_json::Value {
        serde_json::json!({
            "unit": {
                "version": "1.0",
                "messages": [temp_data_msg(data)],
                "unit": unit_hash,
            },
            "messages": [temp_data_msg(data)],
        })
    }

    fn package_fixture(raw_packages: &[Vec<u8>]) -> (serde_json::Value, MockHub) {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};

        let mut all_raw = Vec::new();
        let mut hashes = Vec::new();
        let mut joints = std::collections::HashMap::new();
        for raw in raw_packages {
            let hash = hex::encode(Sha256::digest(raw));
            let blob =
                base64::engine::general_purpose::STANDARD.encode(minuend_settle::gzip_bytes(raw));
            let joint = serde_json::json!({
                "messages": [{
                    "app": "temp_data",
                    "payload": {"data": {"package_blob": blob}},
                }],
            });
            hashes.push(serde_json::Value::String(hash.clone()));
            joints.insert(hash, joint);
            all_raw.extend_from_slice(raw);
        }
        let root = hex::encode(Sha256::digest(&all_raw));
        (
            serde_json::json!({"packages": hashes, "data_root": root}),
            MockHub {
                vars: Default::default(),
                joints,
            },
        )
    }

    #[test]
    fn extract_temp_data_finds_inline_payload() {
        let data = serde_json::json!({"height": 1, "state_root": "aa"});
        let joint = joint_with(&data, "u1");
        let got = extract_temp_data(&joint).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn fetch_da_unit_missing_returns_none() {
        let hub = MockHub {
            vars: Default::default(),
            joints: Default::default(),
        };
        assert!(fetch_da_unit(&hub, "vault", 9).unwrap().is_none());
    }

    #[test]
    fn fetch_da_unit_no_temp_data_is_binding_mismatch() {
        // Joint carries submit data but no inline temp_data message.
        let joint = serde_json::json!({
            "unit": {
                "version": "1.0",
                "messages": [{ "app": "data", "payload": { "submit": 1, "height": 1 } }],
                "unit": "u-no-td",
            },
            "messages": [{ "app": "data", "payload": { "submit": 1, "height": 1 } }],
        });
        let hub = MockHub {
            vars: std::collections::HashMap::from([(
                "da_unit_1".into(),
                serde_json::json!("u-no-td"),
            )]),
            joints: std::collections::HashMap::from([("u-no-td".into(), joint)]),
        };
        let err = fetch_da_unit(&hub, "vault", 1).unwrap_err();
        assert!(
            matches!(err, WatchError::BindingMismatch(_)),
            "empty DA must be BindingMismatch, not HubUnavailable: {err:?}"
        );
        assert!(!matches!(err, WatchError::HubUnavailable(_)));
    }

    #[test]
    fn verify_da_binding_detects_tampered_recorded_hash() {
        // A joint's recomputed unit hash will not equal a bogus recorded hash.
        let data = serde_json::json!({"height": 1});
        let joint = joint_with(&data, "bogus-hash");
        let da = DaUnit {
            height: 1,
            unit_hash: "bogus-hash".to_string(),
            data,
            joint,
        };
        // get_unit_hash over a minimal joint may error or produce a hash that
        // differs from "bogus-hash"; either way it must not return Ok.
        assert!(verify_da_binding(&da).is_err());
    }

    // ---- real-batch replay tests (mirror crates/minuend-settle/examples/export_batch.rs) ----
    use ed25519_dalek::SigningKey;
    use minuend_dag::{genesis_id, sign_unit, unit_id, Op};
    use minuend_settle::Batch;
    use minuend_types::{
        account_id_from_pubkey, OrderType, Side, TimeInForce, BTC_USD, PRICE_SCALE, QTY_SCALE,
        USD_SCALE,
    };

    fn setup_engine() -> Engine {
        let mut eng = Engine::new();
        eng.state
            .markets
            .insert(BTC_USD, minuend_types::genesis_params());
        // Pre-fund the two accounts so a deposit-free Place batch passes intake.
        let mut a = minuend_state::Account::new(account_id_from_pubkey(
            &SigningKey::from_bytes(&[1u8; 32])
                .verifying_key()
                .to_bytes(),
        ));
        a.collateral = 10_000 * USD_SCALE as i128;
        eng.state.accounts.insert(a.id, a);
        let mut b = minuend_state::Account::new(account_id_from_pubkey(
            &SigningKey::from_bytes(&[2u8; 32])
                .verifying_key()
                .to_bytes(),
        ));
        b.collateral = 10_000 * USD_SCALE as i128;
        eng.state.accounts.insert(b.id, b);
        eng
    }

    fn build_batch_da(tamper_root: bool) -> DaUnit {
        let mut eng = setup_engine();
        let prev = eng.state.clone();
        let g = genesis_id();
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        let alice_id =
            account_id_from_pubkey(&SigningKey::from_bytes(&alice).verifying_key().to_bytes());
        let bob_id =
            account_id_from_pubkey(&SigningKey::from_bytes(&bob).verifying_key().to_bytes());
        let mut applied = Vec::new();
        let mut tip = g;

        let px = 100_000 * PRICE_SCALE as i64;
        let qty = QTY_SCALE;
        let ask = sign_unit(
            vec![tip],
            Op::Place {
                account: bob_id,
                market: BTC_USD,
                side: Side::Ask,
                typ: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: px,
                qty,
                client_seq: 1,
                isolated: false,
                margin: 0,
            },
            &bob,
        );
        tip = unit_id(&ask);
        applied.push(tip);
        eng.ingest(ask).unwrap();

        let bid = sign_unit(
            vec![tip],
            Op::Place {
                account: alice_id,
                market: BTC_USD,
                side: Side::Bid,
                typ: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: px,
                qty,
                client_seq: 1,
                isolated: false,
                margin: 0,
            },
            &alice,
        );
        tip = unit_id(&bid);
        applied.push(tip);
        eng.ingest(bid).unwrap();

        let batch = Batch::from_applied(&prev, &mut eng, &applied).expect("batch");
        let payload = batch.temp_data_payload();
        let mut data = payload.data.clone();
        if tamper_root {
            data["state_root"] = serde_json::json!(hex::encode([0xAAu8; 32]));
        }
        DaUnit {
            height: batch.checkpoint.height,
            unit_hash: String::new(),
            data,
            joint: serde_json::Value::Null,
        }
    }

    #[test]
    fn replay_and_check_accepts_good_batch() {
        let da = build_batch_da(false);
        let mut replay = setup_engine();
        let prev_root = replay.state.state_root();
        assert!(
            replay_and_check(&da, prev_root, &mut replay).is_ok(),
            "good batch must replay cleanly"
        );
    }

    #[test]
    fn replay_and_check_rejects_tampered_root() {
        let da = build_batch_da(true);
        let mut replay = setup_engine();
        let prev_root = replay.state.state_root();
        assert!(
            replay_and_check(&da, prev_root, &mut replay).is_err(),
            "tampered batch must not replay"
        );
    }
    /// B11 (#47): the multi-package assembler returns exactly the bytes the
    /// `data_root` covers — no parse-only LF insertion or LF de-duplication.
    #[test]
    fn assemble_frames_returns_exact_committed_bytes() {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        let frames = ["{\"u\":\"one\"}", "{\"u\":\"two-β\"}", "{\"u\":\"three\"}"];
        // Current producer shape: later packages start with LF.
        let raw1 = frames[0].as_bytes().to_vec();
        let raw2 = format!("\n{}\n{}", frames[1], frames[2]).into_bytes();
        let concat = [raw1.clone(), raw2.clone()].concat();
        let (header, hub) = package_fixture(&[raw1, raw2]);
        assert_eq!(header["data_root"], hex::encode(Sha256::digest(&concat)));
        let got = assemble_frames(&hub, &header).unwrap();
        assert_eq!(got, concat, "assembled bytes must be the committed bytes");
        assert_eq!(parse_committed_frames(&got).unwrap(), frames);

        // Wrong root, bad gzip → BindingMismatch.
        let bad = serde_json::json!({"packages": header["packages"].clone(), "data_root": "00".repeat(32)});
        assert!(matches!(
            assemble_frames(&hub, &bad),
            Err(WatchError::BindingMismatch(_))
        ));
        let not_gz = base64::engine::general_purpose::STANDARD.encode(b"not-gzip");
        let hub2 = MockHub {
            vars: Default::default(),
            joints: std::collections::HashMap::from([(
                header["packages"][0].as_str().unwrap().to_string(),
                serde_json::json!({"messages": [{"app": "temp_data", "payload": {"data": {"package_blob": not_gz}}}]}),
            )]),
        };
        let hdr2 = serde_json::json!({"packages": [header["packages"][0].clone()], "data_root": header["data_root"].clone()});
        assert!(matches!(
            assemble_frames(&hub2, &hdr2),
            Err(WatchError::BindingMismatch(_))
        ));
    }

    /// B11 (#47): the frame parser is strict over the committed bytes. Shapes
    /// the old normaliser silently repaired (missing boundary LF, doubled LF,
    /// trailing LF, CR) are now rejected, so no two different committed byte
    /// strings decode to the same batch by normalisation.
    #[test]
    fn parse_committed_frames_is_strict() {
        assert_eq!(
            parse_committed_frames(b"{\"a\":1}\n{\"b\":2}").unwrap(),
            vec!["{\"a\":1}".to_string(), "{\"b\":2}".to_string()]
        );
        for bad in [
            &b""[..],
            b"{\"a\":1}\n",
            b"\n{\"a\":1}",
            b"{\"a\":1}\n\n{\"b\":2}",
            b"{\"a\":1}\r\n{\"b\":2}",
            &[0xff, 0xfe][..],
        ] {
            assert!(
                parse_committed_frames(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    /// B11 (#47): `packages` next to an inline `frames_blob` used to switch
    /// off the inline `data_root` check. Every path now refuses that header,
    /// and an inline header's root is always verified.
    #[test]
    fn packages_key_no_longer_bypasses_inline_data_root() {
        let da = build_batch_da(false);
        assert!(batch_from_data(&da.data).is_ok());
        // Tampered root alone: rejected.
        let mut tampered = da.data.clone();
        tampered["data_root"] = serde_json::json!("00".repeat(32));
        assert!(batch_from_data(&tampered).is_err());
        // Tampered root + a `packages` key: still rejected (was accepted).
        let mut bypass = tampered.clone();
        bypass["packages"] = serde_json::json!([]);
        assert!(batch_from_data(&bypass).is_err());
        let hub = MockHub {
            vars: Default::default(),
            joints: Default::default(),
        };
        assert!(matches!(
            committed_frame_bytes(&hub, &bypass),
            Err(WatchError::BindingMismatch(_))
        ));
        // Even with a correct root, both sources at once is refused.
        let mut both = da.data.clone();
        both["packages"] = serde_json::json!([]);
        assert!(committed_frame_bytes(&hub, &both).is_err());
        // Missing data_root on an inline header is refused.
        let mut no_root = da.data.clone();
        no_root.as_object_mut().unwrap().remove("data_root");
        assert!(batch_from_data(&no_root).is_err());
    }

    /// Real batch through every producer shape: the inline blob, the current
    /// multi-package producer (LF-prefixed later packages), and a frame
    /// split across a package boundary all decode to the same batch from
    /// the exact committed bytes. The pre-#39 multi-package shape without a
    /// boundary LF is rejected (its committed bytes are not LF-separated).
    #[test]
    fn producer_package_formats_rebuild_a_complete_real_batch() {
        let da = build_batch_da(false);
        let expected = batch_from_data(&da.data).unwrap();
        let original = da.data["frames_blob"].as_str().unwrap();
        let original_raw = minuend_settle::decode_package_blob(original).unwrap();
        let frames = parse_committed_frames(&original_raw).unwrap();
        assert!(frames.len() >= 2, "fixture needs multiple frames");

        let multi = |raws: &[Vec<u8>]| -> (serde_json::Value, MockHub) {
            let (pkg_header, hub) = package_fixture(raws);
            let mut h = da.data.clone();
            h.as_object_mut().unwrap().remove("frames_blob");
            h["packages"] = pkg_header["packages"].clone();
            h["data_root"] = pkg_header["data_root"].clone();
            (h, hub)
        };

        // Current Rust producer: one frame per package.
        let new_blobs = minuend_settle::pack_frames_with_cap(&frames, 1);
        assert_eq!(new_blobs.len(), frames.len());
        let new_raws: Vec<_> = new_blobs
            .iter()
            .map(|b| minuend_settle::decode_package_blob(b).unwrap())
            .collect();
        let (h, hub) = multi(&new_raws);
        let raw = committed_frame_bytes(&hub, &h).unwrap();
        assert_eq!(raw, original_raw);
        assert_eq!(batch_from_committed(&h, &raw).unwrap(), expected);

        // A frame split mid-way across two packages: the concatenation is
        // what is committed and parsed, so it decodes identically.
        let cut = original_raw.len() / 2;
        let (h, hub) = multi(&[original_raw[..cut].to_vec(), original_raw[cut..].to_vec()]);
        let raw = committed_frame_bytes(&hub, &h).unwrap();
        assert_eq!(batch_from_committed(&h, &raw).unwrap(), expected);

        // Pre-#39 writer: no LF at the package boundary → rejected.
        let split = frames.len() / 2;
        let legacy = vec![
            frames[..split].join("\n").into_bytes(),
            frames[split..].join("\n").into_bytes(),
        ];
        let (h, hub) = multi(&legacy);
        let raw = committed_frame_bytes(&hub, &h).unwrap();
        assert!(batch_from_committed(&h, &raw).is_err());
    }

    // ---- round 2 of #47 ----

    fn gz(raw: &[u8]) -> Vec<u8> {
        minuend_settle::gzip_bytes(raw)
    }

    /// R2-R-2 / R2-R-15: bounded single-member gunzip.
    #[test]
    fn gunzip_is_bounded_and_single_member() {
        let ok = gz(b"hello");
        assert_eq!(gunzip_bounded(&ok, 5).unwrap(), b"hello");
        // Over the cap (a bomb in miniature): refused, not allocated.
        let bomb = gz(&vec![0u8; 1 << 20]);
        assert!(bomb.len() < 10_000);
        assert!(matches!(
            gunzip_bounded(&bomb, 4096),
            Err(WatchError::BindingMismatch(_))
        ));
        // Two members (Node gunzipSync would return both): refused.
        let two = [gz(b"A"), gz(b"B")].concat();
        assert!(gunzip_bounded(&two, 1024).is_err());
        // Trailing garbage after the member: refused.
        let mut trail = gz(b"A");
        trail.extend_from_slice(b"junk");
        assert!(gunzip_bounded(&trail, 1024).is_err());
        const { assert!(MAX_PACKAGE_RAW_BYTES <= MAX_COMMITTED_RAW_BYTES) };
    }

    /// R2-R-2: an inline `frames_blob` that decompresses beyond the cap is a
    /// BindingMismatch before `data_root` is even looked at, and the
    /// package list is bounded by the header's unit_count.
    #[test]
    fn oversized_inline_blob_and_package_list_are_refused() {
        use base64::Engine as _;
        let blob = base64::engine::general_purpose::STANDARD.encode(gz(&[b'x'; 16]));
        let hdr = serde_json::json!({"frames_blob": blob, "data_root": "00".repeat(32)});
        // sanity: normal size reaches the root check (and fails it)
        assert!(inline_frame_bytes(&hdr).is_err());
        let (mut header, hub) = package_fixture(&[b"{}".to_vec(), b"\n{}".to_vec()]);
        header["unit_count"] = serde_json::json!(1);
        let err = assemble_frames(&hub, &header).unwrap_err();
        assert!(format!("{err}").contains("packages"), "{err}");
        header["unit_count"] = serde_json::json!(2);
        assert!(assemble_frames(&hub, &header).is_ok());
    }

    /// R2-R-2/R2-R-5: the frame count must equal unit_count before parsing.
    #[test]
    fn frame_count_must_match_unit_count() {
        let da = build_batch_da(false);
        let raw = inline_frame_bytes(&da.data).unwrap();
        assert!(batch_from_committed(&da.data, &raw).is_ok());
        let mut wrong = da.data.clone();
        wrong["unit_count"] = serde_json::json!(da.data["unit_count"].as_u64().unwrap() + 1);
        assert!(batch_from_committed(&wrong, &raw).is_err());
        let mut none = da.data.clone();
        none.as_object_mut().unwrap().remove("unit_count");
        assert!(batch_from_committed(&none, &raw).is_err());
    }

    /// The submit `data` message exactly as obyte-local/post_batch.js
    /// builds it from the header.
    fn submit_from_header(h: &serde_json::Value) -> serde_json::Value {
        let forest: String = h["aa_shard_roots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap())
            .collect();
        let mut s = serde_json::json!({
            "submit": 1,
            "chain_id": h["chain_id"],
            "height": h["height"],
            "prev_state_hash": h["prev_state_hash"],
            "state_root": h["state_root"],
            "aa_root": h["aa_root"],
            "aa_forest": forest,
            "assertion_version": h["assertion_version"],
            "wit_root": h["wit_root"],
            "trace_root": h["trace_root"],
            "units_root": h["units_root"],
            "units_set_root": h["units_set_root"],
            "ops_root": h["ops_root"],
            "fills_root": h["fills_root"],
            "counts_root": h["counts_root"],
            "unit_count": h["unit_count"],
            "wit_count": h["wit_count"],
            "fill_count": h["fill_count"],
        });
        if let Some(p) = h.get("perp_burned") {
            s["perp_burned"] = p.clone();
        }
        s
    }

    fn state_from_submit(
        h: u64,
        submit: &serde_json::Value,
    ) -> std::collections::HashMap<String, serde_json::Value> {
        COMMITTED_ROOT_FIELDS
            .iter()
            .map(|(k, p)| (format!("{p}{h}"), submit[*k].clone()))
            .collect()
    }

    /// R2-R-1: honest DA + forged `wit_root` in the submit data (what the
    /// AA stores and the vault pays from) is now detected, both from the
    /// hash-verified joint's data message and from the AA state vars.
    #[test]
    fn forged_onchain_roots_are_detected_against_the_da_header() {
        let da = build_batch_da(false);
        let h = da.height;
        let header = da.data.clone();
        let submit = submit_from_header(&header);
        assert!(check_header_against_submit(&header, &submit, h).is_empty());
        let state: std::collections::BTreeMap<String, serde_json::Value> = COMMITTED_ROOT_FIELDS
            .iter()
            .map(|(k, _)| (k.to_string(), submit[*k].clone()))
            .collect();
        assert!(check_header_against_state(&header, &state).is_empty());

        // Every stored field is covered: forging any one is caught.
        for (k, _) in COMMITTED_ROOT_FIELDS {
            let mut forged = submit.clone();
            forged[*k] = match &submit[*k] {
                serde_json::Value::Number(n) => serde_json::json!(n.as_u64().unwrap() + 1),
                _ => serde_json::json!("A".repeat(44)),
            };
            let p = check_header_against_submit(&header, &forged, h);
            assert!(p.iter().any(|m| m.contains(k)), "{k}: {p:?}");
            let mut st = state.clone();
            st.insert(k.to_string(), forged[*k].clone());
            assert!(!check_header_against_state(&header, &st).is_empty(), "{k}");
        }
        for k in ["chain_id", "assertion_version", "height", "counts_root"] {
            let mut forged = submit.clone();
            forged[k] = serde_json::json!("x");
            assert!(
                !check_header_against_submit(&header, &forged, h).is_empty(),
                "{k}"
            );
        }
        // Numbers vs numeric strings from the hub compare equal.
        let mut st = state.clone();
        st.insert(
            "unit_count".into(),
            serde_json::json!(header["unit_count"].as_u64().unwrap() as f64),
        );
        assert!(check_header_against_state(&header, &st).is_empty());

        // End to end through the hub: joint with both messages + AA vars.
        let joint = serde_json::json!({"messages": [
            temp_data_msg(&header),
            {"app": "data", "payload": submit.clone()},
        ]});
        let mk = |vars| MockHub {
            vars,
            joints: Default::default(),
        };
        let du = |j: serde_json::Value| DaUnit {
            height: h,
            unit_hash: String::new(),
            data: header.clone(),
            joint: j,
        };
        let hub = mk(state_from_submit(h, &submit));
        assert!(check_committed_roots(&hub, "R", &du(joint.clone())).is_ok());
        let mut forged = submit.clone();
        forged["wit_root"] = serde_json::json!("B".repeat(44));
        let hub = mk(state_from_submit(h, &forged));
        let fj = serde_json::json!({"messages": [
            temp_data_msg(&header),
            {"app": "data", "payload": forged.clone()},
        ]});
        let err = check_committed_roots(&hub, "R", &du(fj)).unwrap_err();
        assert!(format!("{err}").contains("ASSERTION/DA MISMATCH"), "{err}");
        assert!(format!("{err}").contains("wit_root"), "{err}");
        // Honest joint but the AA state disagrees: still caught.
        let err = check_committed_roots(&hub, "R", &du(joint)).unwrap_err();
        assert!(format!("{err}").contains("AA state"), "{err}");
        // A DA unit without the submit data message is refused.
        let hub = mk(state_from_submit(h, &submit));
        let only_td = serde_json::json!({"messages": [temp_data_msg(&header)]});
        assert!(check_committed_roots(&hub, "R", &du(only_td)).is_err());
    }

    /// R2-R-9: the checkpoint round-trips the replayed state and the DAG
    /// anchors, and a watcher restarted from it replays the next height.
    #[test]
    fn checkpoint_restart_resumes_replay() {
        let dir = std::env::temp_dir().join(format!("minuend-watch-ckpt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(load_checkpoint(&dir).unwrap().is_none());
        let da = build_batch_da(false);
        let mut eng = setup_engine();
        let prev = eng.state.state_root();
        replay_and_check(&da, prev, &mut eng).unwrap();
        save_checkpoint(&dir, &eng).unwrap();
        let back = load_checkpoint(&dir).unwrap().unwrap();
        assert_eq!(back.state.state_root(), eng.state.state_root());
        assert_eq!(back.state.height, da.height);
        assert_eq!(back.recent_units, eng.recent_units);
        assert!(back.store_dir.is_none());
        assert_eq!(
            resolve_start_height(None, Some(back.state.height)),
            Ok(da.height + 1)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn start_height_resolution() {
        assert_eq!(resolve_start_height(None, None), Ok(1));
        assert_eq!(resolve_start_height(Some(1), None), Ok(1));
        assert!(resolve_start_height(Some(5), None).is_err());
        assert_eq!(resolve_start_height(Some(5), Some(4)), Ok(5));
        assert_eq!(resolve_start_height(Some(2), Some(4)), Ok(5));
        assert_eq!(resolve_start_height(None, Some(9)), Ok(10));
        assert!(resolve_start_height(Some(7), Some(4)).is_err());
    }

    /// R2-R-6/7: the consensus parent window equals the snapshot anchor
    /// ring, so a restored node knows exactly the parents any node accepts.
    #[test]
    fn parent_window_equals_snapshot_anchor_ring() {
        assert_eq!(
            minuend_dag::PARENT_WINDOW,
            minuend_state::persist::DAG_ANCHOR_LIMIT
        );
    }

    /// R2-R-12: proof files are fresh, private and never follow a planted
    /// symlink.
    #[test]
    fn proof_files_are_private_and_fresh() {
        let dir = std::env::temp_dir().join(format!("minuend-watch-proof-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = write_private_proof(&dir, 3, "wpin", &serde_json::json!({"x": 1})).unwrap();
        let b = write_private_proof(&dir, 3, "wpin", &serde_json::json!({"x": 2})).unwrap();
        assert_ne!(a, b);
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "{\"x\":1}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(&a).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600);
            let d = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(d, 0o700);
            // A name that already exists (e.g. a planted symlink) is never
            // opened: the writer only uses create_new on fresh names.
            let victim = dir.join("victim");
            std::fs::write(&victim, "keep").unwrap();
            let link = dir.join("planted");
            std::os::unix::fs::symlink(&victim, &link).unwrap();
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            assert!(o.open(&link).is_err());
            assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R2-R-1: golden vector shared with `daBindHash` in
    /// obyte-local/script_helpers.js on fix/47-r2-aa (computed with node).
    #[test]
    fn da_bind_matches_js_golden_vector() {
        let f = serde_json::json!({
            "chain_id": "minuend-v2", "height": 7,
            "prev_state_hash": "11".repeat(32), "state_root": "22".repeat(32),
            "aa_root": "33".repeat(32), "wit_root": "W".repeat(44),
            "trace_root": "T".repeat(44), "units_root": "U".repeat(44),
            "units_set_root": "S".repeat(44), "ops_root": "O".repeat(44),
            "fills_root": "F".repeat(44), "counts_root": "C".repeat(44),
            "unit_count": 2, "wit_count": 5, "fill_count": 1,
            "assertion_version": 2, "data_root": "44".repeat(32),
        });
        assert_eq!(
            da_bind_from_header(&f).unwrap(),
            "3e905c972e63147ccdf5a69d397fb87111364edef487a7c8428567743e540cf9"
        );
        let mut missing = f.clone();
        missing.as_object_mut().unwrap().remove("counts_root");
        assert!(da_bind_from_header(&missing).is_none());
    }

    /// R2-R-1 with the binding rollup AA: da_bind / data_root / counts_root
    /// / da_hash stored on chain must all agree with the DA header.
    #[test]
    fn binding_aa_vars_are_checked_against_the_header() {
        use base64::Engine as _;
        let da = build_batch_da(false);
        let h = da.height;
        let mut header = da.data.clone();
        header["da_bind"] = serde_json::json!(da_bind_from_header(&header).unwrap());
        let mut submit = submit_from_header(&header);
        submit["da_bind"] = header["da_bind"].clone();
        submit["data_root"] = header["data_root"].clone();
        let da_hash =
            base64::engine::general_purpose::STANDARD.encode(obyte_hash::get_data_hash(&header));
        let mut vars = state_from_submit(h, &submit);
        vars.insert(format!("da_bind_{h}"), header["da_bind"].clone());
        vars.insert(format!("data_root_{h}"), header["data_root"].clone());
        vars.insert(format!("counts_root_{h}"), header["counts_root"].clone());
        vars.insert(format!("da_hash_{h}"), serde_json::json!(da_hash));
        let mut td = temp_data_msg(&header);
        td["payload"]["data_hash"] = serde_json::json!(da_hash);
        let joint = serde_json::json!({"messages": [td.clone(), {"app": "data", "payload": submit.clone()}]});
        let du = |hd: &serde_json::Value, j: &serde_json::Value| DaUnit {
            height: h,
            unit_hash: String::new(),
            data: hd.clone(),
            joint: j.clone(),
        };
        let hub = |v: std::collections::HashMap<String, serde_json::Value>| MockHub {
            vars: v,
            joints: Default::default(),
        };
        check_committed_roots(&hub(vars.clone()), "R", &du(&header, &joint)).unwrap();

        // On-chain da_bind differs from the header's.
        let mut v = vars.clone();
        v.insert(format!("da_bind_{h}"), serde_json::json!("00".repeat(32)));
        assert!(check_committed_roots(&hub(v), "R", &du(&header, &joint)).is_err());
        // Header da_bind is not the hash of its own fields.
        let mut bad = header.clone();
        bad["da_bind"] = serde_json::json!("00".repeat(32));
        let p = check_header_against_state(&bad, &std::collections::BTreeMap::new());
        assert!(p.iter().any(|m| m.contains("recomputed")), "{p:?}");
        // Stored da_hash does not match the temp_data message.
        let mut v = vars.clone();
        v.insert(format!("da_hash_{h}"), serde_json::json!("AAAA"));
        assert!(check_committed_roots(&hub(v), "R", &du(&header, &joint)).is_err());
        // Two temp_data messages in the DA unit.
        let two =
            serde_json::json!({"messages": [td.clone(), td, {"app": "data", "payload": submit}]});
        let err = check_committed_roots(&hub(vars.clone()), "R", &du(&header, &two)).unwrap_err();
        assert!(format!("{err}").contains("temp_data messages"), "{err}");
        // A binding AA that lost a binding var is flagged.
        let mut v = vars;
        v.remove(&format!("counts_root_{h}"));
        assert!(check_committed_roots(&hub(v), "R", &du(&header, &joint)).is_err());
    }

    /// R3-R-7: checkpoint files that all fail to load are an explicit
    /// error, never a silent restart from genesis.
    #[test]
    fn unreadable_checkpoints_refuse_instead_of_genesis() {
        let dir = std::env::temp_dir().join(format!("minuend-watch-badck-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(
            load_checkpoint(&dir).unwrap().is_none(),
            "empty dir = genesis"
        );
        std::fs::write(dir.join("chainstate.7.snap"), b"\x05\0\0\0old-format").unwrap();
        let Err(err) = load_checkpoint(&dir) else {
            panic!("all-unreadable checkpoints must refuse");
        };
        assert!(err.to_string().contains("h=7"), "{err}");
        // One readable checkpoint is enough to resume.
        let mut eng = setup_engine();
        eng.state.height = 3;
        save_checkpoint(&dir, &eng).unwrap();
        assert_eq!(load_checkpoint(&dir).unwrap().unwrap().state.height, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R3-R-2: checkpoints of not-yet-final heights are retained, and an
    /// exact-height checkpoint loads for a rewind.
    #[test]
    fn retained_checkpoints_allow_rewind() {
        let dir = std::env::temp_dir().join(format!("minuend-watch-rw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut eng = setup_engine();
        for h in 1..=6u64 {
            eng.state.height = h;
            save_checkpoint_retaining(&dir, &eng, 2).unwrap();
        }
        let back = load_checkpoint_at(&dir, 2).unwrap().unwrap();
        assert_eq!(back.state.height, 2);
        assert_eq!(back.recent_units, eng.recent_units);
        assert!(
            load_checkpoint_at(&dir, 1).unwrap().is_none(),
            "below last_finalized"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R3-R-2: rewind decisions. Heights above a fraud verdict (or above a
    /// lowered `last_submitted`) and re-submitted heights are replayed
    /// again; an unchanged chain needs no rewind.
    #[test]
    fn rewind_target_detects_verdict_and_resubmission() {
        use std::collections::BTreeMap;
        let accepted: BTreeMap<u64, String> = (3..=8).map(|h| (h, format!("U{h}"))).collect();
        let view = |ls: u64, frozen: u64, changed: Option<u64>| ChainView {
            last_submitted: ls,
            last_finalized: 2,
            frozen_at_last_submitted: frozen,
            da_units: (3..=ls.min(8))
                .map(|h| {
                    let v = if Some(h) == changed {
                        format!("NEW{h}")
                    } else {
                        format!("U{h}")
                    };
                    (h, Some(v))
                })
                .collect(),
        };
        // Unchanged chain (and a chain that moved on) needs nothing.
        assert_eq!(rewind_target(8, &accepted, &view(8, 0, None)), None);
        assert_eq!(rewind_target(8, &accepted, &view(12, 0, None)), None);
        // Verdict on h=5: last_submitted lands on 5 with frozen=2, so 5..=8
        // are dead and the engine goes back to the state after 4.
        assert_eq!(rewind_target(8, &accepted, &view(5, 2, None)), Some(4));
        // Verdict on our own tip.
        assert_eq!(rewind_target(8, &accepted, &view(8, 2, None)), Some(7));
        // h=5 already re-submitted (frozen cleared, new da_unit), ls=5.
        assert_eq!(rewind_target(8, &accepted, &view(5, 0, Some(5))), Some(4));
        // Re-submitted and the chain already moved past our tip again.
        assert_eq!(rewind_target(8, &accepted, &view(12, 0, Some(5))), Some(4));
        // R4-R-4: a da_unit that disappeared (or reads empty) is unknown,
        // not changed: no rewind.
        let mut v = view(8, 0, None);
        v.da_units.insert(6, None);
        assert_eq!(rewind_target(8, &accepted, &v), None);
        v.da_units.insert(6, Some(String::new()));
        assert_eq!(rewind_target(8, &accepted, &v), None);
        // Heights the watcher never recorded are not judged.
        assert_eq!(
            rewind_target(8, &BTreeMap::new(), &view(8, 0, Some(5))),
            None
        );
    }

    /// R4-R-4: an empty `last_submitted` (or a view whose live tip falls to
    /// 0) never rewinds below `last_finalized`; with lf known the rewind is
    /// clamped, and the round's readings are rejected outright.
    #[test]
    fn r4r4_empty_last_submitted_never_rewinds_below_finalized() {
        use std::collections::BTreeMap;
        let accepted: BTreeMap<u64, String> = (6..=8).map(|h| (h, format!("U{h}"))).collect();
        // The old loop read a missing last_submitted as 0 → target 0.
        let bad = ChainView {
            last_submitted: 0,
            last_finalized: 5,
            ..Default::default()
        };
        assert_eq!(rewind_target(8, &accepted, &bad), Some(5));
        // Nothing to rewind when we are at lf already.
        assert_eq!(rewind_target(5, &accepted, &bad), None);
        // And the readings themselves are refused before any rewind.
        assert!(sane_chain_readings(None, Some(5), 5, 8).is_err());
        assert!(sane_chain_readings(Some(0), Some(5), 5, 8).is_err());
        assert!(sane_chain_readings(Some(0), Some(0), 0, 3).is_err());
        assert!(sane_chain_readings(Some(9), None, 5, 8).is_err());
        assert!(
            sane_chain_readings(Some(9), Some(4), 5, 8).is_err(),
            "lf went back"
        );
        assert!(
            sane_chain_readings(Some(4), Some(5), 5, 8).is_err(),
            "ls < lf"
        );
        // Legit readings pass, including a fresh chain with nothing yet.
        assert_eq!(sane_chain_readings(Some(9), Some(5), 5, 8), Ok((9, 5)));
        assert_eq!(sane_chain_readings(Some(5), Some(5), 4, 8), Ok((5, 5)));
        assert_eq!(sane_chain_readings(None, None, 0, 0), Ok((0, 0)));
        assert_eq!(sane_chain_readings(Some(2), None, 0, 0), Ok((2, 0)));
        // A real verdict below lf+1 is still honoured down to lf.
        let verdict = ChainView {
            last_submitted: 6,
            last_finalized: 5,
            frozen_at_last_submitted: 2,
            ..Default::default()
        };
        assert_eq!(rewind_target(8, &accepted, &verdict), Some(5));
    }

    /// R4-R-6: a re-submitted height that already finalized is detected by
    /// the root comparison and the rewind lands on the newest checkpoint
    /// whose root the chain still has — even below `last_finalized`.
    #[test]
    fn r4r6_finalized_resubmission_is_detected_by_root() {
        use serde_json::json;
        let chain: std::collections::BTreeMap<u64, &str> =
            [(3, "R3"), (4, "R4"), (5, "NEW5"), (6, "NEW6")].into();
        let mine: std::collections::BTreeMap<u64, &str> =
            [(3, "R3"), (4, "R4"), (5, "R5"), (6, "R6")].into();
        // Engine at h=6 with root R6; chain has NEW6 → diverged.
        assert!(root_diverged("R6", Some(&json!("NEW6"))));
        assert!(!root_diverged("R6", Some(&json!("R6"))));
        // Unknown readings are not divergence (verdict writes 0, or empty).
        assert!(!root_diverged("R6", None));
        assert!(!root_diverged("R6", Some(&json!(0))));
        assert!(!root_diverged("R6", Some(&json!(""))));
        let pick = pick_root_verified_checkpoint(
            &[6, 5, 4, 3],
            6,
            |h| mine.get(&h).map(|s| s.to_string()),
            |h| Ok(chain.get(&h).map(|s| json!(s))),
        );
        assert_eq!(pick, Ok(Some(4)));
        // An unreadable checkpoint is skipped.
        let pick = pick_root_verified_checkpoint(
            &[6, 5, 4, 3],
            6,
            |h| (h != 4).then(|| mine[&h].to_string()),
            |h| Ok(chain.get(&h).map(|s| json!(s))),
        );
        assert_eq!(pick, Ok(Some(3)));
        // A hub error aborts (caller changes nothing).
        let pick = pick_root_verified_checkpoint(
            &[6, 5, 4, 3],
            6,
            |h| mine.get(&h).map(|s| s.to_string()),
            |_| Err("down".to_string()),
        );
        assert!(pick.is_err());
        // Nothing matches.
        let pick = pick_root_verified_checkpoint(&[5], 6, |_| Some("X".into()), |_| Ok(None));
        assert_eq!(pick, Ok(None));
    }

    /// R4-R-8: only the frozen chain tip is skipped.
    #[test]
    fn r4r8_frozen_tip_is_skipped_not_rechecked() {
        assert!(tip_awaiting_resubmission(7, 7, 2));
        assert!(!tip_awaiting_resubmission(7, 7, 0));
        assert!(!tip_awaiting_resubmission(7, 7, 1));
        assert!(!tip_awaiting_resubmission(6, 7, 2));
    }

    /// R4-R-7 / R5-R-7: clearing a temp checkpoint dir removes checkpoints
    /// and the dead branch but keeps proofs. Liveness is the owner's flock:
    /// an unlocked lock file is swept, a held one is not — whatever pid
    /// `owner.pid` names (a pid of another PID namespace is invisible in
    /// our /proc, which used to wipe live watchers) — and a dir without a
    /// lock file (older version / still starting) is left alone.
    #[test]
    fn r5r7_sweep_uses_flock_not_pid() {
        use minuend_state::persist::{DEAD_SNAPSHOT_DIR, SNAPSHOT_PREFIX};
        let prefix = format!("minuend-watch-r5r7-{}", std::process::id());
        let own = create_private_temp_dir(&prefix).unwrap();
        let stale = create_private_temp_dir(&prefix).unwrap();
        let live = create_private_temp_dir(&prefix).unwrap();
        let legacy = create_private_temp_dir(&prefix).unwrap();
        for d in [&own, &stale, &live, &legacy] {
            std::fs::write(d.join(format!("{SNAPSHOT_PREFIX}1.snap")), b"x").unwrap();
            std::fs::create_dir_all(d.join(DEAD_SNAPSHOT_DIR)).unwrap();
            std::fs::write(
                d.join(DEAD_SNAPSHOT_DIR)
                    .join(format!("{SNAPSHOT_PREFIX}2.snap")),
                b"x",
            )
            .unwrap();
        }
        let _own_lock = lock_temp_dir(&own).unwrap();
        // Live owner in "another PID namespace": its pid is not in our
        // /proc (above pid_max), but it holds the lock.
        let live_lock = lock_temp_dir(&live).unwrap();
        std::fs::write(live.join(TEMP_DIR_OWNER_FILE), "2147483632").unwrap();
        // Stale: lock file left behind by a killed run (nobody holds it),
        // even though its recorded pid (ours) is "running".
        drop(lock_temp_dir(&stale).unwrap());
        std::fs::write(
            stale.join(TEMP_DIR_OWNER_FILE),
            std::process::id().to_string(),
        )
        .unwrap();
        std::fs::create_dir_all(stale.join("proofs")).unwrap();
        std::fs::write(stale.join("proofs").join("p.json"), b"{}").unwrap();
        // Legacy: pid file of a dead process but no lock file.
        std::fs::write(legacy.join(TEMP_DIR_OWNER_FILE), "2147483632").unwrap();
        // A second lock of a held dir fails.
        assert!(lock_temp_dir(&live).is_err());
        let swept = sweep_stale_temp_dirs(&prefix, &own);
        #[cfg(unix)]
        {
            assert_eq!(swept, vec![stale.clone()]);
            assert!(!stale.join(format!("{SNAPSHOT_PREFIX}1.snap")).exists());
            assert!(!stale.join(DEAD_SNAPSHOT_DIR).exists());
            assert!(!stale.join(TEMP_DIR_LOCK_FILE).exists());
            assert!(stale.join("proofs").join("p.json").exists(), "proofs kept");
            assert!(live.join(format!("{SNAPSHOT_PREFIX}1.snap")).exists());
            assert!(legacy.join(format!("{SNAPSHOT_PREFIX}1.snap")).exists());
            // Once the live owner exits (lock released), it is swept.
            drop(live_lock);
            assert_eq!(sweep_stale_temp_dirs(&prefix, &own), vec![live.clone()]);
        }
        #[cfg(not(unix))]
        {
            assert!(swept.is_empty());
            drop(live_lock);
        }
        assert!(own.join(format!("{SNAPSHOT_PREFIX}1.snap")).exists());
        // Our own cleanup at exit: no proofs → the whole dir goes.
        clear_temp_checkpoints(&own);
        assert!(!own.exists());
        for d in [&stale, &live, &legacy] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    /// R5-R-4: a regressed last_submitted is contradictory unless the AA's
    /// verdict marker or a re-submission explains it.
    #[test]
    fn r5r4_regressed_last_submitted_without_freeze_is_contradictory() {
        let seen = Some("U6");
        // Not regressed / verdict marker present → genuine.
        assert!(!regressed_tip_contradictory(9, 5, 8, 0, Some("U9"), None));
        assert!(!regressed_tip_contradictory(6, 5, 8, 2, Some("U6"), seen));
        // Regressed, no freeze, same da_unit we replayed → contradictory.
        assert!(regressed_tip_contradictory(6, 5, 8, 0, Some("U6"), seen));
        // Empty / missing da_unit next to a known acceptance → unknown.
        assert!(regressed_tip_contradictory(6, 5, 8, 0, Some(""), seen));
        assert!(regressed_tip_contradictory(6, 5, 8, 0, None, seen));
        // Re-submitted (new da_unit, frozen cleared) → genuine.
        assert!(!regressed_tip_contradictory(6, 5, 8, 0, Some("U6b"), seen));
        // ls == lf below our tip can never be genuine.
        assert!(regressed_tip_contradictory(5, 5, 8, 0, Some("U5"), None));
        // No record of ls (e.g. after a restart) → not provably wrong.
        assert!(!regressed_tip_contradictory(6, 5, 8, 0, Some("U6"), None));
    }

    fn r5_deposit_batch() -> (Batch, String) {
        use ed25519_dalek::SigningKey;
        use minuend_dag::{genesis_id, sign_unit, unit_id, Op};
        let secret = [7u8; 32];
        let pk = SigningKey::from_bytes(&secret).verifying_key().to_bytes();
        let acct = minuend_types::account_id_from_pubkey(&pk);
        let aa = [9u8; 32];
        let addr = "Q".repeat(32);
        let u = sign_unit(
            vec![genesis_id()],
            Op::Deposit {
                account: acct,
                addr: addr.clone(),
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
        let key = format!(
            "dep_{}",
            base64::engine::general_purpose::STANDARD.encode(aa)
        );
        (batch, key)
    }

    /// R5-R-2: vault records are read only for anchors a P-adr proof
    /// could need, derived from the unit's real op.
    #[test]
    fn r5r2_vault_keys_only_for_needed_anchors() {
        let (batch, key) = r5_deposit_batch();
        assert!(batch.leaf_trace[0].iter().any(|l| l.starts_with("adr:")));
        assert_eq!(vault_keys_needed(&batch), vec![key.clone()]);
        // Operator-written "o" that is not the unit's op: no read.
        let mut forged = batch.clone();
        forged.ops[0] = forged.ops[0].replace(&key[4..], &"A".repeat(44));
        assert!(vault_keys_needed(&forged).is_empty());
        // Posted post tree without the op's new binding: the record is
        // never consulted → no read.
        let mut nobind = batch.clone();
        nobind.leaf_trace[0].retain(|l| !l.starts_with("adr:"));
        assert!(vault_keys_needed(&nobind).is_empty());
        // Many units citing the same anchor: one key.
        let mut dup = batch.clone();
        for _ in 0..50 {
            dup.units.push(dup.units[0].clone());
            dup.ops.push(dup.ops[0].clone());
            dup.leaf_trace.push(dup.leaf_trace[0].clone());
            dup.checkpoint.unit_ids.push(dup.checkpoint.unit_ids[0]);
        }
        assert_eq!(vault_keys_needed(&dup), vec![key]);
    }

    /// R5 integration (vault `pperp_total` cap): a verified base evidence
    /// decides the `dep_` record (no read), but a verified PERP evidence
    /// cited by a `D:` op does not (a cap-bounced deposit still verifies),
    /// so that anchor is read even without a new binding.
    #[test]
    fn r5_perp_evidence_does_not_cover_depp_record() {
        let (batch, key) = r5_deposit_batch();
        let ev = |is_perp: bool| minuend_settle::DepositEvidence {
            aa_unit: hex::encode([9u8; 32]),
            is_perp,
            amount: "100".into(),
            vault_address: String::new(),
            payer: "Q".repeat(32),
            account: String::new(),
            joint: serde_json::Value::Null,
        };
        let yes = |_: &minuend_settle::DepositEvidence| true;
        let mut based = batch.clone();
        based.unit_evidences = vec![Some(ev(false))];
        assert!(vault_keys_needed_with(&based, &yes).is_empty());
        // The same unit as a `D:` (GovDeposit) op with a PERP evidence.
        let mut gov = batch.clone();
        if let minuend_dag::Op::Deposit {
            account,
            addr,
            amount,
            aa_unit,
        } = gov.units[0].op.clone()
        {
            gov.units[0].op = minuend_dag::Op::GovDeposit {
                account,
                addr,
                amount: amount as u128,
                aa_unit,
            };
        }
        let id_hex = hex::encode(gov.checkpoint.unit_ids[0].0);
        gov.ops[0] = minuend_settle::ops_element(&id_hex, &gov.units[0].op);
        assert!(gov.ops[0].starts_with("D:"));
        gov.leaf_trace[0].retain(|l| !l.starts_with("adr:"));
        gov.unit_evidences = vec![Some(ev(true))];
        let pkey = format!("depp_{}", &key[4..]);
        assert_eq!(vault_keys_needed_with(&gov, &yes), vec![pkey]);
        // Unverified PERP evidence and no binding: nothing to read.
        assert!(vault_keys_needed_with(&gov, &|_| false).is_empty());
    }

    struct CountingHub {
        reads: std::cell::Cell<usize>,
    }
    impl HubClient for CountingHub {
        fn get_aa_state_var(
            &self,
            _addr: &str,
            key: &str,
        ) -> Result<Option<serde_json::Value>, String> {
            self.reads.set(self.reads.get() + 1);
            if key.ends_with("_err") {
                return Err("hub down".into());
            }
            if key.ends_with("_absent") {
                return Ok(None);
            }
            Ok(Some(serde_json::json!(format!("P:1:{key}"))))
        }
        fn get_joint(&self, _: &str) -> Result<serde_json::Value, String> {
            Err("n/a".into())
        }
    }

    /// R5-R-2: reads are capped by count and deadline, and every outcome
    /// (failures too) is cached for the round.
    #[test]
    fn r5r2_vault_reads_are_bounded_and_cached() {
        let hub = CountingHub {
            reads: std::cell::Cell::new(0),
        };
        let mut keys: Vec<String> = (0..100).map(|i| format!("dep_k{i}")).collect();
        keys.push("dep_x_err".into());
        keys.insert(0, "dep_y_absent".into());
        keys.insert(0, "dep_z_err".into());
        let mut cache = VaultReadCache::new();
        let mut clock = || 100u64;
        let l = read_vault_ledger_bounded(&hub, "V", &keys, &mut cache, 64, 1000, &mut clock);
        assert_eq!(hub.reads.get(), 64, "count cap");
        assert_eq!(l.len(), 63, "the failed read stays unknown");
        assert_eq!(l.get("dep_y_absent"), Some(&None));
        assert!(!l.contains_key("dep_z_err"));
        // Same round: cached keys (failed one included) are not re-read.
        let l2 =
            read_vault_ledger_bounded(&hub, "V", &keys[..64], &mut cache, 64, 1000, &mut clock);
        assert_eq!(hub.reads.get(), 64);
        assert_eq!(l2.len(), 63);
        // Deadline passed: no further reads at all.
        let mut late = || 1000u64;
        let l3 = read_vault_ledger_bounded(&hub, "V", &keys, &mut cache, 64, 1000, &mut late);
        assert_eq!(hub.reads.get(), 64);
        assert_eq!(l3.len(), 63);
        // A new round retries the failure.
        let mut fresh = VaultReadCache::new();
        read_vault_ledger_bounded(&hub, "V", &keys[..1], &mut fresh, 64, 1000, &mut clock);
        assert_eq!(hub.reads.get(), 65);
        // No vault configured: nothing read.
        assert!(
            read_vault_ledger_bounded(&hub, "", &keys, &mut fresh, 64, 1000, &mut clock).is_empty()
        );
    }

    /// R3-R-6: the no-`--state-dir` proof directory is created fresh at an
    /// unpredictable path with mode 0700, and never reuses an existing one.
    #[test]
    fn private_temp_dir_is_fresh_and_unpredictable() {
        let a = create_private_temp_dir("minuend-watch-test").unwrap();
        let b = create_private_temp_dir("minuend-watch-test").unwrap();
        assert_ne!(a, b);
        let name = a.file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(name.len(), "minuend-watch-test-".len() + 32, "{name}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(&a).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o700);
        }
        // A pre-created directory is never reused by the proof writer path
        // (DirBuilder::create fails on an existing entry).
        assert!(std::fs::DirBuilder::new().create(&a).is_err());
        write_private_proof(&a, 1, "wpin", &serde_json::json!({})).unwrap();
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }
}
