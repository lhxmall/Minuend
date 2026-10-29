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

/// R2-R-2: largest decompressed size accepted for ONE package (or an inline
/// `frames_blob`). A package's gzip source is capped at `PACK_SOURCE_CAP`
/// (4 MB) on-chain; 64 MiB leaves a 16x compression headroom for honest
/// JSON frames while a gzip bomb (~1000:1) is cut off early.
pub const MAX_PACKAGE_RAW_BYTES: usize = 64 << 20;
/// R2-R-2: largest decompressed size accepted for all packages of one
/// height together (the watcher holds these bytes, the split frames and
/// the decoded batch in memory at once).
pub const MAX_COMMITTED_RAW_BYTES: usize = 1 << 30;
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
pub fn load_checkpoint(dir: &std::path::Path) -> std::io::Result<Option<Engine>> {
    let Some((_, state, anchors)) = minuend_state::persist::load_latest_with_anchors(dir)? else {
        return Ok(None);
    };
    let mut engine = Engine::new();
    engine.state = state;
    for a in anchors {
        let id = minuend_types::UnitId(a);
        engine.dag.mark_ancestor_known(id);
        engine.recent_units.push_back(id);
    }
    Ok(Some(engine))
}

/// R2-R-9: persist the engine after a height replayed cleanly. Only
/// replay-verified heights are ever checkpointed.
pub fn save_checkpoint(
    dir: &std::path::Path,
    engine: &Engine,
) -> std::io::Result<std::path::PathBuf> {
    let anchors: Vec<[u8; 32]> = engine.recent_units.iter().map(|u| u.0).collect();
    minuend_state::persist::save_snapshot_with_anchors(dir, &engine.state, &anchors)
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
}
