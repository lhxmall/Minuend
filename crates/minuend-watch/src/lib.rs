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
        let raw = gunzip_blob(&gz)?;
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
    let raw = minuend_settle::decode_package_blob(blob)
        .map_err(|_| WatchError::BindingMismatch("frames_blob not base64(gzip)".into()))?;
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

pub fn gunzip_blob(gz: &[u8]) -> Result<Vec<u8>, WatchError> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut dec = GzDecoder::new(gz);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|_| WatchError::BindingMismatch("package_blob not gzip".into()))?;
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
}
