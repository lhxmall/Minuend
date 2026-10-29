//! `minuend-watch` — independent MINUEND vault-AA watcher binary.
//!
//! Polls a live Obyte hub for the vault's `last_submitted` / `submitted_at_<h>` /
//! `frozen_<h>` state, then for every submitted height inside its
//! challenge window (and not already frozen) fetches `da_unit_<h>`, verifies
//! the unit↔data binding, and replays the batch. A replay/verify failure is a
//! mismatched root that a watcher-owned wallet should challenge on-chain.
//!
//! The watch contract is read-only: the only AA transaction a watcher may
//! eventually emit is a dispute predicate. There is no live-hub signing
//! backend yet: with a key configured every challengeable alert is reported
//! loudly as NOT posted (proof file kept for a manual post); only an explicit
//! `MINUEND_WATCH_DEVNET_CHALLENGE=1` drill spawns post_challenge.js against
//! a local aa-testkit network (#47 L5).

use minuend_exec::Engine;
use minuend_types::env_compat::env_var_compat;
use minuend_watch::{
    batch_from_committed, check_committed_roots, committed_frame_bytes, fetch_da_unit,
    load_checkpoint, prove, resolve_start_height, save_checkpoint, verify_da_binding,
    write_private_proof, HubClient, WatchConfig, WatchError, CHALLENGE_BOND_GROSS,
    DEFAULT_POLL_INTERVAL_SECS,
};
use std::collections::BTreeMap;
use std::env;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// HTTP-backed hub client over Obyte's JSON-RPC (`getAaStateVars`,
/// `getJoint`), matching the hub call shapes used by `post_batch.js`.
///
/// Zero new dependencies: a minimal HTTP/1.1 client over `std::net::TcpStream`
/// (the plan's `std` fallback). V1 targets the `http://` testkit hub — no TLS
/// backend is wired; use an https gateway/SSH tunnel for a remote hub.
struct HttpHubClient {
    host: String,
    port: u16,
}

impl HttpHubClient {
    fn new(base: &str) -> Result<Self, anyhow::Error> {
        let rest = base
            .strip_prefix("http://")
            .or_else(|| base.strip_prefix("https://"))
            .unwrap_or(base);
        let rest = rest.split('/').next().unwrap_or("");
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().unwrap_or(6611)),
            None => (rest.to_string(), 6611),
        };
        if host.is_empty() {
            return Err(anyhow::anyhow!("invalid hub url: {base}"));
        }
        Ok(Self { host, port })
    }

    fn rpc(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        })
        .to_string();

        let addr = format!("{}:{}", self.host, self.port);
        let mut stream = std::net::TcpStream::connect(&addr).map_err(|e| e.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .map_err(|e| e.to_string())?;

        let request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.host,
            body.len(),
            body
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| e.to_string())?;

        // I-3 / R2-R-2: a hub response is bounded too (a hostile or broken
        // hub must not be able to exhaust the watcher's memory).
        let mut resp = Vec::new();
        (&mut stream)
            .take(MAX_HUB_RESPONSE_BYTES + 1)
            .read_to_end(&mut resp)
            .map_err(|e| e.to_string())?;
        if resp.len() as u64 > MAX_HUB_RESPONSE_BYTES {
            return Err(format!("hub response exceeds {MAX_HUB_RESPONSE_BYTES} bytes"));
        }
        let text = String::from_utf8_lossy(&resp).to_string();

        // Split headers from body; honor Content-Length when present.
        let (headers, body) = match text.split_once("\r\n\r\n") {
            Some((h, b)) => (h, b),
            None => ("", text.as_str()),
        };
        let mut clen = None;
        for line in headers.split("\r\n") {
            if let Some((k, v)) = line.split_once(':') {
                if k.eq_ignore_ascii_case("content-length") {
                    clen = v.trim().parse::<usize>().ok();
                }
            }
        }
        let body = match clen {
            Some(n) if body.len() >= n => body[..n].to_string(),
            _ => body.to_string(),
        };

        let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        if let Some(err) = v.get("error").and_then(|e| e.get("message")) {
            return Err(err.as_str().unwrap_or("rpc error").to_string());
        }
        Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null))
    }
}

impl HubClient for HttpHubClient {
    fn get_aa_state_var(
        &self,
        address: &str,
        key: &str,
    ) -> Result<Option<serde_json::Value>, String> {
        let result = self.rpc("getAaStateVars", serde_json::json!([address, key]))?;
        match result {
            serde_json::Value::Null => Ok(None),
            serde_json::Value::Object(map) => Ok(map.get(key).cloned()),
            other => Ok(Some(other)),
        }
    }

    fn get_joint(&self, unit_hash: &str) -> Result<serde_json::Value, String> {
        let result = self.rpc("getJoint", serde_json::json!([unit_hash]))?;
        if result.is_null() {
            return Err(format!("404: no joint {unit_hash}"));
        }
        Ok(result)
    }
}

/// Largest JSON-RPC response accepted from the hub (a 4 MB package joint
/// is base64 + JSON framing, so 64 MiB is generous).
const MAX_HUB_RESPONSE_BYTES: u64 = 64 << 20;

struct Args {
    rollup: String,
    vault: String,
    dispute: Option<String>,
    dispute_fill: Option<String>,
    dispute_bind: Option<String>,
    hub: String,
    from_height: Option<u64>,
    state_dir: Option<PathBuf>,
    poll_interval_secs: u64,
    bond: u64,
}
fn parse_args() -> Result<Args, String> {
    let mut rollup = None;
    let mut vault = None;
    let mut dispute = None;
    let mut dispute_fill = None;
    let mut dispute_bind = None;
    let mut state_dir = None;
    let mut hub = None;
    let mut from_height = None;
    let mut poll_interval_secs = DEFAULT_POLL_INTERVAL_SECS;
    let mut bond = CHALLENGE_BOND_GROSS;

    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--rollup" => rollup = Some(it.next().ok_or("--rollup needs a value")?),
            "--vault" => vault = Some(it.next().ok_or("--vault needs a value")?),
            "--dispute" => dispute = Some(it.next().ok_or("--dispute needs a value")?),
            "--dispute-fill" => {
                dispute_fill = Some(it.next().ok_or("--dispute-fill needs a value")?)
            }
            "--dispute-bind" => {
                dispute_bind = Some(it.next().ok_or("--dispute-bind needs a value")?)
            }
            "--state-dir" => {
                state_dir = Some(PathBuf::from(
                    it.next().ok_or("--state-dir needs a value")?,
                ))
            }
            "--hub" => hub = Some(it.next().ok_or("--hub needs a value")?),
            "--from-height" => {
                from_height = Some(
                    it.next()
                        .ok_or("--from-height needs a value")?
                        .parse()
                        .map_err(|_| "--from-height must be u64")?,
                )
            }
            "--poll-interval" => {
                poll_interval_secs = it
                    .next()
                    .ok_or("--poll-interval needs a value")?
                    .parse()
                    .map_err(|_| "--poll-interval must be u64")?
            }
            "--bond" => {
                bond = it
                    .next()
                    .ok_or("--bond needs a value")?
                    .parse()
                    .map_err(|_| "--bond must be u64")?
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown flag: {other}")),
        }
    }

    Ok(Args {
        rollup: rollup.ok_or("missing --rollup")?,
        vault: vault.ok_or("missing --vault")?,
        dispute,
        dispute_fill,
        dispute_bind,
        hub: hub.ok_or("missing --hub")?,
        from_height,
        state_dir,
        poll_interval_secs,
        bond,
    })
}

fn print_usage() {
    eprintln!(
        "minuend-watch --rollup <rollup-aa-addr> --vault <vault-aa-addr> --hub <hub-url> [--dispute <dispute-aa-addr>] \
 [--dispute-fill <addr>] [--dispute-bind <addr>] [--state-dir <dir>] [--from-height <u64>] \
 [--poll-interval <secs>] [--bond <gross-bytes>]\n\
 \n\
Polls the rollup's da_unit_<h> assertions, checks the DA header against the roots the\n\
rollup AA stored, replays each submitted height, and flags any mismatch inside the\n\
submitted_at+3600 dispute window for a watcher-owned wallet to challenge.\n\
\n\
--state-dir keeps a replay checkpoint (chainstate.<h>.snap) after every replayed height\n\
so a restart resumes instead of replaying from genesis (temp_data is purged after\n\
~24 h). To start above height 1, put a TRUSTED chainstate.<from-1>.snap there.\n\
\n\
Limits (R2-R-2/R2-R-5): <= {MAX_PKG} packages, <= {PKG_MB} MiB decompressed per package,\n\
<= {TOT_MB} MiB per height, unit_count <= 200000. Replay cost is O(units x state size)\n\
(full witness rebuild per unit); size the host for the largest expected state.",
        MAX_PKG = minuend_watch::MAX_PACKAGES,
        PKG_MB = minuend_watch::MAX_PACKAGE_RAW_BYTES >> 20,
        TOT_MB = minuend_watch::MAX_COMMITTED_RAW_BYTES >> 20,
    );
}

const CHALLENGE_WINDOW_SECS: u64 = 3600;
/// B10 (#47): the dispute AAs compare the challenge unit's own `timestamp`
/// against `submitted_at + 3600`. Building the proof, broadcasting and
/// getting the unit stable all take time, so the watcher stops *posting*
/// this many seconds before the deadline (inside the margin it only alerts,
/// rather than paying for a challenge that would bounce as too late).
const CHALLENGE_SAFETY_MARGIN_SECS: u64 = 600;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Is the height still inside the AA's dispute window at all?
fn challenge_window_open(submitted_at: u64, now: u64, frozen: u64) -> bool {
    submitted_at != 0 && now < submitted_at.saturating_add(CHALLENGE_WINDOW_SECS) && frozen == 0
}

/// B10 (#47): may the watcher still *post* a challenge? Same as
/// [`challenge_window_open`] but keeps [`CHALLENGE_SAFETY_MARGIN_SECS`]
/// clear of the AA deadline. Always evaluate with a freshly read clock.
fn challenge_postable(submitted_at: u64, now: u64, frozen: u64) -> bool {
    challenge_window_open(submitted_at, now, frozen)
        && now.saturating_add(CHALLENGE_SAFETY_MARGIN_SECS)
            < submitted_at.saturating_add(CHALLENGE_WINDOW_SECS)
}

/// L5 (#47): what the watcher does with a challengeable alert.
#[derive(Debug, PartialEq, Eq)]
enum ChallengeMode {
    /// No watcher key configured: print the alert only.
    PrintOnly,
    /// `MINUEND_WATCH_MNEMONIC` set: post the challenge on the live network
    /// through `obyte-local/post_challenge_live.js` (light headless wallet;
    /// it re-checks the window and the safety margin against the rollup's
    /// own `submitted_at_<h>` with a fresh clock right before sending).
    Live,
    /// Explicit local-devnet drill (`MINUEND_WATCH_DEVNET_CHALLENGE=1`, no
    /// key): spawn `post_challenge.js` without `--hub`.
    DevnetDrill,
}

fn challenge_mode(has_mnemonic: bool, devnet_drill: bool) -> ChallengeMode {
    match (has_mnemonic, devnet_drill) {
        (true, _) => ChallengeMode::Live,
        (false, true) => ChallengeMode::DevnetDrill,
        (false, false) => ChallengeMode::PrintOnly,
    }
}

fn current_challenge_mode() -> ChallengeMode {
    challenge_mode(
        env_var_compat("MINUEND_WATCH_MNEMONIC").is_some(),
        env_var_compat("MINUEND_WATCH_DEVNET_CHALLENGE").as_deref() == Some("1"),
    )
}

/// L5 (#47): exit code of `post_challenge_live.js` when its own fresh
/// window/margin/frozen gate refused to send (nothing was broadcast).
const LIVE_EXIT_REFUSED: i32 = 3;

/// Addresses the watcher hands to the challenge posters (R2-R-8): the
/// rollup it is actually watching and any dispute AA given on the command
/// line. The live poster reads the dispute AA from the rollup's own
/// `dispute_*aa` state var when none is given.
#[derive(Clone, Debug, Default)]
struct ChallengeCtx {
    rollup: String,
    dispute_main: Option<String>,
    dispute_fill: Option<String>,
    dispute_bind: Option<String>,
    proof_dir: PathBuf,
}

impl ChallengeCtx {
    fn dispute_for(&self, target: &str) -> Option<&str> {
        match target {
            "fill" => self.dispute_fill.as_deref(),
            "bind" => self.dispute_bind.as_deref(),
            _ => self.dispute_main.as_deref(),
        }
    }
}

static CHALLENGE_CTX: OnceLock<ChallengeCtx> = OnceLock::new();

/// L5 (#47): argv for `node post_challenge_live.js` (pure, unit-tested).
/// R2-R-8: always names the watched rollup (`--rollup`) and, when known,
/// the dispute AA (`--dispute-address`), so the script never falls back to
/// whatever `deployment.json` in the checkout happens to say.
fn live_challenge_args(
    script: &std::path::Path,
    h: u64,
    p: &prove::BuiltProof,
    proof_path: &std::path::Path,
    network: &str,
    ctx: &ChallengeCtx,
) -> Vec<std::ffi::OsString> {
    let mut args: Vec<std::ffi::OsString> = vec![
        script.as_os_str().to_owned(),
        "--height".into(),
        h.to_string().into(),
        "--pred".into(),
        p.pred.clone().into(),
        "--proof".into(),
        proof_path.as_os_str().to_owned(),
        "--target".into(),
        p.target().into(),
        "--network".into(),
        network.into(),
        "--rollup".into(),
        ctx.rollup.clone().into(),
    ];
    if let Some(d) = ctx.dispute_for(p.target()) {
        args.push("--dispute-address".into());
        args.push(d.to_string().into());
    }
    args
}

/// R2-R-11: per `(height, predicate)` challenge bookkeeping, so a challenge
/// that is being posted or was already broadcast is not paid for again on
/// the next poll round, and the poster runs without blocking the loop.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AttemptState {
    in_flight: bool,
    broadcast: bool,
    failures: u32,
    refused: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum PostDecision {
    Post,
    InFlight,
    AlreadyBroadcast,
    GaveUp,
}

/// Retries for a poster that exited with an error (nothing broadcast).
const MAX_POST_FAILURES: u32 = 3;

fn post_decision(prev: Option<&AttemptState>) -> PostDecision {
    match prev {
        None => PostDecision::Post,
        Some(s) if s.in_flight => PostDecision::InFlight,
        Some(s) if s.broadcast => PostDecision::AlreadyBroadcast,
        Some(s) if s.refused || s.failures >= MAX_POST_FAILURES => PostDecision::GaveUp,
        Some(_) => PostDecision::Post,
    }
}

/// Fold a finished poster's exit code into its attempt state.
fn record_exit(state: &mut AttemptState, code: Option<i32>) {
    state.in_flight = false;
    match code {
        Some(0) => state.broadcast = true,
        Some(LIVE_EXIT_REFUSED) => state.refused = true,
        _ => state.failures += 1,
    }
}

#[derive(Default)]
struct ChallengeTracker {
    states: BTreeMap<(u64, String), AttemptState>,
    children: BTreeMap<(u64, String), (Child, String)>,
}

impl ChallengeTracker {
    /// Reap finished posters; returns one report line per finished child.
    fn poll(&mut self) -> Vec<String> {
        let mut done = Vec::new();
        for (key, (child, what)) in self.children.iter_mut() {
            if let Ok(Some(st)) = child.try_wait() {
                done.push((key.clone(), st, what.clone()));
            }
        }
        let mut out = Vec::new();
        for (key, st, what) in done {
            self.children.remove(&key);
            let state = self.states.entry(key.clone()).or_default();
            record_exit(state, st.code());
            let (h, pred) = key;
            out.push(match st.code() {
                Some(0) => format!("WATCH: challenge h={h} pred={pred} broadcast ({what})"),
                Some(LIVE_EXIT_REFUSED) => format!(
                    "WATCH CRITICAL: challenge h={h} pred={pred} was NOT posted — the \
                     poster's fresh window/margin check refused it ({what})"
                ),
                _ => format!(
                    "WATCH CRITICAL: challenge h={h} pred={pred} was NOT confirmed (poster \
                     exited {st}; attempt {} of {MAX_POST_FAILURES}) ({what})",
                    state.failures
                ),
            });
        }
        out
    }
}

static TRACKER: Mutex<Option<ChallengeTracker>> = Mutex::new(None);

fn with_tracker<R>(f: impl FnOnce(&mut ChallengeTracker) -> R) -> R {
    let mut g = TRACKER.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(ChallengeTracker::default))
}

/// #37-13: cross-round replay cursor. `processed_upto` is the last height
/// whose replay advanced the engine; the next round starts right after it
/// (never below the configured `from_height`). R2-R-9: with `--state-dir`
/// the engine (and thus the cursor's start) is checkpointed after every
/// replayed height, so a restart resumes where it stopped.
///
/// L4 (#47): a height that does not replay still stops the *replay* (the
/// engine cannot skip a height), but it is now recorded as a stall so the
/// loop keeps surfacing it every round and keeps running the replay-free
/// checks (DA binding, `data_root`, frame decoding) on every later height
/// that is still inside its dispute window, instead of going silent.
#[derive(Debug)]
struct ReplayCursor {
    processed_upto: u64,
    from_height: u64,
    /// First height that failed to advance the engine, and since which
    /// round count it has been stuck there.
    stalled_at: Option<(u64, u64)>,
}

impl ReplayCursor {
    fn new(from_height: u64) -> Self {
        Self {
            processed_upto: from_height.saturating_sub(1),
            from_height,
            stalled_at: None,
        }
    }

    fn next_start(&self) -> u64 {
        self.processed_upto.saturating_add(1).max(self.from_height)
    }

    /// Record a successfully replayed height; the cursor only moves forward.
    fn record(&mut self, height: u64) {
        if height > self.processed_upto {
            self.processed_upto = height;
        }
        if matches!(self.stalled_at, Some((h, _)) if h <= height) {
            self.stalled_at = None;
        }
    }

    /// Record that `height` did not advance the engine this round. Returns
    /// how many consecutive rounds the cursor has been stuck there.
    fn note_stall(&mut self, height: u64) -> u64 {
        let rounds = match self.stalled_at {
            Some((h, n)) if h == height => n + 1,
            _ => 1,
        };
        self.stalled_at = Some((height, rounds));
        rounds
    }

    /// Alert text for a stall that leaves later submitted heights unreplayed.
    /// A single round without DA is normal (the package may not be visible
    /// yet), so nothing is reported until the same height fails twice.
    fn stall_alert(&self, last_submitted: u64) -> Option<String> {
        let (h, rounds) = self.stalled_at?;
        if rounds < 2 {
            return None;
        }
        let unverified = if last_submitted > h {
            format!(
                "heights {}..={} are NOT replay-verified (only DA/data_root checks run)",
                h + 1,
                last_submitted
            )
        } else {
            "no later heights submitted yet".to_string()
        };
        Some(format!(
            "WATCH STALLED at h={h} for {rounds} rounds: replay cannot advance past it; {unverified}"
        ))
    }
}

/// Per-height on-chain window facts read from the rollup AA.
#[derive(Clone, Copy)]
struct WindowFacts {
    submitted_at: u64,
    frozen: u64,
}

fn read_window(hub: &HttpHubClient, config: &WatchConfig, h: u64) -> anyhow::Result<WindowFacts> {
    let sa = hub
        .get_aa_state_var(&config.rollup_address, &format!("submitted_at_{h}"))
        .map_err(|e| anyhow::anyhow!("hub: {e}"))?;
    let frozen = hub
        .get_aa_state_var(&config.rollup_address, &format!("frozen_{h}"))
        .map_err(|e| anyhow::anyhow!("hub: {e}"))?;
    Ok(WindowFacts {
        submitted_at: sa.and_then(|v| v.as_u64()).unwrap_or(0),
        frozen: frozen.and_then(|v| v.as_u64()).unwrap_or(0),
    })
}

/// B10 (#47): decide on a FRESH clock reading whether to post, and annotate
/// the alert accordingly. Called right before any challenge is attempted,
/// not once per poll round.
fn alert_and_maybe_challenge(
    h: u64,
    win: WindowFacts,
    alert: String,
    proof: Option<&prove::BuiltProof>,
) -> String {
    let now = now_secs();
    if challenge_postable(win.submitted_at, now, win.frozen) {
        maybe_post_challenge(h, &alert, proof);
        alert
    } else if challenge_window_open(win.submitted_at, now, win.frozen) {
        format!(
            "{alert} — NOT challenged: less than {CHALLENGE_SAFETY_MARGIN_SECS}s left in the dispute window"
        )
    } else {
        format!("{alert} — outside challenge window (informational)")
    }
}

/// Fetch a height's DA unit and its exact committed frame bytes (B11).
/// `Ok(None)` = nothing to judge yet (no da_unit / hub flaky);
/// `Err(alert)` = a binding/data_root problem worth surfacing.
fn fetch_committed(
    hub: &HttpHubClient,
    config: &WatchConfig,
    h: u64,
    win: WindowFacts,
) -> Result<Option<(minuend_watch::DaUnit, Vec<u8>)>, String> {
    let da = match fetch_da_unit(hub, &config.rollup_address, h) {
        Ok(None) => return Ok(None),
        Ok(Some(da)) => da,
        Err(WatchError::HubUnavailable(_)) => return Ok(None), // backoff, never mis-challenge
        Err(WatchError::BindingMismatch(msg)) => {
            return Err(alert_and_maybe_challenge(
                h,
                win,
                format!("h={h} BINDING MISMATCH: {msg}"),
                None,
            ));
        }
        Err(e) => return Err(format!("h={h} WATCH ERROR: {e}")),
    };
    // #16: the joint we fetched must hash to the value the AA recorded in
    // da_unit_<h> before any downstream step trusts its payload.
    if let Err(e) = verify_da_binding(&da) {
        return Err(alert_and_maybe_challenge(
            h,
            win,
            format!("h={h} BINDING MISMATCH: {e}"),
            None,
        ));
    }
    // R2-R-1: the header we are about to replay must carry exactly the
    // roots the rollup AA stored from this unit's submit data (the vault
    // pays from those). A replay alone only proves the HEADER honest.
    match check_committed_roots(hub, &config.rollup_address, &da) {
        Ok(()) => {}
        Err(WatchError::HubUnavailable(_)) => return Ok(None),
        Err(e) => {
            return Err(alert_and_maybe_challenge(
                h,
                win,
                format!(
                    "h={h} CRITICAL {e} — the on-chain assertion is NOT the replayed DA; \
                     treat height {h} as unverified"
                ),
                None,
            ));
        }
    }
    // B11: the exact bytes data_root commits to (inline blob or the
    // concatenated packages, unmodified). 3 tries + backoff on transport
    // errors, then give up — never mis-challenge on flaky package fetches.
    for attempt in 0..3 {
        match committed_frame_bytes(hub, &da.data) {
            Ok(raw) => return Ok(Some((da, raw))),
            Err(WatchError::HubUnavailable(_)) => {
                std::thread::sleep(Duration::from_millis(500 * (attempt + 1) as u64));
            }
            Err(e) => {
                return Err(alert_and_maybe_challenge(
                    h,
                    win,
                    format!("h={h} BINDING MISMATCH: {e}"),
                    None,
                ));
            }
        }
    }
    Ok(None)
}

/// L4 (#47): replay-free checks for a height above a stall: DA binding,
/// `data_root` and strict frame decoding. Only heights still inside their
/// dispute window are fetched, so a long stall does not refetch history.
fn check_height_without_replay(
    hub: &HttpHubClient,
    config: &WatchConfig,
    h: u64,
) -> anyhow::Result<Option<String>> {
    let win = read_window(hub, config, h)?;
    if !challenge_window_open(win.submitted_at, now_secs(), win.frozen) {
        return Ok(None);
    }
    let (da, raw) = match fetch_committed(hub, config, h, win) {
        Ok(Some(x)) => x,
        Ok(None) => return Ok(None),
        Err(alert) => return Ok(Some(alert)),
    };
    if let Err(e) = batch_from_committed(&da.data, &raw) {
        return Ok(Some(alert_and_maybe_challenge(
            h,
            win,
            format!("h={h} UNDECODABLE BATCH ({e}) above a replay stall"),
            None,
        )));
    }
    Ok(None)
}

/// Replay one height and advance the engine; surface only actionable alerts.
/// Returns `Ok(None)` = nothing actionable (no da_unit, or replay clean),
/// `Ok(Some(alert))` = a mismatch worth surfacing.
fn check_height(
    hub: &HttpHubClient,
    config: &WatchConfig,
    engine: &mut Engine,
    h: u64,
    advanced: &mut bool,
) -> anyhow::Result<Option<String>> {
    let win = read_window(hub, config, h)?;
    let (da, raw) = match fetch_committed(hub, config, h, win) {
        Ok(Some(x)) => x,
        Ok(None) => return Ok(None),
        Err(alert) => return Ok(Some(alert)),
    };
    let batch = match batch_from_committed(&da.data, &raw) {
        Ok(b) => b,
        Err(e) => {
            return Ok(Some(alert_and_maybe_challenge(
                h,
                win,
                format!("h={h} ROOT MISMATCH ({e}): committed frames do not decode"),
                None,
            )));
        }
    };

    let prev_root = engine.state.state_root();
    // R2-R-5: validate first. `validate_against` replays on its own scratch
    // clone and leaves `engine` untouched on failure, so the (expensive)
    // proof-building replay now runs only for a height that actually fails
    // instead of cloning and replaying every honest height twice.
    let err = match batch.validate_against(prev_root, engine) {
        Ok(()) => {
            // R2-R-5: drop this height's per-unit traces (full witness leaf
            // sets per unit) — they are only needed while the height is
            // being judged; the watcher's memory no longer grows with
            // history.
            engine.prune_below(&batch.checkpoint.unit_ids);
            // #37-13: the engine now sits at this height — the poll loop
            // advances its cursor so the next round does not re-scan old
            // heights against an advanced engine (PrevMismatch noise) and
            // does not skip a gap.
            *advanced = true;
            return Ok(None);
        }
        Err(e) => e,
    };
    let proof_hint: Option<prove::BuiltProof> = {
        let mut scratch = engine.clone();
        // Inbox pairs for P-omit: fetch inbox vars is out of scope for the
        // poll loop — caller supplies forced ids via MINUEND_FORCE_IDS
        // (legacy OPERP_FORCE_IDS accepted); the submit timestamp gates
        // staleness.
        let inbox: Vec<(String, u64)> = env_var_compat("MINUEND_FORCE_IDS")
            .map(|s| {
                s.split(',')
                    .filter(|x| x.len() == 64)
                    .map(|x| (x.to_string(), 0u64))
                    .collect()
            })
            .unwrap_or_default();
        prove::build_proof(&batch, &mut scratch, &inbox, win.submitted_at)
    };
    Ok(Some(alert_and_maybe_challenge(
        h,
        win,
        format!(
            "h={} ROOT MISMATCH ({}): watcher should challenge with {} bytes bond",
            h, err, config.challenge_bond_gross
        ),
        proof_hint.as_ref(),
    )))
}

/// Act on a challengeable alert according to [`ChallengeMode`] (L5, #47).
/// A built proof is always written first (R2-R-12: fresh 0600 file in a
/// private directory), so an operator can still post it by hand if the
/// automatic post fails. `Live` spawns `obyte-local/post_challenge_live.js`
/// (mnemonic inherited; the script refuses inside the 600 s margin itself);
/// the devnet drill spawns `post_challenge.js` (never `--hub`, mnemonic
/// stripped). Without a proof nothing is spawned. R2-R-11: posters run in
/// the background (reaped by the poll loop) and a `(height, predicate)`
/// that is in flight or already broadcast is never posted again.
fn maybe_post_challenge(h: u64, alert: &str, proof: Option<&prove::BuiltProof>) {
    let mode = current_challenge_mode();
    if mode == ChallengeMode::PrintOnly {
        eprintln!("WATCH ALERT (print-only, no MINUEND_WATCH_MNEMONIC): {alert}");
        return;
    }
    let Some(p) = proof else {
        eprintln!("WATCH ALERT (NOT CHALLENGED: no expressible proof): {alert}");
        return;
    };
    let key = (h, p.pred.clone());
    match with_tracker(|t| post_decision(t.states.get(&key))) {
        PostDecision::Post => {}
        PostDecision::InFlight => {
            eprintln!("WATCH: challenge h={h} pred={} already in flight ({alert})", p.pred);
            return;
        }
        PostDecision::AlreadyBroadcast => {
            eprintln!(
                "WATCH: challenge h={h} pred={} already broadcast; not paying again ({alert})",
                p.pred
            );
            return;
        }
        PostDecision::GaveUp => {
            eprintln!(
                "WATCH CRITICAL: challenge h={h} pred={} not retried (refused or failed \
                 {MAX_POST_FAILURES} times) — post it manually. Alert: {alert}",
                p.pred
            );
            return;
        }
    }
    let ctx = CHALLENGE_CTX.get().cloned().unwrap_or_default();
    let path = match write_private_proof(&ctx.proof_dir, h, &p.pred, &p.data) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("WATCH CRITICAL (NOT CHALLENGED: proof write failed: {e}): {alert}");
            return;
        }
    };
    let obyte_local = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../obyte-local");
    let mut cmd = Command::new("node");
    if mode == ChallengeMode::Live {
        let network =
            env_var_compat("MINUEND_WATCH_NETWORK").unwrap_or_else(|| "mainnet".to_string());
        let script = obyte_local.join("post_challenge_live.js");
        cmd.args(live_challenge_args(&script, h, p, &path, &network, &ctx));
        eprintln!(
            "posting live challenge: pred={} target={} h={h} network={network} rollup={} proof={}",
            p.pred,
            p.target(),
            ctx.rollup,
            path.display()
        );
    } else {
        // DevnetDrill: local aa-testkit only, so no --hub and no mnemonic in
        // the child's environment (post_challenge.js refuses both by design).
        let script = obyte_local.join("post_challenge.js");
        let mut args: Vec<std::ffi::OsString> = vec![
            script.as_os_str().to_owned(),
            "--height".into(),
            h.to_string().into(),
            "--pred".into(),
            p.pred.clone().into(),
            "--proof".into(),
            path.as_os_str().to_owned(),
        ];
        match p.target() {
            "fill" => args.push("--fill".into()),
            "bind" => args.push("--bind".into()),
            _ => {}
        }
        cmd.args(args)
            .env_remove("MINUEND_WATCH_MNEMONIC")
            .env_remove("OPERP_WATCH_MNEMONIC");
        eprintln!(
            "spawning (devnet drill): node {} pred={} target={}",
            script.display(),
            p.pred,
            p.target()
        );
    }
    match cmd.spawn() {
        Ok(child) => with_tracker(|t| {
            let st = t.states.entry(key.clone()).or_default();
            st.in_flight = true;
            t.children
                .insert(key, (child, format!("proof={} alert: {alert}", path.display())));
        }),
        Err(e) => {
            with_tracker(|t| t.states.entry(key).or_default().failures += 1);
            eprintln!(
                "WATCH CRITICAL: challenge for h={h} was NOT posted (spawn failed: {e}). \
                 proof={} Alert: {alert}",
                path.display()
            );
        }
    }
}

fn main() -> anyhow::Result<()> {
    let args = parse_args().map_err(|e| anyhow::anyhow!(e))?;
    // Vault is the evidence payee; rollup is the assertion AA. Replay reads
    // it via minuend_settle::expected_vault() (env MINUEND_VAULT_AA).
    std::env::set_var("MINUEND_VAULT_AA", &args.vault);
    let hub = HttpHubClient::new(&args.hub)?;
    let config = WatchConfig {
        rollup_address: args.rollup.clone(),
        vault_address: args.vault.clone(),
        dispute_address: args.dispute.clone(),
        hub_url: Some(args.hub.clone()),
        poll_interval_secs: args.poll_interval_secs,
        challenge_bond_gross: args.bond,
    };
    // R2-R-9: resume from the replay checkpoint when --state-dir has one;
    // otherwise the engine starts at genesis. A start height the engine
    // cannot reach (no state for from_height-1) is refused up front.
    let mut engine = match &args.state_dir {
        Some(dir) => load_checkpoint(dir)?.unwrap_or_else(Engine::new),
        None => Engine::new(),
    };
    let checkpoint_h = (engine.state.height > 0).then_some(engine.state.height);
    let start = resolve_start_height(args.from_height, checkpoint_h).map_err(|e| anyhow::anyhow!(e))?;
    if let Some(ch) = checkpoint_h {
        println!(
            "minuend-watch: resumed from checkpoint h={ch} (state_root {})",
            hex::encode(engine.state.state_root())
        );
        // Sanity: the checkpoint should match the chain's stored root.
        if let Ok(Some(v)) =
            hub.get_aa_state_var(&config.rollup_address, &format!("state_root_{ch}"))
        {
            let onchain = v.as_str().unwrap_or("").to_string();
            let mine = hex::encode(engine.state.state_root());
            if onchain != mine {
                println!(
                    "WATCH ALERT: checkpoint h={ch} state_root {mine} != on-chain state_root_{ch} \
                     {onchain} (height re-submitted or checkpoint not trusted)"
                );
            }
        }
    }
    let proof_dir = match &args.state_dir {
        Some(d) => d.join("proofs"),
        None => std::env::temp_dir().join(format!(
            "minuend-watch-{}-{}",
            std::process::id(),
            now_secs()
        )),
    };
    let _ = CHALLENGE_CTX.set(ChallengeCtx {
        rollup: args.rollup.clone(),
        dispute_main: args.dispute.clone(),
        dispute_fill: args.dispute_fill.clone(),
        dispute_bind: args.dispute_bind.clone(),
        proof_dir,
    });

    println!(
        "minuend-watch: watching {} via {} — every {}s, dispute window submitted_at+3600",
        config.rollup_address, args.hub, config.poll_interval_secs
    );

    // L5 (#47): say up front what will happen to a challengeable alert.
    match current_challenge_mode() {
        ChallengeMode::PrintOnly => eprintln!(
            "minuend-watch: no MINUEND_WATCH_MNEMONIC — alerts are print-only"
        ),
        ChallengeMode::Live => eprintln!(
            "minuend-watch: MINUEND_WATCH_MNEMONIC set — challenges are posted live via \
             obyte-local/post_challenge_live.js (network {}, stop {}s before the deadline)",
            env_var_compat("MINUEND_WATCH_NETWORK").unwrap_or_else(|| "mainnet".to_string()),
            CHALLENGE_SAFETY_MARGIN_SECS
        ),
        ChallengeMode::DevnetDrill => eprintln!(
            "minuend-watch: MINUEND_WATCH_DEVNET_CHALLENGE=1 — challenges are local aa-testkit drills only"
        ),
    }

    // #37-13: cross-round replay cursor. Only a height whose replay ADVANCED
    // the engine moves it, so a gap or a mismatch is retried next round
    // instead of being silently skipped or re-checked against stale state.
    let mut cursor = ReplayCursor::new(start);

    loop {
        // R2-R-11: report background challenge posters that finished.
        for line in with_tracker(|t| t.poll()) {
            eprintln!("{line}");
        }
        let ll = hub
            .get_aa_state_var(&config.rollup_address, "last_submitted")
            .map_err(|e| anyhow::anyhow!("hub last_submitted: {e}"))?
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let mut stalled: Option<u64> = None;
        for h in cursor.next_start()..=ll {
            let mut advanced = false;
            match check_height(&hub, &config, &mut engine, h, &mut advanced) {
                Ok(None) => {}
                Ok(Some(msg)) => println!("WATCH ALERT: {msg}"),
                Err(e) => println!("WATCH ERROR at h={h}: {e}"),
            }
            if advanced {
                cursor.record(h);
                // R2-R-9: checkpoint every replay-verified height.
                if let Some(dir) = &args.state_dir {
                    if let Err(e) = save_checkpoint(dir, &engine) {
                        println!("WATCH ERROR: checkpoint at h={h} failed: {e}");
                    }
                }
            } else {
                // No DA yet, or a mismatch this round: the replay retries
                // from here next round (never advance past an unreplayed
                // height).
                cursor.note_stall(h);
                stalled = Some(h);
                break;
            }
        }
        // L4 (#47): never go silent above a stuck height. Report the stall
        // and keep running the replay-free checks on later heights that are
        // still challengeable.
        if let Some(h) = stalled {
            if let Some(msg) = cursor.stall_alert(ll) {
                println!("WATCH ALERT: {msg}");
                for later in h.saturating_add(1)..=ll {
                    match check_height_without_replay(&hub, &config, later) {
                        Ok(None) => {}
                        Ok(Some(msg)) => println!("WATCH ALERT: {msg}"),
                        Err(e) => println!("WATCH ERROR at h={later}: {e}"),
                    }
                }
            }
        }

        std::thread::sleep(Duration::from_secs(config.poll_interval_secs));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        challenge_mode, challenge_postable, challenge_window_open, live_challenge_args,
        post_decision, record_exit, AttemptState, ChallengeCtx, ChallengeMode, PostDecision,
        ReplayCursor, CHALLENGE_SAFETY_MARGIN_SECS, CHALLENGE_WINDOW_SECS, LIVE_EXIT_REFUSED,
        MAX_POST_FAILURES,
    };

    /// B10 (#47): posting stops CHALLENGE_SAFETY_MARGIN_SECS before the AA
    /// deadline while the window itself is still reported open.
    #[test]
    fn challenge_posting_keeps_a_safety_margin() {
        let sa = 1_760_000_000;
        let deadline = sa + CHALLENGE_WINDOW_SECS;
        assert!(challenge_postable(sa, sa + 1, 0));
        assert!(challenge_postable(
            sa,
            deadline - CHALLENGE_SAFETY_MARGIN_SECS - 1,
            0
        ));
        let late = deadline - CHALLENGE_SAFETY_MARGIN_SECS;
        assert!(!challenge_postable(sa, late, 0));
        assert!(
            challenge_window_open(sa, late, 0),
            "window itself still open"
        );
        assert!(!challenge_postable(sa, deadline, 0));
        assert!(!challenge_postable(sa, sa + 1, 2), "frozen height");
        assert!(!challenge_postable(0, 5, 0), "not submitted");
        const { assert!(CHALLENGE_SAFETY_MARGIN_SECS < CHALLENGE_WINDOW_SECS) };
    }

    /// L5 (#47): a configured key selects the live poster (a key always
    /// wins over the devnet drill); no key and no drill = print only.
    #[test]
    fn challenge_mode_selects_live_poster_with_a_key() {
        assert_eq!(challenge_mode(false, false), ChallengeMode::PrintOnly);
        assert_eq!(challenge_mode(true, false), ChallengeMode::Live);
        assert_eq!(challenge_mode(true, true), ChallengeMode::Live);
        assert_eq!(challenge_mode(false, true), ChallengeMode::DevnetDrill);
    }

    /// L5 (#47): the live poster gets the height, predicate, proof file,
    /// dispute-AA target and network — and never a `--hub` URL or key.
    #[test]
    fn live_challenge_args_name_the_target_aa() {
        let mk = |fill_aa: bool, bind_aa: bool| minuend_watch::prove::BuiltProof {
            pred: "wpin".into(),
            fill_aa,
            bind_aa,
            data: serde_json::json!({}),
        };
        let script = std::path::Path::new("/x/post_challenge_live.js");
        let proof = std::path::Path::new("/tmp/p.json");
        let ctx = ChallengeCtx {
            rollup: "R".repeat(32),
            ..Default::default()
        };
        let args: Vec<String> =
            live_challenge_args(script, 7, &mk(false, true), proof, "testnet", &ctx)
                .into_iter()
                .map(|a| a.into_string().unwrap())
                .collect();
        assert_eq!(
            args,
            vec![
                "/x/post_challenge_live.js",
                "--height",
                "7",
                "--pred",
                "wpin",
                "--proof",
                "/tmp/p.json",
                "--target",
                "bind",
                "--network",
                "testnet",
                "--rollup",
                &"R".repeat(32),
            ]
        );
        let fill = live_challenge_args(script, 7, &mk(true, false), proof, "mainnet", &ctx);
        assert!(fill.iter().any(|a| a == "fill"));
        let main = live_challenge_args(script, 7, &mk(false, false), proof, "mainnet", &ctx);
        assert!(main.iter().any(|a| a == "main"));
        assert!(!main.iter().any(|a| a == "--hub"));
    }

    /// R2-R-8: the live poster always gets the WATCHED rollup and, when the
    /// operator configured it, the matching dispute AA for the target.
    #[test]
    fn live_challenge_args_carry_watched_rollup_and_dispute() {
        let mk = |fill_aa: bool, bind_aa: bool| minuend_watch::prove::BuiltProof {
            pred: "deposit".into(),
            fill_aa,
            bind_aa,
            data: serde_json::json!({}),
        };
        let ctx = ChallengeCtx {
            rollup: "X".repeat(32),
            dispute_main: Some("M".repeat(32)),
            dispute_fill: None,
            dispute_bind: Some("B".repeat(32)),
            proof_dir: Default::default(),
        };
        let s = std::path::Path::new("/x/p.js");
        let p = std::path::Path::new("/tmp/p.json");
        let strs = |v: Vec<std::ffi::OsString>| -> Vec<String> {
            v.into_iter().map(|a| a.into_string().unwrap()).collect()
        };
        let main = strs(live_challenge_args(s, 3, &mk(false, false), p, "mainnet", &ctx));
        let i = main.iter().position(|a| a == "--rollup").unwrap();
        assert_eq!(main[i + 1], "X".repeat(32));
        let j = main.iter().position(|a| a == "--dispute-address").unwrap();
        assert_eq!(main[j + 1], "M".repeat(32));
        let bind = strs(live_challenge_args(s, 3, &mk(false, true), p, "mainnet", &ctx));
        assert!(bind.contains(&"B".repeat(32)));
        let fill = strs(live_challenge_args(s, 3, &mk(true, false), p, "mainnet", &ctx));
        assert!(!fill.iter().any(|a| a == "--dispute-address"));
        assert!(fill.contains(&"X".repeat(32)));
    }

    /// R2-R-11: a challenge in flight or already broadcast is never posted
    /// (and paid for) again; errors retry a bounded number of times; a
    /// window refusal is final.
    #[test]
    fn challenge_tracker_never_double_posts() {
        assert_eq!(post_decision(None), PostDecision::Post);
        let mut st = AttemptState {
            in_flight: true,
            ..Default::default()
        };
        assert_eq!(post_decision(Some(&st)), PostDecision::InFlight);
        record_exit(&mut st, Some(0));
        assert_eq!(post_decision(Some(&st)), PostDecision::AlreadyBroadcast);

        let mut e = AttemptState::default();
        for _ in 0..MAX_POST_FAILURES - 1 {
            record_exit(&mut e, Some(1));
            assert_eq!(post_decision(Some(&e)), PostDecision::Post);
        }
        record_exit(&mut e, None);
        assert_eq!(post_decision(Some(&e)), PostDecision::GaveUp);

        let mut r = AttemptState::default();
        record_exit(&mut r, Some(LIVE_EXIT_REFUSED));
        assert_eq!(post_decision(Some(&r)), PostDecision::GaveUp);
    }

    /// L4 (#47): a stuck height is tracked and reported (after the second
    /// round), listing the later heights that are not replay-verified; a
    /// successful replay clears it.
    #[test]
    fn replay_cursor_surfaces_persistent_stall() {
        let mut c = ReplayCursor::new(1);
        c.record(4);
        assert_eq!(c.note_stall(5), 1);
        assert!(c.stall_alert(9).is_none(), "one missing round is normal");
        assert_eq!(c.note_stall(5), 2);
        let msg = c.stall_alert(9).unwrap();
        assert!(msg.contains("h=5"), "{msg}");
        assert!(msg.contains("6..=9"), "{msg}");
        // Stall moves to a new height → counter restarts.
        assert_eq!(c.note_stall(6), 1);
        c.record(6);
        assert!(c.stall_alert(9).is_none());
        assert_eq!(c.next_start(), 7);
    }

    #[test]
    fn normal_seconds_timestamp_is_inside_challenge_window() {
        let submitted_at_secs = 1_760_000_000;
        assert!(challenge_window_open(
            submitted_at_secs,
            submitted_at_secs + 1_800,
            0
        ));
    }

    #[test]
    fn replay_cursor_starts_at_configured_height_and_advances_monotonically() {
        let mut cursor = ReplayCursor::new(1);
        assert_eq!(cursor.next_start(), 1);
        cursor.record(3);
        assert_eq!(cursor.next_start(), 4);
        // Stale/out-of-order records never move it backwards.
        cursor.record(2);
        assert_eq!(cursor.next_start(), 4);
        // A cursor constructed above 1 honours its own floor.
        let mut later = ReplayCursor::new(10);
        assert_eq!(later.next_start(), 10);
        later.record(11);
        assert_eq!(later.next_start(), 12);
    }

    #[test]
    fn challenge_window_closes_at_deadline_and_when_frozen() {
        let submitted_at_secs = 1_760_000_000;
        assert!(!challenge_window_open(
            submitted_at_secs,
            submitted_at_secs + 3_600,
            0
        ));
        assert!(!challenge_window_open(
            submitted_at_secs,
            submitted_at_secs + 1,
            1
        ));
        assert!(!challenge_window_open(0, submitted_at_secs, 0));
    }
}
