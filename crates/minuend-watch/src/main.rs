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
    batch_from_committed, check_committed_roots, clear_temp_checkpoints, committed_frame_bytes,
    create_private_temp_dir, fetch_da_unit, load_checkpoint, load_checkpoint_at, lock_temp_dir,
    pick_root_verified_checkpoint, prove, read_vault_ledger_bounded, regressed_tip_contradictory,
    resolve_start_height, rewind_target, root_diverged, sane_chain_readings,
    save_checkpoint_retaining, sweep_stale_temp_dirs, tip_awaiting_resubmission, vault_keys_needed,
    verify_da_binding, write_private_proof, ChainView, HubClient, VaultReadCache, WatchConfig,
    WatchError, CHALLENGE_BOND_GROSS, DEFAULT_POLL_INTERVAL_SECS, MAX_VAULT_READS_PER_HEIGHT,
    TEMP_DIR_OWNER_FILE, VAULT_READ_BUDGET_SECS, VAULT_READ_DEADLINE_RESERVE_SECS,
};
use std::collections::BTreeMap;
use std::env;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
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

        // R5-R-2: bounded connect (the OS default is ~2 min per attempt).
        let mut stream = self.connect()?;
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
            return Err(format!(
                "hub response exceeds {MAX_HUB_RESPONSE_BYTES} bytes"
            ));
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

impl HttpHubClient {
    fn connect(&self) -> Result<std::net::TcpStream, String> {
        use std::net::ToSocketAddrs;
        let addrs = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| e.to_string())?;
        let mut last = String::from("hub host resolved to no address");
        for a in addrs {
            match std::net::TcpStream::connect_timeout(&a, HUB_CONNECT_TIMEOUT) {
                Ok(s) => return Ok(s),
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    }
}

/// R5-R-2: TCP connect timeout per hub address.
const HUB_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
    dispute_book: Option<String>,
    dispute_claw: Option<String>,
    dispute_xframe: Option<String>,
    dispute_mframe: Option<String>,
    dispute_wf: Option<String>,
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
    let mut dispute_book = None;
    let mut dispute_claw = None;
    let mut dispute_xframe = None;
    let mut dispute_mframe = None;
    let mut dispute_wf = None;
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
            "--dispute-book" => {
                dispute_book = Some(it.next().ok_or("--dispute-book needs a value")?)
            }
            "--dispute-claw" => {
                dispute_claw = Some(it.next().ok_or("--dispute-claw needs a value")?)
            }
            "--dispute-mframe" => {
                dispute_mframe = Some(it.next().ok_or("--dispute-mframe needs a value")?)
            }
            "--dispute-wf" => dispute_wf = Some(it.next().ok_or("--dispute-wf needs a value")?),
            "--dispute-xframe" => {
                dispute_xframe = Some(it.next().ok_or("--dispute-xframe needs a value")?)
            }
            "--state-dir" => {
                state_dir = Some(PathBuf::from(it.next().ok_or("--state-dir needs a value")?))
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
        dispute_book,
        dispute_claw,
        dispute_xframe,
        dispute_mframe,
        dispute_wf,
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
 [--dispute-fill <addr>] [--dispute-bind <addr>] [--dispute-book <addr>] [--dispute-claw <addr>] [--dispute-xframe <addr>] [--dispute-mframe <addr>] [--dispute-wf <addr>] [--state-dir <dir>] [--from-height <u64>] \
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
    /// Round 2: P-ghost / P-skip live on `minuend_dispute_book.aa`
    /// (rollup var `dispute_book_aa`).
    dispute_book: Option<String>,
    /// Round 6: P-claw lives on `minuend_dispute_claw.aa` (rollup var
    /// `dispute_claw_aa`).
    dispute_claw: Option<String>,
    /// Round 7b: P-xframe (+ P-tsize since round 8) lives on
    /// `minuend_dispute_xframe.aa` (rollup var `dispute_xframe_aa`).
    dispute_xframe: Option<String>,
    /// Round 8: P-mframe lives on `minuend_dispute_mframe.aa` (rollup var
    /// `dispute_mframe_aa`); P-noband moved to the claw AA in round 9.
    dispute_mframe: Option<String>,
    /// Round 10: P-wf (malformed leaf / fill field) lives on
    /// `minuend_dispute_wf.aa` (rollup var `dispute_wf_aa`).
    dispute_wf: Option<String>,
    proof_dir: PathBuf,
}

impl ChallengeCtx {
    fn dispute_for(&self, target: &str) -> Option<&str> {
        // A target with no configured address gets none: the live poster
        // then uses the rollup's own `dispute_*_aa` binding.
        match target {
            "main" => self.dispute_main.as_deref(),
            "book" => self.dispute_book.as_deref(),
            "claw" => self.dispute_claw.as_deref(),
            "xframe" => self.dispute_xframe.as_deref(),
            "mframe" => self.dispute_mframe.as_deref(),
            "wf" => self.dispute_wf.as_deref(),
            "fill" => self.dispute_fill.as_deref(),
            "bind" => self.dispute_bind.as_deref(),
            _ => None,
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

/// R2-R-11 / R3-R-3: per `(height, submission, predicate)` challenge
/// bookkeeping, so a challenge
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

/// R3-R-3: a challenge is identified by the height, the SUBMISSION it
/// disputes (the `da_unit_<h>` the replay judged) and the predicate. A
/// height that was frozen and re-submitted is a new submission: its fraud is
/// challenged again even when the predicate repeats, and a refusal or
/// give-up on the old submission does not carry over.
type ChallengeKey = (u64, String, String);

fn challenge_key(h: u64, submission: &str, pred: &str) -> ChallengeKey {
    (h, submission.to_string(), pred.to_string())
}

#[derive(Default)]
struct ChallengeTracker {
    states: BTreeMap<ChallengeKey, AttemptState>,
    children: BTreeMap<ChallengeKey, (Child, String)>,
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
            let (h, _, pred) = key;
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

    /// R3-R-2: the engine was rewound to the state after `height` (heights
    /// above it are dead on-chain); replay resumes right after it.
    fn rewind_to(&mut self, height: u64) {
        self.processed_upto = height;
        self.from_height = self.from_height.min(height.saturating_add(1));
        self.stalled_at = None;
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
    submission: &str,
    win: WindowFacts,
    alert: String,
    proof: Option<&prove::BuiltProof>,
) -> String {
    let now = now_secs();
    if challenge_postable(win.submitted_at, now, win.frozen) {
        maybe_post_challenge(h, submission, &alert, proof);
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
                "",
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
            &da.unit_hash,
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
                &da.unit_hash,
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
                    &da.unit_hash,
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
            &da.unit_hash,
            win,
            format!("h={h} UNDECODABLE BATCH ({e}) above a replay stall"),
            None,
        )));
    }
    Ok(None)
}

/// R4-A-4 / R5-R-2: the vault's `dep_`/`depp_<anchor>` records a P-adr
/// proof of `batch` could need ([`vault_keys_needed`]: derived from the
/// units' real ops, only for posted new bindings not covered by verified
/// evidence), read with hard bounds — at most
/// [`MAX_VAULT_READS_PER_HEIGHT`] reads, within
/// [`VAULT_READ_BUDGET_SECS`] and never later than
/// [`VAULT_READ_DEADLINE_RESERVE_SECS`] before the challenge-posting
/// deadline, every outcome cached for the round (`cache`). Unread keys stay
/// unknown: the proof builder then stays silent on the backing condition.
fn read_vault_ledger<H: HubClient>(
    hub: &H,
    vault: &str,
    batch: &minuend_settle::Batch,
    submitted_at: u64,
    cache: &mut VaultReadCache,
) -> prove::VaultLedger {
    let keys = vault_keys_needed(batch);
    if keys.is_empty() {
        return prove::VaultLedger::new();
    }
    let post_deadline = submitted_at
        .saturating_add(CHALLENGE_WINDOW_SECS)
        .saturating_sub(CHALLENGE_SAFETY_MARGIN_SECS)
        .saturating_sub(VAULT_READ_DEADLINE_RESERVE_SECS);
    let deadline = post_deadline.min(now_secs().saturating_add(VAULT_READ_BUDGET_SECS));
    let ledger = read_vault_ledger_bounded(
        hub,
        vault,
        &keys,
        cache,
        MAX_VAULT_READS_PER_HEIGHT,
        deadline,
        &mut now_secs,
    );
    if ledger.len() < keys.len() {
        eprintln!(
            "WATCH: vault records known for {}/{} deposit anchors of this batch (read budget, \
             deadline or hub errors); proofs resting on the others are not built",
            ledger.len(),
            keys.len()
        );
    }
    ledger
}

/// Replay one height and advance the engine; surface only actionable alerts.
/// Returns `Ok(None)` = nothing actionable (no da_unit, or replay clean),
/// `Ok(Some(alert))` = a mismatch worth surfacing.
/// `advanced` receives the replayed submission (`da_unit_<h>`) when the
/// height advanced the engine.
fn check_height(
    hub: &HttpHubClient,
    config: &WatchConfig,
    engine: &mut Engine,
    h: u64,
    advanced: &mut Option<String>,
    vault_cache: &mut VaultReadCache,
    prev_final: &mut Option<(u64, Vec<String>)>,
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
                &da.unit_hash,
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
            // R8 residue: keep this height's committed final witness leaves
            // (validated leaf_trace tail, pre commit-prune) — the k == 0
            // pre tree of h + 1 that every dispute AA anchors on.
            *prev_final = batch.leaf_trace.last().cloned().map(|l| (h, l));
            // #37-13: the engine now sits at this height — the poll loop
            // advances its cursor so the next round does not re-scan old
            // heights against an advanced engine (PrevMismatch noise) and
            // does not skip a gap.
            *advanced = Some(da.unit_hash.clone());
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
        // R4-A-4: read the vault ledger records the binding AA would read
        // for this batch's deposit anchors, so a P-adr proof is built only
        // when the AA would actually judge it (a hub error leaves the key
        // unknown, never "absent").
        let vault_ledger = read_vault_ledger(
            hub,
            &config.vault_address,
            &batch,
            win.submitted_at,
            vault_cache,
        );
        let prev = prev_final
            .as_ref()
            .filter(|(ph, _)| *ph + 1 == h)
            .map(|(_, l)| l.as_slice());
        prove::build_proof_with_prev(
            &batch,
            &mut scratch,
            &inbox,
            win.submitted_at,
            &vault_ledger,
            prev,
        )
    };
    Ok(Some(alert_and_maybe_challenge(
        h,
        &da.unit_hash,
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
fn maybe_post_challenge(h: u64, submission: &str, alert: &str, proof: Option<&prove::BuiltProof>) {
    let mode = current_challenge_mode();
    if mode == ChallengeMode::PrintOnly {
        eprintln!("WATCH ALERT (print-only, no MINUEND_WATCH_MNEMONIC): {alert}");
        return;
    }
    let Some(p) = proof else {
        eprintln!("WATCH ALERT (NOT CHALLENGED: no expressible proof): {alert}");
        return;
    };
    let key = challenge_key(h, submission, &p.pred);
    match with_tracker(|t| post_decision(t.states.get(&key))) {
        PostDecision::Post => {}
        PostDecision::InFlight => {
            eprintln!(
                "WATCH: challenge h={h} pred={} already in flight ({alert})",
                p.pred
            );
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
            "book" => args.push("--book".into()),
            "claw" => args.push("--claw".into()),
            "xframe" => args.push("--xframe".into()),
            "mframe" => args.push("--mframe".into()),
            "wf" => args.push("--wf".into()),
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
            t.children.insert(
                key,
                (child, format!("proof={} alert: {alert}", path.display())),
            );
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

/// Read one numeric rollup-AA state var (absent = 0).
fn read_u64_var(hub: &HttpHubClient, config: &WatchConfig, key: &str) -> anyhow::Result<u64> {
    Ok(hub
        .get_aa_state_var(&config.rollup_address, key)
        .map_err(|e| anyhow::anyhow!("hub {key}: {e}"))?
        .and_then(|v| v.as_u64())
        .unwrap_or(0))
}

/// R3-R-2: the chain's current view of the accepted, not yet final heights.
fn chain_view(
    hub: &HttpHubClient,
    config: &WatchConfig,
    last_submitted: u64,
    last_finalized: u64,
    processed_upto: u64,
) -> anyhow::Result<ChainView> {
    let mut view = ChainView {
        last_submitted,
        last_finalized,
        frozen_at_last_submitted: read_u64_var(hub, config, &format!("frozen_{last_submitted}"))?,
        ..Default::default()
    };
    for h in last_finalized.saturating_add(1)..=processed_upto.min(last_submitted) {
        let v = hub
            .get_aa_state_var(&config.rollup_address, &format!("da_unit_{h}"))
            .map_err(|e| anyhow::anyhow!("hub da_unit_{h}: {e}"))?;
        view.da_units
            .insert(h, v.and_then(|v| v.as_str().map(str::to_string)));
    }
    Ok(view)
}

/// R3-R-2: load the checkpoint at `target` (or the newest one below it) and
/// retire every checkpoint above it (the dead branch). Returns the engine
/// and the height it sits at (0 = genesis).
///
/// R4-R-4 / I-4: dead-branch checkpoints are MOVED to `dead/`, never
/// deleted, and when no checkpoint at or below a non-zero `target` loads,
/// nothing is touched and the rewind fails (the old code wiped every
/// checkpoint and restarted from genesis, unrecoverable once the DA of the
/// early heights expired). Genesis is only used for `target == 0`, or when
/// `genesis_fallback` is set (a temp-dir run, which started from genesis
/// anyway and keeps only a capped number of checkpoints, R4-R-7).
///
/// R5-R-3: before falling back to genesis, `genesis_ok()` must confirm the
/// DA of h=1 can still be fetched; otherwise nothing is changed and a
/// CRITICAL alert says why (a genesis replay would sit on h=1 forever).
fn rewind_engine(
    dir: &std::path::Path,
    target: u64,
    genesis_fallback: bool,
    genesis_ok: &mut dyn FnMut() -> bool,
) -> anyhow::Result<(Engine, u64)> {
    let mut heights = minuend_state::persist::snapshot_heights(dir)?;
    heights.retain(|h| *h <= target);
    for h in heights {
        if let Ok(Some(e)) = load_checkpoint_at(dir, h) {
            minuend_state::persist::retire_snapshots_above(dir, h)?;
            return Ok((e, h));
        }
    }
    if target > 0 && !genesis_fallback {
        return Err(anyhow::anyhow!(
            "no readable checkpoint at or below h={target}; nothing was changed"
        ));
    }
    if target > 0 && !genesis_ok() {
        return Err(genesis_unreachable(target));
    }
    minuend_state::persist::retire_snapshots_above(dir, 0)?;
    Ok((Engine::new(), 0))
}

/// R5-R-3: the loud refusal when a temp-dir rewind would have to replay
/// from genesis but h=1's DA is gone.
fn genesis_unreachable(target: u64) -> anyhow::Error {
    let msg = format!(
        "a rewind to h={target} would have to replay from GENESIS, but the DA of h=1 can no \
         longer be fetched (temp_data purged after ~24 h): nothing was changed. This watcher \
         cannot verify heights above h={target} any more — restart it with --state-dir and a \
         trusted checkpoint"
    );
    eprintln!("WATCH CRITICAL: {msg}");
    anyhow::anyhow!(msg)
}

/// R5-R-3: can a genesis replay still start, i.e. is the DA of h=1
/// (`da_unit_1` and its temp_data) still on the hub?
fn genesis_da_available(hub: &HttpHubClient, config: &WatchConfig) -> bool {
    matches!(fetch_da_unit(hub, &config.rollup_address, 1), Ok(Some(_)))
}

/// R4-R-6: the engine's root at `processed_upto` no longer matches the
/// chain's `state_root_<processed_upto>` (a height we accepted was judged
/// and re-submitted, and possibly finalized, before we looked). Rewind to
/// the newest checkpoint whose root the chain still has; checkpoints above
/// it are retired to `dead/`. Errors (hub, no matching checkpoint) leave
/// everything untouched, except that a temp-dir run (`genesis_fallback`,
/// which started from genesis and keeps few checkpoints) replays from
/// genesis when no checkpoint matches.
fn rewind_to_chain_root(
    hub: &HttpHubClient,
    config: &WatchConfig,
    dir: &std::path::Path,
    below: u64,
    genesis_fallback: bool,
) -> anyhow::Result<(Engine, u64)> {
    let heights = minuend_state::persist::snapshot_heights(dir)?;
    // R5-R-5: one checkpoint in memory at a time: each candidate is loaded,
    // its root computed and the engine dropped; only the chosen height is
    // loaded again below.
    let pick = pick_root_verified_checkpoint(
        &heights,
        below,
        |h| checkpoint_root(dir, h),
        |h| hub.get_aa_state_var(&config.rollup_address, &format!("state_root_{h}")),
    )
    .map_err(|e| anyhow::anyhow!("hub: {e}"))?;
    let Some(h) = pick else {
        if genesis_fallback {
            if !genesis_da_available(hub, config) {
                return Err(genesis_unreachable(below.saturating_sub(1)));
            }
            minuend_state::persist::retire_snapshots_above(dir, 0)?;
            return Ok((Engine::new(), 0));
        }
        return Err(anyhow::anyhow!(
            "no checkpoint below h={below} matches the chain's state_root; nothing was changed"
        ));
    };
    let engine =
        load_checkpoint_at(dir, h)?.ok_or_else(|| anyhow::anyhow!("checkpoint h={h} vanished"))?;
    minuend_state::persist::retire_snapshots_above(dir, h)?;
    Ok((engine, h))
}

/// R5-R-5: the state root of the checkpoint at `h` (`None` = unreadable);
/// the loaded engine is dropped before returning.
fn checkpoint_root(dir: &std::path::Path, h: u64) -> Option<String> {
    match load_checkpoint_at(dir, h) {
        Ok(Some(e)) => Some(hex::encode(e.state.state_root())),
        _ => None,
    }
}

/// R4-R-7 / R5-R-3: byte budget of a throw-away temp-dir checkpoint store
/// (no `--state-dir`), `dead/` included. Checkpoints are kept back to
/// `last_finalized` within it; the newest and the floor checkpoint (newest
/// at or below `last_finalized`) are always kept
/// (`persist::cap_snapshots_keep_floor`), so a rewind never has to fall
/// back to genesis.
const TEMP_MAX_CHECKPOINT_BYTES: u64 = 1024 * 1024 * 1024;
/// R5-R-6: a temp-dir run keeps at most this many dead-branch checkpoints
/// (within [`TEMP_MAX_CHECKPOINT_BYTES`] together with the live ones).
const TEMP_MAX_DEAD_CHECKPOINTS: usize = 2;
/// R5-R-6: `--state-dir` runs keep at most this many dead-branch
/// checkpoints in `dead/` …
const DEAD_MAX_CHECKPOINTS: usize = 16;
/// … and at most this many bytes of them.
const DEAD_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// R5-R-6: cap `dead/` after a retirement (both modes) and, in temp mode,
/// the whole store to its byte budget.
fn cap_store(dir: &std::path::Path, temp_mode: bool, last_finalized: u64) {
    let (n, bytes) = if temp_mode {
        (TEMP_MAX_DEAD_CHECKPOINTS, TEMP_MAX_CHECKPOINT_BYTES / 4)
    } else {
        (DEAD_MAX_CHECKPOINTS, DEAD_MAX_BYTES)
    };
    if let Err(e) = minuend_state::persist::cap_dead_snapshots(dir, n, bytes) {
        println!("WATCH ERROR: capping {}/dead failed: {e}", dir.display());
    }
    if temp_mode {
        let dead = minuend_state::persist::snapshot_store_bytes(&dir.join("dead")).unwrap_or(0);
        if let Err(e) = minuend_state::persist::cap_snapshots_keep_floor(
            dir,
            last_finalized,
            TEMP_MAX_CHECKPOINT_BYTES.saturating_sub(dead),
        ) {
            println!("WATCH ERROR: capping temp checkpoints failed: {e}");
        }
    }
}

/// R4-R-7: clears this run's temp checkpoints when `main` returns or
/// unwinds (proofs are kept). R5-R-6: SIGINT/SIGTERM make the poll loop
/// return, so this runs on a normal stop too; a run killed hard (SIGKILL)
/// is cleaned up by the next run's `sweep_stale_temp_dirs` (R5-R-7: its
/// `flock` on the lock file is gone with the process).
struct TempCheckpointGuard(Option<PathBuf>, Option<minuend_watch::TempDirLock>);

impl Drop for TempCheckpointGuard {
    fn drop(&mut self) {
        if let Some(dir) = &self.0 {
            clear_temp_checkpoints(dir);
        }
        self.1.take();
    }
}

/// R5-R-6: set by SIGINT / SIGTERM; the poll loop returns at its next check.
static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
mod sig {
    use std::os::raw::c_int;
    pub const SIGINT: c_int = 2;
    pub const SIGTERM: c_int = 15;
    extern "C" {
        pub fn signal(signum: c_int, handler: usize) -> usize;
    }
    pub extern "C" fn on_stop(_: c_int) {
        // Async-signal-safe: one atomic store.
        super::STOP.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// R5-R-6: route SIGINT / SIGTERM to [`STOP`] (no new dependency).
fn install_stop_handlers() {
    #[cfg(unix)]
    {
        let h = sig::on_stop as extern "C" fn(std::os::raw::c_int) as usize;
        // SAFETY: installs an async-signal-safe handler (a single atomic
        // store) for two standard signals.
        unsafe {
            sig::signal(sig::SIGINT, h);
            sig::signal(sig::SIGTERM, h);
        }
    }
}

fn stop_requested() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// R5-R-6: sleep `secs`, waking early when a stop is requested.
fn sleep_unless_stopped(secs: u64) {
    let until = std::time::Instant::now() + Duration::from_secs(secs);
    while !stop_requested() {
        let now = std::time::Instant::now();
        if now >= until {
            break;
        }
        std::thread::sleep((until - now).min(Duration::from_millis(200)));
    }
}

/// R3-R-2 / R3-R-7: pick the checkpoint to resume from. The newest
/// checkpoint whose height is still live on-chain and whose state root
/// equals the chain's `state_root_<h>` wins; checkpoints above it (a branch
/// that was judged fraudulent and re-submitted while the watcher was down)
/// are deleted. If checkpoints exist but none matches, or the chain cannot
/// be read, startup fails hard instead of replaying from a dead branch.
fn resume_engine(
    hub: &HttpHubClient,
    config: &WatchConfig,
    dir: &std::path::Path,
) -> anyhow::Result<Option<Engine>> {
    // R3-R-7: all-unreadable checkpoints are an error here (not genesis).
    if load_checkpoint(dir)?.is_none() {
        return Ok(None);
    }
    let ls = read_u64_var(hub, config, "last_submitted")?;
    let live_top = if read_u64_var(hub, config, &format!("frozen_{ls}"))? == 2 {
        ls.saturating_sub(1)
    } else {
        ls
    };
    for h in minuend_state::persist::snapshot_heights(dir)? {
        if h > live_top {
            println!("minuend-watch: checkpoint h={h} is above the live chain tip h={live_top}; skipping");
            continue;
        }
        let Ok(Some(engine)) = load_checkpoint_at(dir, h) else {
            println!("minuend-watch: checkpoint h={h} is unreadable; trying an older one");
            continue;
        };
        let onchain = hub
            .get_aa_state_var(&config.rollup_address, &format!("state_root_{h}"))
            .map_err(|e| anyhow::anyhow!("hub state_root_{h}: {e} (cannot verify the checkpoint)"))?
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        let mine = hex::encode(engine.state.state_root());
        if onchain == mine {
            // I-4: the dead branch is moved aside, not deleted.
            minuend_state::persist::retire_snapshots_above(dir, h)?;
            return Ok(Some(engine));
        }
        println!(
            "minuend-watch: checkpoint h={h} state_root {mine} != on-chain state_root_{h} \
             {onchain:?} (re-submitted or untrusted); trying an older one"
        );
    }
    Err(anyhow::anyhow!(
        "no checkpoint in {} matches the chain (live tip h={live_top}): refusing to resume \
         from an unverified state. Import a trusted chainstate.<h>.snap or clear the state dir \
         to replay from genesis on purpose",
        dir.display()
    ))
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
    // R3-R-6: without --state-dir a FRESH private directory with an
    // unpredictable name is created right now (never reused if it exists)
    // for proofs and this run's checkpoints, so nobody can pre-plant it.
    // R3-R-2: checkpoints are kept back to last_finalized either way, so
    // the replay can rewind when an accepted height is judged / re-submitted.
    let state_dir = match &args.state_dir {
        Some(d) => d.clone(),
        None => create_private_temp_dir("minuend-watch").map_err(|e| {
            anyhow::anyhow!("cannot create a private temp dir for proofs/checkpoints: {e}")
        })?,
    };
    // R4-R-7: a temp-dir run marks the dir as its own, clears the
    // checkpoints left behind by earlier killed runs, and clears its own on
    // exit; its checkpoint count/size is capped below.
    let temp_mode = args.state_dir.is_none();
    // R5-R-7: a temp-dir run holds an exclusive flock on its own lock file
    // for its whole life; sweeps of other runs (any PID namespace) skip it.
    let temp_lock = if temp_mode {
        Some(lock_temp_dir(&state_dir).map_err(|e| {
            anyhow::anyhow!(
                "cannot lock the private temp dir {}: {e}",
                state_dir.display()
            )
        })?)
    } else {
        None
    };
    let _temp_guard = TempCheckpointGuard(temp_mode.then(|| state_dir.clone()), temp_lock);
    install_stop_handlers();
    if temp_mode {
        let _ = std::fs::write(
            state_dir.join(TEMP_DIR_OWNER_FILE),
            std::process::id().to_string(),
        );
        for d in sweep_stale_temp_dirs("minuend-watch", &state_dir) {
            println!(
                "minuend-watch: cleared checkpoints left by a stopped run in {}",
                d.display()
            );
        }
    }
    let mut engine = match &args.state_dir {
        // R3-R-2 / R3-R-7: resume only from a checkpoint that matches the
        // chain (fail hard otherwise; never a warning, never silent genesis).
        Some(dir) => {
            let e = resume_engine(&hub, &config, dir)?.unwrap_or_else(Engine::new);
            // R5-R-6: resume may have retired a dead branch into dead/.
            cap_store(dir, false, 0);
            e
        }
        None => Engine::new(),
    };
    let checkpoint_h = (engine.state.height > 0).then_some(engine.state.height);
    let start =
        resolve_start_height(args.from_height, checkpoint_h).map_err(|e| anyhow::anyhow!(e))?;
    if let Some(ch) = checkpoint_h {
        println!(
            "minuend-watch: resumed from checkpoint h={ch} (state_root {}, matches the chain)",
            hex::encode(engine.state.state_root())
        );
    }
    let proof_dir = state_dir.join("proofs");
    let _ = CHALLENGE_CTX.set(ChallengeCtx {
        rollup: args.rollup.clone(),
        dispute_main: args.dispute.clone(),
        dispute_fill: args.dispute_fill.clone(),
        dispute_bind: args.dispute_bind.clone(),
        dispute_book: args.dispute_book.clone(),
        dispute_claw: args.dispute_claw.clone(),
        dispute_xframe: args.dispute_xframe.clone(),
        dispute_mframe: args.dispute_mframe.clone(),
        dispute_wf: args.dispute_wf.clone(),
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
    // R3-R-2: the submission (`da_unit_<h>`) each accepted, not yet final
    // height was replayed from.
    let mut accepted: BTreeMap<u64, String> = BTreeMap::new();
    // R4-R-4: highest last_finalized seen (finalization never goes back).
    let mut known_lf: u64 = 0;
    // R4-R-8: the frozen tip already announced as awaiting re-submission.
    let mut announced_frozen: Option<u64> = None;
    // R9-M1: the last validated height's committed final witness leaves
    // (the k == 0 pre tree of the next height) survive across poll rounds —
    // in steady state each round sees ONE new height, so a per-round value
    // was always empty and every k == 0 proof after a bond release bounced
    // 'bad pre wit'. Cleared on every rewind (keyed by height anyway).
    let mut prev_final: Option<(u64, Vec<String>)> = None;

    loop {
        if stop_requested() {
            println!("minuend-watch: stop signal received; exiting (temp checkpoints cleared)");
            return Ok(());
        }
        // R5-R-2: vault reads (failures included) are cached for one round.
        let mut vault_cache = VaultReadCache::new();
        // R2-R-11: report background challenge posters that finished.
        for line in with_tracker(|t| t.poll()) {
            eprintln!("{line}");
        }
        // R4-R-4 / I-1: a failed, empty or contradictory hub reading is
        // "unknown": skip the round (no rewind, no deletion) instead of
        // treating it as 0 — or exiting the process.
        let ls_raw = hub.get_aa_state_var(&config.rollup_address, "last_submitted");
        let lf_raw = hub.get_aa_state_var(&config.rollup_address, "last_finalized");
        let (ls_raw, lf_raw) = match (ls_raw, lf_raw) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e), _) | (_, Err(e)) => {
                println!("WATCH ERROR: hub last_submitted/last_finalized: {e}");
                sleep_unless_stopped(config.poll_interval_secs);
                continue;
            }
        };
        let (ll, lf) = match sane_chain_readings(
            ls_raw.and_then(|v| v.as_u64()),
            lf_raw.and_then(|v| v.as_u64()),
            known_lf,
            cursor.processed_upto,
        ) {
            Ok(r) => r,
            Err(why) => {
                println!("WATCH ERROR: {why}; skipping this round");
                sleep_unless_stopped(config.poll_interval_secs);
                continue;
            }
        };
        known_lf = known_lf.max(lf);

        // R5-R-4: last_submitted below the last verified height without the
        // verdict marker frozen_<ls>=2 and without a re-submitted
        // da_unit_<ls> is a contradictory (stale / lagging hub) reading:
        // skip the round instead of rewinding, retiring checkpoints and
        // re-replaying.
        if ll < cursor.processed_upto {
            let frozen = hub.get_aa_state_var(&config.rollup_address, &format!("frozen_{ll}"));
            let da = hub.get_aa_state_var(&config.rollup_address, &format!("da_unit_{ll}"));
            let skip = match (frozen, da) {
                (Ok(f), Ok(d)) => {
                    let f = f.and_then(|v| v.as_u64()).unwrap_or(0);
                    let d = d.and_then(|v| v.as_str().map(str::to_string));
                    regressed_tip_contradictory(
                        ll,
                        lf,
                        cursor.processed_upto,
                        f,
                        d.as_deref(),
                        accepted.get(&ll).map(String::as_str),
                    )
                    .then(|| {
                        format!(
                            "hub reports last_submitted={ll} below the verified h={} without \
                             frozen_{ll}=2 or a re-submitted da_unit_{ll} (contradictory reading)",
                            cursor.processed_upto
                        )
                    })
                }
                (Err(e), _) | (_, Err(e)) => Some(format!(
                    "hub frozen_{ll}/da_unit_{ll} unreadable while last_submitted={ll} is below \
                     the verified h={}: {e}",
                    cursor.processed_upto
                )),
            };
            if let Some(why) = skip {
                println!("WATCH ERROR: {why}; skipping this round");
                sleep_unless_stopped(config.poll_interval_secs);
                continue;
            }
        }

        // R3-R-2: an accepted height may have been judged fraudulent (by
        // another challenger) and re-submitted since we replayed it. Detect
        // that on-chain and replay the new branch from the checkpoint below.
        // R4-R-4: never below last_finalized (clamped in rewind_target).
        if cursor.processed_upto > lf {
            match chain_view(&hub, &config, ll, lf, cursor.processed_upto) {
                Ok(view) => {
                    if let Some(t) = rewind_target(cursor.processed_upto, &accepted, &view) {
                        println!(
                            "WATCH ALERT: accepted heights {}..={} are no longer the chain's \
                             (last_submitted={ll}, frozen_{ll}={}, or a re-submitted da_unit): \
                             rewinding the replay to h={t} and re-checking them",
                            t + 1,
                            cursor.processed_upto,
                            view.frozen_at_last_submitted
                        );
                        let mut genesis_ok = || genesis_da_available(&hub, &config);
                        match rewind_engine(&state_dir, t, temp_mode, &mut genesis_ok) {
                            Ok((eng, at)) => {
                                cap_store(&state_dir, temp_mode, lf);
                                engine = eng;
                                cursor.rewind_to(at);
                                prev_final = None;
                                accepted.retain(|h, _| *h <= at);
                                if at < t {
                                    println!(
                                        "WATCH CRITICAL: no checkpoint at h={t}; rewound to h={at} \
                                         instead (heights {}..={t} are replayed again)",
                                        at + 1
                                    );
                                }
                            }
                            Err(e) => println!(
                                "WATCH CRITICAL: cannot rewind to h={t}: {e} — heights above \
                                 h={t} are NOT verified; restart with a trusted checkpoint"
                            ),
                        }
                    }
                    // First sight (e.g. after a restart, whose checkpoint was
                    // verified against the chain): record what is there now.
                    for (h, cur) in view.da_units {
                        if let (true, Some(c)) = (h <= cursor.processed_upto, cur) {
                            if !c.is_empty() {
                                accepted.entry(h).or_insert(c);
                            }
                        }
                    }
                }
                Err(e) => println!("WATCH ERROR: re-submission check: {e}"),
            }
        }

        // R4-R-6: the da_unit comparison above only covers heights that are
        // not final yet. If a height we accepted was judged, re-submitted
        // AND finalized before we looked, the chain's root at our tip no
        // longer matches the engine: rewind to the newest checkpoint the
        // chain still agrees with instead of replaying the next height on a
        // dead branch (false ROOT MISMATCH, possibly a paid challenge).
        if cursor.processed_upto >= 1 && cursor.processed_upto <= ll {
            let h = cursor.processed_upto;
            match hub.get_aa_state_var(&config.rollup_address, &format!("state_root_{h}")) {
                Ok(v) => {
                    let mine = hex::encode(engine.state.state_root());
                    if root_diverged(&mine, v.as_ref()) {
                        println!(
                            "WATCH ALERT: the chain's state_root_{h} no longer matches the \
                             replayed h={h} (re-submitted, possibly already finalized): \
                             rewinding to the newest checkpoint the chain agrees with"
                        );
                        match rewind_to_chain_root(&hub, &config, &state_dir, h, temp_mode) {
                            Ok((eng, at)) => {
                                cap_store(&state_dir, temp_mode, lf);
                                engine = eng;
                                cursor.rewind_to(at);
                                prev_final = None;
                                accepted.retain(|k, _| *k <= at);
                                println!("WATCH ALERT: rewound the replay to h={at}");
                            }
                            Err(e) => println!(
                                "WATCH CRITICAL: cannot rewind off the dead branch at h={h}: \
                                 {e} — restart with a trusted checkpoint"
                            ),
                        }
                    }
                }
                Err(e) => println!("WATCH ERROR: state_root_{h}: {e}"),
            }
        }
        accepted.retain(|h, _| *h > lf);

        // R4-R-8: a tip judged fraudulent (frozen = 2) waits for a
        // re-submission; re-checking it each round only produced false
        // BINDING MISMATCH / STALLED alerts.
        let frozen_tip = if cursor.next_start() <= ll {
            read_u64_var(&hub, &config, &format!("frozen_{ll}")).unwrap_or(0)
        } else {
            0
        };
        if frozen_tip != 2 {
            announced_frozen = None;
        }
        let mut stalled: Option<u64> = None;
        for h in cursor.next_start()..=ll {
            if tip_awaiting_resubmission(h, ll, frozen_tip) {
                if announced_frozen != Some(h) {
                    println!(
                        "WATCH INFO: h={h} was judged fraudulent (frozen_{h}=2); waiting for \
                         its re-submission"
                    );
                    announced_frozen = Some(h);
                }
                break;
            }
            let mut advanced: Option<String> = None;
            if stop_requested() {
                break;
            }
            match check_height(
                &hub,
                &config,
                &mut engine,
                h,
                &mut advanced,
                &mut vault_cache,
                &mut prev_final,
            ) {
                Ok(None) => {}
                Ok(Some(msg)) => println!("WATCH ALERT: {msg}"),
                Err(e) => println!("WATCH ERROR at h={h}: {e}"),
            }
            if let Some(submission) = advanced {
                cursor.record(h);
                accepted.insert(h, submission);
                // R2-R-9 / R3-R-2: checkpoint every replay-verified height,
                // keeping every checkpoint back to last_finalized.
                if let Err(e) = save_checkpoint_retaining(&state_dir, &engine, lf) {
                    println!("WATCH ERROR: checkpoint at h={h} failed: {e}");
                }
                // R4-R-7 / R5-R-3: a temp-dir store is capped by bytes but
                // keeps its checkpoints back to last_finalized (floor and
                // newest always).
                if temp_mode {
                    cap_store(&state_dir, true, lf);
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

        sleep_unless_stopped(config.poll_interval_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        challenge_key, challenge_mode, challenge_postable, challenge_window_open,
        live_challenge_args, post_decision, record_exit, AttemptState, ChallengeCtx, ChallengeMode,
        ChallengeTracker, PostDecision, ReplayCursor, CHALLENGE_SAFETY_MARGIN_SECS,
        CHALLENGE_WINDOW_SECS, LIVE_EXIT_REFUSED, MAX_POST_FAILURES,
    };

    /// R3-R-3: the challenge key carries the submission (`da_unit_<h>`): a
    /// frozen and re-submitted height that cheats again with the same
    /// predicate is challenged again, and a refusal / give-up on the old
    /// submission does not carry over. The same submission is still never
    /// paid for twice.
    #[test]
    fn resubmitted_height_is_challenged_again() {
        let mut t = ChallengeTracker::default();
        let old = challenge_key(5, "UNIT_A", "wpin");
        let mut st = AttemptState {
            in_flight: true,
            ..Default::default()
        };
        record_exit(&mut st, Some(0));
        t.states.insert(old.clone(), st);
        assert_eq!(
            post_decision(t.states.get(&old)),
            PostDecision::AlreadyBroadcast
        );
        let new = challenge_key(5, "UNIT_B", "wpin");
        assert_ne!(old, new);
        assert_eq!(post_decision(t.states.get(&new)), PostDecision::Post);
        // A refusal (window/frozen) on the old submission is final for it
        // only.
        let mut r = AttemptState::default();
        record_exit(&mut r, Some(LIVE_EXIT_REFUSED));
        t.states.insert(old.clone(), r);
        assert_eq!(post_decision(t.states.get(&old)), PostDecision::GaveUp);
        assert_eq!(post_decision(t.states.get(&new)), PostDecision::Post);
        // Same height, same predicate, different submission: distinct keys
        // for every combination.
        assert_ne!(
            challenge_key(5, "UNIT_A", "wpin"),
            challenge_key(5, "UNIT_A", "adr")
        );
        assert_ne!(
            challenge_key(5, "UNIT_A", "wpin"),
            challenge_key(6, "UNIT_A", "wpin")
        );
    }

    /// R3-R-2: after a rewind the cursor resumes right above the rewound
    /// height, even below the configured / resumed start height.
    #[test]
    fn replay_cursor_rewinds_below_its_start() {
        let mut c = ReplayCursor::new(10);
        c.record(14);
        c.note_stall(15);
        c.rewind_to(11);
        assert_eq!(c.next_start(), 12);
        assert!(c.stall_alert(20).is_none());
        c.rewind_to(4);
        assert_eq!(c.next_start(), 5, "rewind below the resumed start height");
        c.record(5);
        assert_eq!(c.next_start(), 6);
    }

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
            dispute_book: Some("K".repeat(32)),
            dispute_claw: Some("C".repeat(32)),
            dispute_xframe: Some("Q".repeat(32)),
            dispute_mframe: Some("R".repeat(32)),
            dispute_wf: Some("W".repeat(32)),
            proof_dir: Default::default(),
        };
        let s = std::path::Path::new("/x/p.js");
        let p = std::path::Path::new("/tmp/p.json");
        let strs = |v: Vec<std::ffi::OsString>| -> Vec<String> {
            v.into_iter().map(|a| a.into_string().unwrap()).collect()
        };
        let main = strs(live_challenge_args(
            s,
            3,
            &mk(false, false),
            p,
            "mainnet",
            &ctx,
        ));
        let i = main.iter().position(|a| a == "--rollup").unwrap();
        assert_eq!(main[i + 1], "X".repeat(32));
        let j = main.iter().position(|a| a == "--dispute-address").unwrap();
        assert_eq!(main[j + 1], "M".repeat(32));
        let bind = strs(live_challenge_args(
            s,
            3,
            &mk(false, true),
            p,
            "mainnet",
            &ctx,
        ));
        assert!(bind.contains(&"B".repeat(32)));
        let fill = strs(live_challenge_args(
            s,
            3,
            &mk(true, false),
            p,
            "mainnet",
            &ctx,
        ));
        assert!(!fill.iter().any(|a| a == "--dispute-address"));
        assert!(fill.contains(&"X".repeat(32)));
        // Round 2: ghost/skip proofs target the book AA and carry its
        // configured address (`--dispute-book`).
        let ghost = minuend_watch::prove::BuiltProof {
            pred: "ghost".into(),
            fill_aa: false,
            bind_aa: false,
            data: serde_json::json!({}),
        };
        let book = strs(live_challenge_args(s, 3, &ghost, p, "mainnet", &ctx));
        let t = book.iter().position(|a| a == "--target").unwrap();
        assert_eq!(book[t + 1], "book");
        let j = book.iter().position(|a| a == "--dispute-address").unwrap();
        assert_eq!(book[j + 1], "K".repeat(32));
        // Round 6: claw proofs target the claw AA (`--dispute-claw`).
        let claw = minuend_watch::prove::BuiltProof {
            pred: "claw".into(),
            fill_aa: false,
            bind_aa: false,
            data: serde_json::json!({}),
        };
        let cl = strs(live_challenge_args(s, 3, &claw, p, "mainnet", &ctx));
        let t = cl.iter().position(|a| a == "--target").unwrap();
        assert_eq!(cl[t + 1], "claw");
        let j = cl.iter().position(|a| a == "--dispute-address").unwrap();
        assert_eq!(cl[j + 1], "C".repeat(32));
        // Round 7b: x-frame proofs target the x-frame AA; round 8: the
        // m-frame predicates target the m-frame AA.
        for (pred, tgt, addr) in [
            ("xframe", "xframe", "Q"),
            ("tsize", "xframe", "Q"),
            ("mframe", "mframe", "R"),
            ("noband", "claw", "C"),
            ("wf", "wf", "W"),
        ] {
            let xf = minuend_watch::prove::BuiltProof {
                pred: pred.into(),
                fill_aa: false,
                bind_aa: false,
                data: serde_json::json!({}),
            };
            let a = strs(live_challenge_args(s, 3, &xf, p, "mainnet", &ctx));
            let t = a.iter().position(|x| x == "--target").unwrap();
            assert_eq!(a[t + 1], tgt);
            let j = a.iter().position(|x| x == "--dispute-address").unwrap();
            assert_eq!(a[j + 1], addr.repeat(32));
        }
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
