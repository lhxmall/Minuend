//! Minuend engine pilot port (no_std + alloc) for the riscv32im dispute guest.
//!
//! Faithful subset of fix/47-all @ 20326c0: minuend-book (OrderBook, verbatim except
//! HashMap->BTreeMap), minuend-account (verbatim), minuend-state (ChainState subset,
//! `apply_fill_pair[_journaled]`, journal/rollback verbatim) and minuend-exec
//! (`Engine::place`, `cancel` verbatim; `deposit` simplified). See ../README.md.
//!
//! Batch format (u32 words, read through `rd(i)`, i.e. ecall a7=63 in the guest):
//!   [0] MAGIC  [1] n_accounts  [2] n_ops  [3] flags
//!   n_accounts x 8 words: 32-byte AccountId (little-endian words)
//!   n_ops x 8 words:
//!     w0 = kind | acct_idx << 8          kind 1 Deposit, 2 Place, 3 Cancel, 4/5 isolated Place
//!     Deposit: w1,w2 = amount (i64 lo,hi, USD_SCALE units)
//!     Place:   w1 = side | typ<<1 | tif<<2 (other bits ignored; isolated = kind 4/5);
//!              w2,w3 = price i64; w4,w5 = qty u64;
//!              w6 = client_seq; w7 = market id
//!     Place4:  as Place but isolated, market = BTC_USD (1), w7 = margin in whole USD
//!     Place5:  as Place4 but w7 = margin in USD_SCALE units (<= 4294.967295 USD)
//!   header [3]: bits 0..23 = legacywit skip (units before it get no legacy root), bit 24 = also list
//!     market 2 (genesis params, mark 100 000 USD; upstream test fixtures insert markets the same way)
//!     Cancel:  w6 = client_seq of the account's own order to cancel; w7 = market id
//!              (order id = order_id(account, market, client_seq), computed in the guest)
//!   loop round 4 (upstream ops ported with their engine paths):
//!     6 Withdraw:      w1,w2 = amount (i64); w6,w7 = nonce (u64 lo,hi)
//!     7 Liquidate:     author = keeper (caller); w1 = target account index (LIQ_TARGET_INSURANCE =
//!                      the insurance account); w7 = market. The liquidation order id
//!                      `liq_order_id(unit id)` needs the unit's hash, which the pilot batch does not
//!                      carry: the port uses unit id 0 and the event log writes LIQ_TAKER_EV for the
//!                      taker id of kind-2/3 fills on both sides (production: the unit id is part of
//!                      the unit input)
//!     8 ReportPrice:   author = oracle; w2,w3 = price; w7 = market
//!     9 ExternalPrice: author = source; w2,w3 = price; w6 = source_id (low byte); w7 = market
//!    10 SetHeight:     TEST FIXTURE (refused as kind 0 in `prod`): w1,w2 = new batch height (must be >=
//!                      the current one, else event 2); emits EV_HEIGHT, is neither applied nor rejected
//!                      (no seq), but is a unit for the per-unit roots (unchanged root)
//!   header [3] loop round 4 fixtures: bit 25 = list market 3 as a funding-rate market (the 100x
//!     listing of upstream's funding tests; account 0 of the table is its external feed), bit 26 =
//!     accounts 1..=3 of the table are bonded oracles (oracle_bonds = ORACLE_BOND_PERP)
//! Each op is one unit: seq advances only when it applies (upstream `apply_one`).
//!
//! Segments (loop round 3): an upstream batch (<= 200 000 units) is cut into guest runs of
//! <= MAX_UNITS units. One guest run = one segment = one rollup height. The guest keeps its
//! engine state in memory between runs (`Session`, see main.rs: the rollup carries the final
//! memory of height h-1 into s0 of height h), so segment k starts exactly where k-1 ended. A run
//! starts from genesis only when no session exists yet (first height). Segment boundary
//! commitment: the MNWIT1 root BEFORE the segment's first unit (`WitOut::start_root`, guest
//! OUT[0x1FFF0..8]) and AFTER its last unit (`WitOut::root`, guest OUT[0x1FFE8..8]); segment
//! k's start root == segment k-1's end root (the rollup chains them, design §7.6).
//! Header flags (word 3): test fixtures only (bit 24 market 2 at genesis, bits 0-23 legacywit
//! skip). Feature `prod` (the rollup's committed image) requires flags == 0, else status
//! ST_BAD_FLAGS; a resumed session always requires flags == 0 (genesis flags cannot apply).
//!
//! Input validation (loop round 1, findings/rv-loop-1.md G1/G2): the header is checked BEFORE any
//! op runs; a batch with a bad magic, `n_accounts > MAX_ACCOUNTS` or `n_ops > MAX_UNITS` runs no op
//! and returns status != 0 with a zero state hash (host and guest share this code, so both agree).
//! Within the limits every input index is < 4 + 8*(MAX_ACCOUNTS + MAX_UNITS) < 2^24, so no read can
//! wrap or reach the input ecall's trap range; words past the end of a truncated batch read as 0
//! (input-tree semantics), which decodes as kind 0 = BadAccount. An op whose account index is out of
//! range, or whose account id is the INSURANCE_ACCOUNT (all-zero id; no ed25519 key hashes to it,
//! so the real engine can never see such an author), is rejected BadAccount.
#![no_std]
extern crate alloc;

pub mod account;
pub mod book;
pub mod book_types;
pub mod engine;
pub mod snapshot;
pub mod state;
pub mod types;
pub mod wit;

pub use book_types::*;

use alloc::vec::Vec;
use engine::{Engine, RejectReason};
use sha2::Digest;
use types::*;

pub const MAGIC: u32 = 0x4D4E_5031; // "MNP1"

/// Event code per op (shared numbering with the host harness).
pub fn reason_code(r: &RejectReason) -> u32 {
    match r {
        RejectReason::BadSig => 1,
        RejectReason::BadAccount => 2,
        RejectReason::DuplicateClientSeq => 3,
        RejectReason::DuplicateDeposit => 4,
        RejectReason::UnbackedDeposit => 5,
        RejectReason::DuplicateNonce => 6,
        RejectReason::Risk => 7,
        RejectReason::Book(e) => 0x100 + book_code(e),
        RejectReason::Insufficient => 9,
        RejectReason::NotFound => 10,
        RejectReason::NotLiquidatable => 11,
        RejectReason::NoProposal => 12,
        RejectReason::NotBonded => 13,
        RejectReason::AlreadyBonded => 14,
        RejectReason::Unbonding => 15,
        RejectReason::SlashNotEligible => 16,
        RejectReason::BadCommit => 17,
    }
}
pub fn book_code(e: &BookError) -> u32 {
    match e {
        BookError::NotFound => 1,
        BookError::ZeroQty => 2,
        BookError::ZeroPrice => 3,
        BookError::DuplicateOrder => 4,
        BookError::WrongMarket => 5,
        BookError::SelfTrade => 6,
        BookError::MultiFill => 7,
    }
}
pub const EV_APPLIED: u32 = 0x8000_0000;
pub const MARKET2_FLAG: u32 = 1 << 24;
/// loop round 4 fixtures (header word 3, non-prod): funding-rate market 3 / bonded oracles
pub const FUNDING_MKT_FLAG: u32 = 1 << 25;
pub const ORACLES_FLAG: u32 = 1 << 26;
pub const FUNDING_MKT: MarketId = MarketId(3);
/// Liquidate op: target index meaning the insurance account
pub const LIQ_TARGET_INSURANCE: u32 = 0xFF_FFFF;
/// event word standing in for the taker id of a liquidation fill (kind 2 / 3)
pub const LIQ_TAKER_EV: u32 = 0x4C49_5121;
/// event of a SetHeight fixture op
pub const EV_HEIGHT: u32 = 0x4000_0000;

/// Max units (ops) per guest batch: the per-unit root region OUT+0x20000.. (8 words per unit)
/// ends exactly at the top of the 2^24-word RAM (0x0400_0000), and the event log
/// (<= 7 words per unit: a unit carries at most one fill) fits below the counters at OUT+0x1FFF0.
pub const MAX_UNITS: u32 = 16_384;
/// Max entries of the batch's account table.
pub const MAX_ACCOUNTS: u32 = 4_096;
/// Event-log word capacity in the guest's OUT area (words 13 .. 0x1FFE0; 0x1FFE0.. holds the
/// segment words and counters, loop round 3).
pub const EV_CAP: u32 = 0x1FFD6 - 13;
/// Batch status (OUT[0x1FFF9] in the guest; `Stats::status` on the host).
pub const ST_OK: u32 = 0;
pub const ST_BAD_MAGIC: u32 = 1;
pub const ST_TOO_MANY_ACCOUNTS: u32 = 2;
pub const ST_TOO_MANY_UNITS: u32 = 3;
/// header word 3 != 0 where it must be 0 (feature `prod`, or any resumed session)
pub const ST_BAD_FLAGS: u32 = 4;
/// a previous run of this session aborted (panic / out of memory): its state may be torn
/// mid-unit, so every later run refuses to execute (guest only; main.rs)
pub const ST_DEAD: u32 = 5;
/// loop round 4 (snapshot.rs): EXPORT run without a session
pub const ST_NO_SESSION: u32 = 6;
/// IMPORT input malformed / non-canonical (no session is created; a dead image stays dead)
pub const ST_BAD_SNAP: u32 = 7;
/// IMPORT refused: the image already holds a live session (only a fresh or dead image imports)
pub const ST_SESSION_LIVE: u32 = 8;
/// EXPORT header words 1..3 must be 0
pub const ST_BAD_EXPORT: u32 = 9;
/// input words an import may read (the input tree's index range below the ecall trap range)
pub const SNAP_LIMIT: u32 = (1 << 24) - 1;

/// Event code of a unit rejected by the MNWIT1 depth rule (wit::MAX_WIT_DEPTH, loop round 2 W2);
/// outside the engine's RejectReason codes (1..17, 0x100+).
pub const WIT_DEPTH_CODE: u32 = 18;

/// MNWIT1 depth rule (W2): every key this op could newly create *for its own author* -- the
/// author's `acct:` key if the account does not exist yet (deposit / place), the order's `ord:` key
/// and the author's `pos:` key in the order's market if it has no position there (place) -- must
/// land at depth <= MAX_WIT_DEPTH. Checked against the tree BEFORE the op runs, independent of
/// whether the order then rests or fills (a deterministic, cheap pre-check; no rollback needed).
/// Side-effect insertions (the maker's first `pos:` at a fill) are not checked: making one deep
/// needs a targeted 2^MAX_WIT_DEPTH prefix grind, see wit::MAX_WIT_DEPTH.
pub fn wit_depth_ok(w: &wit::Wit, s: &state::ChainState, op: &BatchOp, author: AccountId) -> bool {
    let ok = |k: &wit::H| w.smt.insert_depth(k).map(|d| d <= wit::MAX_WIT_DEPTH).unwrap_or(true);
    let new_acct = !s.accounts.contains_key(&author);
    match *op {
        BatchOp::Deposit { .. } => !new_acct || ok(&wit::acct_key(&author)),
        // loop round 4: a keeper reward credits the caller (`account_mut(caller)`): its acct: key
        // can be created by the unit -> checked like a deposit's
        BatchOp::Liquidate { .. } => !new_acct || ok(&wit::acct_key(&author)),
        BatchOp::Place { market, client_seq, .. } => {
            let m = MarketId(market);
            let has_pos = s.accounts.get(&author).map(|a| a.positions.contains_key(&m)).unwrap_or(false);
            (!new_acct || ok(&wit::acct_key(&author)))
                && ok(&wit::ord_key(&order_id(author, m, client_seq)))
                && (has_pos || ok(&wit::pos_key(&author, m)))
        }
        _ => true,
    }
}
const _: () = assert!(13 + 7 * MAX_UNITS <= 0x1FFD6);
const _: () = assert!(0x03F0_0000 / 4 + 0x20000 + 8 * MAX_UNITS <= 1 << 24);
const _: () = assert!(4 + 8 * (MAX_ACCOUNTS + MAX_UNITS) < 1 << 24);

/// Header check shared by host and guest. `resumed` = a session already exists (not genesis).
pub fn check_header_seg(rd: &mut dyn FnMut(u32) -> u32, resumed: bool) -> u32 {
    if rd(0) != MAGIC {
        ST_BAD_MAGIC
    } else if rd(1) > MAX_ACCOUNTS {
        ST_TOO_MANY_ACCOUNTS
    } else if rd(2) > MAX_UNITS {
        ST_TOO_MANY_UNITS
    } else if rd(3) != 0 && (resumed || cfg!(feature = "prod")) {
        ST_BAD_FLAGS
    } else {
        ST_OK
    }
}
pub fn check_header(rd: &mut dyn FnMut(u32) -> u32) -> u32 {
    check_header_seg(rd, false)
}

impl state::ChainState {
    /// Mirrors the parts of upstream `ChainState::new()` the pilot keeps, plus the
    /// test-fixture `allow_all` market seed (BTC_USD genesis params).
    /// genesis plus market 2 when `flags` bit 24 is set (batch header word 3)
    pub fn genesis_flags(flags: u32) -> Self {
        Self::genesis_fixture(flags, &[])
    }
    /// loop round 4: + the funding-rate market / oracle fixtures (bits 25 / 26), which name
    /// accounts of the batch's table
    pub fn genesis_fixture(flags: u32, accts: &[AccountId]) -> Self {
        let mut s = Self::genesis();
        if flags & MARKET2_FLAG != 0 {
            s.markets.insert(MarketId(2), genesis_params());
            s.marks.insert(MarketId(2), 100_000 * PRICE_SCALE as i64);
        }
        if flags & FUNDING_MKT_FLAG != 0 {
            s.markets.insert(FUNDING_MKT, funding_fixture_params());
            if let Some(a) = accts.first() {
                s.external_sources.insert(*a);
            }
        }
        if flags & ORACLES_FLAG != 0 {
            for a in accts.iter().skip(1).take(3) {
                s.oracle_bonds.insert(*a, ORACLE_BOND_PERP);
            }
        }
        s
    }
    pub fn genesis() -> Self {
        let mut s = Self::default();
        s.books.insert(BTC_USD, book::OrderBook::new(BTC_USD));
        s.marks.insert(BTC_USD, 100_000 * PRICE_SCALE as i64);
        let mut insurance = account::Account::new(INSURANCE_ACCOUNT);
        insurance.collateral = 10_000 * USD_SCALE as Usd; // INSURANCE_SEED
        s.put_account(INSURANCE_ACCOUNT, insurance);
        s.markets.insert(BTC_USD, genesis_params());
        s
    }
}

/// Params of the funding-rate fixture market (upstream test `funding_rate_lists_at_100x`:
/// tick 1, im 100, mm 50, fee 5, keeper 10, funding_rate, usd_per_unit 10 000, cap 10 bps).
pub fn funding_fixture_params() -> MarketParams {
    let mut symbol = [0u8; 16];
    symbol[..6].copy_from_slice(b"HUNDRD");
    MarketParams {
        symbol,
        tick_size: 1,
        im_bps: 100,
        mm_bps: 50,
        taker_fee_bps: 5,
        keeper_reward_bps: 10,
        delisted: false,
        spot_only: false,
        funding_rate: true,
        usd_per_unit: 10_000,
        funding_cap_bps: 10,
        min_price: 0,
        max_price: 0,
    }
}

/// Copied from minuend-state/src/lib.rs `account_leaf` (perp / withdrawn passed in).
pub fn account_leaf(acct: &account::Account, perp: u128, withdrawn: i128) -> [u8; 32] {
    let mut b = Vec::new();
    b.extend_from_slice(b"acct");
    b.extend_from_slice(&acct.id.0);
    b.extend_from_slice(&acct.collateral.to_le_bytes());
    b.extend_from_slice(&acct.realized_pnl.to_le_bytes());
    b.extend_from_slice(&(acct.positions.len() as u32).to_le_bytes());
    for (m, p) in &acct.positions {
        b.extend_from_slice(&m.0.to_le_bytes());
        b.extend_from_slice(&p.qty.to_le_bytes());
        b.extend_from_slice(&p.entry_price.to_le_bytes());
    }
    b.extend_from_slice(&(acct.isolated_margin.len() as u32).to_le_bytes());
    for (m, margin) in &acct.isolated_margin {
        b.extend_from_slice(&m.0.to_le_bytes());
        b.extend_from_slice(&margin.to_le_bytes());
    }
    b.extend_from_slice(&perp.to_le_bytes());
    b.extend_from_slice(&withdrawn.to_le_bytes());
    sha256(&b)
}

/// Pilot state hash (the host harness computes the same bytes from the real ChainState):
/// sha256("MNPILOT1" || seq le8 || n_acc le4 || account_leaf(a,0,0)* || n_books le4 ||
///        (market le4 || sha256(book.commitment_bytes()))* || n_marks le4 ||
///        (market le4 || mark le8)* || n_seen le4 || (account 32 || client_seq le8)*)
pub fn state_hash(s: &state::ChainState) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    h.update(b"MNPILOT1");
    h.update(s.seq.to_le_bytes());
    h.update((s.accounts.len() as u32).to_le_bytes());
    for a in s.accounts.values() {
        h.update(account_leaf(a, 0, s.withdrawn_total.get(&a.id).copied().unwrap_or(0)));
    }
    h.update((s.books.len() as u32).to_le_bytes());
    for (m, b) in &s.books {
        h.update(m.0.to_le_bytes());
        h.update(sha256(&b.commitment_bytes()));
    }
    h.update((s.marks.len() as u32).to_le_bytes());
    for (m, p) in &s.marks {
        h.update(m.0.to_le_bytes());
        h.update(p.to_le_bytes());
    }
    h.update((s.seen_client_seq.len() as u32).to_le_bytes());
    for (a, c) in &s.seen_client_seq {
        h.update(a.0);
        h.update(c.to_le_bytes());
    }
    // loop round 4: oracle / funding / withdrawal state (the host computes the same bytes from
    // the real ChainState, engine-diff `real_hash`)
    h.update(b"MNPILOT2");
    h.update(s.height.to_le_bytes());
    h.update((s.withdrawals.len() as u32).to_le_bytes());
    for ((a, n), w) in &s.withdrawals {
        h.update(a.0);
        h.update(n.to_le_bytes());
        h.update(w.amount.to_le_bytes());
        h.update([w.pending as u8]);
        h.update(w.height.to_le_bytes());
    }
    h.update((s.oracle_reports.len() as u32).to_le_bytes());
    for ((m, a), p) in &s.oracle_reports {
        h.update(m.0.to_le_bytes());
        h.update(a.0);
        h.update(p.to_le_bytes());
    }
    for map in [&s.last_index, &s.funding_index_twap] {
        h.update((map.len() as u32).to_le_bytes());
        for (m, p) in map {
            h.update(m.0.to_le_bytes());
            h.update(p.to_le_bytes());
        }
    }
    h.update((s.last_funding_height.len() as u32).to_le_bytes());
    for (m, x) in &s.last_funding_height {
        h.update(m.0.to_le_bytes());
        h.update(x.to_le_bytes());
    }
    for map in [&s.oracle_twap, &s.funding_twap] {
        h.update((map.len() as u32).to_le_bytes());
        for (m, q) in map {
            h.update(m.0.to_le_bytes());
            h.update((q.len() as u32).to_le_bytes());
            for t in q {
                h.update(t.seq.to_le_bytes());
                h.update(t.height.to_le_bytes());
                h.update(t.median.to_le_bytes());
            }
        }
    }
    h.update((s.oracle_report_history.len() as u32).to_le_bytes());
    for ((m, a), q) in &s.oracle_report_history {
        h.update(m.0.to_le_bytes());
        h.update(a.0);
        h.update((q.len() as u32).to_le_bytes());
        for t in q {
            h.update(t.height.to_le_bytes());
            h.update(t.price.to_le_bytes());
            h.update(t.seq.to_le_bytes());
        }
    }
    h.update((s.external_price_ring.len() as u32).to_le_bytes());
    for (m, q) in &s.external_price_ring {
        h.update(m.0.to_le_bytes());
        h.update((q.len() as u32).to_le_bytes());
        for t in q {
            h.update(t.seq.to_le_bytes());
            h.update(t.height.to_le_bytes());
            h.update(t.price.to_le_bytes());
            h.update([t.source_id]);
        }
    }
    h.finalize().into()
}

pub struct Stats {
    /// ST_* (0 = header accepted and every op ran)
    pub status: u32,
    pub applied: u32,
    pub rejected: u32,
    pub fills: u32,
}

/// Decoded op (host tools share this decoder with the guest).
#[derive(Clone, Copy, Debug)]
pub enum BatchOp {
    Deposit { acct: u32, amount: i64 },
    Place { acct: u32, side: Side, typ: OrderType, tif: TimeInForce, isolated: bool, price: i64, qty: u64, client_seq: u64, market: u32, margin: u64 },
    Cancel { acct: u32, client_seq: u64, market: u32 },
    Withdraw { acct: u32, amount: i64, nonce: u64 },
    Liquidate { acct: u32, target: u32, market: u32 },
    Report { acct: u32, price: i64, market: u32 },
    ExtPrice { acct: u32, price: i64, source_id: u8, market: u32 },
    SetHeight { height: u64 },
    Bad,
}
pub fn decode_op(w: &[u32; 8]) -> BatchOp {
    let acct = w[0] >> 8;
    let lo64 = |a: u32, b: u32| (a as u64) | ((b as u64) << 32);
    match w[0] & 0xff {
        1 => BatchOp::Deposit { acct, amount: lo64(w[1], w[2]) as i64 },
        k @ (2 | 4 | 5) => BatchOp::Place {
            acct,
            side: if w[1] & 1 == 0 { Side::Bid } else { Side::Ask },
            typ: if w[1] & 2 == 0 { OrderType::Limit } else { OrderType::Market },
            tif: if w[1] & 4 == 0 { TimeInForce::Gtc } else { TimeInForce::Ioc },
            isolated: k >= 4,
            price: lo64(w[2], w[3]) as i64,
            qty: lo64(w[4], w[5]),
            client_seq: w[6] as u64,
            market: if k >= 4 { 1 } else { w[7] },
            margin: match k { 4 => w[7] as u64 * USD_SCALE, 5 => w[7] as u64, _ => 0 },
        },
        3 => BatchOp::Cancel { acct, client_seq: w[6] as u64, market: w[7] },
        6 => BatchOp::Withdraw { acct, amount: lo64(w[1], w[2]) as i64, nonce: lo64(w[6], w[7]) },
        7 => BatchOp::Liquidate { acct, target: w[1], market: w[7] },
        8 => BatchOp::Report { acct, price: lo64(w[2], w[3]) as i64, market: w[7] },
        9 => BatchOp::ExtPrice { acct, price: lo64(w[2], w[3]) as i64, source_id: w[6] as u8, market: w[7] },
        10 if !cfg!(feature = "prod") => BatchOp::SetHeight { height: lo64(w[1], w[2]) },
        _ => BatchOp::Bad,
    }
}

/// Per-unit witness mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitMode {
    /// no per-unit commitment (the 2d01fe8 pilot)
    Off,
    /// MNWIT1 incremental sparse Merkle root after every unit (proposal)
    Incremental,
    /// legacy fix/47-all style full rebuild (sort + Obyte merkle) after every unit with index >= skip
    Legacy { skip: u32 },
}

pub struct WitOut {
    /// final incremental root (Incremental) or last legacy root; = segment end root
    pub root: [u8; 32],
    /// MNWIT1 root before the first unit of this run (segment start root; Incremental only)
    pub start_root: [u8; 32],
    /// Incremental: final root == root of a tree rebuilt from scratch over the final state
    pub scratch_ok: bool,
    pub leaves: u32,
    pub leaf_updates: u64,
    pub node_hashes: u64,
}

/// Engine state carried from one segment (guest run) to the next.
pub struct Session {
    pub eng: Engine,
    pub w: Option<wit::Wit>,
    pub mode: WitMode,
    /// segments run so far (incl. ones whose header was rejected)
    pub segs: u32,
}
impl Session {
    pub fn genesis(flags: u32, mode: WitMode) -> Self {
        Self::genesis_with(flags, mode, &[])
    }
    pub fn genesis_with(flags: u32, mode: WitMode, accts: &[AccountId]) -> Self {
        let mut eng = Engine { state: state::ChainState::genesis_fixture(flags, accts) };
        let w = if mode == WitMode::Incremental { Some(wit::Wit::from_state(&eng.state)) } else { None };
        let _ = eng.state.take_dirty();
        Session { eng, w, mode, segs: 0 }
    }
}

/// Run one batch (no witness), as in 2d01fe8.
pub fn run_batch(rd: &mut dyn FnMut(u32) -> u32, ev: &mut dyn FnMut(u32)) -> ([u8; 32], Stats) {
    let (h, st, _) = run_batch_wit(rd, ev, &mut |_, _, _| {}, WitMode::Off);
    (h, st)
}

/// Run one batch. `rd(i)` returns input word i; `ev(word)` receives the event log
/// (per op: EV_APPLIED|n_fills followed by 6 words per fill [maker_id w0, taker_id w0,
/// price lo, price hi, qty lo, qty hi], or a reject code); `unit(i, state, root)` is called
/// after every unit (applied or rejected, as upstream `apply_one` pushes one wit root per unit)
/// with the unit's witness root (zero when mode = Off, or Legacy before `skip`).
pub fn run_batch_wit(
    rd: &mut dyn FnMut(u32) -> u32,
    ev: &mut dyn FnMut(u32),
    unit: &mut dyn FnMut(u32, &state::ChainState, &[u8; 32]),
    mode: WitMode,
) -> ([u8; 32], Stats, WitOut) {
    let mut sess = None;
    run_segment(rd, ev, unit, mode, &mut sess)
}

/// Run one segment on `sess` (None = no session yet: start from genesis with the header's flags,
/// and leave the new session in `sess`). A rejected header runs no op and leaves `sess` as it was
/// (hash zero). The returned hash is the state hash after the segment.
pub fn run_segment(
    rd: &mut dyn FnMut(u32) -> u32,
    ev: &mut dyn FnMut(u32),
    unit: &mut dyn FnMut(u32, &state::ChainState, &[u8; 32]),
    mode: WitMode,
    sess: &mut Option<Session>,
) -> ([u8; 32], Stats, WitOut) {
    let mut st = Stats { status: ST_OK, applied: 0, rejected: 0, fills: 0 };
    let mut wo = WitOut { root: [0; 32], start_root: [0; 32], scratch_ok: false, leaves: 0, leaf_updates: 0, node_hashes: 0 };
    if let Some(s) = sess.as_mut() {
        s.segs += 1;
    }
    st.status = check_header_seg(rd, sess.is_some());
    if st.status != ST_OK {
        return ([0u8; 32], st, wo);
    }
    let n_acc = rd(1);
    let n_ops = rd(2);
    let mut accts: Vec<AccountId> = Vec::with_capacity(n_acc as usize);
    for a in 0..n_acc {
        let mut id = [0u8; 32];
        for k in 0..8 {
            id[k * 4..k * 4 + 4].copy_from_slice(&rd(4 + a * 8 + k as u32).to_le_bytes());
        }
        accts.push(AccountId(id));
    }
    let base = 4 + n_acc * 8;
    if sess.is_none() {
        let mut s = Session::genesis_with(rd(3), mode, &accts);
        s.segs = 1;
        *sess = Some(s);
    }
    let Session { eng, w, .. } = sess.as_mut().unwrap();
    if let Some(w) = w.as_mut() {
        wo.root = w.root();
        wo.start_root = wo.root;
    }
    for i in 0..n_ops {
        let mut ow = [0u32; 8];
        for (k, x) in ow.iter_mut().enumerate() {
            *x = rd(base + i * 8 + k as u32);
        }
        let seq = eng.state.seq;
        // INSURANCE_ACCOUNT can never author a signed unit upstream (ids are pubkey hashes).
        let acct_of = |a: u32| accts.get(a as usize).copied().filter(|id| *id != INSURANCE_ACCOUNT);
        let op = decode_op(&ow);
        let author = match op {
            BatchOp::Deposit { acct, .. }
            | BatchOp::Place { acct, .. }
            | BatchOp::Cancel { acct, .. }
            | BatchOp::Withdraw { acct, .. }
            | BatchOp::Liquidate { acct, .. }
            | BatchOp::Report { acct, .. }
            | BatchOp::ExtPrice { acct, .. } => acct_of(acct),
            BatchOp::SetHeight { .. } | BatchOp::Bad => None,
        };
        // W2 depth rule (only where the tree exists: Incremental mode; Off/Legacy are bench builds)
        let too_deep = match (w.as_ref(), author) {
            (Some(w), Some(a)) => !wit_depth_ok(w, &eng.state, &op, a),
            _ => false,
        };
        let mut height_op = false;
        let res = if too_deep { Err(None) } else { match op {
            BatchOp::Deposit { acct, amount } => match acct_of(acct) {
                Some(a) => eng.deposit(a, amount as Usd),
                None => Err(RejectReason::BadAccount),
            },
            BatchOp::Place { acct, side, typ, tif, isolated, price, qty, client_seq, market, margin } => match acct_of(acct) {
                Some(a) => eng.place(a, MarketId(market), side, typ, tif, price, qty, client_seq, [0u8; 32], seq, isolated, margin),
                None => Err(RejectReason::BadAccount),
            },
            BatchOp::Cancel { acct, client_seq, market } => match acct_of(acct) {
                Some(a) => eng.cancel(a, order_id(a, MarketId(market), client_seq)),
                None => Err(RejectReason::BadAccount),
            },
            BatchOp::Withdraw { acct, amount, nonce } => match acct_of(acct) {
                Some(a) => eng.withdraw(a, amount as Usd, nonce),
                None => Err(RejectReason::BadAccount),
            },
            BatchOp::Liquidate { acct, target, market } => {
                let t = if target == LIQ_TARGET_INSURANCE { Some(INSURANCE_ACCOUNT) } else { accts.get(target as usize).copied() };
                match (acct_of(acct), t) {
                    (Some(a), Some(t)) => eng.liquidate([0u8; 32], seq, a, t, MarketId(market)),
                    _ => Err(RejectReason::BadAccount),
                }
            }
            BatchOp::Report { acct, price, market } => match acct_of(acct) {
                Some(a) => eng.report_price(a, MarketId(market), price),
                None => Err(RejectReason::BadAccount),
            },
            BatchOp::ExtPrice { acct, price, source_id, market } => match acct_of(acct) {
                Some(a) => eng.update_external_price(a, MarketId(market), price, source_id, seq),
                None => Err(RejectReason::BadAccount),
            },
            BatchOp::SetHeight { height } => {
                if height >= eng.state.height {
                    eng.state.height = height;
                    height_op = true;
                    Ok(Vec::new())
                } else {
                    Err(RejectReason::BadAccount)
                }
            }
            BatchOp::Bad => Err(RejectReason::BadAccount),
        }.map_err(Some) };
        match res {
            Ok(_) if height_op => ev(EV_HEIGHT),
            Ok(fills) => {
                eng.state.seq += 1;
                st.applied += 1;
                st.fills += fills.len() as u32;
                ev(EV_APPLIED | fills.len() as u32);
                for f in &fills {
                    ev(u32::from_le_bytes([f.maker_id.0[0], f.maker_id.0[1], f.maker_id.0[2], f.maker_id.0[3]]));
                    ev(if f.kind == 2 || f.kind == 3 {
                        LIQ_TAKER_EV
                    } else {
                        u32::from_le_bytes([f.taker_id.0[0], f.taker_id.0[1], f.taker_id.0[2], f.taker_id.0[3]])
                    });
                    ev(f.price as u32);
                    ev((f.price >> 32) as u32);
                    ev(f.qty as u32);
                    ev((f.qty >> 32) as u32);
                }
            }
            Err(r) => {
                st.rejected += 1;
                ev(r.as_ref().map(reason_code).unwrap_or(WIT_DEPTH_CODE));
            }
        }
        let root = match mode {
            WitMode::Off => {
                let _ = eng.state.take_dirty();
                [0u8; 32]
            }
            WitMode::Incremental => w.as_mut().unwrap().commit(&mut eng.state),
            WitMode::Legacy { skip } => {
                let _ = eng.state.take_dirty();
                if i >= skip { wit::legacy_root(&eng.state) } else { [0u8; 32] }
            }
        };
        if mode != WitMode::Off {
            wo.root = root;
        }
        unit(i, &eng.state, &root);
    }
    if let Some(w) = w.as_mut() {
        // from-scratch rebuild; also a duplicate-kid check (W3): every leaf put from scratch must
        // land on its own key (count == puts), else two live leaves share a kid.
        // Loop round 4 (item c): O(state) per segment -> test builds only. The `prod` image skips
        // it (scratch_ok stays false = "not checked") and returns a zero state hash: neither is
        // read by the rollup (rv_witbind binds the segment end root, the dispute game the
        // machine roots), and both grow with the whole session state, not with the segment.
        if !cfg!(feature = "prod") {
            let mut sw = wit::Wit::from_state(&eng.state);
            wo.scratch_ok = sw.smt.count as u64 == sw.leaf_updates && sw.root() == wo.root;
        }
        wo.leaves = w.smt.count;
        wo.leaf_updates = w.leaf_updates;
        wo.node_hashes = w.smt.node_hashes;
    }
    let h = if cfg!(feature = "prod") { [0u8; 32] } else { state_hash(&eng.state) };
    (h, st, wo)
}

/// Result of an EXPORT / IMPORT run (loop round 4, snapshot.rs).
pub struct SnapOut {
    pub status: u32,
    /// sha256 over the snapshot words (export: produced; import: consumed)
    pub digest: [u8; 32],
    pub words: u32,
    /// MNWIT1 root of the session (export: current; import: rebuilt) -- both segment roots
    pub root: [u8; 32],
}

/// EXPORT run: stream the live session's canonical snapshot through sha256. Counts as a segment
/// (`segs` += 1 before encoding, so the snapshot carries it); changes nothing else.
pub fn run_export(rd: &mut dyn FnMut(u32) -> u32, sess: &mut Option<Session>) -> SnapOut {
    let mut o = SnapOut { status: ST_OK, digest: [0; 32], words: 0, root: [0; 32] };
    if rd(0) != snapshot::EXPORT_MAGIC {
        o.status = ST_BAD_MAGIC;
        return o;
    }
    if rd(1) != 0 || rd(2) != 0 || rd(3) != 0 {
        o.status = ST_BAD_EXPORT;
        return o;
    }
    let Some(s) = sess.as_mut() else {
        o.status = ST_NO_SESSION;
        return o;
    };
    s.segs += 1;
    let (d, n, _) = snapshot::export(s, false);
    o.digest = d;
    o.words = n;
    if let Some(w) = s.w.as_mut() {
        o.root = w.root();
    }
    o
}

/// IMPORT run: only without a live session. On success `sess` holds the decoded session (the
/// import itself does not count as a segment: the imported session IS the exported one).
pub fn run_import(rd: &mut dyn FnMut(u32) -> u32, sess: &mut Option<Session>) -> SnapOut {
    let mut o = SnapOut { status: ST_OK, digest: [0; 32], words: 0, root: [0; 32] };
    if sess.is_some() {
        o.status = ST_SESSION_LIVE;
        return o;
    }
    let mut r = snapshot::SnapR::new(rd, SNAP_LIMIT);
    match snapshot::decode(&mut r) {
        Ok(mut s) => {
            o.words = r.i;
            o.digest = r.digest();
            if let Some(w) = s.w.as_mut() {
                o.root = w.root();
            }
            *sess = Some(s);
        }
        Err(()) => o.status = ST_BAD_SNAP,
    }
    o
}
