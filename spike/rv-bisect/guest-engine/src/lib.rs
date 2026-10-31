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
//! Each op is one unit: seq advances only when it applies (upstream `apply_one`).
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

/// Max units (ops) per guest batch: the per-unit root region OUT+0x20000.. (8 words per unit)
/// ends exactly at the top of the 2^24-word RAM (0x0400_0000), and the event log
/// (<= 7 words per unit: a unit carries at most one fill) fits below the counters at OUT+0x1FFF0.
pub const MAX_UNITS: u32 = 16_384;
/// Max entries of the batch's account table.
pub const MAX_ACCOUNTS: u32 = 4_096;
/// Event-log word capacity in the guest's OUT area (words 13 .. 0x1FFF0).
pub const EV_CAP: u32 = 0x1FFF0 - 13;
/// Batch status (OUT[0x1FFF9] in the guest; `Stats::status` on the host).
pub const ST_OK: u32 = 0;
pub const ST_BAD_MAGIC: u32 = 1;
pub const ST_TOO_MANY_ACCOUNTS: u32 = 2;
pub const ST_TOO_MANY_UNITS: u32 = 3;
const _: () = assert!(13 + 7 * MAX_UNITS <= 0x1FFF0);
const _: () = assert!(0x03F0_0000 / 4 + 0x20000 + 8 * MAX_UNITS <= 1 << 24);
const _: () = assert!(4 + 8 * (MAX_ACCOUNTS + MAX_UNITS) < 1 << 24);

/// Header check shared by host and guest.
pub fn check_header(rd: &mut dyn FnMut(u32) -> u32) -> u32 {
    if rd(0) != MAGIC {
        ST_BAD_MAGIC
    } else if rd(1) > MAX_ACCOUNTS {
        ST_TOO_MANY_ACCOUNTS
    } else if rd(2) > MAX_UNITS {
        ST_TOO_MANY_UNITS
    } else {
        ST_OK
    }
}

impl state::ChainState {
    /// Mirrors the parts of upstream `ChainState::new()` the pilot keeps, plus the
    /// test-fixture `allow_all` market seed (BTC_USD genesis params).
    /// genesis plus market 2 when `flags` bit 24 is set (batch header word 3)
    pub fn genesis_flags(flags: u32) -> Self {
        let mut s = Self::genesis();
        if flags & MARKET2_FLAG != 0 {
            s.markets.insert(MarketId(2), genesis_params());
            s.marks.insert(MarketId(2), 100_000 * PRICE_SCALE as i64);
        }
        s
    }
    pub fn genesis() -> Self {
        let mut s = Self::default();
        s.books.insert(BTC_USD, book::OrderBook::new(BTC_USD));
        s.marks.insert(BTC_USD, 100_000 * PRICE_SCALE as i64);
        let mut insurance = account::Account::new(INSURANCE_ACCOUNT);
        insurance.collateral = 10_000 * USD_SCALE as Usd; // INSURANCE_SEED
        s.accounts.insert(INSURANCE_ACCOUNT, insurance);
        s.markets.insert(BTC_USD, genesis_params());
        s
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
        h.update(account_leaf(a, 0, 0));
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
    /// final incremental root (Incremental) or last legacy root
    pub root: [u8; 32],
    /// Incremental: final root == root of a tree rebuilt from scratch over the final state
    pub scratch_ok: bool,
    pub leaves: u32,
    pub leaf_updates: u64,
    pub node_hashes: u64,
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
    let mut st = Stats { status: ST_OK, applied: 0, rejected: 0, fills: 0 };
    let mut wo = WitOut { root: [0; 32], scratch_ok: false, leaves: 0, leaf_updates: 0, node_hashes: 0 };
    st.status = check_header(rd);
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
    let mut eng = Engine { state: state::ChainState::genesis_flags(rd(3)) };
    let mut w = if mode == WitMode::Incremental { Some(wit::Wit::from_state(&eng.state)) } else { None };
    eng.state.wit_dirty = Default::default();
    if let Some(w) = w.as_mut() {
        wo.root = w.root();
    }
    for i in 0..n_ops {
        let mut ow = [0u32; 8];
        for (k, x) in ow.iter_mut().enumerate() {
            *x = rd(base + i * 8 + k as u32);
        }
        let seq = eng.state.seq;
        // INSURANCE_ACCOUNT can never author a signed unit upstream (ids are pubkey hashes).
        let acct_of = |a: u32| accts.get(a as usize).copied().filter(|id| *id != INSURANCE_ACCOUNT);
        let res = match decode_op(&ow) {
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
            BatchOp::Bad => Err(RejectReason::BadAccount),
        };
        match res {
            Ok(fills) => {
                eng.state.seq += 1;
                st.applied += 1;
                st.fills += fills.len() as u32;
                ev(EV_APPLIED | fills.len() as u32);
                for f in &fills {
                    ev(u32::from_le_bytes([f.maker_id.0[0], f.maker_id.0[1], f.maker_id.0[2], f.maker_id.0[3]]));
                    ev(u32::from_le_bytes([f.taker_id.0[0], f.taker_id.0[1], f.taker_id.0[2], f.taker_id.0[3]]));
                    ev(f.price as u32);
                    ev((f.price >> 32) as u32);
                    ev(f.qty as u32);
                    ev((f.qty >> 32) as u32);
                }
            }
            Err(r) => {
                st.rejected += 1;
                ev(reason_code(&r));
            }
        }
        let root = match mode {
            WitMode::Off => {
                eng.state.wit_dirty = Default::default();
                [0u8; 32]
            }
            WitMode::Incremental => w.as_mut().unwrap().commit(&mut eng.state),
            WitMode::Legacy { skip } => {
                eng.state.wit_dirty = Default::default();
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
        // land on its own key (count == puts), else two live leaves share a kid
        let mut sw = wit::Wit::from_state(&eng.state);
        wo.scratch_ok = sw.smt.count as u64 == sw.leaf_updates && sw.root() == wo.root;
        wo.leaves = w.smt.count;
        wo.leaf_updates = w.leaf_updates;
        wo.node_hashes = w.smt.node_hashes;
    }
    (state_hash(&eng.state), st, wo)
}
