//! Minuend engine pilot port (no_std + alloc) for the riscv32im dispute guest.
//!
//! Faithful subset of fix/47-all @ 20326c0: minuend-book (OrderBook, verbatim except
//! HashMap->BTreeMap), minuend-account (verbatim), minuend-state (ChainState subset,
//! `apply_fill_pair[_journaled]`, journal/rollback verbatim) and minuend-exec
//! (`Engine::place`, `cancel` verbatim; `deposit` simplified). See ../README.md.
//!
//! Batch format (u32 words, read through `rd(i)`, i.e. ecall a7=63 in the guest):
//!   [0] MAGIC  [1] n_accounts  [2] n_ops  [3] 0
//!   n_accounts x 8 words: 32-byte AccountId (little-endian words)
//!   n_ops x 8 words:
//!     w0 = kind | acct_idx << 8          kind 1 Deposit, 2 Place, 3 Cancel, 4 isolated Place
//!     Deposit: w1,w2 = amount (i64 lo,hi, USD_SCALE units)
//!     Place:   w1 = side | typ<<1 | tif<<2 | isolated<<3; w2,w3 = price i64; w4,w5 = qty u64;
//!              w6 = client_seq; w7 = market id
//!     Place4:  as Place but isolated, market = BTC_USD (1), w7 = margin in whole USD
//!     Cancel:  w6 = client_seq of the account's own order to cancel; w7 = market id
//!              (order id = order_id(account, market, client_seq), computed in the guest)
//! Each op is one unit: seq advances only when it applies (upstream `apply_one`).
#![no_std]
extern crate alloc;

pub mod account;
pub mod book;
pub mod book_types;
pub mod engine;
pub mod state;
pub mod types;

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

impl state::ChainState {
    /// Mirrors the parts of upstream `ChainState::new()` the pilot keeps, plus the
    /// test-fixture `allow_all` market seed (BTC_USD genesis params).
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
        k @ (2 | 4) => BatchOp::Place {
            acct,
            side: if w[1] & 1 == 0 { Side::Bid } else { Side::Ask },
            typ: if w[1] & 2 == 0 { OrderType::Limit } else { OrderType::Market },
            tif: if w[1] & 4 == 0 { TimeInForce::Gtc } else { TimeInForce::Ioc },
            isolated: k == 4,
            price: lo64(w[2], w[3]) as i64,
            qty: lo64(w[4], w[5]),
            client_seq: w[6] as u64,
            market: if k == 4 { 1 } else { w[7] },
            margin: if k == 4 { w[7] as u64 * USD_SCALE } else { 0 },
        },
        3 => BatchOp::Cancel { acct, client_seq: w[6] as u64, market: w[7] },
        _ => BatchOp::Bad,
    }
}

/// Run one batch. `rd(i)` returns input word i; `ev(word)` receives the event log
/// (per op: EV_APPLIED|n_fills followed by 6 words per fill [maker_id w0, taker_id w0,
/// price lo, price hi, qty lo, qty hi], or a reject code).
pub fn run_batch(rd: &mut dyn FnMut(u32) -> u32, ev: &mut dyn FnMut(u32)) -> ([u8; 32], Stats) {
    let mut st = Stats { applied: 0, rejected: 0, fills: 0 };
    if rd(0) != MAGIC {
        return ([0u8; 32], st);
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
    let mut eng = Engine { state: state::ChainState::genesis() };
    for i in 0..n_ops {
        let mut w = [0u32; 8];
        for (k, x) in w.iter_mut().enumerate() {
            *x = rd(base + i * 8 + k as u32);
        }
        let seq = eng.state.seq;
        let acct_of = |a: u32| accts.get(a as usize).copied();
        let res = match decode_op(&w) {
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
    }
    (state_hash(&eng.state), st)
}
