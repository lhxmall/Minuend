//! Loop round 4 (R3-H2): session export / import -- the guest-upgrade and dead-session
//! migration path.
//!
//! A session lives in guest memory across rollup heights (round 3). If a run aborts or traps the
//! session is dead for good (ST_DEAD), and a guest-image upgrade cannot read the old image's heap
//! layout. Both are solved by a canonical, layout-free snapshot of the WHOLE session state:
//!
//!   EXPORT run (input header word 0 = EXPORT_MAGIC, words 1..3 = 0): the image that owns the live
//!     session streams `encode(session)` through sha256 (nothing is stored) and publishes
//!     `snap digest` + `snap words` (+ the MNWIT1 root as both segment roots, no unit runs).
//!   IMPORT run (input = the snapshot words, word 0 = SNAP_MAGIC): accepted only when the image has
//!     NO live session -- a fresh image (upgrade: new GENMEM) or a dead one (revive: the allocator
//!     is reset and the torn session abandoned). The guest decodes and validates the words, rebuilds
//!     the engine state, the derived indexes and the MNWIT1 tree, and publishes the digest of the
//!     words it consumed + the rebuilt root as start = end root. A malformed snapshot -> ST_BAD_SNAP,
//!     no session (a dead image stays dead).
//!
//! Binding (design §7.7): the rollup accepts an import at height i only when its digest equals the
//! digest of an export run at height e whose start memory is the last good final memory, and
//! start_root(i) == end_root(e). Both runs are ordinary disputable runs, so a wrong export (by the
//! old image) or a wrong rebuild (by the new image) loses the bisection game. The export digest
//! covers every field of the session, so the import cannot change state the MNWIT1 root does not
//! commit (seen client_seq, realized PnL, order type / qty, oracle rings, withdrawals, ...).
//!
//! Encoding (u32 words, little-endian multiword integers; maps in key order, levels in FIFO order):
//!   SNAP_MAGIC, SNAP_VERSION, mode (0 off, 1 incremental, 2 legacy | skip << 8), segs,
//!   ChainState: height, seq, accounts, markets, books, marks, oracle_reports, oracle_bonds,
//!   last_index, withdrawals, withdrawn_total, oracle_configs, oracle_report_history, oracle_twap,
//!   funding_twap, funding_index_twap, funding_source, external_price_ring, external_sources,
//!   last_funding_height, seen_client_seq; SNAP_END.
//! Book arrival numbers are not encoded (only their order matters): import numbers each book's
//! level entries 0.. in (ask levels ascending, bid levels descending, FIFO) order, so an imported
//! session exports the identical words.
use crate::account::{Account, Position};
use crate::book::OrderBook;
use crate::book_types::Order;
use crate::state::ChainState;
use crate::types::*;
use crate::{Session, WitMode};
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

pub const SNAP_MAGIC: u32 = 0x4D4E_5331; // "MNS1"
pub const SNAP_END: u32 = 0x4D4E_5345; // "MNSE"
pub const EXPORT_MAGIC: u32 = 0x4D4E_5845; // "MNXE"
pub const SNAP_VERSION: u32 = 1;
/// Import refuses counts above these (each bounds one map of the snapshot; the session caps of
/// state.rs keep honest exports far below them). Keeps a malformed snapshot from exhausting the
/// guest heap before the digest check would reject it.
pub const SNAP_MAX_ITEMS: u32 = 1 << 20;

/// Word sink: running sha256 over the LE bytes of every word, optionally keeping the words.
pub struct SnapW {
    h: Sha256,
    pub n: u32,
    pub keep: Option<Vec<u32>>,
}
impl SnapW {
    pub fn new(keep: bool) -> Self {
        SnapW { h: Sha256::new(), n: 0, keep: if keep { Some(Vec::new()) } else { None } }
    }
    pub fn w(&mut self, x: u32) {
        self.h.update(x.to_le_bytes());
        self.n += 1;
        if let Some(k) = self.keep.as_mut() {
            k.push(x);
        }
    }
    pub fn u64(&mut self, x: u64) {
        self.w(x as u32);
        self.w((x >> 32) as u32);
    }
    pub fn i64(&mut self, x: i64) {
        self.u64(x as u64);
    }
    pub fn u128(&mut self, x: u128) {
        self.u64(x as u64);
        self.u64((x >> 64) as u64);
    }
    pub fn i128(&mut self, x: i128) {
        self.u128(x as u128);
    }
    pub fn b(&mut self, x: bool) {
        self.w(x as u32);
    }
    pub fn id(&mut self, x: &[u8; 32]) {
        for k in 0..8 {
            self.w(u32::from_le_bytes([x[4 * k], x[4 * k + 1], x[4 * k + 2], x[4 * k + 3]]));
        }
    }
    pub fn len(&mut self, n: usize) {
        self.w(n as u32);
    }
    pub fn digest(self) -> ([u8; 32], u32, Option<Vec<u32>>) {
        (self.h.finalize().into(), self.n, self.keep)
    }
}

/// Word source over the input tree (`rd(i)`), hashing what it reads. Every read past `limit`
/// fails the decode (the guest's input words past the end read as 0 -- never trusted here).
pub struct SnapR<'a> {
    rd: &'a mut dyn FnMut(u32) -> u32,
    pub i: u32,
    limit: u32,
    h: Sha256,
}
pub type Res<T> = Result<T, ()>;
impl<'a> SnapR<'a> {
    pub fn new(rd: &'a mut dyn FnMut(u32) -> u32, limit: u32) -> Self {
        SnapR { rd, i: 0, limit, h: Sha256::new() }
    }
    pub fn w(&mut self) -> Res<u32> {
        if self.i >= self.limit {
            return Err(());
        }
        let x = (self.rd)(self.i);
        self.i += 1;
        self.h.update(x.to_le_bytes());
        Ok(x)
    }
    pub fn u64(&mut self) -> Res<u64> {
        let lo = self.w()? as u64;
        Ok(lo | ((self.w()? as u64) << 32))
    }
    pub fn i64(&mut self) -> Res<i64> {
        Ok(self.u64()? as i64)
    }
    pub fn u128(&mut self) -> Res<u128> {
        let lo = self.u64()? as u128;
        Ok(lo | ((self.u64()? as u128) << 64))
    }
    pub fn i128(&mut self) -> Res<i128> {
        Ok(self.u128()? as i128)
    }
    pub fn b(&mut self) -> Res<bool> {
        match self.w()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(()),
        }
    }
    pub fn id(&mut self) -> Res<[u8; 32]> {
        let mut o = [0u8; 32];
        for k in 0..8 {
            o[4 * k..4 * k + 4].copy_from_slice(&self.w()?.to_le_bytes());
        }
        Ok(o)
    }
    pub fn len(&mut self) -> Res<u32> {
        let n = self.w()?;
        if n > SNAP_MAX_ITEMS || n > self.limit - self.i {
            return Err(()); // every item takes >= 1 word
        }
        Ok(n)
    }
    pub fn digest(self) -> [u8; 32] {
        self.h.finalize().into()
    }
}

fn w_params(w: &mut SnapW, p: &MarketParams) {
    for k in 0..4 {
        w.w(u32::from_le_bytes([p.symbol[4 * k], p.symbol[4 * k + 1], p.symbol[4 * k + 2], p.symbol[4 * k + 3]]));
    }
    w.i64(p.tick_size);
    w.u64(p.im_bps);
    w.u64(p.mm_bps);
    w.u64(p.taker_fee_bps);
    w.u64(p.keeper_reward_bps);
    w.b(p.delisted);
    w.b(p.spot_only);
    w.b(p.funding_rate);
    w.u64(p.usd_per_unit);
    w.u64(p.funding_cap_bps);
    w.i64(p.min_price);
    w.i64(p.max_price);
}
fn r_params(r: &mut SnapR) -> Res<MarketParams> {
    let mut symbol = [0u8; 16];
    for k in 0..4 {
        symbol[4 * k..4 * k + 4].copy_from_slice(&r.w()?.to_le_bytes());
    }
    Ok(MarketParams {
        symbol,
        tick_size: r.i64()?,
        im_bps: r.u64()?,
        mm_bps: r.u64()?,
        taker_fee_bps: r.u64()?,
        keeper_reward_bps: r.u64()?,
        delisted: r.b()?,
        spot_only: r.b()?,
        funding_rate: r.b()?,
        usd_per_unit: r.u64()?,
        funding_cap_bps: r.u64()?,
        min_price: r.i64()?,
        max_price: r.i64()?,
    })
}
pub fn w_order(w: &mut SnapW, o: &Order) {
    w.id(&o.id.0);
    w.id(&o.account.0);
    w.w(o.market.0);
    w.w(o.side.as_u8() as u32);
    w.w(o.typ.as_u8() as u32);
    w.w(o.tif.as_u8() as u32);
    w.i64(o.price);
    w.u64(o.qty);
    w.u64(o.remaining);
    w.u64(o.seq);
    w.b(o.isolated);
    w.u64(o.margin_left);
}
pub fn r_order(r: &mut SnapR) -> Res<Order> {
    Ok(Order {
        id: OrderId(r.id()?),
        account: AccountId(r.id()?),
        market: MarketId(r.w()?),
        side: Side::from_u8(r.w()? as u8).ok_or(())?,
        typ: OrderType::from_u8(r.w()? as u8).ok_or(())?,
        tif: TimeInForce::from_u8(r.w()? as u8).ok_or(())?,
        price: r.i64()?,
        qty: r.u64()?,
        remaining: r.u64()?,
        seq: r.u64()?,
        isolated: r.b()?,
        margin_left: r.u64()?,
    })
}

/// Stream the session into `w` (canonical: a pure function of the logical state).
pub fn encode(sess: &Session, w: &mut SnapW) {
    let s = &sess.eng.state;
    w.w(SNAP_MAGIC);
    w.w(SNAP_VERSION);
    w.w(match sess.mode {
        WitMode::Off => 0,
        WitMode::Incremental => 1,
        WitMode::Legacy { skip } => 2 | (skip << 8),
    });
    w.w(sess.segs);
    w.u64(s.height);
    w.u64(s.seq);
    w.len(s.accounts.len());
    for (id, a) in &s.accounts {
        w.id(&id.0);
        w.i128(a.collateral);
        w.i128(a.realized_pnl);
        w.len(a.positions.len());
        for (m, p) in &a.positions {
            w.w(m.0);
            w.w(p.market.0);
            w.i64(p.qty);
            w.i64(p.entry_price);
            w.b(p.isolated);
        }
        w.len(a.isolated_margin.len());
        for (m, x) in &a.isolated_margin {
            w.w(m.0);
            w.i128(*x);
        }
    }
    w.len(s.markets.len());
    for (m, p) in &s.markets {
        w.w(m.0);
        w_params(w, p);
    }
    w.len(s.books.len());
    for (m, b) in &s.books {
        w.w(m.0);
        b.snap_write(w);
    }
    w.len(s.marks.len());
    for (m, p) in &s.marks {
        w.w(m.0);
        w.i64(*p);
    }
    w.len(s.oracle_reports.len());
    for ((m, a), p) in &s.oracle_reports {
        w.w(m.0);
        w.id(&a.0);
        w.i64(*p);
    }
    w.len(s.oracle_bonds.len());
    for (a, x) in &s.oracle_bonds {
        w.id(&a.0);
        w.u128(*x);
    }
    w.len(s.last_index.len());
    for (m, p) in &s.last_index {
        w.w(m.0);
        w.i64(*p);
    }
    w.len(s.withdrawals.len());
    for ((a, n), x) in &s.withdrawals {
        w.id(&a.0);
        w.u64(*n);
        w.i128(x.amount);
        w.b(x.pending);
        w.u64(x.height);
    }
    w.len(s.withdrawn_total.len());
    for (a, x) in &s.withdrawn_total {
        w.id(&a.0);
        w.i128(*x);
    }
    w.len(s.oracle_configs.len());
    for (m, c) in &s.oracle_configs {
        w.w(m.0);
        w.u64(c.deviation_bps);
        w.u64(c.twap_window);
        w.u64(c.slash_reward_bps);
    }
    w.len(s.oracle_report_history.len());
    for ((m, a), q) in &s.oracle_report_history {
        w.w(m.0);
        w.id(&a.0);
        w.len(q.len());
        for x in q {
            w.u64(x.height);
            w.i64(x.price);
            w.u64(x.seq);
        }
    }
    for map in [&s.oracle_twap, &s.funding_twap] {
        w.len(map.len());
        for (m, q) in map {
            w.w(m.0);
            w.len(q.len());
            for x in q {
                w.u64(x.seq);
                w.u64(x.height);
                w.i64(x.median);
            }
        }
    }
    w.len(s.funding_index_twap.len());
    for (m, p) in &s.funding_index_twap {
        w.w(m.0);
        w.i64(*p);
    }
    w.w(s.funding_source as u32);
    w.len(s.external_price_ring.len());
    for (m, q) in &s.external_price_ring {
        w.w(m.0);
        w.len(q.len());
        for x in q {
            w.u64(x.seq);
            w.u64(x.height);
            w.i64(x.price);
            w.w(x.source_id as u32);
        }
    }
    w.len(s.external_sources.len());
    for a in &s.external_sources {
        w.id(&a.0);
    }
    w.len(s.last_funding_height.len());
    for (m, h) in &s.last_funding_height {
        w.w(m.0);
        w.u64(*h);
    }
    w.len(s.seen_client_seq.len());
    for (a, c) in &s.seen_client_seq {
        w.id(&a.0);
        w.u64(*c);
    }
    w.w(SNAP_END);
}

/// keys must arrive strictly ascending (canonical form; also rules out duplicates)
fn asc<K: Ord + Copy>(prev: &mut Option<K>, k: K) -> Res<()> {
    if let Some(p) = *prev {
        if k <= p {
            return Err(());
        }
    }
    *prev = Some(k);
    Ok(())
}

/// Decode a snapshot into a fresh session (state, derived indexes, MNWIT1 tree). Errors on any
/// malformed or non-canonical input. Returns the session and the digest of the words consumed.
pub fn decode(r: &mut SnapR) -> Res<Session> {
    if r.w()? != SNAP_MAGIC || r.w()? != SNAP_VERSION {
        return Err(());
    }
    let mode = match r.w()? {
        0 => WitMode::Off,
        1 => WitMode::Incremental,
        x if x & 0xff == 2 => WitMode::Legacy { skip: x >> 8 },
        _ => return Err(()),
    };
    let segs = r.w()?;
    let mut s = ChainState::default();
    s.height = r.u64()?;
    s.seq = r.u64()?;
    let mut pk = None;
    for _ in 0..r.len()? {
        let id = AccountId(r.id()?);
        asc(&mut pk, id)?;
        let mut a = Account::new(id);
        a.collateral = r.i128()?;
        a.realized_pnl = r.i128()?;
        let mut pm = None;
        for _ in 0..r.len()? {
            let m = MarketId(r.w()?);
            asc(&mut pm, m)?;
            let p = Position { market: MarketId(r.w()?), qty: r.i64()?, entry_price: r.i64()?, isolated: r.b()? };
            a.positions.insert(m, p);
        }
        let mut pm = None;
        for _ in 0..r.len()? {
            let m = MarketId(r.w()?);
            asc(&mut pm, m)?;
            a.isolated_margin.insert(m, r.i128()?);
        }
        s.accounts.insert(id, a);
    }
    let mut pk = None;
    for _ in 0..r.len()? {
        let m = MarketId(r.w()?);
        asc(&mut pk, m)?;
        s.markets.insert(m, r_params(r)?);
    }
    let mut pk = None;
    for _ in 0..r.len()? {
        let m = MarketId(r.w()?);
        asc(&mut pk, m)?;
        s.books.insert(m, OrderBook::snap_read(r, m)?);
    }
    let mut pk = None;
    for _ in 0..r.len()? {
        let m = MarketId(r.w()?);
        asc(&mut pk, m)?;
        s.marks.insert(m, r.i64()?);
    }
    let mut pk = None;
    for _ in 0..r.len()? {
        let k = (MarketId(r.w()?), AccountId(r.id()?));
        asc(&mut pk, k)?;
        s.oracle_reports.insert(k, r.i64()?);
    }
    let mut pk = None;
    for _ in 0..r.len()? {
        let a = AccountId(r.id()?);
        asc(&mut pk, a)?;
        s.oracle_bonds.insert(a, r.u128()?);
    }
    let mut pk = None;
    for _ in 0..r.len()? {
        let m = MarketId(r.w()?);
        asc(&mut pk, m)?;
        s.last_index.insert(m, r.i64()?);
    }
    let mut pk = None;
    for _ in 0..r.len()? {
        let k = (AccountId(r.id()?), r.u64()?);
        asc(&mut pk, k)?;
        s.withdrawals.insert(k, Withdrawal { amount: r.i128()?, pending: r.b()?, height: r.u64()? });
    }
    let mut pk = None;
    for _ in 0..r.len()? {
        let a = AccountId(r.id()?);
        asc(&mut pk, a)?;
        s.withdrawn_total.insert(a, r.i128()?);
    }
    let mut pk = None;
    for _ in 0..r.len()? {
        let m = MarketId(r.w()?);
        asc(&mut pk, m)?;
        s.oracle_configs.insert(m, OracleConfig { deviation_bps: r.u64()?, twap_window: r.u64()?, slash_reward_bps: r.u64()? });
    }
    let mut pk = None;
    for _ in 0..r.len()? {
        let k = (MarketId(r.w()?), AccountId(r.id()?));
        asc(&mut pk, k)?;
        let mut q = VecDeque::new();
        for _ in 0..r.len()? {
            q.push_back(ReportSample { height: r.u64()?, price: r.i64()?, seq: r.u64()? });
        }
        s.oracle_report_history.insert(k, q);
    }
    for which in 0..2 {
        let mut pk = None;
        for _ in 0..r.len()? {
            let m = MarketId(r.w()?);
            asc(&mut pk, m)?;
            let mut q = VecDeque::new();
            for _ in 0..r.len()? {
                q.push_back(TwapSample { seq: r.u64()?, height: r.u64()?, median: r.i64()? });
            }
            if which == 0 {
                s.oracle_twap.insert(m, q);
            } else {
                s.funding_twap.insert(m, q);
            }
        }
    }
    let mut pk = None;
    for _ in 0..r.len()? {
        let m = MarketId(r.w()?);
        asc(&mut pk, m)?;
        s.funding_index_twap.insert(m, r.i64()?);
    }
    s.funding_source = match r.w()? {
        0 => FundingSourceKind::BondedMedianTwap,
        1 => FundingSourceKind::AggregatedExternal,
        _ => return Err(()),
    };
    let mut pk = None;
    for _ in 0..r.len()? {
        let m = MarketId(r.w()?);
        asc(&mut pk, m)?;
        let mut q = VecDeque::new();
        for _ in 0..r.len()? {
            let (seq, height, price) = (r.u64()?, r.u64()?, r.i64()?);
            let sid = r.w()?;
            if sid > 0xff {
                return Err(());
            }
            q.push_back(ExternalSample { seq, height, price, source_id: sid as u8 });
        }
        s.external_price_ring.insert(m, q);
    }
    let mut pk = None;
    for _ in 0..r.len()? {
        let a = AccountId(r.id()?);
        asc(&mut pk, a)?;
        s.external_sources.insert(a);
    }
    let mut pk = None;
    for _ in 0..r.len()? {
        let m = MarketId(r.w()?);
        asc(&mut pk, m)?;
        s.last_funding_height.insert(m, r.u64()?);
    }
    let mut pk = None;
    for _ in 0..r.len()? {
        let a = AccountId(r.id()?);
        asc(&mut pk, a)?;
        s.seen_client_seq.insert(a, r.u64()?);
    }
    if r.w()? != SNAP_END {
        return Err(());
    }
    // every book must belong to a listed market (engine invariant: market_params indexes them)
    if s.books.keys().any(|m| !s.markets.contains_key(m)) {
        return Err(());
    }
    let w = if mode == WitMode::Incremental { Some(crate::wit::Wit::from_state(&s)) } else { None };
    let _ = s.take_dirty();
    // the account cap is a consensus constant, not session state; an import above it is malformed
    if s.accounts.len() > crate::MAX_STATE_ACCOUNTS {
        return Err(());
    }
    Ok(Session { eng: crate::engine::Engine { state: s }, w, mode, segs, state_cap: crate::MAX_STATE_ACCOUNTS })
}

/// Host / guest export: (digest, words, kept words).
pub fn export(sess: &Session, keep: bool) -> ([u8; 32], u32, Option<Vec<u32>>) {
    let mut w = SnapW::new(keep);
    encode(sess, &mut w);
    w.digest()
}
