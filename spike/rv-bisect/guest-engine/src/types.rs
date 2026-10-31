//! Subset of minuend-types @ fix/47-all 20326c0, copied verbatim (serde derives, hex Debug impls,
//! std-only helpers dropped). Sources: minuend-types/src/{lib,amount,ids,order}.rs.
// ---- lib.rs (constants + types) ----
pub type Price = i64;
pub type Qty = u64;
pub type Usd = i128;
pub type Seq = u64;
pub type Height = u64;
pub type Bps = u64;
pub const PRICE_SCALE: u64 = 100_000_000;
pub const QTY_SCALE: u64 = 100_000_000;
pub const USD_SCALE: u64 = 1_000_000;
pub const QTY_CAP: u64 = 1_000_000_000_000_000;
pub const MARK_CAP: i64 = 1_000_000_000_000_000;
pub const IM_RATE_BPS: u64 = 1000;
pub const MM_RATE_BPS: u64 = 500;
pub const MIN_OPEN_EQUITY: Usd = USD_SCALE as Usd;
pub const MAX_LIVE_ORDERS_PER_ACCOUNT: usize = 64;
pub const LIQ_RATIO_BPS: u64 = 10_500;
pub const REDUCE_ONLY_RATIO_BPS: u64 = 12_000;
pub const TAKER_FEE_BPS: u64 = 5;
pub const FUNDING_PRICE_OFFSET: Price = 10_000 * PRICE_SCALE as Price;
pub const FUNDING_BPS_UNIT: Price = (PRICE_SCALE / 10_000) as Price;
pub const BTC_USD: MarketId = MarketId(1);
pub const INSURANCE_ACCOUNT: AccountId = AccountId([0u8; 32]);
pub const KEEPER_REWARD_BPS: u64 = 100;
pub fn funding_rate_bps(price: Price) -> i64 {
    price.saturating_sub(FUNDING_PRICE_OFFSET) / FUNDING_BPS_UNIT
}
pub fn spot_market_tradeable(p: &MarketParams) -> bool {
    !p.spot_only || (p.im_bps == 10_000 && p.min_price > 0 && p.max_price > p.min_price)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MarketId(pub u32);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarketParams {
    /// Right-zero-padded ASCII symbol.
    pub symbol: [u8; 16],
    pub tick_size: Price,
    pub im_bps: Bps,
    pub mm_bps: Bps,
    pub taker_fee_bps: Bps,
    pub keeper_reward_bps: Bps,
    pub delisted: bool,
    /// Meme/contract-only market: fixed at creation, no ParamKey flips it.
    /// Spot-only markets reject every price report and never accrue funding.
    pub spot_only: bool,
    /// Funding-rate market: book price is an external venue funding rate
    /// (encoded via `encode_funding_price`), reports write the index only,
    /// fills write the mark, and funding settles as the peg. Fixed at
    /// creation; old JSON without this field parses as `false`.
    pub funding_rate: bool,
    /// Dollars per 1.0 qty, listing-time money scale for funding-rate
    /// markets. 0 unless `funding_rate`. Fixed at creation.
    pub usd_per_unit: u64,
    /// Per-window peg cap in bps for this funding-rate market. 0 unless
    /// `funding_rate`. Fixed at creation.
    pub funding_cap_bps: u64,
    /// Lowest price this market may ever trade at (signed price grid).
    /// `0` = unbounded below; each side of the band is independent (#47 L2),
    /// so `[min, 0]` is a floor-only band. For a `spot_only` market (no
    /// oracle, so the mark freezes) it must be strictly positive: a long's
    /// worst case `qty × (entry − min_price)` is what its collateral
    /// reserves (#47 C2). Fixed at creation. Old JSON parses as `0`.
    pub min_price: Price,
    /// Highest price this market may ever trade at (signed price grid).
    /// `0` = unbounded above. Limit orders above it are refused (admission
    /// gate) and off-book ADL prints are clamped to it. Required on a
    /// `spot_only` market, where a short reserves `qty × (max_price −
    /// entry)`. Fixed at creation. Old JSON parses as `0`.
    pub max_price: Price,
}
pub fn genesis_params() -> MarketParams {
    let mut symbol = [0u8; 16];
    symbol[..7].copy_from_slice(b"BTC_USD");
    MarketParams {
        symbol,
        tick_size: 1,
        im_bps: IM_RATE_BPS,
        mm_bps: MM_RATE_BPS,
        taker_fee_bps: TAKER_FEE_BPS,
        keeper_reward_bps: KEEPER_REWARD_BPS,
        delisted: false,
        spot_only: false,
        funding_rate: false,
        usd_per_unit: 0,
        funding_cap_bps: 0,
        min_price: 0,
        max_price: 0,
    }
}
// ---- order.rs ----

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    Bid,
    Ask,
}

impl Side {
    pub fn as_u8(self) -> u8 {
        match self {
            Side::Bid => 0,
            Side::Ask => 1,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Side::Bid),
            1 => Some(Side::Ask),
            _ => None,
        }
    }

    pub fn opposite(self) -> Self {
        match self {
            Side::Bid => Side::Ask,
            Side::Ask => Side::Bid,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OrderType {
    Limit,
    Market,
}

impl OrderType {
    pub fn as_u8(self) -> u8 {
        match self {
            OrderType::Limit => 0,
            OrderType::Market => 1,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(OrderType::Limit),
            1 => Some(OrderType::Market),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimeInForce {
    Gtc,
    Ioc,
}

impl TimeInForce {
    pub fn as_u8(self) -> u8 {
        match self {
            TimeInForce::Gtc => 0,
            TimeInForce::Ioc => 1,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(TimeInForce::Gtc),
            1 => Some(TimeInForce::Ioc),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExecStatus {
    Optimistic,
    Final,
}
// ---- ids.rs ----
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AccountId(pub [u8; 32]);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OrderId(pub [u8; 32]);
pub fn order_id(account: AccountId, market: MarketId, client_seq: u64) -> OrderId {
    let mut buf = [0u8; 32 + 4 + 8];
    buf[..32].copy_from_slice(&account.0);
    buf[32..36].copy_from_slice(&market.0.to_le_bytes());
    buf[36..44].copy_from_slice(&client_seq.to_le_bytes());
    OrderId(sha256(&buf))
}
// ---- amount.rs ----

pub fn notional_usd(qty: Qty, price: Price) -> Usd {
    i128::from(qty) * i128::from(price) / i128::from(PRICE_SCALE) * i128::from(USD_SCALE)
        / i128::from(QTY_SCALE)
}

pub fn signed_notional_usd(qty_signed: i64, price: Price) -> Usd {
    i128::from(qty_signed) * i128::from(price) / i128::from(PRICE_SCALE) * i128::from(USD_SCALE)
        / i128::from(QTY_SCALE)
}

/// Notional for a funding-rate market: `qty` units priced at `usd_per_unit`
/// dollars per 1.0 qty. The encoded book price there is a rate in bps, not a
/// dollar price, so `notional_usd` must not see it.
pub fn funding_notional_usd(qty: Qty, usd_per_unit: u64) -> Usd {
    i128::from(qty) * i128::from(usd_per_unit) * i128::from(USD_SCALE) / i128::from(QTY_SCALE)
}

/// Signed cash for `diff_bps` on `qty_signed` (1.0 qty = `QTY_SCALE`).
/// 1 bp on 1.0 qty pays `usd_per_unit / 10_000` dollars.
pub fn funding_rate_cash(qty_signed: i64, diff_bps: i64, usd_per_unit: u64) -> Usd {
    i128::from(qty_signed) * i128::from(diff_bps) * i128::from(usd_per_unit) * i128::from(USD_SCALE)
        / i128::from(QTY_SCALE)
        / 10_000
}

/// Absolute bps of `value`. IM/MM use abs notional.
pub fn bps(value: Usd, bps: Bps) -> Usd {
    value.saturating_abs() * i128::from(bps) / 10_000
}

pub fn i128_to_le16(v: Usd) -> [u8; 16] {
    v.to_le_bytes()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

// ---- PILOT (loop round 4): oracle / funding / withdraw / liquidation types and constants,
// copied from minuend-types/src/{lib,ids}.rs and minuend-state/src/lib.rs (`Withdrawal`) @ 20326c0
pub const LIQ_MIN_BOOK_FILL_DIV: u64 = 10;
pub const FUNDING_CAP_BPS: i64 = 50;
pub const FUNDING_PEG_INTERVAL_HEIGHTS: Height = 14_400;
pub const ORACLE_TWAP_WINDOW: Height = 256;
pub const ORACLE_TWAP_MAX: Height = 1800;
pub const SLASH_DEVIATION_BPS: u64 = 500;
pub const SLASH_REWARD_BPS: u64 = 5000;
pub const FUNDING_TWAP_WINDOW: Height = 256;
pub const FUNDING_TWAP_MIN_SAMPLES: usize = 2;
pub const FUNDING_EXTERNAL_MAX_STALENESS: Height = 32;
pub const ORACLE_BOND_PERP: u128 = 50_000;
/// minuend-exec: pending withdrawals per account / smallest partial withdrawal
pub const MAX_PENDING_WITHDRAWALS_PER_ACCOUNT: usize = 64;
pub const MIN_WITHDRAW_AMOUNT: Usd = USD_SCALE as Usd;
pub fn encode_funding_price(rate_bps: i64) -> Price {
    FUNDING_PRICE_OFFSET + rate_bps.saturating_mul(FUNDING_BPS_UNIT)
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum FundingSourceKind {
    #[default]
    BondedMedianTwap = 0,
    AggregatedExternal = 1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OracleConfig {
    pub deviation_bps: u64,
    pub twap_window: u64,
    pub slash_reward_bps: u64,
}
impl Default for OracleConfig {
    fn default() -> Self {
        Self {
            deviation_bps: SLASH_DEVIATION_BPS,
            twap_window: ORACLE_TWAP_WINDOW,
            slash_reward_bps: SLASH_REWARD_BPS,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TwapSample {
    pub seq: Seq,
    pub height: Height,
    pub median: Price,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportSample {
    pub height: Height,
    pub price: Price,
    pub seq: Seq,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExternalSample {
    pub seq: Seq,
    pub height: Height,
    pub price: Price,
    pub source_id: u8,
}
#[derive(Clone, Debug)]
pub struct Withdrawal {
    pub amount: Usd,
    pub pending: bool,
    pub height: Height,
}
/// minuend-types ids.rs `liq_order_id` (the unit id is an input of the unit; see engine.rs)
pub fn liq_order_id(unit: [u8; 32]) -> OrderId {
    let mut buf = alloc::vec::Vec::with_capacity(3 + 32);
    buf.extend_from_slice(b"liq");
    buf.extend_from_slice(&unit);
    OrderId(sha256(&buf))
}
