// Copied from minuend-book/src/lib.rs @ fix/47-all 20326c0 (serde/thiserror derives dropped).
use crate::types::{AccountId, MarketId, OrderId, OrderType, Price, Qty, Seq, Side, TimeInForce, Usd};
use alloc::vec::Vec;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    pub id: OrderId,
    pub account: AccountId,
    pub market: MarketId,
    pub side: Side,
    pub typ: OrderType,
    pub tif: TimeInForce,
    pub price: Price,
    pub qty: Qty,
    pub remaining: Qty,
    pub seq: Seq,
    /// Margin mode of this order: `true` = isolated, `false` = cross.
    pub isolated: bool,
    /// Un-escrowed remainder of this order's isolated margin (USD_SCALE).
    /// Always 0 for cross orders.
    pub margin_left: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fill {
    pub taker_id: OrderId,
    pub maker_id: OrderId,
    pub taker: AccountId,
    pub maker: AccountId,
    pub market: MarketId,
    pub price: Price,
    pub qty: Qty,
    pub seq: Seq,
    pub taker_side: Side,
    /// Taker's share of this fill's isolated margin, allocated pro-rata
    /// (USD_SCALE). Always 0 when the taker order is cross.
    pub taker_post: Usd,
    /// Maker's share of this fill's isolated margin, allocated pro-rata
    /// (USD_SCALE). Always 0 when the maker order is cross.
    pub maker_post: Usd,
    pub taker_isolated: bool,
    pub maker_isolated: bool,
    /// Provenance of this fill, committed by `fills_element` so the dispute
    /// AA picks the right collateral identity: 0 = book submit (regular
    /// market), 1 = book submit on a funding-rate market (cash PnL),
    /// 2 = off-book ADL synthetic (no fee), 3 = book fill inside
    /// `Engine::liquidate` (keeper reward applies).
    pub kind: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchResult {
    pub fills: Vec<Fill>,
    pub taker_remaining: Qty,
    pub taker_resting: bool,
    pub canceled_maker: Vec<OrderId>,
    /// Local taker's un-escrowed margin remainder at return (USD_SCALE);
    /// its full remainder when the taker did not rest.
    pub taker_margin_left: u64,
    /// Escrowed margin to refund to makers removed without filling
    /// (self-trade prevention), as (account, amount USD_SCALE).
    pub refunds: Vec<(AccountId, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BookError {
    NotFound,
    ZeroQty,
    ZeroPrice,
    DuplicateOrder,
    WrongMarket,
    SelfTrade,
    /// Round 7: a Limit + Gtc order would take a second maker (one fill
    /// per unit, see `OrderBook::submit_journaled`).
    MultiFill,
}

/// How `OrderBook::submit` treats a self-trade (the incoming order
/// crosses a resting order of the SAME account).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelfTrade {
    /// Cancel the own maker and keep matching. The liquidation path needs
    /// this: the target's book must clear for its close order to execute.
    CancelMaker,
    /// Reject the incoming order outright when the own maker holds
    /// escrowed margin: canceling it would move that margin_left into
    /// collateral inside the same unit — a cash leg no fill predicate can
    /// model, so the exact-identity dispute would false-verdict the honest
    /// batch. Cross makers (`margin_left == 0`) move no cash and still
    /// take the cancel-maker path. The place path uses this.
    Reject,
}

