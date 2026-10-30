mod book;

pub use book::{BookJournal, OrderBook};

use minuend_types::{
    AccountId, MarketId, OrderId, OrderType, Price, Qty, Seq, Side, TimeInForce, Usd,
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    #[serde(default)]
    pub isolated: bool,
    /// Un-escrowed remainder of this order's isolated margin (USD_SCALE).
    /// Always 0 for cross orders.
    #[serde(default)]
    pub margin_left: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    #[serde(default)]
    pub taker_post: Usd,
    /// Maker's share of this fill's isolated margin, allocated pro-rata
    /// (USD_SCALE). Always 0 when the maker order is cross.
    #[serde(default)]
    pub maker_post: Usd,
    #[serde(default)]
    pub taker_isolated: bool,
    #[serde(default)]
    pub maker_isolated: bool,
    /// Provenance of this fill, committed by `fills_element` so the dispute
    /// AA picks the right collateral identity: 0 = book submit (regular
    /// market), 1 = book submit on a funding-rate market (cash PnL),
    /// 2 = off-book ADL synthetic (no fee), 3 = book fill inside
    /// `Engine::liquidate` (keeper reward applies).
    #[serde(default)]
    pub kind: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum BookError {
    #[error("not found")]
    NotFound,
    #[error("zero qty")]
    ZeroQty,
    #[error("zero price")]
    ZeroPrice,
    #[error("duplicate order")]
    DuplicateOrder,
    #[error("wrong market")]
    WrongMarket,
    #[error("self trade with escrowed own order")]
    SelfTrade,
    /// Round 7: a Limit + Gtc order would take a second maker (one fill
    /// per unit, see `OrderBook::submit_journaled`).
    #[error("order would take more than one maker")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use minuend_types::{order_id, BTC_USD, PRICE_SCALE, QTY_SCALE, USD_SCALE};

    fn acct(n: u8) -> AccountId {
        AccountId([n; 32])
    }

    fn oid(a: AccountId, seq: u64) -> OrderId {
        order_id(a, BTC_USD, seq)
    }

    #[allow(clippy::too_many_arguments)]
    fn order(
        account: AccountId,
        client_seq: u64,
        side: Side,
        typ: OrderType,
        tif: TimeInForce,
        price: Price,
        qty: Qty,
        seq: Seq,
    ) -> Order {
        let id = oid(account, client_seq);
        Order {
            id,
            account,
            market: BTC_USD,
            side,
            typ,
            tif,
            price,
            qty,
            remaining: qty,
            seq,
            isolated: false,
            margin_left: 0,
        }
    }

    #[test]
    fn limit_buy_crosses_one_sell() {
        let mut book = OrderBook::new(BTC_USD);
        let maker = acct(1);
        let taker = acct(2);
        let px = 100 * PRICE_SCALE as i64;
        let qty = QTY_SCALE;
        book.submit(order(
            maker,
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            1,
        ))
        .unwrap();
        let r = book
            .submit(order(
                taker,
                1,
                Side::Bid,
                OrderType::Limit,
                TimeInForce::Gtc,
                px + PRICE_SCALE as i64,
                qty * 2,
                2,
            ))
            .unwrap();
        assert_eq!(r.fills.len(), 1);
        assert_eq!(r.fills[0].price, px);
        assert_eq!(r.fills[0].qty, qty);
        assert!(r.taker_resting);
        assert_eq!(r.taker_remaining, qty);
        assert_eq!(book.best_bid().unwrap().0, px + PRICE_SCALE as i64);
    }

    #[test]
    fn partial_fill_then_rest() {
        let mut book = OrderBook::new(BTC_USD);
        let maker = acct(1);
        let taker = acct(2);
        let px = 50 * PRICE_SCALE as i64;
        book.submit(order(
            maker,
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE / 2,
            1,
        ))
        .unwrap();
        let r = book
            .submit(order(
                taker,
                1,
                Side::Bid,
                OrderType::Limit,
                TimeInForce::Gtc,
                px,
                QTY_SCALE,
                2,
            ))
            .unwrap();
        assert_eq!(r.fills[0].qty, QTY_SCALE / 2);
        assert!(r.taker_resting);
        assert_eq!(r.taker_remaining, QTY_SCALE / 2);
    }

    #[test]
    fn market_buy_eats_two_ask_levels() {
        let mut book = OrderBook::new(BTC_USD);
        let maker = acct(1);
        let taker = acct(2);
        book.submit(order(
            maker,
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            100 * PRICE_SCALE as i64,
            QTY_SCALE,
            1,
        ))
        .unwrap();
        book.submit(order(
            maker,
            2,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            101 * PRICE_SCALE as i64,
            QTY_SCALE,
            2,
        ))
        .unwrap();
        let r = book
            .submit(order(
                taker,
                1,
                Side::Bid,
                OrderType::Market,
                TimeInForce::Ioc,
                0,
                2 * QTY_SCALE,
                3,
            ))
            .unwrap();
        assert_eq!(r.fills.len(), 2);
        assert_eq!(r.fills[0].price, 100 * PRICE_SCALE as i64);
        assert_eq!(r.fills[1].price, 101 * PRICE_SCALE as i64);
        assert!(!r.taker_resting);
        assert_eq!(book.best_ask(), None);
    }

    #[test]
    fn cancel_resting_then_missing_errors() {
        let mut book = OrderBook::new(BTC_USD);
        let a = acct(1);
        let o = order(
            a,
            1,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            10 * PRICE_SCALE as i64,
            QTY_SCALE,
            1,
        );
        let id = o.id;
        book.submit(o).unwrap();
        book.cancel(id).unwrap();
        assert!(matches!(book.cancel(id), Err(BookError::NotFound)));
    }

    #[test]
    fn self_trade_cancel_taker() {
        let mut book = OrderBook::new(BTC_USD);
        let a = acct(1);
        let b = acct(2);
        let px = 100 * PRICE_SCALE as i64;
        // Own resting ask at the front of the queue...
        book.submit(order(
            a,
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            1,
        ))
        .unwrap();
        // ...followed by another account's at the same price.
        book.submit(order(
            b,
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            2,
        ))
        .unwrap();
        let r = book
            .submit(order(
                a,
                2,
                Side::Bid,
                OrderType::Limit,
                TimeInForce::Gtc,
                px,
                2 * QTY_SCALE,
                3,
            ))
            .unwrap();
        // Own maker was canceled, not matched against.
        assert_eq!(r.canceled_maker, vec![oid(a, 1)]);
        assert!(book.get(oid(a, 1)).is_none());
        // Matching continued against the next account's order.
        assert_eq!(r.fills.len(), 1);
        assert_eq!(r.fills[0].maker, b);
        assert_eq!(r.fills[0].qty, QTY_SCALE);
        // GTC remainder rests back in the book.
        assert!(r.taker_resting);
        assert_eq!(r.taker_remaining, QTY_SCALE);
        assert_eq!(book.get(oid(a, 2)).unwrap().remaining, QTY_SCALE);
        // Ask level is fully drained (cancel + fill), no phantom qty.
        assert_eq!(book.best_ask(), None);
    }

    #[test]
    fn escrowed_self_trade_rejects_in_reject_mode() {
        // An own maker holding ESCROWED margin must not be canceled by a
        // place-path submit: the refund would move its margin_left into
        // collateral inside the same fill-bearing unit — a cash leg no
        // fill predicate can model. Reject mode fails the whole submit
        // with the book untouched; CancelMaker (liquidation path) keeps
        // the historical cancel-and-continue behavior.
        let mut book = OrderBook::new(BTC_USD);
        let a = acct(1);
        let px = 100 * PRICE_SCALE as i64;
        let mut iso = order(
            a,
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            1,
        );
        iso.isolated = true;
        iso.margin_left = 5 * USD_SCALE;
        book.submit(iso).unwrap();

        let cross = || {
            let mut o = order(
                a,
                2,
                Side::Bid,
                OrderType::Limit,
                TimeInForce::Gtc,
                px,
                QTY_SCALE,
                2,
            );
            o.isolated = true;
            o
        };
        // Reject mode: the self-trade error fires before any mutation —
        // maker still in the book, nothing canceled, nothing filled.
        let err = book.submit_with(cross(), SelfTrade::Reject);
        assert_eq!(err, Err(BookError::SelfTrade));
        assert_eq!(book.get(oid(a, 1)).unwrap().margin_left, 5 * USD_SCALE);
        assert!(book.get(oid(a, 2)).is_none());

        // CancelMaker: the own maker is canceled and its escrow refund is
        // reported (the caller returns it to collateral).
        let r = book.submit(cross()).unwrap();
        assert_eq!(r.canceled_maker, vec![oid(a, 1)]);
        assert_eq!(r.refunds, vec![(a, 5 * USD_SCALE)]);
        assert!(book.get(oid(a, 1)).is_none());
    }

    #[test]
    fn reject_after_prior_maker_match_preserves_entire_book() {
        let mut book = OrderBook::new(BTC_USD);
        let taker = acct(1);
        let external_maker = acct(2);
        let px = 100 * PRICE_SCALE as i64;
        let qty = QTY_SCALE;
        book.submit(order(
            external_maker,
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            1,
        ))
        .unwrap();
        let mut own = order(
            taker,
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            2,
        );
        own.isolated = true;
        own.margin_left = 5 * USD_SCALE;
        book.submit(own).unwrap();
        let before = book.commitment_bytes();

        let mut incoming = order(
            taker,
            2,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            2 * qty,
            3,
        );
        incoming.isolated = true;
        assert_eq!(
            book.submit_with(incoming, SelfTrade::Reject),
            Err(BookError::SelfTrade)
        );
        assert_eq!(book.commitment_bytes(), before);
        assert_eq!(book.order_count(), 2);
        assert_eq!(book.get(oid(external_maker, 1)).unwrap().remaining, qty);
        assert_eq!(book.get(oid(taker, 1)).unwrap().margin_left, 5 * USD_SCALE);
        assert!(book.get(oid(taker, 2)).is_none());
    }

    #[test]
    fn price_time_fifo_same_price() {
        let mut book = OrderBook::new(BTC_USD);
        let m1 = acct(1);
        let m2 = acct(2);
        let t = acct(3);
        let px = 100 * PRICE_SCALE as i64;
        book.submit(order(
            m1,
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            1,
        ))
        .unwrap();
        book.submit(order(
            m2,
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            2,
        ))
        .unwrap();
        let r = book
            .submit(order(
                t,
                1,
                Side::Bid,
                OrderType::Limit,
                TimeInForce::Gtc,
                px,
                QTY_SCALE,
                3,
            ))
            .unwrap();
        assert_eq!(r.fills.len(), 1);
        assert_eq!(r.fills[0].maker, m1);
        assert_eq!(book.get(oid(m2, 1)).unwrap().remaining, QTY_SCALE);
        assert_eq!(book.best_ask().unwrap(), (px, QTY_SCALE));
    }

    #[test]
    fn full_fill_does_not_disturb_opposite_side() {
        // Regression: maker completion must pop the MAKER's own queue, not the
        // taker-side queue. Resting bid @99 must survive a market buy that
        // fully fills an ask.
        let mut book = OrderBook::new(BTC_USD);
        book.submit(order(
            acct(1),
            1,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            99 * PRICE_SCALE as i64,
            QTY_SCALE,
            1,
        ))
        .unwrap();
        book.submit(order(
            acct(2),
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            101 * PRICE_SCALE as i64,
            QTY_SCALE,
            1,
        ))
        .unwrap();
        book.submit(order(
            acct(2),
            2,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            100 * PRICE_SCALE as i64,
            QTY_SCALE,
            2,
        ))
        .unwrap();
        let r = book
            .submit(order(
                acct(3),
                1,
                Side::Bid,
                OrderType::Market,
                TimeInForce::Ioc,
                0,
                QTY_SCALE,
                3,
            ))
            .unwrap();
        assert_eq!(r.fills.len(), 1);
        assert_eq!(r.fills[0].price, 100 * PRICE_SCALE as i64);
        // The resting bid @99 must still be live and matchable.
        let r2 = book
            .submit(order(
                acct(4),
                1,
                Side::Ask,
                OrderType::Market,
                TimeInForce::Ioc,
                0,
                QTY_SCALE,
                4,
            ))
            .unwrap();
        assert_eq!(r2.fills.len(), 1);
        assert_eq!(r2.fills[0].price, 99 * PRICE_SCALE as i64);
    }

    #[test]
    fn cancel_non_head_decrements_cache() {
        let mut book = OrderBook::new(BTC_USD);
        let a1 = order(
            acct(1),
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            100 * PRICE_SCALE as i64,
            QTY_SCALE,
            1,
        );
        let a2 = order(
            acct(2),
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            100 * PRICE_SCALE as i64,
            QTY_SCALE * 3,
            2,
        );
        book.submit(a1.clone()).unwrap();
        book.submit(a2.clone()).unwrap();
        assert_eq!(
            book.best_ask().unwrap(),
            (100 * PRICE_SCALE as i64, QTY_SCALE * 4)
        );
        // Cancel the non-head order (acct2): visible qty must drop to X only.
        book.cancel(a2.id).unwrap();
        assert_eq!(
            book.best_ask().unwrap(),
            (100 * PRICE_SCALE as i64, QTY_SCALE)
        );
        // Drain the head too: level disappears entirely (no phantom qty).
        book.cancel(a1.id).unwrap();
        assert_eq!(book.best_ask(), None);
    }

    #[test]
    fn cancel_non_head_bid_side_mirror() {
        let mut book = OrderBook::new(BTC_USD);
        let b1 = order(
            acct(1),
            1,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            99 * PRICE_SCALE as i64,
            QTY_SCALE * 2,
            1,
        );
        let b2 = order(
            acct(2),
            1,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            99 * PRICE_SCALE as i64,
            QTY_SCALE,
            2,
        );
        book.submit(b1.clone()).unwrap();
        book.submit(b2.clone()).unwrap();
        assert_eq!(
            book.best_bid().unwrap(),
            (99 * PRICE_SCALE as i64, QTY_SCALE * 3)
        );
        book.cancel(b2.id).unwrap();
        assert_eq!(
            book.best_bid().unwrap(),
            (99 * PRICE_SCALE as i64, QTY_SCALE * 2)
        );
        book.cancel(b1.id).unwrap();
        assert_eq!(book.best_bid(), None);
    }

    /// #47 B4: the undo journal must restore the book EXACTLY — both when
    /// `submit_with` fails mid-match (self-trade reject after earlier
    /// fills) and when a caller rolls back a successful submit. Drives a
    /// deterministic pseudo-random order flow (several accounts, both
    /// sides, limit/market, GTC/IOC, escrowed makers, cancels, stale queue
    /// entries) and checks `rollback(journal) == clone-before` every step.
    #[test]
    fn journal_rollback_restores_book_exactly() {
        let mut book = OrderBook::new(BTC_USD);
        let mut rng: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let mut live: Vec<OrderId> = Vec::new();
        let (mut errs, mut fills) = (0usize, 0usize);
        for step in 0..3000u64 {
            let r = next();
            if r % 7 == 0 && !live.is_empty() {
                let id = live[(r as usize / 7) % live.len()];
                let _ = book.cancel(id);
                continue;
            }
            let account = acct((r % 4) as u8 + 1);
            let side = if (r >> 8) % 2 == 0 {
                Side::Bid
            } else {
                Side::Ask
            };
            let market = (r >> 12) % 6 == 0;
            let typ = if market {
                OrderType::Market
            } else {
                OrderType::Limit
            };
            let tif = if market || (r >> 16) % 3 == 0 {
                TimeInForce::Ioc
            } else {
                TimeInForce::Gtc
            };
            let price = if market {
                0
            } else {
                (95 + ((r >> 20) % 10) as i64) * PRICE_SCALE as i64
            };
            let qty = (1 + (r >> 28) % 5) * QTY_SCALE;
            let mut o = order(account, step, side, typ, tif, price, qty, step);
            if (r >> 36) % 4 == 0 && !market {
                o.isolated = true;
                o.margin_left = 1_000;
            }
            let before = book.clone();
            match book.submit_journaled(o.clone(), SelfTrade::Reject) {
                Ok((res, j)) => {
                    fills += res.fills.len();
                    let after = book.clone();
                    book.rollback(j);
                    assert_eq!(book, before, "rollback after Ok diverged at step {step}");
                    book = after;
                    if res.taker_resting {
                        live.push(o.id);
                    }
                }
                Err(_) => {
                    errs += 1;
                    assert_eq!(
                        book, before,
                        "failed submit mutated the book at step {step}"
                    );
                }
            }
        }
        // The flow must actually exercise both paths.
        assert!(errs > 0 && fills > 0, "errs={errs} fills={fills}");
    }
}
