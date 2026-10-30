use crate::{BookError, Fill, MatchResult, Order, SelfTrade};
use minuend_types::{AccountId, MarketId, OrderId, OrderType, Price, Qty, Side, TimeInForce, Usd};
use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

/// Share of an order's escrowed isolated margin consumed by one fill:
/// pro-rata of quantity, floored. The fill that exhausts the order's
/// remaining quantity takes the whole rest, so the sum across fills is
/// exact. Cross orders carry `margin_left == 0` → always 0.
fn pro_rata_post(margin_left: u64, fill_qty: u64, remaining_before: u64) -> u64 {
    if margin_left == 0 || remaining_before == 0 {
        return 0;
    }
    if fill_qty >= remaining_before {
        margin_left
    } else {
        (u128::from(margin_left) * u128::from(fill_qty) / u128::from(remaining_before)) as u64
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OrderBook {
    market: MarketId,
    bids: BTreeMap<Reverse<Price>, VecDeque<OrderId>>,
    asks: BTreeMap<Price, VecDeque<OrderId>>,
    orders: HashMap<OrderId, Order>,
    /// Incrementally-maintained visible qty per price level (bids).
    bid_qty: BTreeMap<Reverse<Price>, Qty>,
    /// Incrementally-maintained visible qty per price level (asks).
    ask_qty: BTreeMap<Price, Qty>,
}

/// #47 B4: undo log for one `submit`. Holds the first-touch pre-image of
/// every order and price level the match changed, so the book can be put
/// back exactly as it was without cloning the whole book up front. Cost is
/// proportional to what the match touched, not to the book size.
/// (is_bid, price, level deque, level visible qty) before the first touch.
type LevelPreImage = (bool, Price, Option<VecDeque<OrderId>>, Option<Qty>);

#[derive(Debug, Default)]
pub struct BookJournal {
    orders: Vec<(OrderId, Option<Order>)>,
    seen_orders: HashSet<OrderId>,
    levels: Vec<LevelPreImage>,
    seen_levels: HashSet<(bool, Price)>,
}

impl OrderBook {
    pub fn new(market: MarketId) -> Self {
        Self {
            market,
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            orders: HashMap::new(),
            bid_qty: BTreeMap::new(),
            ask_qty: BTreeMap::new(),
        }
    }

    pub fn market(&self) -> MarketId {
        self.market
    }

    pub fn order_count(&self) -> u64 {
        self.orders.values().filter(|o| o.remaining > 0).count() as u64
    }

    /// Canonical commitment over the FULL resting book — every price level and
    /// every live order, not just best bid/ask/count. Encoding:
    ///   b"book" || market le4
    ///   || for each ask level ascending by price, then each bid level
    ///      descending by price:
    ///        price le8 || live-order count u32le
    ///        || per live order in deque order (stale ids not present in
    ///           `orders`, if any, are skipped):
    ///            order_id 32B || remaining le8 || isolated u8 || margin_left le8
    /// BTreeMap iteration makes level order deterministic across replays.
    /// O(book size) — fine for settlement-time commitment.
    pub fn commitment_bytes(&self) -> Vec<u8> {
        fn encode_level(
            b: &mut Vec<u8>,
            price: Price,
            q: &VecDeque<OrderId>,
            orders: &HashMap<OrderId, Order>,
        ) {
            let mut body = Vec::new();
            let mut live = 0u32;
            for id in q {
                if let Some(o) = orders.get(id) {
                    live += 1;
                    body.extend_from_slice(&o.id.0);
                    body.extend_from_slice(&o.remaining.to_le_bytes());
                    body.push(o.isolated as u8);
                    body.extend_from_slice(&o.margin_left.to_le_bytes());
                }
            }
            b.extend_from_slice(&price.to_le_bytes());
            b.extend_from_slice(&live.to_le_bytes());
            b.extend_from_slice(&body);
        }
        let mut b = Vec::new();
        b.extend_from_slice(b"book");
        b.extend_from_slice(&self.market.0.to_le_bytes());
        // asks BTreeMap iterates ascending; bids keyed Reverse<Price> iterate
        // descending — both canonical.
        for (price, q) in &self.asks {
            encode_level(&mut b, *price, q, &self.orders);
        }
        for (price, q) in &self.bids {
            encode_level(&mut b, price.0, q, &self.orders);
        }
        b
    }

    pub fn get(&self, id: OrderId) -> Option<&Order> {
        self.orders.get(&id)
    }
    /// Live orders (remaining > 0) for witness-leaf commitment.
    pub fn live_orders(&self) -> impl Iterator<Item = &Order> {
        self.orders.values().filter(|o| o.remaining > 0)
    }

    pub fn best_bid(&self) -> Option<(Price, Qty)> {
        // O(log depth): cached visible qty; zero-qty levels pruned on update.
        self.bid_qty
            .iter()
            .next()
            .map(|(Reverse(price), q)| (*price, *q))
    }

    pub fn best_ask(&self) -> Option<(Price, Qty)> {
        self.ask_qty.iter().next().map(|(price, q)| (*price, *q))
    }

    fn level_add(&mut self, side: Side, price: Price, delta: i64) {
        // R2-E-9: two resting orders of qty ≤ i64::MAX at one price used to
        // overflow `*e as i64 + delta` (debug panic on every node ingesting
        // the unit). Modular u64 arithmetic is bit-identical to the old
        // release-build behaviour (so no replica diverges) and exact while
        // the level's true total stays below 2^64; this cache only feeds
        // `best_bid`/`best_ask`, never matching.
        match side {
            Side::Bid => {
                let e = self.bid_qty.entry(Reverse(price)).or_insert(0);
                *e = e.wrapping_add_signed(delta);
                if *e == 0 {
                    self.bid_qty.remove(&Reverse(price));
                }
            }
            Side::Ask => {
                let e = self.ask_qty.entry(price).or_insert(0);
                *e = e.wrapping_add_signed(delta);
                if *e == 0 {
                    self.ask_qty.remove(&price);
                }
            }
        }
    }

    /// Submit with the default self-trade policy: cancel-maker-continue
    /// (money-neutral for cross makers; liquidation and the tests rely on
    /// it). Place-path callers opt into [`SelfTrade::Reject`] via
    /// `submit_with` so an escrowed own maker can never refund into
    /// collateral inside a fill-bearing unit.
    pub fn submit(&mut self, order: Order) -> Result<MatchResult, BookError> {
        self.submit_with(order, SelfTrade::CancelMaker)
    }

    /// Atomic: on `Err` the book is exactly as before the call. #47 B4:
    /// atomicity comes from an undo journal of the touched orders/levels
    /// instead of a deep clone of the whole book per submit.
    pub fn submit_with(
        &mut self,
        order: Order,
        self_trade: SelfTrade,
    ) -> Result<MatchResult, BookError> {
        let mut j = BookJournal::default();
        match self.submit_inner(order, self_trade, false, &mut j) {
            Ok(r) => Ok(r),
            Err(e) => {
                self.rollback(j);
                Err(e)
            }
        }
    }

    /// Like [`OrderBook::submit_with`], but also returns the undo journal
    /// so a caller whose LATER step fails (e.g. applying the fills to
    /// accounts) can put the book back with [`OrderBook::rollback`].
    ///
    /// Round 7 (PR #51 未修复项 19, consensus): this is the engine's only
    /// submit path and it emits AT MOST ONE fill per order. A Market / IOC
    /// order stops after its first fill (the remainder never rests, so it
    /// is simply not filled); a Limit + Gtc order whose remainder would
    /// still cross a second maker is refused whole
    /// ([`BookError::MultiFill`]), because resting a crossing remainder
    /// would cross the book. Every fill-bearing unit therefore has exactly
    /// one fill, which the single-fill dispute predicates judge in full,
    /// and a committed fill with `idx != 0` is fraud by itself (P-fsane).
    pub fn submit_journaled(
        &mut self,
        order: Order,
        self_trade: SelfTrade,
    ) -> Result<(MatchResult, BookJournal), BookError> {
        let mut j = BookJournal::default();
        match self.submit_inner(order, self_trade, true, &mut j) {
            Ok(r) => Ok((r, j)),
            Err(e) => {
                self.rollback(j);
                Err(e)
            }
        }
    }

    /// Undo everything recorded in `j` (restores each first-touch
    /// pre-image; entries that did not exist before are removed).
    pub fn rollback(&mut self, j: BookJournal) {
        for (id, pre) in j.orders {
            match pre {
                Some(o) => {
                    self.orders.insert(id, o);
                }
                None => {
                    self.orders.remove(&id);
                }
            }
        }
        for (is_bid, price, dq, qty) in j.levels {
            if is_bid {
                match dq {
                    Some(d) => self.bids.insert(Reverse(price), d),
                    None => self.bids.remove(&Reverse(price)),
                };
                match qty {
                    Some(q) => self.bid_qty.insert(Reverse(price), q),
                    None => self.bid_qty.remove(&Reverse(price)),
                };
            } else {
                match dq {
                    Some(d) => self.asks.insert(price, d),
                    None => self.asks.remove(&price),
                };
                match qty {
                    Some(q) => self.ask_qty.insert(price, q),
                    None => self.ask_qty.remove(&price),
                };
            }
        }
    }

    fn save_order(&self, j: &mut BookJournal, id: OrderId) {
        if j.seen_orders.insert(id) {
            j.orders.push((id, self.orders.get(&id).cloned()));
        }
    }

    fn save_level(&self, j: &mut BookJournal, side: Side, price: Price) {
        let is_bid = side == Side::Bid;
        if j.seen_levels.insert((is_bid, price)) {
            let (dq, qty) = if is_bid {
                (
                    self.bids.get(&Reverse(price)).cloned(),
                    self.bid_qty.get(&Reverse(price)).copied(),
                )
            } else {
                (
                    self.asks.get(&price).cloned(),
                    self.ask_qty.get(&price).copied(),
                )
            };
            j.levels.push((is_bid, price, dq, qty));
        }
    }

    fn submit_inner(
        &mut self,
        mut order: Order,
        self_trade: SelfTrade,
        one_fill: bool,
        j: &mut BookJournal,
    ) -> Result<MatchResult, BookError> {
        if order.market != self.market {
            return Err(BookError::WrongMarket);
        }
        if order.qty == 0 || order.remaining == 0 {
            return Err(BookError::ZeroQty);
        }
        if order.typ == OrderType::Limit && order.price == 0 {
            return Err(BookError::ZeroPrice);
        }
        if self.orders.contains_key(&order.id) {
            return Err(BookError::DuplicateOrder);
        }

        let mut fills = Vec::new();
        let mut canceled_maker = Vec::new();
        let mut refunds: Vec<(AccountId, u64)> = Vec::new();

        let rests_type = order.typ == OrderType::Limit && order.tif == TimeInForce::Gtc;
        while order.remaining > 0 {
            // Round 7: a non-resting order is done after its first fill.
            if one_fill && !fills.is_empty() && !rests_type {
                break;
            }
            let head = match order.side {
                Side::Bid => self.next_ask_head(j),
                Side::Ask => self.next_bid_head(j),
            };
            let (maker_id, maker_price) = match head {
                Some(v) => v,
                None => break,
            };

            let crosses = match order.side {
                Side::Bid => match order.typ {
                    OrderType::Market => true,
                    OrderType::Limit => maker_price <= order.price,
                },
                Side::Ask => match order.typ {
                    OrderType::Market => true,
                    OrderType::Limit => maker_price >= order.price,
                },
            };
            if !crosses {
                break;
            }

            // Every mutation below touches only this maker and its level.
            self.save_level(j, order.side.opposite(), maker_price);
            self.save_order(j, maker_id);
            let (maker_account, maker_side, maker_remaining) = match self.orders.get(&maker_id) {
                Some(m) => (m.account, m.side, m.remaining),
                None => {
                    self.pop_head(order.side.opposite());
                    continue;
                }
            };
            if maker_account == order.account {
                // The canceled maker's escrow remainder would return to
                // collateral inside THIS unit — a cash leg no fill
                // predicate can model. Place-path callers therefore
                // reject the incoming order when the own maker holds
                // escrow; cross makers (margin_left == 0) move no cash
                // and keep cancel-maker-continue.
                let maker_margin_left = self
                    .orders
                    .get(&maker_id)
                    .map(|m| m.margin_left)
                    .unwrap_or(0);
                if self_trade == SelfTrade::Reject && maker_margin_left > 0 {
                    return Err(BookError::SelfTrade);
                }
                // STP (cancel-maker-continue): the taker hit its own resting
                // order; cancel that maker and keep matching the queue.
                // Cache: canceled maker's visible qty leaves the level.
                self.level_add(maker_side, maker_price, -(maker_remaining as i64));
                canceled_maker.push(maker_id);
                // The canceled maker never filled: its escrow remainder
                // (if any) is refunded to collateral.
                if maker_margin_left > 0 {
                    refunds.push((maker_account, maker_margin_left));
                }
                self.orders.remove(&maker_id);
                self.pop_head(maker_side);
                continue;
            }

            // Round 7: a resting-type order that would take a SECOND maker
            // is refused whole (its remainder still crosses the book).
            if one_fill && !fills.is_empty() {
                return Err(BookError::MultiFill);
            }
            let taker_remaining_before = order.remaining;
            let (
                fill_qty,
                maker_side,
                maker_acct,
                maker_done,
                maker_isolated,
                maker_post,
                taker_post,
            ) = {
                let maker = self.orders.get_mut(&maker_id).expect("maker present");
                let maker_remaining_before = maker.remaining;
                let fill_qty = order.remaining.min(maker.remaining);
                let maker_post = pro_rata_post(maker.margin_left, fill_qty, maker_remaining_before);
                maker.remaining -= fill_qty;
                maker.margin_left -= maker_post;
                order.remaining -= fill_qty;
                let taker_post = pro_rata_post(order.margin_left, fill_qty, taker_remaining_before);
                order.margin_left -= taker_post;
                let maker_done = maker.remaining == 0;
                (
                    fill_qty,
                    maker.side,
                    maker.account,
                    maker_done,
                    maker.isolated,
                    maker_post,
                    taker_post,
                )
            };
            // Cache: maker's visible qty shrinks by the filled amount.
            self.level_add(maker_side, maker_price, -(fill_qty as i64));

            fills.push(Fill {
                taker_id: order.id,
                maker_id,
                taker: order.account,
                maker: maker_acct,
                market: order.market,
                price: maker_price,
                qty: fill_qty,
                seq: order.seq,
                taker_side: order.side,
                taker_post: taker_post as Usd,
                maker_post: maker_post as Usd,
                taker_isolated: order.isolated,
                maker_isolated,
                kind: 0,
            });

            if maker_done {
                self.orders.remove(&maker_id);
                self.pop_head(maker_side);
            }
        }

        let rest = rests_type && order.remaining > 0;

        let taker_remaining = if rest { order.remaining } else { 0 };
        let taker_margin_left = order.margin_left;
        if rest {
            let (order_side, order_price, q) = (order.side, order.price, order.remaining);
            self.save_level(j, order_side, order_price);
            self.save_order(j, order.id);
            self.enqueue(order);
            // Cache: resting order adds visible qty at its level.
            self.level_add(order_side, order_price, q as i64);
        }

        Ok(MatchResult {
            fills,
            taker_remaining,
            taker_resting: rest,
            canceled_maker,
            taker_margin_left,
            refunds,
        })
    }

    pub fn cancel(&mut self, id: OrderId) -> Result<Order, BookError> {
        let order = self.orders.get(&id).ok_or(BookError::NotFound)?;
        if order.remaining == 0 {
            return Err(BookError::NotFound);
        }
        let price = order.price;
        let side = order.side;
        let mut order = self.orders.remove(&id).ok_or(BookError::NotFound)?;

        let removed = {
            let dq = match side {
                Side::Bid => self.bids.get_mut(&Reverse(price)),
                Side::Ask => self.asks.get_mut(&price),
            };
            match dq {
                Some(dq) => match dq.iter().position(|x| x == &id) {
                    Some(pos) => {
                        dq.remove(pos);
                        true
                    }
                    None => false,
                },
                None => false,
            }
        };
        // Visible qty is defined by order existence, not queue position: the
        // cache decrements for EVERY cancel, and the id is removed from its
        // level deque so no ghost ids linger.
        self.level_add(side, price, -(order.remaining as i64));
        if removed {
            self.drop_empty_level(side, price);
        }
        order.remaining = 0;
        Ok(order)
    }

    fn enqueue(&mut self, order: Order) {
        match order.side {
            Side::Bid => {
                self.bids
                    .entry(Reverse(order.price))
                    .or_default()
                    .push_back(order.id);
            }
            Side::Ask => {
                self.asks
                    .entry(order.price)
                    .or_default()
                    .push_back(order.id);
            }
        }
        self.orders.insert(order.id, order);
    }

    /// Best live ask, discarding stale queue entries on the way. Stale
    /// pops are journaled (level + order pre-images) before they happen.
    fn next_ask_head(&mut self, j: &mut BookJournal) -> Option<(OrderId, Price)> {
        loop {
            let price = *self.asks.keys().next()?;
            while let Some(id) = self.asks.get(&price).and_then(|dq| dq.front().copied()) {
                match self.orders.get(&id) {
                    Some(o) if o.remaining > 0 => return Some((id, price)),
                    _ => {
                        self.save_level(j, Side::Ask, price);
                        self.save_order(j, id);
                        if let Some(dq) = self.asks.get_mut(&price) {
                            dq.pop_front();
                        }
                        self.orders.remove(&id);
                    }
                }
            }
            self.save_level(j, Side::Ask, price);
            self.asks.remove(&price);
        }
    }

    fn next_bid_head(&mut self, j: &mut BookJournal) -> Option<(OrderId, Price)> {
        loop {
            let Reverse(price) = *self.bids.keys().next()?;
            while let Some(id) = self
                .bids
                .get(&Reverse(price))
                .and_then(|dq| dq.front().copied())
            {
                match self.orders.get(&id) {
                    Some(o) if o.remaining > 0 => return Some((id, price)),
                    _ => {
                        self.save_level(j, Side::Bid, price);
                        self.save_order(j, id);
                        if let Some(dq) = self.bids.get_mut(&Reverse(price)) {
                            dq.pop_front();
                        }
                        self.orders.remove(&id);
                    }
                }
            }
            self.save_level(j, Side::Bid, price);
            self.bids.remove(&Reverse(price));
        }
    }

    fn pop_head(&mut self, maker_side: Side) {
        match maker_side {
            Side::Ask => {
                if let Some((&price, _)) = self.asks.iter().next() {
                    if let Some(dq) = self.asks.get_mut(&price) {
                        dq.pop_front();
                    }
                    self.drop_empty_level(Side::Ask, price);
                }
            }
            Side::Bid => {
                if let Some((&Reverse(price), _)) = self.bids.iter().next() {
                    if let Some(dq) = self.bids.get_mut(&Reverse(price)) {
                        dq.pop_front();
                    }
                    self.drop_empty_level(Side::Bid, price);
                }
            }
        }
    }

    fn drop_empty_level(&mut self, side: Side, price: Price) {
        match side {
            Side::Bid => {
                let empty = self
                    .bids
                    .get(&Reverse(price))
                    .map(|d| d.is_empty())
                    .unwrap_or(true);
                if empty {
                    self.bids.remove(&Reverse(price));
                }
            }
            Side::Ask => {
                let empty = self.asks.get(&price).map(|d| d.is_empty()).unwrap_or(true);
                if empty {
                    self.asks.remove(&price);
                }
            }
        }
    }
}
