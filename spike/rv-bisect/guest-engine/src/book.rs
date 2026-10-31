use crate::{BookError, Fill, MatchResult, Order, SelfTrade};
use crate::types::{AccountId, MarketId, OrderId, OrderType, Price, Qty, Side, TimeInForce, Usd};
use core::cmp::Reverse;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
// PILOT: HashMap/HashSet -> BTreeMap/BTreeSet (no_std). Only lookups + order-independent folds iterate `orders`.
type HashMap<K, V> = BTreeMap<K, V>;
type HashSet<K> = BTreeSet<K>;

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

/// PILOT (loop round 3, S1b): a price level is an arrival-ordered map (arrival number -> id)
/// instead of upstream's `VecDeque<OrderId>`. Iteration order = arrival order = the deque's
/// FIFO order, so matching, the commitment bytes and every result are unchanged; `cancel`
/// becomes O(log n) (id -> arrival lookup in `OrderBook::arr`, then a map remove) instead of
/// a linear `position` scan + `VecDeque::remove` (O(orders at that price)).
pub type Level = BTreeMap<u64, OrderId>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderBook {
    market: MarketId,
    bids: BTreeMap<Reverse<Price>, Level>,
    asks: BTreeMap<Price, Level>,
    /// PILOT (S1b): arrival number of every id present in a level (one entry per level entry;
    /// ids are unique, see `submit_inner`'s DuplicateOrder check and `level_ok`).
    arr: BTreeMap<OrderId, u64>,
    /// PILOT (S1b): next arrival number (monotone; restored on rollback). Not committed: only
    /// the relative order of arrivals matters, and that is the FIFO order upstream keeps.
    next_arr: u64,
    orders: HashMap<OrderId, Order>,
    /// Incrementally-maintained visible qty per price level (bids).
    bid_qty: BTreeMap<Reverse<Price>, Qty>,
    /// Incrementally-maintained visible qty per price level (asks).
    ask_qty: BTreeMap<Price, Qty>,
    /// PILOT (loop round 2, S1): secondary index account -> ids of its entries in `orders`
    /// (kept in lockstep by `oins` / `orem`). Lets the engine visit one account's orders in
    /// O(own orders) instead of filtering every order of the book. Iterating it (OrderId order)
    /// visits exactly `orders.values().filter(|o| o.account == a)` in the same order.
    by_acct: BTreeMap<AccountId, BTreeSet<OrderId>>,
}

/// #47 B4: undo log for one `submit`. Holds the first-touch pre-image of
/// every order and price level the match changed, so the book can be put
/// back exactly as it was without cloning the whole book up front. Cost is
/// proportional to what the match touched, not to the book size.
/// (is_bid, price, level deque, level visible qty) before the first touch.
/// PILOT (loop round 2, W4/S1): instead of cloning the whole level deque on first touch
/// (O(level) time and heap per submit), record the deque operations a submit performs on the
/// level -- it only ever pops from the front (heads) and pushes one id to the back (resting
/// remainder) -- and undo them in reverse. Rollback restores the identical id sequence.
#[derive(Debug)]
struct LevelUndo {
    is_bid: bool,
    price: Price,
    /// the level (deque) existed before the first touch
    existed: bool,
    /// (arrival, id) popped from the front, in pop order
    popped: Vec<(u64, OrderId)>,
    /// ids pushed to the back
    pushed: u32,
    /// visible qty pre-image
    qty: Option<Qty>,
}

#[derive(Debug, Default)]
pub struct BookJournal {
    orders: Vec<(OrderId, Option<Order>)>,
    seen_orders: HashSet<OrderId>,
    levels: Vec<LevelUndo>,
    seen_levels: BTreeMap<(bool, Price), usize>,
    /// PILOT (S1b): `next_arr` before the submit
    next_arr0: Option<u64>,
}

impl BookJournal {
    /// PILOT (MNWIT1): ids of every order this journal touched (inserted, filled, removed).
    pub fn touched_orders(&self) -> impl Iterator<Item = OrderId> + '_ {
        self.orders.iter().map(|(id, _)| *id)
    }
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
            by_acct: BTreeMap::new(),
            arr: BTreeMap::new(),
            next_arr: 0,
        }
    }

    // PILOT (S1b): level primitives. Every level mutation goes through these three, so the
    // `arr` index stays in lockstep with the level entries.
    fn lvl_mut(&mut self, side: Side, price: Price) -> Option<&mut Level> {
        match side {
            Side::Bid => self.bids.get_mut(&Reverse(price)),
            Side::Ask => self.asks.get_mut(&price),
        }
    }
    /// pop the level's first (oldest) entry
    fn lvl_pop_front(&mut self, side: Side, price: Price) -> Option<(u64, OrderId)> {
        let (a, id) = self.lvl_mut(side, price)?.pop_first()?;
        if self.arr.get(&id) == Some(&a) {
            self.arr.remove(&id);
        }
        Some((a, id))
    }
    /// re-insert an entry with its original arrival number (rollback of a pop)
    fn lvl_put(lvl: &mut Level, arr: &mut BTreeMap<OrderId, u64>, a: u64, id: OrderId) {
        lvl.insert(a, id);
        arr.insert(id, a);
    }
    /// PILOT (loop round 4, snapshot.rs): canonical export. Orders map (id order), ask levels
    /// ascending then bid levels descending (each: price, count, ids in FIFO order), then the
    /// two visible-qty caches. Arrival numbers are not exported (only their order matters).
    pub fn snap_write(&self, w: &mut crate::snapshot::SnapW) {
        w.len(self.orders.len());
        for o in self.orders.values() {
            crate::snapshot::w_order(w, o);
        }
        w.len(self.asks.len());
        for (p, l) in &self.asks {
            w.i64(*p);
            w.len(l.len());
            for id in l.values() {
                w.id(&id.0);
            }
        }
        w.len(self.bids.len());
        for (p, l) in &self.bids {
            w.i64(p.0);
            w.len(l.len());
            for id in l.values() {
                w.id(&id.0);
            }
        }
        w.len(self.ask_qty.len());
        for (p, q) in &self.ask_qty {
            w.i64(*p);
            w.u64(*q);
        }
        w.len(self.bid_qty.len());
        for (p, q) in &self.bid_qty {
            w.i64(p.0);
            w.u64(*q);
        }
    }
    /// Inverse of `snap_write`; refuses non-canonical input (keys not strictly in iteration
    /// order, an order of another market, a level id twice or without an order, empty levels).
    /// Arrival numbers are reassigned 0.. in export order (asks, then bids), so re-exporting the
    /// result gives the same words.
    pub fn snap_read(r: &mut crate::snapshot::SnapR, market: MarketId) -> Result<Self, ()> {
        let mut b = Self::new(market);
        let mut prev: Option<OrderId> = None;
        for _ in 0..r.len()? {
            let o = crate::snapshot::r_order(r)?;
            if prev.is_some_and(|p| o.id <= p) || o.market != market {
                return Err(());
            }
            prev = Some(o.id);
            b.oins(o.id, o);
        }
        let mut a = 0u64;
        let mut pp: Option<Price> = None;
        for _ in 0..r.len()? {
            let p = r.i64()?;
            if pp.is_some_and(|x| p <= x) {
                return Err(());
            }
            pp = Some(p);
            let n = r.len()?;
            if n == 0 {
                return Err(());
            }
            let mut l = Level::new();
            for _ in 0..n {
                let id = OrderId(r.id()?);
                if !b.orders.contains_key(&id) || b.arr.contains_key(&id) {
                    return Err(());
                }
                Self::lvl_put(&mut l, &mut b.arr, a, id);
                a += 1;
            }
            b.asks.insert(p, l);
        }
        let mut pp: Option<Price> = None;
        for _ in 0..r.len()? {
            let p = r.i64()?;
            if pp.is_some_and(|x| p >= x) {
                return Err(());
            }
            pp = Some(p);
            let n = r.len()?;
            if n == 0 {
                return Err(());
            }
            let mut l = Level::new();
            for _ in 0..n {
                let id = OrderId(r.id()?);
                if !b.orders.contains_key(&id) || b.arr.contains_key(&id) {
                    return Err(());
                }
                Self::lvl_put(&mut l, &mut b.arr, a, id);
                a += 1;
            }
            b.bids.insert(Reverse(p), l);
        }
        b.next_arr = a;
        let mut pp: Option<Price> = None;
        for _ in 0..r.len()? {
            let p = r.i64()?;
            if pp.is_some_and(|x| p <= x) {
                return Err(());
            }
            pp = Some(p);
            b.ask_qty.insert(p, r.u64()?);
        }
        let mut pp: Option<Price> = None;
        for _ in 0..r.len()? {
            let p = r.i64()?;
            if pp.is_some_and(|x| p >= x) {
                return Err(());
            }
            pp = Some(p);
            b.bid_qty.insert(Reverse(p), r.u64()?);
        }
        Ok(b)
    }
    /// PILOT (S1b): `arr` == exactly the level entries (host tests).
    pub fn level_ok(&self) -> bool {
        let n: usize = self.bids.values().map(|l| l.len()).sum::<usize>() + self.asks.values().map(|l| l.len()).sum::<usize>();
        n == self.arr.len()
            && self.bids.values().chain(self.asks.values()).all(|l| {
                !l.is_empty() && l.iter().all(|(a, id)| self.arr.get(id) == Some(a) && *a < self.next_arr)
            })
    }

    // PILOT (S1): the only two ways `orders` changes membership.
    fn oins(&mut self, id: OrderId, o: Order) {
        let a = o.account;
        if let Some(old) = self.orders.insert(id, o) {
            if old.account != a {
                self.idx_del(old.account, id);
            }
        }
        self.by_acct.entry(a).or_default().insert(id);
    }
    fn orem(&mut self, id: &OrderId) -> Option<Order> {
        let o = self.orders.remove(id)?;
        self.idx_del(o.account, *id);
        Some(o)
    }
    fn idx_del(&mut self, a: AccountId, id: OrderId) {
        if let Some(set) = self.by_acct.get_mut(&a) {
            set.remove(&id);
            if set.is_empty() {
                self.by_acct.remove(&a);
            }
        }
    }
    /// PILOT (S1): live orders (remaining > 0) of one account, in OrderId order -- the same
    /// sequence as `live_orders().filter(|o| o.account == account)`.
    pub fn live_orders_of(&self, account: AccountId) -> impl Iterator<Item = &Order> + '_ {
        self.by_acct
            .get(&account)
            .into_iter()
            .flat_map(move |set| set.iter().filter_map(move |id| self.orders.get(id)))
            .filter(|o| o.remaining > 0)
    }
    /// PILOT (S1): index consistency (host tests).
    pub fn index_ok(&self) -> bool {
        let n: usize = self.by_acct.values().map(|s| s.len()).sum();
        n == self.orders.len()
            && self.by_acct.iter().all(|(a, set)| {
                !set.is_empty() && set.iter().all(|id| self.orders.get(id).map(|o| o.account == *a).unwrap_or(false))
            })
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
            q: &Level,
            orders: &HashMap<OrderId, Order>,
        ) {
            let mut body = Vec::new();
            let mut live = 0u32;
            for id in q.values() {
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

    /// Round 7b (R7-H1): remaining qty of the maker a crossing market order
    /// on `taker_side` would fill FIRST, skipping ghost heads and (the
    /// cancel-maker self-trade policy) the taker account's own orders.
    /// Read-only mirror of the head walk in `submit_inner`.
    pub fn first_maker_qty(&self, taker_side: Side, taker: AccountId) -> Option<Qty> {
        let first = |ids: &Level| {
            ids.values().find_map(|id| {
                self.orders
                    .get(id)
                    .filter(|o| o.remaining > 0 && o.account != taker)
                    .map(|o| o.remaining)
            })
        };
        match taker_side {
            Side::Bid => self.asks.values().find_map(first),
            Side::Ask => self.bids.values().find_map(first),
        }
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
        let mut j = BookJournal { next_arr0: Some(self.next_arr), ..Default::default() };
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
        let mut j = BookJournal { next_arr0: Some(self.next_arr), ..Default::default() };
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
        if let Some(n) = j.next_arr0 {
            self.next_arr = n;
        }
        for (id, pre) in j.orders {
            match pre {
                Some(o) => {
                    self.oins(id, o);
                }
                None => {
                    self.orem(&id);
                }
            }
        }
        for u in j.levels {
            let LevelUndo { is_bid, price, existed, popped, pushed, qty } = u;
            let cur = if is_bid { self.bids.remove(&Reverse(price)) } else { self.asks.remove(&price) };
            let mut dq = cur.unwrap_or_default();
            for _ in 0..pushed {
                // pushes got the largest arrival numbers: undo = drop the last entries
                if let Some((a, id)) = dq.pop_last() {
                    if self.arr.get(&id) == Some(&a) {
                        self.arr.remove(&id);
                    }
                }
            }
            for (a, id) in popped.into_iter().rev() {
                Self::lvl_put(&mut dq, &mut self.arr, a, id);
            }
            if !existed {
                // a level created by this submit is dropped whole: its entries leave `arr` too
                for (a, id) in dq.iter() {
                    if self.arr.get(id) == Some(a) {
                        self.arr.remove(id);
                    }
                }
            }
            if existed {
                if is_bid {
                    self.bids.insert(Reverse(price), dq);
                } else {
                    self.asks.insert(price, dq);
                }
            }
            if is_bid {
                match qty {
                    Some(q) => self.bid_qty.insert(Reverse(price), q),
                    None => self.bid_qty.remove(&Reverse(price)),
                };
            } else {
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
        if !j.seen_levels.contains_key(&(is_bid, price)) {
            let (existed, qty) = if is_bid {
                (self.bids.contains_key(&Reverse(price)), self.bid_qty.get(&Reverse(price)).copied())
            } else {
                (self.asks.contains_key(&price), self.ask_qty.get(&price).copied())
            };
            j.seen_levels.insert((is_bid, price), j.levels.len());
            j.levels.push(LevelUndo { is_bid, price, existed, popped: Vec::new(), pushed: 0, qty });
        }
    }

    /// PILOT (W4): journal entry of a level already saved by `save_level`.
    fn jlevel<'a>(&self, j: &'a mut BookJournal, side: Side, price: Price) -> &'a mut LevelUndo {
        self.save_level(j, side, price);
        let i = j.seen_levels[&(side == Side::Bid, price)];
        &mut j.levels[i]
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
                    self.pop_head(order.side.opposite(), j);
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
                self.orem(&maker_id);
                self.pop_head(maker_side, j);
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
                self.orem(&maker_id);
                self.pop_head(maker_side, j);
            }
        }

        let rest = rests_type && order.remaining > 0;

        let taker_remaining = if rest { order.remaining } else { 0 };
        let taker_margin_left = order.margin_left;
        if rest {
            let (order_side, order_price, q) = (order.side, order.price, order.remaining);
            self.save_level(j, order_side, order_price);
            self.save_order(j, order.id);
            self.jlevel(j, order_side, order_price).pushed += 1;
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
        let mut order = self.orem(&id).ok_or(BookError::NotFound)?;

        // PILOT (S1b): O(log n) -- id -> arrival, then remove that entry from the order's level
        // (upstream: `dq.iter().position(id)` + `VecDeque::remove`, O(orders at that price)).
        // Same outcome: the id's (unique) entry leaves its level, `removed` as before.
        let removed = match self.arr.get(&id).copied() {
            Some(a) => {
                let hit = match side {
                    Side::Bid => self.bids.get_mut(&Reverse(price)),
                    Side::Ask => self.asks.get_mut(&price),
                }
                .map(|l| {
                    if l.get(&a) == Some(&id) {
                        l.remove(&a);
                        true
                    } else {
                        false
                    }
                })
                .unwrap_or(false);
                if hit {
                    self.arr.remove(&id);
                }
                hit
            }
            None => false,
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
        // PILOT (S1b): push_back = insert under the next arrival number
        let a = self.next_arr;
        self.next_arr += 1;
        let lvl = match order.side {
            Side::Bid => self.bids.entry(Reverse(order.price)).or_default(),
            Side::Ask => self.asks.entry(order.price).or_default(),
        };
        Self::lvl_put(lvl, &mut self.arr, a, order.id);
        self.oins(order.id, order);
    }

    /// Best live ask, discarding stale queue entries on the way. Stale
    /// pops are journaled (level + order pre-images) before they happen.
    fn next_ask_head(&mut self, j: &mut BookJournal) -> Option<(OrderId, Price)> {
        loop {
            let price = *self.asks.keys().next()?;
            while let Some(id) = self.asks.get(&price).and_then(|dq| dq.values().next().copied()) {
                match self.orders.get(&id) {
                    Some(o) if o.remaining > 0 => return Some((id, price)),
                    _ => {
                        self.save_level(j, Side::Ask, price);
                        self.save_order(j, id);
                        let x = self.lvl_pop_front(Side::Ask, price);
                        if let Some(x) = x {
                            self.jlevel(j, Side::Ask, price).popped.push(x);
                        }
                        self.orem(&id);
                    }
                }
            }
            self.save_level(j, Side::Ask, price);
            self.asks.remove(&price); // empty here (the loop above drained it)
        }
    }

    fn next_bid_head(&mut self, j: &mut BookJournal) -> Option<(OrderId, Price)> {
        loop {
            let Reverse(price) = *self.bids.keys().next()?;
            while let Some(id) = self
                .bids
                .get(&Reverse(price))
                .and_then(|dq| dq.values().next().copied())
            {
                match self.orders.get(&id) {
                    Some(o) if o.remaining > 0 => return Some((id, price)),
                    _ => {
                        self.save_level(j, Side::Bid, price);
                        self.save_order(j, id);
                        let x = self.lvl_pop_front(Side::Bid, price);
                        if let Some(x) = x {
                            self.jlevel(j, Side::Bid, price).popped.push(x);
                        }
                        self.orem(&id);
                    }
                }
            }
            self.save_level(j, Side::Bid, price);
            self.bids.remove(&Reverse(price));
        }
    }

    fn pop_head(&mut self, maker_side: Side, j: &mut BookJournal) {
        match maker_side {
            Side::Ask => {
                if let Some((&price, _)) = self.asks.iter().next() {
                    self.save_level(j, Side::Ask, price);
                    let x = self.lvl_pop_front(Side::Ask, price);
                    if let Some(x) = x {
                        self.jlevel(j, Side::Ask, price).popped.push(x);
                    }
                    self.drop_empty_level(Side::Ask, price);
                }
            }
            Side::Bid => {
                if let Some((&Reverse(price), _)) = self.bids.iter().next() {
                    self.save_level(j, Side::Bid, price);
                    let x = self.lvl_pop_front(Side::Bid, price);
                    if let Some(x) = x {
                        self.jlevel(j, Side::Bid, price).popped.push(x);
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
