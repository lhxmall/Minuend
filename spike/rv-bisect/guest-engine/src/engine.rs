//! Engine place / cancel paths, copied verbatim from minuend-exec/src/lib.rs @ fix/47-all
//! 20326c0 (`Engine::place`, `cancel`, `own_live_order_mode`, `has_non_spot_exposure`,
//! `has_cross_spot_exposure`, `collateral_of`, `funding_open_interest`,
//! `taker_fee_keeps_cash`, `resting_open_im`, `open_share`, `map_acct`, `RejectReason`).
//! `deposit` is a PILOT simplification (credit only; see below).
use crate::account::AccountError;
use crate::book_types::{BookError, Fill, Order};
use crate::state::ChainState;
use crate::types::{
    bps, funding_notional_usd, funding_rate_bps, funding_rate_cash, liq_order_id, notional_usd,
    order_id, AccountId, Bps, MarketId, MarketParams, OrderId, OrderType, Price, Qty, Seq, Side,
    TimeInForce, Usd, INSURANCE_ACCOUNT, MAX_LIVE_ORDERS_PER_ACCOUNT,
    MAX_PENDING_WITHDRAWALS_PER_ACCOUNT, MIN_OPEN_EQUITY, MIN_WITHDRAW_AMOUNT,
};
use alloc::vec::Vec;
mod minuend_account { pub use crate::account::*; }
mod minuend_book { pub use crate::book_types::*; }
mod minuend_state { pub use crate::state::*; pub use crate::types::Withdrawal; }
mod minuend_types { pub use crate::types::*; }
/// PILOT: stands in for minuend_types::UnitId (only threaded through `place`, never read).
pub type UnitId = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RejectReason {
    BadSig,
    BadAccount,
    DuplicateClientSeq,
    DuplicateDeposit,
    /// Deposit op referencing an AA unit not in the batch's on-chain deposit set.
    UnbackedDeposit,
    DuplicateNonce,
    Risk,
    Book(BookError),
    Insufficient,
    NotFound,
    NotLiquidatable,
    /// Vote/FinalizeProposal referencing an unknown proposal id.
    NoProposal,
    NotBonded,
    AlreadyBonded,
    Unbonding,
    SlashNotEligible,
    /// Commit-reveal v2: commit unknown/expired/consumed, hash mismatch,
    /// wrong account, or reveal missing its Commit parent (doc 03 §2.3.3).
    BadCommit,
}

fn open_share(notional: Usd, open_qty: i128, side_qty: i128) -> Usd {
    if side_qty <= 0 {
        return 0;
    }
    match notional.checked_mul(open_qty) {
        Some(v) => v / side_qty,
        None => Usd::MAX / 4,
    }
}

fn map_acct(e: AccountError) -> RejectReason {
    match e {
        AccountError::Insufficient | AccountError::NonPositive => RejectReason::Insufficient,
        AccountError::Overflow | AccountError::QtyTooLarge | AccountError::Risk => {
            RejectReason::Risk
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Engine {
    pub state: ChainState,
}

impl Engine {
    pub fn place(
        &mut self,
        account: AccountId,
        market: minuend_types::MarketId,
        side: Side,
        typ: OrderType,
        tif: TimeInForce,
        price: minuend_types::Price,
        qty: Qty,
        client_seq: u64,
        unit: UnitId,
        seq: Seq,
        isolated: bool,
        margin: u64,
    ) -> Result<Vec<Fill>, RejectReason> {
        let last = self
            .state
            .seen_client_seq
            .get(&account)
            .copied()
            .unwrap_or(0);
        let ok_seq = if last == 0 {
            client_seq == 1
        } else {
            client_seq == last + 1
        };
        if !ok_seq {
            return Err(RejectReason::DuplicateClientSeq);
        }

        // Intake overflow guards (DoS): qty must fit i64 for positions, and the
        // price*qty product must fit i128 before signed notional math (blocks
        // u64::MAX-style inputs that would wrap notional_usd / bps).
        if qty > i64::MAX as u64 {
            return Err(RejectReason::Risk);
        }
        // R10-L1: a limit price at / above MARK_CAP could never become the
        // mark (R9-H2: the dispute AAs compare marks exactly only below
        // 1e15), so such an order is REJECTED instead of trading while the
        // mark silently freezes. Market orders (price 0) only fill against
        // admitted limits; ADL prints at the (capped) mark.
        if typ == OrderType::Limit && price.unsigned_abs() >= minuend_types::MARK_CAP.unsigned_abs()
        {
            return Err(RejectReason::Risk);
        }
        let mark = *self.state.marks.get(&market).unwrap_or(&0);
        let px_for_notional = if typ == OrderType::Limit && price != 0 {
            price
        } else {
            mark
        };
        // Worst-case bound: estimate notional at max(limit/mark, mark) for
        // both sides. Previously Ask used max but Bid used mark alone, under-
        // estimating margin for Market Bids. Also gate unknown market.
        match self.state.markets.get(&market) {
            // #47 C2: a legacy spot listing (leveraged, band-less, or with a
            // floor ≤ 0) has no finite worst case; it cannot fill anyway
            // (`apply_fill_pair` refuses it), so do not let orders rest.
            Some(p) if !p.delisted && minuend_types::spot_market_tradeable(p) => {}
            _ => return Err(RejectReason::Risk),
        }
        // Live-order count cap across every book: applies even to an IOC
        // that would never rest — otherwise a spam loop of IOC places is
        // unbounded even though resting state stays bounded.
        let live_count = self
            .state
            .books
            .values()
            .map(|b| b.live_orders_of(account).count())
            .sum::<usize>();
        if live_count >= MAX_LIVE_ORDERS_PER_ACCOUNT {
            return Err(RejectReason::Risk);
        }
        // R6-H1: quantities and positions stay below QTY_CAP (1e15), where
        // the dispute AAs' Oscript compares `qty` with `|position|`
        // exactly. Invariant per (account, market): |position| + the
        // remaining qty of its live orders + this order's qty < QTY_CAP —
        // fills only move an order's remaining into its position, and a
        // liquidation / ADL only shrinks positions, so no fill can lift
        // any position (taker or maker) to the cap.
        {
            let pos_abs = self
                .state
                .accounts
                .get(&account)
                .and_then(|a| a.positions.get(&market))
                .map(|p| u128::from(p.qty.unsigned_abs()))
                .unwrap_or(0);
            let open: u128 = self
                .state
                .books
                .get(&market)
                .map(|b| {
                    b.live_orders_of(account) // PILOT (S1): per-account index
                        .map(|o| u128::from(o.remaining))
                        .sum()
                })
                .unwrap_or(0);
            if pos_abs + open + u128::from(qty) >= u128::from(minuend_types::QTY_CAP) {
                return Err(RejectReason::Risk);
            }
        }
        // Signed prices: margin must cover the larger *magnitude* — a plain
        // max() would let a short at -100 post margin against mark -1.
        let px_est = if px_for_notional.unsigned_abs() >= mark.unsigned_abs() {
            px_for_notional
        } else {
            mark
        };
        // unsigned_abs is exact (no MIN-wrap): negative estimates feed the
        // guard as magnitudes.
        let px_abs: u128 = px_est.unsigned_abs() as u128;
        if px_abs
            .checked_mul(qty as u128)
            .map(|n| n > i128::MAX as u128)
            .unwrap_or(true)
        {
            return Err(RejectReason::Risk);
        }
        // Tick alignment: limit orders must sit on the market's price grid.
        // Market orders (price = 0) are exempt by construction; unknown or
        // delisted markets were rejected above.
        if typ == OrderType::Limit && price != 0 {
            if let Some(p) = self.state.markets.get(&market) {
                if p.tick_size != 0 && price % p.tick_size != 0 {
                    return Err(RejectReason::Risk);
                }
            }
        }
        // Tradeable price range (#37 follow-up): a market may declare a
        // [min_price, max_price] band at listing (0 = unbounded on that
        // side). It is an ADMISSION gate for limit prices: out-of-band
        // limits are rejected. Market orders (price 0) need no gate of their
        // own — they only ever fill against resting limits, which were all
        // admitted inside the band (the band is fixed at listing). #47 L3:
        // the off-book prints (ADL at the mark) are clamped into the band in
        // `liquidate_inner`, and funding-rate markets may not list a band,
        // so no fill on any market prints outside it.
        // Bounding the band is what keeps a `spot_only` position's
        // worst-case loss finite: its mark is frozen, so the range is the
        // only cap on how far the real price can run against it.
        {
            let p = self.state.market_params(market);
            if (p.min_price != 0 || p.max_price != 0)
                && typ == OrderType::Limit
                && price != 0
                && ((p.min_price != 0 && price < p.min_price)
                    || (p.max_price != 0 && price > p.max_price))
            {
                return Err(RejectReason::Risk);
            }
        }
        // Funding band (#7): an encoded rate beyond ±100% is a broken feed,
        // not a market — same comparison as update_external_price. Applies
        // to closes as well as opens: every margin/OI figure prices off
        // usd_per_unit, so an out-of-band rate can only promise the
        // insurance fund money the order never risked. A market order's
        // price of 0 is far out of band on purpose — funding-rate books
        // trade explicit rates only.
        if self.state.market_params(market).funding_rate && funding_rate_bps(price).abs() > 10_000 {
            return Err(RejectReason::Risk);
        }

        let snap = {
            let acct = self.state.accounts.get(&account);
            match acct {
                Some(a) => a.snapshot(&self.state.marks, &self.state.markets),
                None => minuend_account::Account::new(account)
                    .snapshot(&self.state.marks, &self.state.markets),
            }
        };
        let pos_qty = self
            .state
            .accounts
            .get(&account)
            .and_then(|a| a.positions.get(&market))
            .map(|p| p.qty)
            .unwrap_or(0);
        // Mode gate: an account's exposure to one market has one mode —
        // the position's if it exists, else its first live order's. A
        // mismatched order would let cross losses leak into a bucket (or
        // vice versa), so it is rejected before any risk math.
        let pos_mode = if qty != 0 {
            self.state
                .accounts
                .get(&account)
                .and_then(|a| a.positions.get(&market))
                .map(|p| p.isolated)
        } else {
            None
        };
        let order_mode = self.own_live_order_mode(account, market);
        if let Some(m) = pos_mode.or(order_mode) {
            if m != isolated {
                return Err(RejectReason::Risk);
            }
        }
        // Reduce-only gate: isolated positions are judged on their own
        // bucket risk, cross positions on the pooled snapshot as today.
        let reduce_only = if isolated {
            self.state
                .accounts
                .get(&account)
                .map(|a| a.isolated_risk(market, &self.state.marks, &self.state.markets))
                .map(|r| r.reduce_only)
                .unwrap_or(false)
        } else {
            snap.reduce_only
        };
        if reduce_only {
            let reducing = match side {
                Side::Bid => pos_qty < 0,
                Side::Ask => pos_qty > 0,
            };
            if !reducing {
                return Err(RejectReason::Risk);
            }
        }

        // Open-quantity IM gate: the part of the order that closes existing
        // position is reduce-exempt; only the remainder that opens or flips
        // past zero must post initial margin. A flat-out direction check
        // would let undercollateralized accounts flip positions for free.
        let signed = match side {
            Side::Bid => qty as i64,
            Side::Ask => -(qty as i64),
        };
        let open_qty = if pos_qty != 0 && signed.signum() != pos_qty.signum() {
            // R2-E-10: unsigned_abs never overflows (|i64::MIN| fits u64);
            // the min() with |signed| ≤ i64::MAX keeps the cast exact.
            signed + (pos_qty.unsigned_abs().min(signed.unsigned_abs()) as i64) * pos_qty.signum()
        } else {
            signed
        };
        // R3-E-2: on a spot_only market an order that can REST (limit GTC)
        // is gated on its full qty, as if it opened all of it. Whether a
        // resting order reduces is only known at placement: the position can
        // be closed by another order afterwards, and the maker leg of a fill
        // is never re-checked — a zero-reserve "reduce" would then open an
        // unbacked spot position. IOC/market orders fill now against the
        // current position, so their netted open qty is exact.
        let open_qty = if self.state.market_params(market).spot_only
            && typ == OrderType::Limit
            && tif == TimeInForce::Gtc
        {
            signed
        } else {
            open_qty
        };
        // Margin-field rules (before the open block: they apply to pure
        // reduces too). Cross orders carry no margin; an isolated pure
        // reduce has no opening exposure to back, so escrow there is
        // meaningless and rejected.
        if margin != 0 && !isolated {
            return Err(RejectReason::Risk);
        }
        if isolated && open_qty == 0 && margin != 0 {
            return Err(RejectReason::Risk);
        }
        if open_qty != 0 {
            // Unmarked-market hole: with no mark and no limit price, px_est
            // is 0, so the IM estimate below is 0 and a zero-collateral
            // account walks straight through the gate.
            if px_est == 0 {
                return Err(RejectReason::Risk);
            }
            let params = self.state.market_params(market);
            // R2-E-8: a CROSS spot_only reserve is only subtracted from
            // pooled equity, so any other exposure in the same account —
            // perp losses, funding, keeper rewards and isolated-liquidation
            // rewards (all paid from cross collateral) — could eat it and
            // break the band-solvency guarantee. Cross spot exposure may
            // therefore not coexist with ANY non-spot exposure (cross or
            // isolated) in one account. Isolated spot is unaffected (its
            // worst case is escrowed in its own bucket), and pure reduces
            // of pre-existing mixed exposure stay allowed.
            if params.spot_only && !isolated {
                if self.has_non_spot_exposure(account) {
                    return Err(RejectReason::Risk);
                }
            } else if !params.spot_only && self.has_cross_spot_exposure(account) {
                return Err(RejectReason::Risk);
            }
            // Funding-rate markets price money off the listing multiplier:
            // the encoded book price there is a rate, not dollars.
            let open_notional = match params.funding_rate {
                true => funding_notional_usd(open_qty.unsigned_abs(), params.usd_per_unit),
                false => notional_usd(open_qty.unsigned_abs(), px_est),
            };
            // An opening order must carry real notional; a zero-notional
            // *reduce* order may still close an unmarked position.
            if open_notional == 0 {
                return Err(RejectReason::Risk);
            }
            let extra_im = bps(open_notional, params.im_bps);
            // Funding-rate opens must also cover this order's own worst-case
            // peg payout (notional × cap), not just im_bps: the peg pays
            // rate-cash peer-to-peer up to the cap regardless of the
            // encoded-price distance.
            let extra_im = if params.funding_rate {
                extra_im.max(
                    funding_notional_usd(open_qty.unsigned_abs(), params.usd_per_unit)
                        * i128::from(params.funding_cap_bps)
                        / 10_000,
                )
            } else {
                extra_im
            };
            // #47 C2: a spot_only order reserves its worst case inside the
            // listed band instead (both closing directions, plus taker
            // fees), never anything priced off the frozen mark.
            let limit_px = if typ == OrderType::Limit { price } else { 0 };
            let extra_im = minuend_account::spot_order_requirement(
                side,
                limit_px,
                open_qty.unsigned_abs(),
                &params,
            )
            .unwrap_or(extra_im);
            let resting = self.resting_open_im(account);
            if isolated {
                // Isolated floor: the bucket must cover this order's own IM
                // (at least 1 USD unit — a zero bucket would be free
                // exposure), fit inside spendable collateral, and leave the
                // cross pool healthy after escrow. No MIN_OPEN_EQUITY: the
                // margin floor is its equivalent.
                if i128::from(margin) < extra_im.max(1) {
                    return Err(RejectReason::Risk);
                }
                if i128::from(margin) > self.collateral_of(account) {
                    return Err(RejectReason::Risk);
                }
                if snap.equity - i128::from(margin) < snap.im + resting {
                    return Err(RejectReason::Risk);
                }
            } else {
                // Equity must cover position IM + the IM reserved for resting
                // opening orders + this order's own opening IM. `snapshot` only
                // sees booked positions, not the margin pending openings will
                // demand once they fill; the order being placed is not in the
                // book yet, so it is not double-counted. Reduce-only orders
                // cannot grow exposure, so they are not subject to this check.
                if snap.equity < snap.im + resting + extra_im {
                    return Err(RejectReason::Risk);
                }
                if snap.equity < MIN_OPEN_EQUITY {
                    return Err(RejectReason::Risk);
                }
            }
            // Funding-rate open-interest cap: worst-case peg payout
            // (notional × market cap) must fit inside the insurance fund at
            // all times, so a burst of openings can never promise more than
            // the fund can pay. A non-positive fund rejects every opening.
            // Runs for both margin modes, after the mode's own gates.
            if params.funding_rate {
                let oi = self.funding_open_interest(market, account, open_qty);
                let worst_payout = funding_notional_usd(oi, params.usd_per_unit)
                    * i128::from(params.funding_cap_bps)
                    / 10_000;
                let insurance = self
                    .state
                    .accounts
                    .get(&INSURANCE_ACCOUNT)
                    .map(|a| a.collateral.max(0))
                    .unwrap_or(0);
                if worst_payout > insurance {
                    return Err(RejectReason::Risk);
                }
            }
        }

        // Escrow: margin leaves collateral while the order lives in the
        // book; it returns via fills (bucket), cancel, or the unfilled
        // remainder. An escrowed own maker is rejected outright
        // (SelfTrade::Reject): canceling it would refund its margin_left
        // to collateral inside this same unit — a cash leg no fill
        // predicate can model, so the dispute's exact identity would
        // false-verdict the honest batch.
        let escrow = if isolated { i128::from(margin) } else { 0 };
        // Matching may mutate earlier makers before a later fill fails.
        // #47 B4: book, escrow, account fills and refunds are recorded in an
        // undo journal (only the touched book levels/orders, fill-party
        // accounts, insurance and this market's scalars) and rolled back on
        // any Err — same all-or-nothing result as the old whole-ChainState
        // clone, without copying the entire chain per order.
        let mut journal = minuend_state::StateJournal::default();
        if escrow != 0 {
            self.state.journal_account(&mut journal, account);
            self.state.account_mut(account).collateral -= escrow;
        }
        let oid = order_id(account, market, client_seq);
        let order = Order {
            id: oid,
            account,
            market,
            side,
            typ,
            tif,
            price,
            qty,
            remaining: qty,
            seq,
            isolated,
            margin_left: if isolated { margin } else { 0 },
        };
        let mut result =
            match self
                .state
                .submit_journaled(&mut journal, order, minuend_book::SelfTrade::Reject)
            {
                Ok(r) => r,
                Err(e) => {
                    self.state.rollback(journal);
                    return Err(RejectReason::Book(e));
                }
            };
        // Funding-rate markets realize rate-cash, not price-diff PnL; tag
        // the fills so the dispute AA picks the funding identity (book
        // submit defaults to kind 0).
        if self.state.market_params(market).funding_rate {
            for f in &mut result.fills {
                f.kind = 1;
            }
        }
        // R2-E-6: an isolated taker's fee is charged to its CROSS collateral
        // (the fill identity the dispute AA mirrors), not to its bucket. If
        // that fee is what drives the collateral negative, the claw would
        // bill the MAKER for the taker's fee. Simulate the taker leg of each
        // fill exactly as `apply_fill_pair` does (fill, then fee) and reject
        // the order (rolled back) when a fee takes non-negative collateral
        // below zero. Pure isolated closes are unaffected whenever the
        // released bucket covers the fee.
        // R3-E-4: the simulation runs on the taker's REAL account right
        // before each fill is applied, so every earlier fill of this order
        // — including the claws `apply_fill_pair` runs between the two
        // parties — is already reflected (a separately simulated account
        // missed those claws and over-stated the collateral of later fills).
        let sim_taker = if isolated {
            let params = self.state.market_params(market);
            Some((
                params.funding_rate.then_some(params.usd_per_unit),
                params.taker_fee_bps,
            ))
        } else {
            None
        };
        for fill in &result.fills {
            if let Some((funding_usd, fee_bps)) = sim_taker {
                if fill.taker == account
                    && fill.kind != 2
                    && !self.taker_fee_keeps_cash(fill, funding_usd, fee_bps)
                {
                    self.state.rollback(journal);
                    return Err(RejectReason::Risk);
                }
            }
            if let Err(e) = self.state.apply_fill_pair_journaled(&mut journal, fill) {
                self.state.rollback(journal);
                return Err(map_acct(e));
            }
        }
        // Refunds: STP-canceled makers' escrow and the taker's unfilled
        // remainder (when it did not rest) return to collateral. Nothing
        // below can fail, so these need no journal entries.
        for (acct, amt) in &result.refunds {
            if *amt > 0 {
                self.state.account_mut(*acct).collateral += i128::from(*amt);
            }
        }
        if !result.taker_resting && result.taker_margin_left > 0 {
            self.state.account_mut(account).collateral += i128::from(result.taker_margin_left);
        }
        // Round 7 (PR #51 未修复项 19, consensus): no in-unit force-sell.
        // It used to liquidate a fill party that was still liquidatable
        // after this fill in the SAME unit, appending book / ADL fills — a
        // multi-fill unit no predicate could judge. A unit now carries at
        // most one fill; a party left liquidatable is closed by a keeper
        // `Liquidate` in a later unit (with the keeper reward as incentive).
        let _ = (unit, seq);
        self.state.seen_client_seq.insert(account, client_seq);
        self.state.note_journal(&journal); // PILOT (MNWIT1)
        Ok(result.fills)
    }

    /// First live order of `account` on `books[market]`'s margin mode, if
    /// any: orders from the same account on one market must share a mode.
    fn own_live_order_mode(&self, account: AccountId, market: MarketId) -> Option<bool> {
        self.state
            .books
            .get(&market)
            .and_then(|b| b.live_orders_of(account).next())
            .map(|o| o.isolated)
    }

    /// R2-E-8: does `account` hold a position or a live order on any market
    /// that is not `spot_only` (either margin mode)?
    fn has_non_spot_exposure(&self, account: AccountId) -> bool {
        let is_spot = |m: &MarketId| {
            self.state
                .markets
                .get(m)
                .map(|p| p.spot_only)
                .unwrap_or(false)
        };
        let pos = self
            .state
            .accounts
            .get(&account)
            .map(|a| a.positions.iter().any(|(m, p)| p.qty != 0 && !is_spot(m)))
            .unwrap_or(false);
        pos || self
            .state
            .books
            .iter()
            .any(|(m, b)| !is_spot(m) && b.live_orders_of(account).next().is_some())
    }

    /// R2-E-8: does `account` hold a CROSS position or a live cross order on
    /// a `spot_only` market?
    fn has_cross_spot_exposure(&self, account: AccountId) -> bool {
        let is_spot = |m: &MarketId| {
            self.state
                .markets
                .get(m)
                .map(|p| p.spot_only)
                .unwrap_or(false)
        };
        let pos = self
            .state
            .accounts
            .get(&account)
            .map(|a| {
                a.positions
                    .iter()
                    .any(|(m, p)| p.qty != 0 && !p.isolated && is_spot(m))
            })
            .unwrap_or(false);
        pos || self.state.books.iter().any(|(m, b)| {
            is_spot(m) && b.live_orders_of(account).any(|o| !o.isolated)
        })
    }

    fn collateral_of(&self, account: AccountId) -> Usd {
        self.state
            .accounts
            .get(&account)
            .map(|a| a.collateral)
            .unwrap_or(0)
    }

    /// Funding-rate open interest for `market`: positive position qty
    /// across all accounts, plus this order's opening qty, plus the
    /// opening remaining qty of this account's resting orders on the market
    /// (bids above the short they reduce, asks above the long they reduce).
    /// Over-counting resting qty is intentional — the cap is a worst case.
    fn funding_open_interest(&self, market: MarketId, account: AccountId, open_qty: i64) -> Qty {
        // PILOT (loop round 3, S1b): running total instead of iterating every account (same value:
        // ChainState::oi_long = sum of positive qty in `market` over all accounts, see oi_ok).
        let mut oi: u128 = self.state.accounts.oi_long_of(market);
        oi += open_qty.unsigned_abs() as u128;
        if let Some(book) = self.state.books.get(&market) {
            let pos_qty = self
                .state
                .accounts
                .get(&account)
                .and_then(|a| a.positions.get(&market))
                .map(|p| p.qty)
                .unwrap_or(0);
            let mut bid_qty: u128 = 0;
            let mut ask_qty: u128 = 0;
            for o in book.live_orders_of(account) {
                match o.side {
                    Side::Bid => bid_qty += o.remaining as u128,
                    Side::Ask => ask_qty += o.remaining as u128,
                }
            }
            // R2-E-10: no i64 negation (overflows at i64::MIN).
            let short = if pos_qty < 0 {
                pos_qty.unsigned_abs() as u128
            } else {
                0
            };
            let long = pos_qty.max(0) as u128;
            oi += bid_qty.saturating_sub(short);
            oi += ask_qty.saturating_sub(long);
        }
        // Positions fit i64 by intake guards; clamp instead of trusting the
        // accumulation above.
        oi.min(i64::MAX as u128) as Qty
    }

    /// R2-E-6 / R3-E-4: whether the taker leg of `fill`, applied to the
    /// taker's current account and followed by its taker fee, leaves
    /// non-negative collateral non-negative and does not dip into a cross
    /// reserve. A fill that would itself fail returns `true` (the real
    /// apply fails the same way and rolls back).
    fn taker_fee_keeps_cash(&self, fill: &Fill, funding_usd: Option<u64>, fee_bps: Bps) -> bool {
        let mut sim = self
            .state
            .accounts
            .get(&fill.taker)
            .cloned()
            .unwrap_or_else(|| minuend_account::Account::new(fill.taker));
        if sim
            .apply_fill(
                fill.taker_side,
                true,
                fill.price,
                fill.qty,
                fill.market,
                funding_usd,
                fill.taker_post,
                fill.taker_isolated,
            )
            .is_err()
        {
            return true;
        }
        let notional = match funding_usd {
            Some(usd) => funding_notional_usd(fill.qty, usd),
            None => notional_usd(fill.qty, fill.price),
        };
        let fee = bps(notional, fee_bps);
        if fee <= 0 {
            return true;
        }
        // Cross equity too: the fee must not dip into a cross spot reserve
        // (R2-E-8) any more than into negative cash.
        let pre = sim.collateral;
        let pre_eq = sim.snapshot(&self.state.marks, &self.state.markets).equity;
        let post = sim.collateral.saturating_sub(fee);
        !((pre >= 0 && post < 0) || (pre_eq >= 0 && pre_eq < fee))
    }

    /// IM that the account's currently resting orders will demand once they
    /// fill and open (or add to) positions. `snapshot` cannot see these —
    /// booked positions only materialize at fill time — so `place` reserves
    /// them on top. On a perp market only the larger side is reserved
    /// (`max(bid_im, ask_im)`): positions there are liquidatable, so a
    /// both-sides-fill sequence has a bounded loss. R4-E-3: on a
    /// `spot_only` market the two sides are SUMMED — a bid fill can be
    /// closed by an IOC and the resting ask then opens a new short, and
    /// spot positions are never liquidated.
    ///
    /// #37-19: the OPENING quantity is what costs margin, so the notional is
    /// priced on the open-only qty difference, not the whole resting side.
    /// Bids reduce a short and asks reduce a long, so the reservable qty on
    /// each side is `resting - reducible`; the whole-side qty (and notional)
    /// was over-reserving IM and rejecting legitimate reduce-only style
    /// resting orders. Per-order notional still uses each order's own price,
    /// so the per-qty rate is a weighted average across the side.
    ///
    /// R3-E-2: two holes closed. (1) On a `spot_only` market every resting
    /// order is reserved on its FULL remaining qty, never netted against
    /// the position: `place` charged it that way (a GTC "reduce" can turn
    /// into an open once the position is closed by another order, and the
    /// maker leg of a fill is never re-checked). (2) Isolated resting
    /// orders are no longer skipped: their open part's requirement is
    /// counted net of the escrow they still carry (`margin_left`), so a
    /// placement-time reduce (escrow 0) that later opens is reserved here
    /// and blocks withdrawing the cash it would need.
    fn resting_open_im(&self, account: AccountId) -> Usd {
        let mut total: Usd = 0;
        for (market, book) in &self.state.books {
            let params = self.state.market_params(*market);
            // [cross, isolated] × [bid, ask]: (qty, notional, escrow left).
            // R2-E-9: i128 accumulators — up to 64 orders of qty ≤ i64::MAX
            // each overflow an i64 sum (debug panic / release wrap to a
            // zero reserve).
            let mut acc = [[(0i128, 0 as Usd, 0 as Usd); 2]; 2];
            for o in book.live_orders_of(account) {
                // Funding-rate books rest at encoded rates: their margin is
                // the multiplier notional, not a dollar price.
                let n = match self.state.markets.get(market) {
                    Some(p) if p.funding_rate => funding_notional_usd(o.remaining, p.usd_per_unit),
                    // #47 C2: a resting spot_only order reserves the same
                    // band worst case `place` charged for it (im_bps is
                    // 10 000 there, so the bps() below is the identity).
                    Some(p) if p.spot_only => {
                        minuend_account::spot_order_requirement(o.side, o.price, o.remaining, p)
                            .unwrap_or(Usd::MAX / 4)
                    }
                    _ => {
                        let px = if o.price != 0 {
                            o.price
                        } else {
                            self.state.marks.get(market).copied().unwrap_or(0)
                        };
                        notional_usd(o.remaining, px)
                    }
                };
                let slot = &mut acc[usize::from(o.isolated)][match o.side {
                    Side::Bid => 0,
                    Side::Ask => 1,
                }];
                slot.0 += i128::from(o.remaining);
                slot.1 = slot.1.saturating_add(n);
                slot.2 = slot.2.saturating_add(i128::from(o.margin_left));
            }
            if acc.iter().flatten().all(|s| s.0 == 0) {
                continue;
            }
            let pos_qty = self
                .state
                .accounts
                .get(&account)
                .and_then(|a| a.positions.get(market))
                .map(|p| p.qty)
                .unwrap_or(0);
            // Bids reduce only a short, asks reduce only a long: only the qty
            // beyond what the position absorbs actually opens. R3-E-2: on a
            // spot_only market nothing is netted (see above).
            let (short, long) = if params.spot_only {
                (0, 0)
            } else {
                ((-i128::from(pos_qty)).max(0), i128::from(pos_qty).max(0))
            };
            for (mode, sides) in acc.iter().enumerate() {
                // Open-only notional: the reducible slice is priced out, the
                // rest keeps the side's per-qty rate. A side with nothing to
                // reduce prices the whole side; one that only reduces prices
                // zero. #47 H1: multiply BEFORE dividing.
                let side_im = |(qty, notional, escrow): (i128, Usd, Usd), reducible: i128| {
                    let open = qty - reducible;
                    let im = if qty > 0 && open > 0 {
                        bps(open_share(notional, open, qty), params.im_bps)
                    } else {
                        0
                    };
                    // Isolated orders: what their escrow already covers is
                    // not reserved twice.
                    if mode == 1 {
                        (im - escrow).max(0)
                    } else {
                        im
                    }
                };
                let bid_im = side_im(sides[0], short);
                let ask_im = side_im(sides[1], long);
                // R4-E-3: on a spot_only market BOTH sides can fill in
                // turn — a bid fill closed out by an IOC (pure reduce, no
                // gate) leaves the resting ask to open a fresh short — so
                // `max` would let the second side open on cash already
                // spent by the first. Spot positions are never liquidated,
                // so reserve the sum. Perp markets keep `max`: a position
                // opened there is liquidatable, so the loss is bounded.
                let side_total = if params.spot_only {
                    bid_im.saturating_add(ask_im)
                } else {
                    bid_im.max(ask_im)
                };
                total = total.saturating_add(side_total);
            }
        }
        total
    }

    pub fn cancel(&mut self, account: AccountId, order_id: OrderId) -> Result<Vec<Fill>, RejectReason> {
        // Cross-market lookup: order ids bind account+market+client_seq, so the
        // id alone identifies the market. books is bounded by listed markets.
        let market = self
            .state
            .books
            .iter()
            .find(|(_, book)| book.get(order_id).map(|o| o.account) == Some(account))
            .map(|(m, _)| *m)
            .ok_or(RejectReason::NotFound)?;
        let canceled = self
            .state
            .book_mut(market)
            .cancel(order_id)
            .map_err(RejectReason::Book)?;
        self.state.wit_dirty.orders.insert((market, order_id)); // PILOT (MNWIT1)
        // Isolated escrow rides on the order: cancel returns its remainder.
        if canceled.margin_left > 0 {
            self.state.account_mut(account).collateral += i128::from(canceled.margin_left);
        }
        Ok(Vec::new())
    }

    /// R3-A-5 / R3-E-3: the anchor's payer-designated account (vault
    /// `trigger.data.account`, recorded with the verified payment in
    /// `ChainState::deposit_backing`) must be the op's account. Production
    /// replay (`Batch::validate_inner`) records a backing for every deposit
    /// anchor whose evidence verifies; an anchor without one (unit-test
    /// fixtures seeding `deposits_allowed` directly) keeps the pre-R3
    /// behaviour.
    /// PILOT: upstream `Engine::deposit` additionally checks the AA anchor
    /// (`deposits_allowed`, `deposit_backing`, duplicate anchor), validates and binds the
    /// Obyte address and records the anchor; none of that touches the account fields
    /// hashed here, and the differential batches only use fresh, endorsed anchors. The
    /// account effect is identical: `credit(amount)` on a clone, then insert.
    pub fn deposit(&mut self, account: AccountId, amount: Usd) -> Result<Vec<Fill>, RejectReason> {
        let mut acct = self
            .state
            .accounts
            .get(&account)
            .cloned()
            .unwrap_or_else(|| minuend_account::Account::new(account));
        acct.credit(amount).map_err(map_acct)?;
        self.state.put_account(account, acct); // PILOT (S1b)
        self.state.wit_dirty.accounts.insert(account); // PILOT (MNWIT1)
        Ok(Vec::new())
    }

    // ---- PILOT (loop round 4): withdraw, liquidate (book path + ADL + funding-rate off-book
    // close), update_external_price and the ReportPrice dispatch arm, copied verbatim from
    // minuend-exec/src/lib.rs @ 20326c0 (lines 1534-2296, 2807-2862, 546-582). Edits marked
    // PILOT: `mut` bindings for the guarded account handles, the holders index instead of
    // full account scans, `note_journal` for the MNWIT1 dirty set, no re-entrancy flag. ----
    /// upstream `dispatch` arm `Op::ReportPrice`
    pub fn report_price(&mut self, oracle: AccountId, market: MarketId, price: Price) -> Result<Vec<Fill>, RejectReason> {
        // Bond gate: only PERP-bonded accounts may report prices;
        // unknown markets have no book to index either.
        if !self.state.oracle_bonds.contains_key(&oracle) {
            return Err(RejectReason::BadAccount);
        }
        if !self.state.markets.contains_key(&market) {
            return Err(RejectReason::NotFound);
        }
        // Spot-only markets have no oracle feed: same signal as
        // unknown markets so watchers need no new error path.
        if self
            .state
            .markets
            .get(&market)
            .map(|p| p.spot_only)
            .unwrap_or(false)
        {
            return Err(RejectReason::NotFound);
        }
        // R10-L1: a report at / above MARK_CAP is rejected (it can
        // never become the mark; R9-H2) rather than recorded.
        if price.unsigned_abs() >= minuend_types::MARK_CAP.unsigned_abs() {
            return Err(RejectReason::Risk);
        }
        // Doc 06 §2.7: pass the pre-increment global seq so TWAP
        // samples carry intra-height ordering without wall clocks.
        let caller_seq = self.state.seq;
        self.state
            .apply_report(oracle, market, price, caller_seq)
            .map_err(|_| RejectReason::NotFound)?;
        self.state.wit_dirty.markets.insert(market); // PILOT (MNWIT1): the mark is in `meta:`
        Ok(Vec::new())
    }
    pub fn withdraw(
        &mut self,
        account: AccountId,
        amount: Usd,
        nonce: u64,
    ) -> Result<Vec<Fill>, RejectReason> {
        if self.state.withdrawals.contains_key(&(account, nonce)) {
            return Err(RejectReason::DuplicateNonce);
        }
        let pending = self
            .state
            .withdrawals
            .range((account, 0)..=(account, u64::MAX))
            .count();
        if pending >= MAX_PENDING_WITHDRAWALS_PER_ACCOUNT {
            return Err(RejectReason::Risk);
        }
        // R2-E-3: cash reserved by this account's resting cross opening
        // orders (spot band worst cases, perp IM) is not withdrawable —
        // otherwise an order placed against collateral could be filled after
        // that collateral already left, leaving an unbacked position.
        let resting = self.resting_open_im(account);
        // #47 (cross-PR): an unknown account has nothing to withdraw. The
        // old `account_mut(..).debit(..)` created an empty account first and
        // left it behind on the Insufficient reject.
        let Some(mut acct) = self.state.accounts.get_mut(&account) else {
            return Err(RejectReason::Insufficient);
        };
        if amount > 0 && amount < MIN_WITHDRAW_AMOUNT && amount != acct.collateral {
            return Err(RejectReason::Risk);
        }
        acct.debit(amount, &self.state.marks, &self.state.markets)
            .map_err(map_acct)?;
        if resting > 0 && acct.snapshot(&self.state.marks, &self.state.markets).equity < resting {
            acct.collateral += amount;
            return Err(RejectReason::Insufficient);
        }
        // Cumulative signed-withdrawal ledger committed as `W` in the AA
        // leaf: the vault AA enforces "this claim + prior claims <= W".
        *self.state.withdrawn_total.entry(account).or_insert(0) += amount;
        self.state.withdrawals.insert(
            (account, nonce),
            minuend_state::Withdrawal {
                amount,
                pending: true,
                height: self.state.height,
            },
        );
        Ok(Vec::new())
    }

    /// Guarded entry — dispatch and force-sell both land here. A nested
    /// call (one made while another `liquidate` is mid-flight) returns no
    /// fills before touching any state, so an outer call's book submit,
    /// fills, and ADL never interleave with a second cascade. The flag is
    /// cleared on every exit path, `Err` included.
    pub fn liquidate(
        &mut self,
        unit: UnitId,
        seq: Seq,
        caller: AccountId,
        target: AccountId,
        market: minuend_types::MarketId,
    ) -> Result<Vec<Fill>, RejectReason> {
        // PILOT: upstream's `liquidating` re-entrancy flag is dropped: nothing in the port
        // (no force-sell) calls `liquidate` from inside another engine op.
        self.liquidate_inner(unit, seq, caller, target, market)
    }

    fn liquidate_inner(
        &mut self,
        unit: UnitId,
        seq: Seq,
        caller: AccountId,
        target: AccountId,
        market: minuend_types::MarketId,
    ) -> Result<Vec<Fill>, RejectReason> {
        // Self-liquidation is banned: a keeper must not trigger its own account.
        if caller == target {
            return Err(RejectReason::BadAccount);
        }
        if target == INSURANCE_ACCOUNT || caller == INSURANCE_ACCOUNT {
            // Insurance fund never liquidates or is liquidated.
            return Err(RejectReason::NotLiquidatable);
        }
        let pos = self
            .state
            .accounts
            .get(&target)
            .and_then(|a| a.positions.get(&market))
            .cloned();
        // Isolation fork: an isolated position is liquidatable on its own
        // bucket risk (`isolated_risk`), a cross one on the pooled account
        // snapshot as today.
        let liquidatable = match &pos {
            Some(p) if p.isolated => self
                .state
                .accounts
                .get(&target)
                .map(|a| {
                    a.isolated_risk(market, &self.state.marks, &self.state.markets)
                        .liquidatable
                })
                .unwrap_or(false),
            _ => {
                self.state
                    .accounts
                    .get(&target)
                    .ok_or(RejectReason::NotFound)?
                    .snapshot(&self.state.marks, &self.state.markets)
                    .liquidatable
            }
        };
        if !liquidatable {
            return Err(RejectReason::NotLiquidatable);
        }
        let pos_qty = pos.as_ref().map(|p| p.qty).unwrap_or(0);
        if pos_qty == 0 {
            return Err(RejectReason::NotLiquidatable);
        }
        // Funding-rate markets close off-book at the external index: their
        // book prices are rates, so an IOC there would trade against a rate
        // ladder instead of unwinding dollars. No book submit, no mark write.
        if self
            .state
            .markets
            .get(&market)
            .map(|p| p.funding_rate)
            .unwrap_or(false)
        {
            // R2-E-11: the off-book close mutates the target, every ADL
            // counterparty (holders of this market), and the keeper; any
            // `?` mid-way used to leave half of it applied. Journal all of
            // them and roll back on Err (all-or-nothing, B4).
            let mut journal = minuend_state::StateJournal::default();
            self.state.journal_account(&mut journal, target);
            self.state.journal_account(&mut journal, caller);
            // PILOT (loop round 4): holders index (same ids, same order)
            let holders: Vec<AccountId> = self.state.accounts.holders_of(market).collect();
            for h in holders {
                self.state.journal_account(&mut journal, h);
            }
            let out = self.liquidate_funding_off_book(unit, seq, caller, target, market, pos_qty);
            if out.is_err() {
                self.state.rollback(journal);
            } else {
                self.state.note_journal(&journal); // PILOT (MNWIT1)
            }
            return out;
        }
        // #47 L1: a legacy spot listing (see `spot_market_tradeable`) can
        // never fill — `apply_fill_pair` returns `Risk` for it. Refuse
        // BEFORE the book is touched instead of matching makers first.
        if !minuend_types::spot_market_tradeable(&self.state.market_params(market)) {
            return Err(RejectReason::Risk);
        }
        // R2-E-4: a (tradeable) spot_only position is never liquidated —
        // neither by a keeper `Liquidate` nor by force-sell. Its mark is
        // frozen, so the ADL fallback would close honest opposite holders
        // at a stale price; its band worst case is already reserved (cross)
        // or escrowed (isolated), so there is nothing for a liquidation to
        // protect. A distressed account is liquidated through its non-spot
        // positions instead. Refused before any state is touched.
        if self.state.market_params(market).spot_only {
            return Err(RejectReason::NotLiquidatable);
        }
        // #47 L1/B4: everything below (book IOC, fills, refunds, ADL, keeper
        // payout) is journaled and rolled back on any Err, so a failing
        // liquidation leaves no half-applied book or account state.
        let mut journal = minuend_state::StateJournal::default();
        let out =
            self.liquidate_book_path(&mut journal, unit, seq, caller, target, market, pos_qty);
        // #47 (owner item "escrow refunds of fill-less forced liquidation"):
        // a book-path liquidation that closed NOTHING is a no-op. Without
        // this, its IOC could still cancel the target's own escrowed orders
        // (CancelMaker) and refund their margin — a cash leg no fill string
        // carries. In a force-sell after a single-fill Place that refund
        // landed on a fill party's leaf, so the fill dispute AA's exact
        // collateral identity judged the HONEST unit as fraud.
        match &out {
            Err(_) => self.state.rollback(journal),
            Ok(fills) if fills.is_empty() => self.state.rollback(journal),
            Ok(_) => self.state.note_journal(&journal), // PILOT (MNWIT1)
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn liquidate_book_path(
        &mut self,
        journal: &mut minuend_state::StateJournal,
        unit: UnitId,
        seq: Seq,
        caller: AccountId,
        target: AccountId,
        market: minuend_types::MarketId,
        pos_qty: i64,
    ) -> Result<Vec<Fill>, RejectReason> {
        let target_isolated_pos = self
            .state
            .accounts
            .get(&target)
            .and_then(|a| a.positions.get(&market))
            .map(|p| p.isolated)
            .unwrap_or(false);
        let side = if pos_qty > 0 { Side::Ask } else { Side::Bid };
        let qty = pos_qty.unsigned_abs();
        let oid = liq_order_id(unit);
        let order = Order {
            id: oid,
            account: target,
            market,
            side,
            typ: OrderType::Market,
            tif: TimeInForce::Ioc,
            price: 0,
            qty,
            remaining: qty,
            seq,
            isolated: false,
            margin_left: 0,
        };
        // Round 7b (R7-H1): one fill per unit lets a dust order at the top
        // of the book absorb each `Liquidate` (1 lot closed, no ADL because
        // the book "filled"). When the first maker would close less than
        // 1/LIQ_MIN_BOOK_FILL_DIV of the position, skip the book: the ADL
        // path below runs in this same unit (a book of no crossing maker
        // behaves exactly as before).
        let dust = self
            .state
            .books
            .get(&market)
            .and_then(|b| b.first_maker_qty(side, target))
            .is_some_and(|q| q.saturating_mul(minuend_types::LIQ_MIN_BOOK_FILL_DIV) < qty);
        let result = if dust {
            minuend_book::MatchResult {
                fills: Vec::new(),
                taker_remaining: qty,
                taker_resting: false,
                canceled_maker: Vec::new(),
                taker_margin_left: 0,
                refunds: Vec::new(),
            }
        } else {
            self.state
                .submit_journaled(journal, order, minuend_book::SelfTrade::CancelMaker)
                .map_err(RejectReason::Book)?
        };
        // Default self-trade policy: cancel-maker-continue (the target's
        // book must clear for the close to execute; kind 3's identity is
        // unchanged by this PR).
        let mut fills = result.fills;
        // Liquidation book fills carry the keeper reward, distinct from a
        // plain place (kind 0/1): the AA subtracts the reward on taker legs.
        for f in &mut fills {
            f.kind = 3;
        }
        for fill in &fills {
            // An AccountError here (should one ever fire) no longer leaves
            // partially-applied state: the caller rolls the journal back.
            self.state
                .apply_fill_pair_journaled(journal, fill)
                .map_err(map_acct)?;
        }
        // Escrow returns (#10): STP refunds and the liquidation IOC's
        // unfilled remainder are the target's own money — mirror place().
        for (acct, amt) in &result.refunds {
            if *amt > 0 {
                self.state.journal_account(journal, *acct);
                self.state.account_mut(*acct).collateral += i128::from(*amt);
            }
        }
        if !result.taker_resting && result.taker_margin_left > 0 {
            self.state.journal_account(journal, target);
            self.state.account_mut(target).collateral += i128::from(result.taker_margin_left);
        }
        let still = if target_isolated_pos {
            self.state
                .accounts
                .get(&target)
                .map(|a| {
                    a.isolated_risk(market, &self.state.marks, &self.state.markets)
                        .liquidatable
                })
                .unwrap_or(false)
        } else {
            self.state
                .accounts
                .get(&target)
                .map(|a| {
                    a.snapshot(&self.state.marks, &self.state.markets)
                        .liquidatable
                })
                .unwrap_or(false)
        };
        let remaining_pos = self
            .state
            .accounts
            .get(&target)
            .and_then(|a| a.positions.get(&market))
            .map(|p| p.qty)
            .unwrap_or(0);
        let mut keeper_paid = Usd::from(0u64);
        // Round 7 (one fill per unit): ADL only when the book IOC filled
        // nothing; a remainder after a book fill waits for the next
        // `Liquidate`.
        if still && remaining_pos != 0 && fills.is_empty() {
            // ADL remainder: the book did not finish the close, so the
            // still-liquidatable remainder is walked onto opposite-sign
            // positions at the current mark — insurance is never the
            // buyer of last resort. Each take is a zero-sum kind-2 fill
            // (the dispute AA always bounces kind 2; no haircut formula
            // here). Candidates exhausted → the unsold qty stays:
            // negative collateral remains, the target is not credited,
            // nothing is printed.
            let mark = *self.state.marks.get(&market).unwrap_or(&0);
            // #47 L3: the ADL print is clamped into the market's listed
            // band (each side only when set). The oracle mark itself is not
            // bounded by the band, but no fill may print outside it.
            let mark = clamp_to_band(mark, &self.state.market_params(market));
            let close_side = if remaining_pos > 0 {
                Side::Ask
            } else {
                Side::Bid
            };
            let remaining = remaining_pos.unsigned_abs();
            // Opposite-sign holders only, excluding the target and
            // insurance. Larger |qty| first, AccountId ascending on ties
            // (explicit tie-break keeps the order deterministic).
            // PILOT (loop round 4): holders index instead of every account (same filter result,
            // same AccountId order before the sort).
            let accts = &self.state.accounts;
            let mut candidates: Vec<(AccountId, Qty)> = accts
                .holders_of(market)
                .map(|id| (id, &accts[&id]))
                .filter(|(id, a)| {
                    *id != target
                        && *id != INSURANCE_ACCOUNT
                        && a.positions
                            .get(&market)
                            .is_some_and(|p| p.qty.signum() == -remaining_pos.signum())
                })
                .map(|(id, a)| (id, a.positions[&market].qty.unsigned_abs()))
                .collect();
            candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            let target_isolated = self
                .state
                .accounts
                .get(&target)
                .and_then(|a| a.positions.get(&market))
                .map(|p| p.isolated)
                .unwrap_or(false);
            for (maker_acct, maker_qty) in candidates {
                if remaining == 0 {
                    break;
                }
                let take = remaining.min(maker_qty);
                if take == 0 {
                    continue;
                }
                let fill = Fill {
                    taker_id: oid,
                    maker_id: OrderId([0u8; 32]),
                    taker: target,
                    maker: maker_acct,
                    market,
                    price: mark,
                    qty: take,
                    seq,
                    taker_side: close_side,
                    taker_post: 0,
                    maker_post: 0,
                    taker_isolated: target_isolated,
                    maker_isolated: false,
                    kind: 2,
                };
                self.state
                    .apply_fill_pair_journaled(journal, &fill)
                    .map_err(map_acct)?;
                fills.push(fill);
                // Round 7: one ADL counterparty per unit.
                break;
            }
        }
        // Keeper reward: bps of filled notional, seized from the
        // liquidatee's own collateral — insurance never funds the reward.
        // A target with no positive collateral leaves the keeper with
        // nothing.
        for f in &fills {
            let keeper_bps = self.state.market_params(market).keeper_reward_bps;
            keeper_paid += bps(notional_usd(f.qty, f.price), keeper_bps);
        }
        if keeper_paid > 0 {
            // Realized PnL settles into collateral, so the target's spendable
            // balance is just its collateral.
            let bal = self
                .state
                .accounts
                .get(&target)
                .map(|a| a.collateral)
                .unwrap_or(0);
            let pay = keeper_paid.min(bal.max(0));
            if pay > 0 {
                self.state.journal_account(journal, target);
                self.state.journal_account(journal, caller);
                if let Some(mut a) = self.state.accounts.get_mut(&target) {
                    a.collateral -= pay;
                }
                self.state
                    .account_mut(caller)
                    .credit(pay)
                    .map_err(map_acct)?;
            }
        }
        Ok(fills)
    }

    /// Funding-rate liquidation, off-book: close the target at the external
    /// index (mark as fallback), ADL the closed qty onto opposite-sign
    /// positions, then positive-PnL counterparties take a pro-rata haircut
    /// of any residual hole — zero-sum, insurance untouched. A hole they
    /// cannot cover stays on the account: collateral is never printed.
    /// Keeper reward is seized from the target afterwards, on the qty the
    /// ADL actually closed (R2-A-11); when no opposite-sign holder exists
    /// nothing closes and the liquidation is rejected (`NotLiquidatable`,
    /// the caller rolls the journal back), so no reward is paid.
    /// Returns synthetic fills for the event log (state is already applied).
    fn liquidate_funding_off_book(
        &mut self,
        unit: UnitId,
        seq: Seq,
        caller: AccountId,
        target: AccountId,
        market: MarketId,
        pos_qty: i64,
    ) -> Result<Vec<Fill>, RejectReason> {
        let usd = self.state.market_params(market).usd_per_unit;
        // Price: fresh external index; fall back to a non-zero mark when the
        // feed is dead; both missing means there is nothing to close at.
        let price = match self.state.fresh_external_index(market) {
            Some(p) => p,
            None => match self.state.marks.get(&market).copied() {
                Some(m) if m != 0 => m,
                _ => return Err(RejectReason::NotLiquidatable),
            },
        };
        let abs_qty = pos_qty.unsigned_abs();
        // Smallest close (1..=abs_qty) whose simulated fill leaves the
        // target not liquidatable; none qualifies → full close.
        let mut lo: u64 = 1;
        let mut hi: u64 = abs_qty;
        let mut dq: u64 = abs_qty;
        let close_side = if pos_qty > 0 { Side::Ask } else { Side::Bid };
        while lo <= hi {
            let mid = lo + (hi - lo) / 2;
            let qualifies = self
                .state
                .accounts
                .get(&target)
                .cloned()
                .map(|mut sim| {
                    let target_isolated = self
                        .state
                        .accounts
                        .get(&target)
                        .and_then(|a| a.positions.get(&market))
                        .map(|p| p.isolated)
                        .unwrap_or(false);
                    sim.apply_fill(
                        close_side,
                        true,
                        price,
                        mid,
                        market,
                        Some(usd),
                        0,
                        target_isolated,
                    )
                    .is_ok()
                        && !if target_isolated {
                            // Isolated: the simulated close must restore the
                            // bucket's own health, not the cross snapshot's.
                            sim.isolated_risk(market, &self.state.marks, &self.state.markets)
                                .liquidatable
                        } else {
                            sim.snapshot(&self.state.marks, &self.state.markets)
                                .liquidatable
                        }
                })
                .unwrap_or(false);
            if qualifies {
                dq = mid;
                if mid == 1 {
                    break;
                }
                hi = mid - 1;
            } else {
                lo = mid + 1;
            }
        }
        // ADL candidates: opposite-sign positions, excluding the target and
        // insurance. Deterministic order: close-price unrealized rate cash
        // desc, then notional/equity desc, then AccountId asc.
        let mut cps: Vec<(AccountId, i64, Usd)> = Vec::new();
        // PILOT (loop round 4): holders index (same ids, same order)
        for id in self.state.accounts.holders_of(market) {
            let a = &self.state.accounts[&id];
            let id = &id;
            if *id == target || *id == INSURANCE_ACCOUNT {
                continue;
            }
            if let Some(p) = a.positions.get(&market) {
                if p.qty != 0 && p.qty.signum() == -pos_qty.signum() {
                    let unrealized = funding_rate_cash(
                        p.qty,
                        funding_rate_bps(price) - funding_rate_bps(p.entry_price),
                        usd,
                    );
                    cps.push((*id, p.qty, unrealized));
                }
            }
        }
        cps.sort_by(|a, b| {
            b.2.cmp(&a.2)
                .then_with(|| {
                    let ratio = |id: AccountId, q: Qty| {
                        let e = self
                            .state
                            .accounts
                            .get(&id)
                            .map(|x| {
                                // Isolated cp positions rank on their own
                                // bucket equity; cross ones on the pooled
                                // snapshot as today.
                                let cp_isolated = x
                                    .positions
                                    .get(&market)
                                    .map(|p| p.isolated)
                                    .unwrap_or(false);
                                if cp_isolated {
                                    x.isolated_risk(market, &self.state.marks, &self.state.markets)
                                        .equity
                                } else {
                                    x.snapshot(&self.state.marks, &self.state.markets).equity
                                }
                            })
                            .unwrap_or(0)
                            .max(1);
                        funding_notional_usd(q, usd) / e
                    };
                    ratio(b.0, b.1.unsigned_abs()).cmp(&ratio(a.0, a.1.unsigned_abs()))
                })
                .then_with(|| a.0.cmp(&b.0))
        });
        let oid = liq_order_id(unit);
        let mut fills: Vec<Fill> = Vec::new();
        let mut remaining = dq;
        // Positive collateral deltas recorded for this call: the only pools
        // the residual haircut may ever touch.
        let mut pos_deltas: Vec<(AccountId, Usd)> = Vec::new();
        for (cp, cp_qty, _) in cps {
            if remaining == 0 {
                break;
            }
            let take = cp_qty.unsigned_abs().min(remaining);
            if take == 0 {
                continue;
            }
            // Opposite-sign holder closes its own way: a short buys back,
            // a long sells — paired with the target's closing side.
            let cp_side = if cp_qty > 0 { Side::Ask } else { Side::Bid };
            let before = self
                .state
                .accounts
                .get(&cp)
                .map(|a| a.collateral)
                .unwrap_or(0);
            let cp_isolated = self
                .state
                .accounts
                .get(&cp)
                .and_then(|a| a.positions.get(&market))
                .map(|p| p.isolated)
                .unwrap_or(false);
            let target_isolated = self
                .state
                .accounts
                .get(&target)
                .and_then(|a| a.positions.get(&market))
                .map(|p| p.isolated)
                .unwrap_or(false);
            {
                let mut a = self.state.account_mut(cp);
                a.apply_fill(
                    cp_side,
                    true,
                    price,
                    take,
                    market,
                    Some(usd),
                    0,
                    cp_isolated,
                )
                .map_err(map_acct)?;
            }
            {
                let mut a = self.state.account_mut(target);
                a.apply_fill(
                    close_side,
                    false,
                    price,
                    take,
                    market,
                    Some(usd),
                    0,
                    target_isolated,
                )
                .map_err(map_acct)?;
            }
            let after = self
                .state
                .accounts
                .get(&cp)
                .map(|a| a.collateral)
                .unwrap_or(0);
            if after > before {
                pos_deltas.push((cp, after - before));
            }
            // No taker fee inside this fill and no socialization: ADL is
            // the transfer, not a trade.
            fills.push(Fill {
                taker_id: oid,
                maker_id: OrderId([0u8; 32]),
                taker: cp,
                maker: target,
                market,
                price,
                qty: take,
                seq,
                taker_side: cp_side,
                taker_post: 0,
                maker_post: 0,
                taker_isolated: cp_isolated,
                maker_isolated: target_isolated,
                kind: 2,
            });
            remaining -= take;
            // Round 7 (one fill per unit): one ADL counterparty per
            // off-book liquidation; the rest waits for the next call.
            break;
        }
        // R2-A-11 (round 2 of #47): only the qty the ADL loop actually
        // closed counts. With no opposite-sign holders nothing closed: the
        // old code still paid the keeper on the full `dq` (a cash transfer
        // with no fill behind it, invisible to the fill dispute AA) and
        // reported success. Now that is a rejected Liquidate: no state
        // change (the caller rolls the journal back), no reward.
        let closed = dq - remaining;
        if closed == 0 {
            return Err(RejectReason::NotLiquidatable);
        }
        let target_equity = |s: &ChainState| {
            s.accounts
                .get(&target)
                .map(|a| {
                    // Isolated: residual bucket + remaining uPnL after the
                    // ADL fills; cross: pooled equity as today.
                    let tgt_isolated = a
                        .positions
                        .get(&market)
                        .map(|p| p.isolated)
                        .unwrap_or(false);
                    if tgt_isolated {
                        a.isolated_risk(market, &s.marks, &s.markets).equity
                    } else {
                        a.snapshot(&s.marks, &s.markets).equity
                    }
                })
                .unwrap_or(0)
        };
        // No insurance top-up: the fund never pays a loss. The residual
        // hole below is haircut from positive-PnL ADL counterparties
        // instead (zero-sum, insurance not debited); whatever they cannot
        // cover stays on the account as negative equity.
        let equity = target_equity(&self.state);
        // Residual hole: haircut positive-PnL ADL counterparties pro-rata,
        // last in ADL order takes the remainder. Each is debited at most
        // the positive delta recorded for this call, and every debit lands
        // on the target (collateral or isolated bucket) — money moves, it
        // never vanishes (#9).
        if equity < 0 {
            let mut hole = -equity;
            let total: Usd = pos_deltas.iter().map(|(_, d)| *d).sum();
            if total > 0 {
                let last = pos_deltas.last().map(|(id, _)| *id);
                for (id, delta) in &pos_deltas {
                    if hole <= 0 || total <= 0 {
                        break;
                    }
                    let share = adl_haircut_share(hole, *delta, total, Some(*id) == last);
                    if share <= 0 {
                        continue;
                    }
                    if let Some(mut a) = self.state.accounts.get_mut(id) {
                        a.collateral -= share;
                    }
                    // Credit the target through the isolated-vs-cross
                    // branch (bucket while the position still exists,
                    // collateral once it is gone).
                    let tgt_still_isolated = self
                        .state
                        .accounts
                        .get(&target)
                        .map(|a| {
                            a.positions
                                .get(&market)
                                .map(|p| p.isolated)
                                .unwrap_or(false)
                        })
                        .unwrap_or(false);
                    if tgt_still_isolated {
                        if let Some(mut a) = self.state.accounts.get_mut(&target) {
                            *a.isolated_margin.entry(market).or_insert(0) += share;
                        }
                    } else if let Some(mut a) = self.state.accounts.get_mut(&target) {
                        a.collateral += share;
                    }
                    hole -= share;
                }
            }
        }
        // Keeper reward: bps of the multiplier notional of the qty actually
        // closed (R2-A-11: `closed`, not the planned `dq`), seized from the
        // target's positive collateral after the steps above. No book fill,
        // so no reward from a book price.
        let reward = bps(
            funding_notional_usd(closed, usd),
            self.state.market_params(market).keeper_reward_bps,
        );
        if reward > 0 {
            let bal = self
                .state
                .accounts
                .get(&target)
                .map(|a| a.collateral.max(0))
                .unwrap_or(0);
            let pay = reward.min(bal);
            if pay > 0 {
                if let Some(mut a) = self.state.accounts.get_mut(&target) {
                    a.collateral -= pay;
                }
                self.state
                    .account_mut(caller)
                    .credit(pay)
                    .map_err(map_acct)?;
            }
        }
        Ok(fills)
    }

    pub fn update_external_price(
        &mut self,
        source: AccountId,
        market: MarketId,
        price: Price,
        source_id: u8,
        caller_seq: Seq,
    ) -> Result<Vec<Fill>, RejectReason> {
        let funding_rate = self
            .state
            .markets
            .get(&market)
            .map(|p| p.funding_rate)
            .unwrap_or(false);
        // Funding-rate markets trade the external rate itself: their feed
        // must work regardless of the global source selection (the peg pays
        // only from a fresh external print). Regular markets keep the
        // AggregatedExternal gate.
        if !funding_rate
            && self.state.funding_source != minuend_types::FundingSourceKind::AggregatedExternal
        {
            return Err(RejectReason::NotFound);
        }
        if !self.state.external_sources.contains(&source) {
            return Err(RejectReason::BadAccount);
        }
        if !self.state.markets.contains_key(&market) || price == 0 {
            return Err(RejectReason::NotFound);
        }
        // The ring carries an encoded rate on funding-rate markets; a print
        // beyond ±100% is a broken feed, not a market. Regular markets carry
        // dollar prices in the same ring — their scale is untouched here.
        if funding_rate && minuend_types::funding_rate_bps(price).abs() > 10_000 {
            return Err(RejectReason::NotFound);
        }
        if self
            .state
            .markets
            .get(&market)
            .map(|p| p.spot_only)
            .unwrap_or(false)
        {
            return Err(RejectReason::NotFound);
        }
        self.state
            .apply_external_price(source, market, price, source_id, caller_seq);
        // A fresh print may unblock this window's peg payment (or arm it).
        if funding_rate {
            self.state.settle_funding_peg(market);
        }
        Ok(Vec::new())
    }
}

/// #47 L3: clamp an off-book print into the market's listed band. `0` on
/// either side means unbounded (see `create_market`).
fn clamp_to_band(price: minuend_types::Price, p: &MarketParams) -> minuend_types::Price {
    let mut px = price;
    if p.min_price != 0 && px < p.min_price {
        px = p.min_price;
    }
    if p.max_price != 0 && px > p.max_price {
        px = p.max_price;
    }
    px
}

fn adl_haircut_share(hole: i128, delta: i128, total: i128, is_last: bool) -> i128 {
    let raw = if is_last { hole } else { hole * delta / total };
    raw.min(delta)
}
