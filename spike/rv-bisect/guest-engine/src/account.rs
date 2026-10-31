use crate::types::{
    bps, funding_notional_usd, funding_rate_bps, funding_rate_cash, notional_usd,
    signed_notional_usd, spot_market_tradeable, AccountId, MarketId, MarketParams, Price, Qty,
    Side, Usd, IM_RATE_BPS, LIQ_RATIO_BPS, MM_RATE_BPS, PRICE_SCALE, QTY_SCALE,
    REDUCE_ONLY_RATIO_BPS, USD_SCALE,
};
use alloc::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Position {
    pub market: MarketId,
    pub qty: i64,
    pub entry_price: Price,
    /// Margin mode seeded from the opening fill's order. Once the position
    /// exists this flag is authoritative (mode cannot change mid-position).
    pub isolated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub id: AccountId,
    pub collateral: Usd,
    pub realized_pnl: Usd,
    pub positions: BTreeMap<MarketId, Position>,
    /// Per-market escrowed isolated margin (USD_SCALE units). Money here has
    /// already left `collateral`: `collateral + Σisolated_margin + Σlive
    /// order margin_left` only changes via deposit/withdraw/PnL.
    pub isolated_margin: BTreeMap<MarketId, Usd>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RiskSnapshot {
    pub equity: Usd,
    pub mm: Usd,
    pub im: Usd,
    pub margin_ratio_bps: Option<u64>,
    pub liquidatable: bool,
    pub reduce_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountError {
    Insufficient,
    Overflow,
    QtyTooLarge,
    NonPositive,
    /// A market-level risk rejection raised outside the account itself (a
    /// legacy leveraged `spot_only` market whose mark is frozen). Maps to
    /// `RejectReason::Risk` at the engine boundary.
    Risk,
}

impl Account {
    pub fn new(id: AccountId) -> Self {
        Self {
            id,
            collateral: 0,
            realized_pnl: 0,
            positions: BTreeMap::new(),
            isolated_margin: BTreeMap::new(),
        }
    }

    /// `cash_per_bp` is `Some(usd_per_unit)` on funding-rate markets: the
    /// reducing fill then realizes rate-delta cash instead of the encoded
    /// price delta (whose dollar scale there is meaningless). `None` keeps
    /// today's `realize` path.
    #[allow(clippy::too_many_arguments)]
    pub fn apply_fill(
        &mut self,
        side: Side,
        _is_taker: bool,
        price: Price,
        qty: Qty,
        market: MarketId,
        cash_per_bp: Option<u64>,
        post: Usd,
        isolated: bool,
    ) -> Result<(), AccountError> {
        if qty > i64::MAX as u64 {
            return Err(AccountError::QtyTooLarge);
        }
        let delta: i64 = match side {
            Side::Bid => qty as i64,
            Side::Ask => -(qty as i64),
        };
        let pos = self.positions.get(&market).cloned().unwrap_or(Position {
            market,
            qty: 0,
            entry_price: 0,
            isolated,
        });
        let old = pos.qty;
        // Seed-only: a flat account takes the fill's order mode; an existing
        // position keeps its flag (Step 4's mode gate rejects mismatches).
        let seed = if old == 0 { isolated } else { pos.isolated };
        // Whether this fill creates or grows open quantity (as opposed to a
        // pure reduce). Decides where `post` lands: into the bucket when it
        // backs new exposure, back to collateral when it was escrow for a
        // reduce phase that never opened.
        let mut produced_open = false;
        if old == 0 || same_sign(old, delta) {
            produced_open = true;
            let new_qty = old.checked_add(delta).ok_or(AccountError::Overflow)?;
            // R2-E-10: |qty| must stay ≤ i64::MAX. `-1 + -i64::MAX` is
            // exactly i64::MIN (no checked_add error), and every later
            // `abs()`/negation of it overflows (debug panic, release wrap).
            if new_qty == i64::MIN {
                return Err(AccountError::Overflow);
            }
            let entry = if old == 0 {
                price
            } else {
                vwap(old.unsigned_abs(), pos.entry_price, qty, price)
            };
            self.positions.insert(
                market,
                Position {
                    market,
                    qty: new_qty,
                    entry_price: entry,
                    isolated: seed,
                },
            );
        } else {
            let close = old.unsigned_abs().min(delta.unsigned_abs());
            // Isolated close releases a proportional share of the bucket into
            // collateral BEFORE realized PnL settles, so a loss lands on
            // released margin first and the bucket never goes negative. A
            // full close (`close == old_abs`) empties the bucket exactly.
            if pos.isolated {
                let old_abs = old.unsigned_abs();
                if old_abs > 0 {
                    if let Some(bucket) = self.isolated_margin.get_mut(&market) {
                        let release = *bucket * i128::from(close) / i128::from(old_abs);
                        let release = release.clamp(0, *bucket);
                        *bucket -= release;
                        self.collateral = self
                            .collateral
                            .checked_add(release)
                            .ok_or(AccountError::Overflow)?;
                    }
                }
            }
            let pnl = match cash_per_bp {
                None => realize(old, pos.entry_price, price, close),
                // Sign follows the position: long profits when the exit
                // rate exceeds the entry rate, short the reverse.
                Some(usd) => funding_rate_cash(
                    if old > 0 {
                        close as i64
                    } else {
                        -(close as i64)
                    },
                    funding_rate_bps(price) - funding_rate_bps(pos.entry_price),
                    usd,
                ),
            };
            // Settle realized PnL into spendable collateral immediately so
            // winners can withdraw profits and the withdrawal-proof leaf
            // (which commits collateral only) reflects true solvency.
            // `realized_pnl` remains a cumulative statistic only.
            self.collateral = self
                .collateral
                .checked_add(pnl)
                .ok_or(AccountError::Overflow)?;
            self.realized_pnl = self.realized_pnl.saturating_add(pnl);
            let leftover = (old.unsigned_abs() as i64) - (close as i64);
            if leftover == 0 {
                let open = delta.unsigned_abs() - close;
                if open == 0 {
                    self.positions.remove(&market);
                } else {
                    produced_open = true;
                    self.positions.insert(
                        market,
                        Position {
                            market,
                            qty: if delta > 0 {
                                open as i64
                            } else {
                                -(open as i64)
                            },
                            entry_price: price,
                            isolated: seed,
                        },
                    );
                }
            } else {
                let signed = if old > 0 { leftover } else { -leftover };
                self.positions.insert(
                    market,
                    Position {
                        market,
                        qty: signed,
                        entry_price: pos.entry_price,
                        isolated: seed,
                    },
                );
            }
        }
        if let Some(p) = self.positions.get(&market) {
            if p.qty == 0 {
                self.positions.remove(&market);
            }
        }
        // Post placement: open quantity escrows into the bucket (or tops up
        // an existing one); a pure-reduce post is returned escrow. Entries
        // are never deleted — a 0 entry is pending escrow for a live flip
        // order or a harmless zero.
        if post != 0 {
            if produced_open {
                *self.isolated_margin.entry(market).or_insert(0) += post;
            } else {
                self.collateral = self
                    .collateral
                    .checked_add(post)
                    .ok_or(AccountError::Overflow)?;
            }
        }
        Ok(())
    }

    pub fn snapshot(
        &self,
        marks: &BTreeMap<MarketId, Price>,
        params: &BTreeMap<MarketId, MarketParams>,
    ) -> RiskSnapshot {
        let mut upnl: Usd = 0;
        let mut mm: Usd = 0;
        let mut im: Usd = 0;
        // Positions in markets without a mark are excluded from equity/margin
        // and force reduce-only: a zero mark would fabricate full-notional
        // "losses" (longs) or "profits" (shorts) while zeroing margin needs.
        let mut has_unmarked = false;
        let mut spot_reserve: Usd = 0;
        for (m, pos) in &self.positions {
            // Isolation: cross equity/risk never sees isolated positions —
            // their losses stop at their own bucket (see `isolated_risk`).
            if pos.isolated {
                continue;
            }
            // #47 C2: a spot_only position never reads the (frozen) mark.
            // Its worst-case loss inside the listed band is reserved out of
            // equity up front, so it needs no MM/IM and no liquidation.
            if let Some(r) = spot_position_requirement(pos, params) {
                spot_reserve = spot_reserve.saturating_add(r);
                continue;
            }
            let mark = match marks.get(m).copied() {
                Some(p) if p != 0 => p,
                _ => {
                    has_unmarked = true;
                    continue;
                }
            };
            let (u, m2, i2) = position_risk(pos, mark, params);
            upnl += u;
            mm += m2;
            im += i2;
        }
        // Realized PnL settles into `collateral` at close time, so equity is
        // collateral + unrealized. realized_pnl is a cumulative stat only.
        // #47 C2: cash reserved for spot_only worst cases is not equity
        // available to anything else (orders, withdrawals, other markets).
        let equity = self.collateral + upnl - spot_reserve;
        let margin_ratio_bps = if mm == 0 {
            None
        } else if equity < 0 {
            Some(0)
        } else {
            Some((equity.saturating_mul(10_000) / mm) as u64)
        };
        let liquidatable = mm > 0 && equity * 10_000 <= mm * i128::from(LIQ_RATIO_BPS);
        let reduce_only =
            has_unmarked || (mm > 0 && equity * 10_000 <= mm * i128::from(REDUCE_ONLY_RATIO_BPS));
        RiskSnapshot {
            equity,
            mm,
            im,
            margin_ratio_bps,
            liquidatable,
            reduce_only,
        }
    }

    /// Risk of `market`'s position when it is isolated: equity is the
    /// position's own bucket plus its unrealized PnL, so losses stop at the
    /// bucket and never touch cross collateral. No position, or a cross
    /// position: a trivial snapshot that is never liquidatable/reduce-only
    /// (the cross `snapshot` is the authority there). Missing mark: the
    /// bucket alone with reduce-only forced — uPnL is unknowable, so the
    /// position can only shrink.
    pub fn isolated_risk(
        &self,
        market: MarketId,
        marks: &BTreeMap<MarketId, Price>,
        params: &BTreeMap<MarketId, MarketParams>,
    ) -> RiskSnapshot {
        let trivial = |equity: Usd, reduce_only: bool| RiskSnapshot {
            equity,
            mm: 0,
            im: 0,
            margin_ratio_bps: None,
            liquidatable: false,
            reduce_only,
        };
        let pos = match self.positions.get(&market) {
            Some(p) if p.isolated => p,
            _ => return trivial(self.collateral, false),
        };
        let bucket = self.isolated_margin.get(&market).copied().unwrap_or(0);
        // #47 C2: an isolated spot_only bucket is judged against the
        // position's worst case, never the frozen mark. It is never
        // liquidatable; `equity` is the bucket's surplus over the reserve.
        if let Some(r) = spot_position_requirement(pos, params) {
            return trivial(bucket - r, false);
        }
        let mark = match marks.get(&market).copied() {
            Some(p) if p != 0 => p,
            _ => return trivial(bucket, true),
        };
        let (upnl, mm, im) = position_risk(pos, mark, params);
        let equity = bucket + upnl;
        let margin_ratio_bps = if mm == 0 {
            None
        } else if equity < 0 {
            Some(0)
        } else {
            Some((equity.saturating_mul(10_000) / mm) as u64)
        };
        let liquidatable = mm > 0 && equity * 10_000 <= mm * i128::from(LIQ_RATIO_BPS);
        let reduce_only = mm > 0 && equity * 10_000 <= mm * i128::from(REDUCE_ONLY_RATIO_BPS);
        RiskSnapshot {
            equity,
            mm,
            im,
            margin_ratio_bps,
            liquidatable,
            reduce_only,
        }
    }

    pub fn credit(&mut self, amount: Usd) -> Result<(), AccountError> {
        if amount < 0 {
            return Err(AccountError::NonPositive);
        }
        self.collateral = self
            .collateral
            .checked_add(amount)
            .ok_or(AccountError::Overflow)?;
        Ok(())
    }

    pub fn debit(
        &mut self,
        amount: Usd,
        marks: &BTreeMap<MarketId, Price>,
        params: &BTreeMap<MarketId, MarketParams>,
    ) -> Result<(), AccountError> {
        if amount <= 0 {
            return Err(AccountError::NonPositive);
        }
        if self.collateral < amount {
            return Err(AccountError::Insufficient);
        }
        self.collateral -= amount;
        let snap = self.snapshot(marks, params);
        // #47 C2: besides the MM-based reduce-only test, a withdrawal may
        // never dip into cash reserved for spot_only worst cases
        // (`equity` already has that reserve subtracted). Without this,
        // collateral posted at open could walk straight back out.
        if snap.reduce_only || snap.equity < 0 {
            self.collateral += amount;
            return Err(AccountError::Insufficient);
        }
        Ok(())
    }
}

fn same_sign(a: i64, b: i64) -> bool {
    (a > 0 && b > 0) || (a < 0 && b < 0)
}

/// Loss of `qty` units when the price moves `diff` against the holder,
/// using the same multiply-first formula as [`realize`] (so the bound
/// truncates exactly like the PnL it bounds). Saturates instead of
/// overflowing: a saturated requirement simply cannot be met.
fn loss_bound(qty: Qty, diff: i128) -> Usd {
    if diff <= 0 {
        return 0;
    }
    diff.checked_mul(i128::from(qty))
        .and_then(|v| v.checked_mul(i128::from(USD_SCALE)))
        .map(|v| v / i128::from(PRICE_SCALE) / i128::from(QTY_SCALE))
        .unwrap_or(i128::MAX)
}

/// #47 C2: collateral a `spot_only` position must keep so that closing it
/// at ANY price inside `[min_price, max_price]` can never drive the
/// holder's cash negative.
///
/// * long  (`qty > 0`): worst exit is `min_price` → loss `qty × (entry − min)`
/// * short (`qty < 0`): worst exit is `max_price` → loss `qty × (max − entry)`
///
/// plus the largest taker fee the close can pay (fee on `qty × max_price`),
/// and never less than the market's own full-collateral IM on the entry
/// notional (`im_bps` is 10 000 on a tradeable spot market). The frozen
/// mark is never read.
///
/// Returns `None` for a non-spot market, or for a legacy spot market that
/// [`spot_market_tradeable`] rejects (no finite worst case exists there;
/// such markets cannot trade, and their positions keep the old mark math).
pub fn spot_requirement(qty_signed: i64, entry: Price, p: &MarketParams) -> Option<Usd> {
    if !p.spot_only || !spot_market_tradeable(p) {
        return None;
    }
    let q = qty_signed.unsigned_abs();
    if q == 0 {
        return Some(0);
    }
    let worst_loss = if qty_signed > 0 {
        loss_bound(q, i128::from(entry) - i128::from(p.min_price))
    } else {
        loss_bound(q, i128::from(p.max_price) - i128::from(entry))
    };
    let close_fee = bps(notional_usd(q, p.max_price), p.taker_fee_bps);
    let full = bps(notional_usd(q, entry), p.im_bps);
    Some(worst_loss.saturating_add(close_fee).max(full))
}

/// Worst-case [`spot_requirement`] for an ORDER that may open `qty` on a
/// spot_only market, over every price it can fill at: a bid fills at or
/// below its limit (or anywhere up to `max_price` as a market order), an
/// ask at or above its limit (or anywhere down to `min_price`). Includes
/// the taker fee the opening fill itself may pay. `None` off spot markets.
pub fn spot_order_requirement(side: Side, limit: Price, qty: Qty, p: &MarketParams) -> Option<Usd> {
    if !p.spot_only || !spot_market_tradeable(p) {
        return None;
    }
    if qty == 0 {
        return Some(0);
    }
    let q = qty.min(i64::MAX as u64) as i64;
    let open_fee = bps(notional_usd(qty, p.max_price), p.taker_fee_bps);
    let req = match side {
        // Both terms of a long's requirement grow with entry: the worst
        // entry is the highest price the bid can pay.
        Side::Bid => {
            let worst_entry = if limit != 0 { limit } else { p.max_price };
            spot_requirement(q, worst_entry.clamp(p.min_price, p.max_price), p)?
        }
        // A short's loss term shrinks with entry while its notional term
        // grows: take each term at its own worst end of [lowest entry, max].
        Side::Ask => {
            let lowest_entry = if limit != 0 { limit } else { p.min_price };
            let lo = spot_requirement(-q, lowest_entry.clamp(p.min_price, p.max_price), p)?;
            let hi = spot_requirement(-q, p.max_price, p)?;
            lo.max(hi)
        }
    };
    Some(req.saturating_add(open_fee))
}

fn spot_position_requirement(
    pos: &Position,
    params: &BTreeMap<MarketId, MarketParams>,
) -> Option<Usd> {
    spot_requirement(pos.qty, pos.entry_price, params.get(&pos.market)?)
}

/// Per-position (unrealized PnL, mm, im) at `mark`, verbatim from the
/// pooled `snapshot` math: funding-rate markets scale off the listing
/// multiplier, regular markets off notional. Shared by `snapshot` (cross)
/// and `isolated_risk`.
fn position_risk(
    pos: &Position,
    mark: Price,
    params: &BTreeMap<MarketId, MarketParams>,
) -> (Usd, Usd, Usd) {
    let m = &pos.market;
    // Per-market margin rates; a market absent from the map (stale
    // book, e.g. unit tests) falls back to the genesis rates.
    let fp = params.get(m).filter(|p| p.funding_rate);
    if let Some(p) = fp {
        // Funding-rate market: money scales with the listing-time
        // multiplier — book/marks there encode bps, not dollars.
        let notional = funding_notional_usd(pos.qty.unsigned_abs(), p.usd_per_unit);
        let upnl = funding_rate_cash(
            pos.qty,
            funding_rate_bps(mark) - funding_rate_bps(pos.entry_price),
            p.usd_per_unit,
        );
        return (upnl, bps(notional, p.mm_bps), bps(notional, p.im_bps));
    }
    let im_bps = params.get(m).map(|p| p.im_bps).unwrap_or(IM_RATE_BPS);
    let mm_bps = params.get(m).map(|p| p.mm_bps).unwrap_or(MM_RATE_BPS);
    let upnl = signed_notional_usd(pos.qty, mark) - signed_notional_usd(pos.qty, pos.entry_price);
    let abs_n = notional_usd(pos.qty.unsigned_abs(), mark).abs();
    (upnl, bps(abs_n, mm_bps), bps(abs_n, im_bps))
}

fn vwap(old_qty: Qty, old_px: Price, fill_qty: Qty, fill_px: Price) -> Price {
    // Signed i128 math: prices may print negative while quantities stay
    // non-negative; truncation toward zero matches `realize` below.
    let num = i128::from(old_qty) * i128::from(old_px) + i128::from(fill_qty) * i128::from(fill_px);
    let den = i128::from(old_qty) + i128::from(fill_qty);
    (num / den) as Price
}

fn realize(old_qty: i64, entry: Price, exit: Price, reduce_qty: Qty) -> Usd {
    let signed = if old_qty > 0 {
        i128::from(exit) - i128::from(entry)
    } else {
        i128::from(entry) - i128::from(exit)
    };
    // Scale up BEFORE dividing: `x / PRICE_SCALE * USD_SCALE` truncates
    // toward zero on every partial step (fixed by multiplying first).
    signed * i128::from(reduce_qty) * i128::from(USD_SCALE)
        / i128::from(PRICE_SCALE)
        / i128::from(QTY_SCALE)
}

