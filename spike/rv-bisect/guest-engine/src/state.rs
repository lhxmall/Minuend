//! Subset of minuend-state::ChainState @ fix/47-all 20326c0 (crates/minuend-state/src/lib.rs):
//! only the fields the place/cancel/deposit paths read or write. Methods below are copied
//! verbatim except where marked `PILOT:`.
use crate::account::Account;
use crate::book::{BookJournal, OrderBook};
use crate::types::{
    bps, notional_usd, funding_notional_usd, AccountId, Height, MarketId, MarketParams, Price, Seq,
    INSURANCE_ACCOUNT, USD_SCALE,
};
use crate::{Fill, SelfTrade};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
type HashSet<K> = BTreeSet<K>;
mod minuend_account { pub use crate::account::AccountError; }
mod minuend_book { pub use crate::{BookError, MatchResult, Order}; }
mod minuend_types { pub use crate::types::*; }

#[derive(Debug, Default)]
pub struct StateJournal {
    accounts: Vec<(AccountId, Option<Account>)>,
    seen_accounts: HashSet<AccountId>,
    /// (market, mark, last_funding_height) pre-images.
    markets: Vec<(MarketId, Option<Price>, Option<Height>)>,
    seen_markets: HashSet<MarketId>,
    /// (market, book existed before, book undo log)
    book: Option<(MarketId, bool, BookJournal)>,
}

#[derive(Clone, Debug, Default)]
pub struct ChainState {
    pub seq: Seq,
    pub accounts: BTreeMap<AccountId, Account>,
    pub markets: BTreeMap<MarketId, MarketParams>,
    pub books: BTreeMap<MarketId, OrderBook>,
    pub marks: BTreeMap<MarketId, Price>,
    /// PILOT: always empty (no ReportPrice ops in the pilot); kept so the mark
    /// guard in `apply_fill_pair` reads exactly as upstream.
    pub oracle_reports: BTreeMap<(MarketId, AccountId), Price>,
    pub oracle_bonds: BTreeMap<AccountId, u128>,
    pub last_index: BTreeMap<MarketId, Price>,
    pub last_funding_height: BTreeMap<MarketId, Height>,
    /// upstream: HashMap<AccountId, u64>
    pub seen_client_seq: BTreeMap<AccountId, u64>,
}

impl ChainState {
    pub fn journal_account(&self, j: &mut StateJournal, id: AccountId) {
        if j.seen_accounts.insert(id) {
            j.accounts.push((id, self.accounts.get(&id).cloned()));
        }
    }

    /// Record the per-market scalars `apply_fill_pair` may write.
    fn journal_market(&self, j: &mut StateJournal, m: MarketId) {
        if j.seen_markets.insert(m) {
            j.markets.push((
                m,
                self.marks.get(&m).copied(),
                self.last_funding_height.get(&m).copied(),
            ));
        }
    }

    /// Book submit whose changes are recorded in `j` (at most one book per
    /// journal). On `Err` the book is already untouched.
    pub fn submit_journaled(
        &mut self,
        j: &mut StateJournal,
        order: minuend_book::Order,
        self_trade: SelfTrade,
    ) -> Result<minuend_book::MatchResult, minuend_book::BookError> {
        let market = order.market;
        assert!(j.book.is_none(), "one book submit per journal");
        let existed = self.books.contains_key(&market);
        let (res, bj) = match self.book_mut(market).submit_journaled(order, self_trade) {
            Ok(v) => v,
            Err(e) => {
                if !existed {
                    self.books.remove(&market);
                }
                return Err(e);
            }
        };
        j.book = Some((market, existed, bj));
        Ok(res)
    }

    /// `apply_fill_pair` with every state it can touch recorded in `j`
    /// first. `apply_fill_pair` itself writes nothing when it errors, so
    /// the journal only has to undo the fills applied before this one.
    pub fn apply_fill_pair_journaled(
        &mut self,
        j: &mut StateJournal,
        fill: &Fill,
    ) -> Result<(), minuend_account::AccountError> {
        self.journal_account(j, fill.taker);
        self.journal_account(j, fill.maker);
        self.journal_account(j, INSURANCE_ACCOUNT);
        self.journal_market(j, fill.market);
        // A funding-rate fill can fire `settle_funding_peg`, which moves
        // cash between every holder of the market.
        if self
            .markets
            .get(&fill.market)
            .is_some_and(|p| p.funding_rate)
        {
            let holders: Vec<AccountId> = self
                .accounts
                .iter()
                .filter(|(_, a)| a.positions.contains_key(&fill.market))
                .map(|(id, _)| *id)
                .collect();
            for id in holders {
                self.journal_account(j, id);
            }
        }
        self.apply_fill_pair(fill)
    }

    /// Restore every pre-image recorded in `j`.
    pub fn rollback(&mut self, j: StateJournal) {
        if let Some((market, existed, bj)) = j.book {
            if existed {
                self.book_mut(market).rollback(bj);
            } else {
                self.books.remove(&market);
            }
        }
        for (id, pre) in j.accounts {
            match pre {
                Some(a) => {
                    self.accounts.insert(id, a);
                }
                None => {
                    self.accounts.remove(&id);
                }
            }
        }
        for (m, mark, lfh) in j.markets {
            match mark {
                Some(v) => self.marks.insert(m, v),
                None => self.marks.remove(&m),
            };
            match lfh {
                Some(v) => self.last_funding_height.insert(m, v),
                None => self.last_funding_height.remove(&m),
            };
        }
    }

    pub fn book_mut(&mut self, market: MarketId) -> &mut OrderBook {
        self.books
            .entry(market)
            .or_insert_with(|| OrderBook::new(market))
    }

    pub fn account_mut(&mut self, id: AccountId) -> &mut Account {
        self.accounts.entry(id).or_insert_with(|| Account::new(id))
    }

    pub fn apply_fill_pair(&mut self, fill: &Fill) -> Result<(), minuend_account::AccountError> {
        // A spot_only market has no price-oracle path, so its mark freezes at
        // the first qualifying fill: equity, margin and liquidation are then
        // priced against a stale mark and leveraged losses escape both. New
        // listings must be full-collateral (`risk_params_ok`); this guards
        // pre-existing leveraged listings by refusing to trade them at all.
        // #47 C2: the same refusal covers spot listings without a strictly
        // positive two-sided band (no finite worst case to reserve).
        if let Some(p) = self.markets.get(&fill.market) {
            if !minuend_types::spot_market_tradeable(p) {
                return Err(minuend_account::AccountError::Risk);
            }
        }
        let funding_usd = self
            .markets
            .get(&fill.market)
            .filter(|p| p.funding_rate)
            .map(|p| p.usd_per_unit);
        // Stage both account transitions before writing either one back. In
        // particular, a maker-side overflow must not leave the taker applied.
        let mut taker = self
            .accounts
            .get(&fill.taker)
            .cloned()
            .unwrap_or_else(|| Account::new(fill.taker));
        taker.apply_fill(
            fill.taker_side,
            true,
            fill.price,
            fill.qty,
            fill.market,
            funding_usd,
            fill.taker_post,
            fill.taker_isolated,
        )?;
        if fill.taker == fill.maker {
            taker.apply_fill(
                fill.taker_side.opposite(),
                false,
                fill.price,
                fill.qty,
                fill.market,
                funding_usd,
                fill.maker_post,
                fill.maker_isolated,
            )?;
            self.accounts.insert(fill.taker, taker);
        } else {
            let mut maker = self
                .accounts
                .get(&fill.maker)
                .cloned()
                .unwrap_or_else(|| Account::new(fill.maker));
            maker.apply_fill(
                fill.taker_side.opposite(),
                false,
                fill.price,
                fill.qty,
                fill.market,
                funding_usd,
                fill.maker_post,
                fill.maker_isolated,
            )?;
            self.accounts.insert(fill.taker, taker);
            self.accounts.insert(fill.maker, maker);
        }
        // Taker fee: bps of notional debited from the taker's collateral and
        // credited to the insurance fund — the fund's income leg, offsetting
        // bad-debt absorption and keeper payouts. The fee flows through the
        // same Account::apply_fill path the withdrawal-proof leaf commits.
        // The rate is a per-market parameter since permissionless listing.
        // Funding-rate markets charge it on the multiplier notional: their
        // encoded price is a rate, not dollars.
        // #37-16: kind 2 (ADL transfer, not a trade) pays no taker fee —
        // the fill AA models kind 2 with fee 0, and charging here would
        // drift honest ADL collateral off the provable identity.
        if fill.taker != INSURANCE_ACCOUNT && fill.kind != 2 {
            let params = self.market_params(fill.market);
            let notional = match funding_usd {
                Some(usd) => funding_notional_usd(fill.qty, usd),
                None => notional_usd(fill.qty, fill.price),
            };
            let fee = bps(notional, params.taker_fee_bps);
            if fee > 0 {
                if let Some(a) = self.accounts.get_mut(&fill.taker) {
                    a.collateral -= fee;
                }
                self.account_mut(INSURANCE_ACCOUNT).collateral += fee;
            }
        }
        // Insurance never pays a trading loss. A party whose collateral went
        // negative in this fill claws back from the counterparty, capped at
        // what the counterparty can pay: a zero-sum transfer between the two
        // fill parties only. No snapshot equity is read — only this fill's
        // collateral deficit counts, so the amount does not depend on other
        // positions — and insurance is never debited (it is neither clawed
        // from nor clawed into). Whatever the claw cannot cover stays as
        // negative collateral on the loser and is never printed.
        for party in [fill.taker, fill.maker] {
            if party == INSURANCE_ACCOUNT {
                continue;
            }
            let counterparty = if party == fill.taker {
                fill.maker
            } else {
                fill.taker
            };
            // Insurance never funds a user's loss.
            if counterparty == INSURANCE_ACCOUNT {
                continue;
            }
            let pay = match (self.accounts.get(&party), self.accounts.get(&counterparty)) {
                (Some(p), Some(cp)) if p.collateral < 0 => {
                    (-p.collateral).min(cp.collateral.max(0))
                }
                _ => 0,
            };
            if pay > 0 {
                if let Some(a) = self.accounts.get_mut(&party) {
                    a.collateral += pay;
                }
                if let Some(a) = self.accounts.get_mut(&counterparty) {
                    a.collateral -= pay;
                }
            }
        }
        // Funding-rate markets: fills are the mark source. Guards: the
        // notional must be >= 100 USD (dust cannot move the peg) and the
        // printed rate must step from the current anchor — bootstrapping
        // from the index, then ≤10% of the old rate (min 1 bps) per fill.
        // PILOT: the funding-rate mark/peg block (fresh_external_index, settle_funding_peg)
        // is not ported; the pilot never lists a funding-rate market (place rejects it first).
        if funding_usd.is_some() {
            return Ok(());
        }
        // Mark oracle guards: fills move the mark only for markets where NO
        // bonded reporter has spoken yet (oracles are authoritative once
        // present), the notional magnitude is >= 100 USD, and the move is within ±10%
        // of the previous mark (first qualifying fill sets unconditionally).
        if notional_usd(fill.qty, fill.price).abs() >= 100 * USD_SCALE as i128
            && !self
                .oracle_reports
                .keys()
                .any(|(m, o)| *m == fill.market && self.oracle_bonds.contains_key(o))
        {
            // Unoracled freeze: the first qualifying fill sets the mark
            // unconditionally, but once a non-zero mark exists only a real
            // reporter index (`last_index`) may keep it moving — otherwise
            // every trade walks the mark ±10% with no external anchor.
            let has_index = self
                .last_index
                .get(&fill.market)
                .map(|i| *i != 0)
                .unwrap_or(false);
            let existing = self.marks.get(&fill.market).copied().unwrap_or(0);
            if existing == 0 || has_index {
                let capped = match existing {
                    old if old != 0 => {
                        let dev = (fill.price as i128 - old as i128).abs();
                        if dev <= (old as i128).abs() / 10 {
                            fill.price
                        } else {
                            old
                        }
                    }
                    _ => fill.price,
                };
                // R9-H2: a mark at / above MARK_CAP is never written.
                if capped.unsigned_abs() < minuend_types::MARK_CAP.unsigned_abs() {
                    self.marks.insert(fill.market, capped);
                }
            }
        }
        Ok(())
    }

    pub fn market_params(&self, m: MarketId) -> MarketParams {
        self.markets[&m]
    }
}
