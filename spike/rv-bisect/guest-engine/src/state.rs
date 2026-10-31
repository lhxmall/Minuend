//! Subset of minuend-state::ChainState @ fix/47-all 20326c0 (crates/minuend-state/src/lib.rs):
//! only the fields the place/cancel/deposit paths read or write. Methods below are copied
//! verbatim except where marked `PILOT:`.
use crate::account::Account;
use crate::book::{BookJournal, OrderBook};
use crate::types::{
    bps, notional_usd, funding_notional_usd, funding_rate_bps, AccountId, ExternalSample,
    FundingSourceKind, Height, MarketId, MarketParams, OracleConfig, Price, ReportSample, Seq,
    TwapSample, Withdrawal, FUNDING_EXTERNAL_MAX_STALENESS, FUNDING_TWAP_MIN_SAMPLES,
    FUNDING_TWAP_WINDOW, INSURANCE_ACCOUNT, USD_SCALE,
};
use crate::{Fill, SelfTrade};
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
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

/// PILOT (loop round 4, R3-O1 fix): the account map behind a type that only hands out
/// *guarded* mutable access. `Deref` gives every read-only `BTreeMap` method (`get`, `iter`,
/// `contains_key`, `values`, `len`, ...), so upstream read code compiles unchanged; the
/// inherent `get_mut` / `insert` / `remove` shadow the map's and keep three derived indexes
/// current on every write: `oi_long` (running sum of positive position qty per market, the
/// first term of `funding_open_interest`), `holders` (accounts with a position per market, in
/// AccountId order = upstream's `accounts.iter().filter(has position)` order) and `dirty`
/// (MNWIT1 keys touched since the last witness commit). `BTreeMap::get_mut`, `entry`,
/// `iter_mut`, `values_mut` are unreachable (no `DerefMut`), so a future path that edits
/// positions in place cannot desync them -- the compiler refuses it.
#[derive(Clone, Debug, Default)]
pub struct Accounts {
    map: BTreeMap<AccountId, Account>,
    // loop round 5 (R4-L4): the derived indexes are private; reads go through `oi_long_of` /
    // `holders_of`, the only writers are the guarded paths below + `mark_dirty` / `drain_dirty`
    oi_long: BTreeMap<MarketId, u128>,
    holders: BTreeMap<MarketId, BTreeSet<AccountId>>,
    dirty: BTreeSet<AccountId>,
}
impl core::ops::Deref for Accounts {
    type Target = BTreeMap<AccountId, Account>;
    fn deref(&self) -> &Self::Target {
        &self.map
    }
}
impl<'a> IntoIterator for &'a Accounts {
    type Item = (&'a AccountId, &'a Account);
    type IntoIter = alloc::collections::btree_map::Iter<'a, AccountId, Account>;
    fn into_iter(self) -> Self::IntoIter {
        self.map.iter()
    }
}
fn idx_adj(
    oi: &mut BTreeMap<MarketId, u128>,
    holders: &mut BTreeMap<MarketId, BTreeSet<AccountId>>,
    id: AccountId,
    pos: &[(MarketId, i64)],
    add: bool,
) {
    for (m, q) in pos {
        if *q > 0 {
            let e = oi.entry(*m).or_insert(0);
            if add {
                *e += *q as u128;
            } else {
                *e -= *q as u128;
            }
            if *e == 0 {
                oi.remove(m);
            }
        }
        if add {
            holders.entry(*m).or_default().insert(id);
        } else if let Some(h) = holders.get_mut(m) {
            h.remove(&id);
            if h.is_empty() {
                holders.remove(m);
            }
        }
    }
}
fn pos_of(a: &Account) -> Vec<(MarketId, i64)> {
    a.positions.iter().map(|(m, p)| (*m, p.qty)).collect()
}
impl Accounts {
    pub fn insert(&mut self, id: AccountId, a: Account) -> Option<Account> {
        self.dirty.insert(id);
        let new = pos_of(&a);
        let old = self.map.insert(id, a);
        // remove the old entry's contribution BEFORE adding the new one (holders is a set)
        if let Some(o) = &old {
            idx_adj(&mut self.oi_long, &mut self.holders, id, &pos_of(o), false);
        }
        idx_adj(&mut self.oi_long, &mut self.holders, id, &new, true);
        old
    }
    pub fn remove(&mut self, id: &AccountId) -> Option<Account> {
        let old = self.map.remove(id);
        if let Some(o) = &old {
            self.dirty.insert(*id);
            idx_adj(&mut self.oi_long, &mut self.holders, *id, &pos_of(o), false);
        }
        old
    }
    pub fn get_mut(&mut self, id: &AccountId) -> Option<AcctMut<'_>> {
        let Accounts { map, oi_long, holders, dirty } = self;
        let a = map.get_mut(id)?;
        dirty.insert(*id);
        let before = pos_of(a);
        Some(AcctMut { a, oi: oi_long, holders, before })
    }
    /// upstream `accounts.entry(id).or_insert_with(|| Account::new(id))`, guarded
    pub fn get_or_new(&mut self, id: AccountId) -> AcctMut<'_> {
        if !self.map.contains_key(&id) {
            self.map.insert(id, Account::new(id));
        }
        self.get_mut(&id).unwrap()
    }
    /// full recomputation of the derived indexes == the running ones (host tests)
    pub fn idx_ok(&self) -> bool {
        let mut oi = BTreeMap::new();
        let mut h = BTreeMap::new();
        for (id, a) in &self.map {
            idx_adj(&mut oi, &mut h, *id, &pos_of(a), true);
        }
        oi == self.oi_long && h == self.holders
    }
    /// running sum of positive position qty in `m` (first term of `funding_open_interest`)
    pub fn oi_long_of(&self, m: MarketId) -> u128 {
        self.oi_long.get(&m).copied().unwrap_or(0)
    }
    /// mark an account's MNWIT1 key dirty (a superset is harmless: an unchanged leaf rehashes
    /// to the same value)
    pub fn mark_dirty(&mut self, id: AccountId) {
        self.dirty.insert(id);
    }
    /// move the dirty account keys into `out` (witness commit)
    pub fn drain_dirty(&mut self, out: &mut BTreeSet<AccountId>) {
        out.append(&mut self.dirty);
    }
    /// accounts holding a position in `m`, ascending AccountId (empty iterator if none)
    pub fn holders_of(&self, m: MarketId) -> impl Iterator<Item = AccountId> + '_ {
        self.holders.get(&m).into_iter().flat_map(|s| s.iter().copied())
    }
}
/// Guarded `&mut Account`: on drop, re-indexes the account's positions (OI + holders).
pub struct AcctMut<'a> {
    a: &'a mut Account,
    oi: &'a mut BTreeMap<MarketId, u128>,
    holders: &'a mut BTreeMap<MarketId, BTreeSet<AccountId>>,
    before: Vec<(MarketId, i64)>,
}
impl core::ops::Deref for AcctMut<'_> {
    type Target = Account;
    fn deref(&self) -> &Account {
        self.a
    }
}
impl core::ops::DerefMut for AcctMut<'_> {
    fn deref_mut(&mut self) -> &mut Account {
        self.a
    }
}
impl Drop for AcctMut<'_> {
    fn drop(&mut self) {
        let after = pos_of(self.a);
        if after != self.before {
            let id = self.a.id;
            idx_adj(self.oi, self.holders, id, &self.before, false);
            idx_adj(self.oi, self.holders, id, &after, true);
        }
    }
}

/// Verbatim minuend-state `CommitEntry` (loop round 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitEntry {
    pub account: AccountId,
    pub commit_unit: [u8; 32],
    pub commit_height: Height,
    pub ttl_height: Height,
    pub revealed: bool,
}

/// Verbatim minuend-state `Proposal` (loop round 6; `voted` HashSet -> BTreeSet).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub creator: AccountId,
    pub market: MarketId,
    pub key: crate::types::ParamKey,
    pub value: u64,
    pub created_seq: Seq,
    pub deadline_seq: Seq,
    pub supply_at_create: u128,
    pub yes: u128,
    pub no: u128,
    pub voted: alloc::collections::BTreeSet<AccountId>,
    pub weight_snapshot: BTreeMap<AccountId, u128>,
}

#[derive(Clone, Debug, Default)]
pub struct ChainState {
    /// PILOT: the batch height. Upstream sets it per batch; the pilot sets it only through the
    /// test-fixture op `SetHeight` (kind 10, non-`prod` builds), the real-engine harness writes
    /// `eng.state.height` at the same unit.
    pub height: Height,
    pub seq: Seq,
    /// PILOT (loop round 4): guarded map, see [`Accounts`].
    pub accounts: Accounts,
    pub markets: BTreeMap<MarketId, MarketParams>,
    pub books: BTreeMap<MarketId, OrderBook>,
    pub marks: BTreeMap<MarketId, Price>,
    pub oracle_reports: BTreeMap<(MarketId, AccountId), Price>,
    pub oracle_bonds: BTreeMap<AccountId, u128>,
    /// loop round 5 (R4-M3): PERP ledger + oracle unbonding / slash state (upstream fields).
    /// A PERP balance gives its id an `acct:` leaf even without an `accounts` entry (upstream
    /// R8-C3); every write marks the id's MNWIT1 key dirty.
    pub perp_balances: BTreeMap<AccountId, u128>,
    pub perp_supply: u128,
    pub perp_burned: u128,
    pub oracle_unbonding: BTreeMap<AccountId, Height>,
    pub oracle_slash_nonce: u64,
    pub last_index: BTreeMap<MarketId, Price>,
    pub withdrawals: BTreeMap<(AccountId, u64), Withdrawal>,
    pub withdrawn_total: BTreeMap<AccountId, i128>,
    pub oracle_configs: BTreeMap<MarketId, OracleConfig>,
    pub oracle_report_history: BTreeMap<(MarketId, AccountId), VecDeque<ReportSample>>,
    pub oracle_twap: BTreeMap<MarketId, VecDeque<TwapSample>>,
    pub funding_twap: BTreeMap<MarketId, VecDeque<TwapSample>>,
    pub funding_index_twap: BTreeMap<MarketId, Price>,
    pub funding_source: FundingSourceKind,
    pub external_price_ring: BTreeMap<MarketId, VecDeque<ExternalSample>>,
    pub external_sources: BTreeSet<AccountId>,
    pub last_funding_height: BTreeMap<MarketId, Height>,
    /// upstream: HashMap<AccountId, u64>
    pub seen_client_seq: BTreeMap<AccountId, u64>,
    /// loop round 6 (R4-M3 rest): governance + commit-reveal state (upstream fields; HashMap /
    /// HashSet -> BTree). `next_market_id` / `next_proposal_id` start at 2 / 1 (`genesis`).
    pub next_market_id: u32,
    pub proposals: BTreeMap<u64, Proposal>,
    pub next_proposal_id: u64,
    pub seen_gov_nonces: BTreeMap<AccountId, u64>,
    pub commits: BTreeMap<[u8; 32], CommitEntry>,
    /// PILOT (MNWIT1 proposal): order / market keys touched since the last witness commit
    /// (account keys: `accounts.dirty`).
    pub wit_dirty: crate::wit::WitDirty,
}

impl ChainState {
    /// PILOT: `accounts.insert` (kept for the S1b call sites).
    pub fn put_account(&mut self, id: AccountId, a: Account) {
        self.accounts.insert(id, a);
    }
    /// PILOT: `accounts.remove`.
    pub fn del_account(&mut self, id: &AccountId) {
        self.accounts.remove(id);
    }
    /// loop round 5 (R4-M3): `perp_balances.insert`, marking the id's acct: key dirty
    pub fn set_perp(&mut self, id: AccountId, v: u128) {
        self.perp_balances.insert(id, v);
        self.accounts.mark_dirty(id);
    }
    /// Verbatim minuend-state `apply_stake` (StateError -> RejectReason as exec `map_state`).
    pub fn apply_stake(&mut self, account: AccountId) -> Result<(), crate::engine::RejectReason> {
        use crate::engine::RejectReason as R;
        if self.oracle_bonds.contains_key(&account) {
            return Err(R::AlreadyBonded);
        }
        if self.oracle_unbonding.contains_key(&account) {
            return Err(R::Unbonding);
        }
        let bal = self.perp_balances.get(&account).copied().unwrap_or(0);
        if bal < crate::types::ORACLE_BOND_PERP {
            return Err(R::Insufficient);
        }
        self.set_perp(account, bal - crate::types::ORACLE_BOND_PERP);
        self.oracle_bonds.insert(account, crate::types::ORACLE_BOND_PERP);
        Ok(())
    }
    /// Verbatim `apply_unstake`.
    pub fn apply_unstake(&mut self, account: AccountId) -> Result<(), crate::engine::RejectReason> {
        use crate::engine::RejectReason as R;
        if !self.oracle_bonds.contains_key(&account) {
            return Err(R::NotBonded);
        }
        if self.oracle_unbonding.contains_key(&account) {
            return Err(R::Unbonding);
        }
        let unlock = self.height.saturating_add(crate::types::ORACLE_UNBOND_HEIGHTS);
        self.oracle_unbonding.insert(account, unlock);
        Ok(())
    }
    /// Verbatim `apply_slash`.
    pub fn apply_slash(&mut self, challenger: AccountId, target: AccountId, market: MarketId) -> Result<(), crate::engine::RejectReason> {
        use crate::engine::RejectReason as R;
        if !self.markets.contains_key(&market) {
            return Err(R::NotFound);
        }
        if !self.oracle_bonds.contains_key(&target) {
            return Err(R::NotBonded);
        }
        let twap = self.compute_twap(market).or_else(|| self.compute_funding_twap(market)).ok_or(R::SlashNotEligible)?;
        if twap == 0 {
            return Err(R::SlashNotEligible);
        }
        let hist = self.oracle_report_history.get(&(market, target)).ok_or(R::SlashNotEligible)?;
        if hist.len() < crate::types::SLASH_TWAP_STREAK as usize {
            return Err(R::SlashNotEligible);
        }
        let n = crate::types::SLASH_TWAP_STREAK as usize;
        let start = hist.len() - n;
        let deviation_bps = self.oracle_config(market).deviation_bps;
        let latest_height = hist.back().map(|s| s.height).unwrap_or(0);
        if self.height.saturating_sub(latest_height) > 256 {
            return Err(R::SlashNotEligible);
        }
        for i in 0..n {
            let idx = start + i;
            let sample = hist[idx];
            if i > 0 {
                let prev = hist[idx - 1];
                if sample.height != prev.height + 1 {
                    return Err(R::SlashNotEligible);
                }
            }
            let dev = ((sample.price as i128 - twap as i128).abs() * 10_000 / (twap as i128).abs()) as u64;
            if dev < deviation_bps {
                return Err(R::SlashNotEligible);
            }
        }
        let bond = self.oracle_bonds.remove(&target).unwrap_or(crate::types::ORACLE_BOND_PERP);
        self.oracle_unbonding.remove(&target);
        self.oracle_reports.remove(&(market, target));
        self.oracle_report_history.remove(&(market, target));
        let burn = bond * (crate::types::SLASH_REWARD_BPS as u128) / 10_000;
        let reward = bond.saturating_sub(burn);
        self.perp_burned = self.perp_burned.saturating_add(burn);
        if self.perp_supply >= burn {
            self.perp_supply = self.perp_supply.saturating_sub(burn);
        }
        let challenger_bal = self.perp_balances.get(&challenger).copied().unwrap_or(0);
        self.set_perp(challenger, challenger_bal.saturating_add(reward));
        self.oracle_slash_nonce = self.oracle_slash_nonce.wrapping_add(1);
        Ok(())
    }
    /// Verbatim `prune_commits` (batch-commit hook, loop round 6).
    pub fn prune_commits(&mut self, min_height: Height) {
        self.commits.retain(|_, e| e.ttl_height >= min_height);
    }
    /// Verbatim `prune_oracle_unbonding` (batch-commit hook).
    pub fn prune_oracle_unbonding(&mut self, current_height: Height) {
        let mut to_release = Vec::new();
        for (acct, unlock) in &self.oracle_unbonding {
            if *unlock <= current_height {
                to_release.push(*acct);
            }
        }
        for acct in to_release {
            self.oracle_unbonding.remove(&acct);
            if let Some(bond) = self.oracle_bonds.remove(&acct) {
                let bal = self.perp_balances.get(&acct).copied().unwrap_or(0);
                self.set_perp(acct, bal.saturating_add(bond));
                self.oracle_reports.retain(|(_, o), _| *o != acct);
                self.oracle_report_history.retain(|(_, o), _| *o != acct);
            }
        }
    }
    /// PILOT: running indexes == full recomputation (host tests).
    pub fn oi_ok(&self) -> bool {
        self.accounts.idx_ok()
    }
    /// PILOT (MNWIT1): drain every dirty key (orders / markets + guarded account writes).
    pub fn take_dirty(&mut self) -> crate::wit::WitDirty {
        let mut d = core::mem::take(&mut self.wit_dirty);
        self.accounts.drain_dirty(&mut d.accounts);
        d
    }
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
            // PILOT (loop round 4): holders index (same set, same AccountId order).
            let holders: Vec<AccountId> = self.accounts.holders_of(fill.market).collect();
            for id in holders {
                self.journal_account(j, id);
            }
        }
        self.apply_fill_pair(fill)
    }

    /// PILOT (MNWIT1): every key a journal recorded is a dirty witness key (superset of
    /// what the unit changed; unchanged leaves rehash to the same value and cost no path).
    pub fn note_journal(&mut self, j: &StateJournal) {
        for (id, _) in &j.accounts {
            self.accounts.mark_dirty(*id);
        }
        for (m, _, _) in &j.markets {
            self.wit_dirty.markets.insert(*m);
        }
        if let Some((m, _, bj)) = &j.book {
            for id in bj.touched_orders() {
                self.wit_dirty.orders.insert((*m, id));
            }
        }
    }

    /// Restore every pre-image recorded in `j`.
    pub fn rollback(&mut self, j: StateJournal) {
        self.note_journal(&j); // PILOT (MNWIT1)
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
                    self.put_account(id, a); // PILOT (S1b)
                }
                None => {
                    self.del_account(&id); // PILOT (S1b)
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

    /// PILOT (loop round 4): guarded (`AcctMut` keeps OI / holders / dirty current).
    pub fn account_mut(&mut self, id: AccountId) -> crate::state::AcctMut<'_> {
        self.accounts.get_or_new(id)
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
            self.put_account(fill.taker, taker); // PILOT (S1b)
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
            self.put_account(fill.taker, taker); // PILOT (S1b)
            self.put_account(fill.maker, maker);
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
                if let Some(mut a) = self.accounts.get_mut(&fill.taker) {
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
                if let Some(mut a) = self.accounts.get_mut(&party) {
                    a.collateral += pay;
                }
                if let Some(mut a) = self.accounts.get_mut(&counterparty) {
                    a.collateral -= pay;
                }
            }
        }
        // Funding-rate markets: fills are the mark source. Guards: the
        // notional must be >= 100 USD (dust cannot move the peg) and the
        // printed rate must step from the current anchor — bootstrapping
        // from the index, then ≤10% of the old rate (min 1 bps) per fill.
        if let Some(usd) = funding_usd {
            let cap = self
                .markets
                .get(&fill.market)
                .map(|p| p.funding_cap_bps)
                .unwrap_or(0) as i64;
            // The $100 gate prices the fill at the multiplier notional: the
            // encoded rate price carries no dollar scale on this market.
            let notional_ok = funding_notional_usd(fill.qty, usd).abs() >= 100 * USD_SCALE as i128;
            if !notional_ok {
                return Ok(());
            }
            let old = self.marks.get(&fill.market).copied().unwrap_or(0);
            let step_ok = if old != 0 {
                let step = (funding_rate_bps(old).unsigned_abs() / 10).max(1) as i64;
                (funding_rate_bps(fill.price) - funding_rate_bps(old)).abs() <= step
            } else {
                // Bootstrap: anchor the first print to the fresh external
                // index, gap capped at this market's peg cap.
                match self.fresh_external_index(fill.market) {
                    Some(index) => {
                        (funding_rate_bps(fill.price) - funding_rate_bps(index)).abs() <= cap
                    }
                    _ => false,
                }
            };
            // R9-H2: a print at / above MARK_CAP never becomes the mark.
            if step_ok && fill.price.unsigned_abs() < minuend_types::MARK_CAP.unsigned_abs() {
                self.marks.insert(fill.market, fill.price);
                // The mark just moved: re-evaluate the peg so its interval
                // clock arms as soon as index + mark + fresh reports exist.
                self.settle_funding_peg(fill.market);
            }
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
    // ---- PILOT (loop round 4): oracle / TWAP / funding, copied verbatim from
    // minuend-state/src/lib.rs @ 20326c0 (oracle_config .. effective_funding_index,
    // apply_report .. transfer_funding_rate); edits marked PILOT. ----
    // -----------------------------------------------------------------------
    // Oracle config / TWAP helpers
    pub fn oracle_config(&self, market: MarketId) -> OracleConfig {
        self.oracle_configs
            .get(&market)
            .copied()
            .unwrap_or_default()
    }

    fn record_twap_sample(&mut self, market: MarketId, median: Price, seq: Seq) {
        let cfg = self.oracle_config(market);
        let window_len = cfg.twap_window as usize;
        // Cap window_len to max to avoid unbounded growth if governance mis-sets
        let cap = window_len
            .min(minuend_types::ORACLE_TWAP_MAX as usize)
            .max(2);
        let q = self.oracle_twap.entry(market).or_default();
        if q.back().map(|s| s.height == self.height).unwrap_or(false) {
            // Same height: overwrite median if different (multiple reporters same batch)
            if q.back().unwrap().median != median {
                let back = q.back_mut().unwrap();
                back.median = median;
                back.seq = seq;
            } else {
                return;
            }
        } else {
            q.push_back(TwapSample {
                seq,
                height: self.height,
                median,
            });
            while q.len() > cap {
                q.pop_front();
            }
        }
        // Mirror into funding_twap and cache funding_index_twap for effective_funding_index.
        // Doc 06 §2.4: dedup same-height-same-median so multiple reporters in one batch
        // don't double-count; a different median at the same height overwrites (last wins).
        let fq = self.funding_twap.entry(market).or_default();
        if fq.back().map(|s| s.height == self.height).unwrap_or(false) {
            if fq.back().unwrap().median != median {
                let back = fq.back_mut().unwrap();
                back.median = median;
                back.seq = seq;
            }
        } else {
            fq.push_back(TwapSample {
                seq,
                height: self.height,
                median,
            });
            while fq.len() > FUNDING_TWAP_WINDOW as usize {
                fq.pop_front();
            }
        }
        if let Some(twap) = self.compute_twap(market) {
            self.funding_index_twap.insert(market, twap);
        }
        if let Some(ftwap) = self.compute_funding_twap(market) {
            self.funding_index_twap.insert(market, ftwap);
        }
    }

    /// Record an external keeper tick (doc 06 §2.6): allowlist + live-market +
    /// positive-price gated by the caller; ring capped at the funding window.
    pub fn apply_external_price(
        &mut self,
        _source: AccountId,
        market: MarketId,
        price: Price,
        source_id: u8,
        seq: Seq,
    ) {
        let q = self.external_price_ring.entry(market).or_default();
        q.push_back(ExternalSample {
            seq,
            height: self.height,
            price,
            source_id,
        });
        while q.len() > FUNDING_TWAP_WINDOW as usize {
            q.pop_front();
        }
    }

    /// Latest external ring sample that is still fresh at the current
    /// height and non-zero. Used as the peg payment index — a dead feed
    /// means the window pays nothing, never a stale or zero index.
    pub fn fresh_external_index(&self, market: MarketId) -> Option<Price> {
        let q = self.external_price_ring.get(&market)?;
        q.iter()
            .rev()
            .find(|s| s.height + FUNDING_EXTERNAL_MAX_STALENESS > self.height && s.price != 0)
            .map(|s| s.price)
    }

    /// TWAP over the external keeper ring (doc 06 §2.6 rule 2): requires
    /// MIN_SAMPLES and freshness within FUNDING_EXTERNAL_MAX_STALENESS so a
    /// dead feed falls back instead of freezing funding.
    pub fn external_twap(&self, market: MarketId) -> Option<Price> {
        let q = self.external_price_ring.get(&market)?;
        if q.len() < FUNDING_TWAP_MIN_SAMPLES {
            return None;
        }
        let last = q.back()?;
        if last.height + FUNDING_EXTERNAL_MAX_STALENESS <= self.height {
            return None;
        }
        Self::mean_price(q.iter().map(|s| s.price), q.len())
    }


    /// Signed mean over at most `FUNDING_TWAP_WINDOW` `i64` samples. The
    /// `i128` sum cannot overflow (window cap 1800); `try_from` is only the
    /// backstop. Returns `None` on `n == 0` or an impossible conversion —
    /// never panics, never substitutes `0`.
    fn mean_price(samples: impl Iterator<Item = i64>, n: usize) -> Option<Price> {
        if n == 0 {
            return None;
        }
        let sum: i128 = samples.map(i128::from).sum();
        i64::try_from(sum / n as i128).ok()
    }

    /// Mark must stay within ±10% of the funding index (the external
    /// anchor): anchor 0 means no index exists, so nothing to anchor to.
    fn within_band(candidate: Price, anchor: Price) -> bool {
        anchor == 0
            || (i128::from(candidate) - i128::from(anchor)).abs() <= i128::from(anchor).abs() / 10
    }

    pub fn compute_twap(&self, market: MarketId) -> Option<Price> {
        let q = self.oracle_twap.get(&market)?;
        if q.len() < 2 {
            return None;
        }
        Self::mean_price(q.iter().map(|s| s.median), q.len())
    }

    pub fn compute_funding_twap(&self, market: MarketId) -> Option<Price> {
        let q = self.funding_twap.get(&market)?;
        if q.len() < 2 {
            return None;
        }
        Self::mean_price(q.iter().map(|s| s.median), q.len())
    }
    pub fn effective_funding_index(&self, market: MarketId, median: Price) -> Price {
        match self.funding_source {
            FundingSourceKind::BondedMedianTwap => self
                .funding_index_twap
                .get(&market)
                .copied()
                .unwrap_or(median),
            FundingSourceKind::AggregatedExternal => {
                // Doc 06 §2.6 rule 1: external TWAP overrides when fresh and
                // populated; else fall back to bonded-median TWAP, then the
                // instant median — funding never freezes.
                self.external_twap(market).unwrap_or_else(|| {
                    self.funding_index_twap
                        .get(&market)
                        .copied()
                        .unwrap_or(median)
                })
            }
        }
    }
    pub fn prune_oracle_twap(&mut self, _min_height: Height) {
        // TWAP is bounded by VecDeque length cap, not height expiry; no-op for v1
    }

    /// Apply a bonded oracle's report for `market` and recompute the effective
    /// mark as the median of all current bonded reporters, subject to the
    /// ±10% deviation cap vs the previous mark (the first report for a market
    /// sets the mark unconditionally). Fills no longer move the mark for
    /// markets where any bonded reporter has spoken. Zero prices and unbonded
    /// reporters are ignored defensively — the exec layer pre-validates bonds.
    pub fn apply_report(
        &mut self,
        oracle: AccountId,
        market: MarketId,
        price: Price,
        caller_seq: Seq,
    ) -> Result<(), ()> {
        if price == 0 || !self.oracle_bonds.contains_key(&oracle) {
            return Ok(());
        }
        self.oracle_reports.insert((market, oracle), price);
        // Record per-reporter history for slash streak detection (depth 8)
        {
            let q = self
                .oracle_report_history
                .entry((market, oracle))
                .or_default();
            // Push new sample; dedup same height by overwriting last
            if q.back().map(|s| s.height == self.height).unwrap_or(false) {
                if let Some(back) = q.back_mut() {
                    back.price = price;
                    back.seq = self.seq;
                }
            } else {
                q.push_back(ReportSample {
                    height: self.height,
                    price,
                    seq: self.seq,
                });
                while q.len() > 8 {
                    q.pop_front();
                }
            }
        }
        // Median over reporters that hold BOTH a bond and a current report
        // for this market. sorted[(len-1)/2] is the exact middle when the
        // count is odd and the smaller middle when even — deterministic in
        // both cases, no rounding drift.
        let mut prices: Vec<Price> = self
            .oracle_reports
            .iter()
            .filter(|((m, o), _)| *m == market && self.oracle_bonds.contains_key(o))
            .map(|(_, p)| *p)
            .collect();
        if prices.is_empty() {
            return Ok(());
        }
        prices.sort();
        let median = prices[(prices.len() - 1) / 2];
        // Funding index: unclamped median, so the premium reflects true
        // reporter consensus even while the spot mark lags behind the cap.
        self.last_index.insert(market, median);
        // Funding-rate markets: the oracle writes the index only. The mark
        // comes from fills, so the ±10% band and the premium block are
        // skipped; funding settles as the peg instead. The TWAP ring is
        // still recorded so slash sees the reporter's sample.
        if self
            .markets
            .get(&market)
            .map(|p| p.funding_rate)
            .unwrap_or(false)
        {
            self.record_twap_sample(market, median, caller_seq);
            self.settle_funding_peg(market);
            return Ok(());
        }
        // Signed marks: the ±10% band is measured on the old mark's
        // magnitude, so a negative mark can still move by capped steps.
        let mut capped = match self.marks.get(&market) {
            Some(&old) if old != 0 => {
                let dev = (median as i128 - old as i128).abs();
                if dev <= (old as i128).abs() / 10 {
                    median
                } else {
                    old
                }
            }
            _ => median,
        };
        // Index band: a median outside ±10% of the funding index must not
        // become the mark. Keep the previous mark if one exists (do not
        // walk a legacy out-of-band mark toward the index); with no mark,
        // bootstrap directly to the index rather than the out-of-band
        // median.
        let index = self.effective_funding_index(market, median);
        if index != 0 && !Self::within_band(capped, index) {
            capped = self
                .marks
                .get(&market)
                .copied()
                .filter(|p| *p != 0)
                .unwrap_or(index);
        }
        // R9-H2: a mark at / above MARK_CAP is never written.
        if capped.unsigned_abs() < minuend_types::MARK_CAP.unsigned_abs() {
            self.marks.insert(market, capped);
        }
        // Record TWAP sample after median update
        self.record_twap_sample(market, median, caller_seq);
        // Funding: once at least two valid reports exist, every report tick
        // settles peer-to-peer funding.
        // premium_bps = (spot − funding_index)/funding_index, clamped to ±FUNDING_CAP_BPS.
        // funding_index = twap when height >= activation else median.
        // notional = signed_notional_usd(qty, funding_index)
        if prices.len() >= 2 {
            let funding_index = self.effective_funding_index(market, median);
            let index = funding_index as i128;
            let spot = capped as i128;
            if index != 0 {
                // Pay at most once per height: reporters report in batch at
                // the same height, and a non-zero premium must not transfer
                // again for every report tick at that height.
                if self.last_funding_height.get(&market) != Some(&self.height) {
                    let diff_bps = ((spot - index) * 10_000 / index).clamp(
                        -(minuend_types::FUNDING_CAP_BPS as i128),
                        minuend_types::FUNDING_CAP_BPS as i128,
                    );
                    if diff_bps != 0 {
                        self.transfer_funding(market, funding_index, diff_bps);
                    }
                    // Record consideration even when diff_bps == 0: a later
                    // report at this height must not pay either.
                    self.last_funding_height.insert(market, self.height);
                }
            }
        }
        Ok(())
    }

    /// Two-phase peer-to-peer funding transfer: Phase 1 collects signed
    /// payments in ascending AccountId order, Phase 2a debits payers clamped
    /// at non-negative collateral into a budget, Phase 2b credits receivers
    /// until the budget is spent. Conservation is exact; insurance
    /// participates like any account.
    fn transfer_funding(&mut self, market: MarketId, funding_index: Price, diff_bps: i128) {
        // Phase 1: signed payments in ascending AccountId order.
        // PILOT (loop round 4): holders index instead of every account (same ids, same order).
        let payments: Vec<(AccountId, i128)> = self
            .accounts
            .holders_of(market)
            .filter_map(|id| {
                let a = &self.accounts[&id];
                a.positions.get(&market).map(|pos| {
                    let id = &id;
                    (
                        *id,
                        minuend_types::signed_notional_usd(pos.qty, funding_index) * diff_bps
                            / 10_000,
                    )
                })
            })
            .filter(|(_, p)| *p != 0)
            .collect();
        // Phase 2a: debit payers, clamped at non-negative collateral.
        let mut budget: i128 = 0;
        for (id, payment) in &payments {
            if *payment <= 0 {
                continue;
            }
            if let Some(mut a) = self.accounts.get_mut(id) {
                let debit = (*payment).min(a.collateral.max(0));
                a.collateral -= debit;
                budget += debit;
            }
        }
        // Phase 2b: credit receivers until the budget is spent.
        for (id, payment) in &payments {
            if budget == 0 {
                break;
            }
            if *payment >= 0 {
                continue;
            }
            let want = -*payment;
            let credit = want.min(budget);
            if let Some(mut a) = self.accounts.get_mut(id) {
                a.collateral += credit;
            }
            budget -= credit;
        }
    }

    /// Funding-rate peg settlement for a `funding_rate` market:
    /// - needs a non-zero fill-written mark, else no-op (clock untouched);
    /// - the first observation arms `last_funding_height` and pays nothing
    ///   (no reporters and no external print required to arm);
    /// - windows at least `FUNDING_PEG_INTERVAL_HEIGHTS` after the armed
    ///   height always re-arm; payment happens only when a fresh external
    ///   print exists — no fresh print means that window pays nothing;
    /// - diff is `mark rate − index rate`, clamped to the market's
    ///   `funding_cap_bps`, then paid rate-cash peer-to-peer.
    pub fn settle_funding_peg(&mut self, market: MarketId) {
        let mark = match self.marks.get(&market).copied() {
            Some(m) if m != 0 => m,
            _ => return,
        };
        let height = self.height;
        match self.last_funding_height.get(&market).copied() {
            // Not armed: arm the interval clock, pay nothing.
            None => {
                self.last_funding_height.insert(market, height);
                return;
            }
            Some(last) if height < last + minuend_types::FUNDING_PEG_INTERVAL_HEIGHTS => {
                return;
            }
            _ => {}
        }
        // Window elapsed: re-arm unconditionally, even with no fresh feed.
        self.last_funding_height.insert(market, height);
        let index = match self.fresh_external_index(market) {
            Some(i) => i,
            None => return,
        };
        let cap = self
            .markets
            .get(&market)
            .map(|p| p.funding_cap_bps)
            .unwrap_or(0) as i64;
        if cap == 0 {
            return;
        }
        let diff_bps = (funding_rate_bps(mark) - funding_rate_bps(index)).clamp(-cap, cap);
        if diff_bps != 0 {
            self.transfer_funding_rate(market, diff_bps);
        }
    }

    /// Rate-cash sibling of `transfer_funding`: same two-phase debit/credit
    /// conservation, but each payment is `funding_rate_cash(qty, diff_bps,
    /// usd_per_unit)` of the market's listing-time multiplier.
    fn transfer_funding_rate(&mut self, market: MarketId, diff_bps: i64) {
        let usd = match self.markets.get(&market) {
            Some(p) if p.funding_rate => p.usd_per_unit,
            _ => return,
        };
        // Phase 1: signed payments in ascending AccountId order.
        // PILOT (loop round 4): holders index instead of every account (same ids, same order).
        let payments: Vec<(AccountId, i128)> = self
            .accounts
            .holders_of(market)
            .filter_map(|id| {
                let a = &self.accounts[&id];
                a.positions.get(&market).map(|pos| {
                    let id = &id;
                    (
                        *id,
                        minuend_types::funding_rate_cash(pos.qty, diff_bps, usd),
                    )
                })
            })
            .filter(|(_, p)| *p != 0)
            .collect();
        // Phase 2a: debit payers, clamped at non-negative collateral.
        let mut budget: i128 = 0;
        for (id, payment) in &payments {
            if *payment <= 0 {
                continue;
            }
            if let Some(mut a) = self.accounts.get_mut(id) {
                let debit = (*payment).min(a.collateral.max(0));
                a.collateral -= debit;
                budget += debit;
            }
        }
        // Phase 2b: credit receivers until the budget is spent.
        for (id, payment) in &payments {
            if budget == 0 {
                break;
            }
            if *payment >= 0 {
                continue;
            }
            let want = -*payment;
            let credit = want.min(budget);
            if let Some(mut a) = self.accounts.get_mut(id) {
                a.collateral += credit;
            }
            budget -= credit;
        }
    }

    // -------------------------------------------------------------------
}
