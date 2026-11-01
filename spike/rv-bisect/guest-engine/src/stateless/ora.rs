//! Loop round 20: the stateless ORACLE (design docs/rv-stateless-guest.md §12.1, round-20 implementation).
//!
//! MNWIT-S leaves (pure functions of the session state, absent = the session's default):
//!   ostk:<acct>     :<bond or ->:<unlock or ->                 oracle_bonds / oracle_unbonding of one account
//!   orm:<acct>      :<n>:<sha256(markets u32 LE ascending)>     markets where the account has a report or a history
//!   orep:<m>        :<n>:<sha256(entries by oracle)>            the market's reporters: one entry per oracle with a
//!                                                               report or a history in m = (oracle, has report, price,
//!                                                               bonded now, history length, sha256(history samples));
//!                                                               `bonded` is the median / `oracled` input. The history
//!                                                               ring (slash streak, <= 8 samples) is sent only where a
//!                                                               unit reads / writes it (R20-M1: no per-(market, oracle)
//!                                                               leaf -- a bond change costs one record per MARKET)
//!   omk:<m>         :<cfg>:<fit>:<lfh>:<n>:<dg>:<n>:<dg>         oracle config, funding_index_twap, last_funding_height,
//!                                                               the oracle / funding TWAP rings of the market
//!   oglob:0         :<funding source>:<slash nonce>:<head>:<tail>  global oracle facts + the expiry queue's ends
//!   oexp:<u>        :<prev>:<next>:<n>:<sha256(accounts)>       expiry queue (R19-I2): the oracles whose unbonding
//!                                                               ends at height u; a doubly linked list over the
//!                                                               distinct unlock heights in ascending order
//! Eager expiry (R19-I2): a run that moves the height to h loads `oglob:0` and every queue group u <= h (plus the next
//! one), every listed oracle's `ostk:` / account record / `orm:` and each `orep:` of its list, and applies the session's
//! `prune_oracle_unbonding(h)` on the partial state (an expired oracle's entries -- report and history -- leave the
//! loaded report sets). R20-M2: at most SL_MAX_UNSTAKES oracles per expiry group (an Unstake beyond it is refused, code
//! 19), so one height's expiry is bounded. Stake / Unstake / Report run unchanged on the loaded
//! records; a Report that would pay funding (the O(holders) transfer, R19-I1) or runs on a funding-rate market /
//! with the AggregatedExternal source is unsupported. Slash: unsupported (round-20 step 3).
use super::*;
use crate::types::{FundingSourceKind, OracleConfig, ReportSample, TwapSample};
use alloc::collections::VecDeque;

/// stateless bound: markets an oracle may hold a report / history in (keeps `orm:` and a bond change loadable)
pub const SL_MAX_ORACLE_MKTS: usize = 64;
/// stateless bound: reporters per market (keeps `orep:` loadable)
pub const SL_MAX_REPORTERS: usize = 64;
const HIST_MAX: usize = 8;
/// R20-M2 (stateless bound, code 19): oracles that may start unbonding at one height (= one expiry group)
pub const SL_MAX_UNSTAKES: usize = 64;
const OTW_MAX: usize = crate::types::ORACLE_TWAP_MAX as usize;
const FTW_MAX: usize = crate::types::FUNDING_TWAP_WINDOW as usize;

const AMIN: AccountId = AccountId([0u8; 32]);
const AMAX: AccountId = AccountId([0xffu8; 32]);

// ------------------------------------------------------------------------------------------------
// leaf strings
// ------------------------------------------------------------------------------------------------
fn optw(b: &mut Buf, x: Option<u128>) {
    match x {
        Some(v) => {
            let _ = write!(b, "{}", v);
        }
        None => {
            let _ = write!(b, "-");
        }
    }
}
pub fn ostk_kid(b: &mut Buf, id: &AccountId) {
    b.n = 0;
    let _ = write!(b, "ostk:");
    hexw(b, &id.0);
    mark(b);
}
pub fn ostk_leaf(b: &mut Buf, id: &AccountId, bond: Option<u128>, unlock: Option<u64>) {
    ostk_kid(b, id);
    let _ = write!(b, ":");
    optw(b, bond);
    let _ = write!(b, ":");
    optw(b, unlock.map(|x| x as u128));
}
pub fn orm_kid(b: &mut Buf, id: &AccountId) {
    b.n = 0;
    let _ = write!(b, "orm:");
    hexw(b, &id.0);
    mark(b);
}
pub fn orm_leaf(b: &mut Buf, id: &AccountId, mk: &[u32]) {
    orm_kid(b, id);
    let _ = write!(b, ":{}:", mk.len());
    hexw(b, &apos_digest(mk));
}
/// (oracle, report price if any, bonded now, history length, history digest)
pub type OrepE = (AccountId, Option<Price>, bool, u8, H);
pub fn hist_digest(q: Option<&VecDeque<ReportSample>>) -> H {
    let mut h = Sha256::new();
    for x in q.into_iter().flatten() {
        h.update(x.height.to_le_bytes());
        h.update(x.price.to_le_bytes());
        h.update(x.seq.to_le_bytes());
    }
    h.finalize().into()
}
pub fn orep_digest(es: &[OrepE]) -> H {
    let mut h = Sha256::new();
    for (o, p, bd, n, dg) in es {
        h.update(o.0);
        h.update([p.is_some() as u8]);
        h.update(p.unwrap_or(0).to_le_bytes());
        h.update([*bd as u8, *n]);
        h.update(dg);
    }
    h.finalize().into()
}
pub fn orep_kid(b: &mut Buf, m: u32) {
    b.n = 0;
    let _ = write!(b, "orep:{}", m);
    mark(b);
}
pub fn orep_leaf(b: &mut Buf, m: u32, es: &[OrepE]) {
    orep_kid(b, m);
    let _ = write!(b, ":{}:", es.len());
    hexw(b, &orep_digest(es));
}
fn twap_digest(q: Option<&VecDeque<TwapSample>>) -> H {
    let mut h = Sha256::new();
    for x in q.into_iter().flatten() {
        h.update(x.seq.to_le_bytes());
        h.update(x.height.to_le_bytes());
        h.update(x.median.to_le_bytes());
    }
    h.finalize().into()
}
pub fn omk_kid(b: &mut Buf, m: u32) {
    b.n = 0;
    let _ = write!(b, "omk:{}", m);
    mark(b);
}
/// the market's oracle state exists in the session (absent = every field at its default)
pub fn omk_present(s: &ChainState, m: MarketId) -> bool {
    s.oracle_configs.contains_key(&m)
        || s.funding_index_twap.contains_key(&m)
        || s.last_funding_height.contains_key(&m)
        || s.oracle_twap.get(&m).is_some_and(|q| !q.is_empty())
        || s.funding_twap.get(&m).is_some_and(|q| !q.is_empty())
}
pub fn omk_leaf(b: &mut Buf, s: &ChainState, m: MarketId) {
    omk_kid(b, m.0);
    match s.oracle_configs.get(&m) {
        Some(c) => {
            let _ = write!(b, ":{},{},{}", c.deviation_bps, c.twap_window, c.slash_reward_bps);
        }
        None => {
            let _ = write!(b, ":-");
        }
    }
    match s.funding_index_twap.get(&m) {
        Some(v) => {
            let _ = write!(b, ":{}", v);
        }
        None => {
            let _ = write!(b, ":-");
        }
    }
    let _ = write!(b, ":");
    optw(b, s.last_funding_height.get(&m).map(|x| *x as u128));
    let (o, f) = (s.oracle_twap.get(&m), s.funding_twap.get(&m));
    let _ = write!(b, ":{}:", o.map(|q| q.len()).unwrap_or(0));
    hexw(b, &twap_digest(o));
    let _ = write!(b, ":{}:", f.map(|q| q.len()).unwrap_or(0));
    hexw(b, &twap_digest(f));
}
pub fn oglob_kid(b: &mut Buf) {
    b.n = 0;
    let _ = write!(b, "oglob:0");
    mark(b);
}
pub fn oglob_leaf(b: &mut Buf, fs: u8, nonce: u64, head: Option<u64>, tail: Option<u64>) {
    oglob_kid(b);
    let _ = write!(b, ":{}:{}:", fs, nonce);
    optw(b, head.map(|x| x as u128));
    let _ = write!(b, ":");
    optw(b, tail.map(|x| x as u128));
}
fn oglob_present(fs: u8, nonce: u64, head: Option<u64>) -> bool {
    fs != 0 || nonce != 0 || head.is_some()
}
pub fn oexp_kid(b: &mut Buf, u: u64) {
    b.n = 0;
    let _ = write!(b, "oexp:{}", u);
    mark(b);
}
pub fn oexp_leaf(b: &mut Buf, u: u64, prev: Option<u64>, next: Option<u64>, ids: &BTreeSet<AccountId>) {
    let mut h = Sha256::new();
    for a in ids {
        h.update(a.0);
    }
    let dg: H = h.finalize().into();
    oexp_kid(b, u);
    let _ = write!(b, ":");
    optw(b, prev.map(|x| x as u128));
    let _ = write!(b, ":");
    optw(b, next.map(|x| x as u128));
    let _ = write!(b, ":{}:", ids.len());
    hexw(b, &dg);
}

// ------------------------------------------------------------------------------------------------
// reference (full state)
// ------------------------------------------------------------------------------------------------
/// (market, oracle) pairs with a report or a non-empty history (an empty ring is the session's "no history")
fn pairs_of(s: &ChainState) -> BTreeSet<(MarketId, AccountId)> {
    let mut v: BTreeSet<(MarketId, AccountId)> = s.oracle_reports.keys().copied().collect();
    v.extend(s.oracle_report_history.iter().filter(|(_, q)| !q.is_empty()).map(|(k, _)| *k));
    v.retain(|(_, o)| *o != pseudo_oracle());
    v
}
pub fn orm_of(s: &ChainState, id: &AccountId) -> Vec<u32> {
    pairs_of(s).into_iter().filter(|(_, o)| o == id).map(|(m, _)| m.0).collect()
}
fn entry_of(s: &ChainState, m: MarketId, o: &AccountId) -> OrepE {
    let q = s.oracle_report_history.get(&(m, *o));
    (*o, s.oracle_reports.get(&(m, *o)).copied(), s.oracle_bonds.contains_key(o), q.map(|q| q.len()).unwrap_or(0) as u8, hist_digest(q))
}
pub fn orep_of(s: &ChainState, m: u32) -> Vec<OrepE> {
    let mid = MarketId(m);
    pairs_of(s).into_iter().filter(|(mm, _)| *mm == mid).map(|(_, o)| entry_of(s, mid, &o)).collect()
}
pub type OGroups = BTreeMap<u64, BTreeSet<AccountId>>;
pub fn oexp_groups(s: &ChainState) -> OGroups {
    let mut g: OGroups = BTreeMap::new();
    for (a, u) in &s.oracle_unbonding {
        g.entry(*u).or_default().insert(*a);
    }
    g
}
fn nbr(g: &OGroups, u: u64) -> (Option<u64>, Option<u64>) {
    (g.range(..u).next_back().map(|x| *x.0), g.range(u + 1..).next().map(|x| *x.0))
}
pub fn leaves(s: &ChainState, push: &mut dyn FnMut(&Buf)) {
    let mut b = Buf::new();
    let ids: BTreeSet<AccountId> = s.oracle_bonds.keys().chain(s.oracle_unbonding.keys()).copied().collect();
    for id in &ids {
        ostk_leaf(&mut b, id, s.oracle_bonds.get(id).copied(), s.oracle_unbonding.get(id).copied());
        push(&b);
    }
    let pr = pairs_of(s);
    let rids: BTreeSet<AccountId> = pr.iter().map(|(_, o)| *o).collect();
    for id in &rids {
        orm_leaf(&mut b, id, &orm_of(s, id));
        push(&b);
    }
    let rms: BTreeSet<u32> = pr.iter().map(|(m, _)| m.0).collect();
    for m in rms {
        orep_leaf(&mut b, m, &orep_of(s, m));
        push(&b);
    }
    let oms: BTreeSet<MarketId> = s
        .oracle_configs
        .keys()
        .chain(s.funding_index_twap.keys())
        .chain(s.last_funding_height.keys())
        .chain(s.oracle_twap.keys())
        .chain(s.funding_twap.keys())
        .copied()
        .collect();
    for m in oms {
        if omk_present(s, m) {
            omk_leaf(&mut b, s, m);
            push(&b);
        }
    }
    let g = oexp_groups(s);
    let fs = s.funding_source as u8;
    let head = g.keys().next().copied();
    if oglob_present(fs, s.oracle_slash_nonce, head) {
        oglob_leaf(&mut b, fs, s.oracle_slash_nonce, head, g.keys().next_back().copied());
        push(&b);
    }
    for (u, ids) in &g {
        let (p, n) = nbr(&g, *u);
        oexp_leaf(&mut b, *u, p, n, ids);
        push(&b);
    }
}
/// migration bound (R15-M1 style): every oracle object stays loadable under the stateless bounds
pub fn mig_ok(s: &ChainState) -> bool {
    let pr = pairs_of(s);
    let mut per_o: BTreeMap<AccountId, usize> = BTreeMap::new();
    let mut per: BTreeMap<MarketId, usize> = BTreeMap::new();
    for (m, o) in &pr {
        *per_o.entry(*o).or_default() += 1;
        *per.entry(*m).or_default() += 1;
    }
    if per_o.values().any(|n| *n > SL_MAX_ORACLE_MKTS) {
        return false;
    }
    if per.values().any(|n| *n > SL_MAX_REPORTERS) {
        return false;
    }
    if s.oracle_report_history.values().any(|q| q.len() > HIST_MAX) || s.oracle_twap.values().any(|q| q.len() > OTW_MAX) || s.funding_twap.values().any(|q| q.len() > FTW_MAX) {
        return false;
    }
    // unlock height 0 is the queue's "none"; a group above OEXP_MAX accounts is not loadable
    if s.oracle_unbonding.values().any(|u| *u == 0) || oexp_groups(s).values().any(|g| g.len() > SL_MAX_UNSTAKES) {
        return false;
    }
    !s.oracle_reports.keys().any(|(_, o)| *o == pseudo_oracle()) && !s.oracle_bonds.contains_key(&pseudo_oracle())
}

// ------------------------------------------------------------------------------------------------
// the loaded oracle records (guest)
// ------------------------------------------------------------------------------------------------
#[derive(Default)]
pub(super) struct Ora {
    /// glob height at load (the hook runs when the run moved it)
    pub h0: u64,
    /// `oglob:0` loaded: (funding source, slash nonce, head, tail) -- head / tail kept current by `sync`
    pub glob: Option<(u8, u64, Option<u64>, Option<u64>)>,
    /// accounts whose `ostk:` was loaded (present or proven absent)
    pub stk: BTreeSet<AccountId>,
    /// loaded accounts' unlock height as of the last queue sync
    pub unb: BTreeMap<AccountId, Option<u64>>,
    /// loaded `orm:` lists (start)
    pub rm: BTreeMap<AccountId, Vec<u32>>,
    /// markets whose report set was loaded, with `oracled` at load
    pub rep: BTreeMap<u32, bool>,
    /// (market, oracle) whose history samples were loaded (verified against the orep: entry)
    pub hist: BTreeSet<(u32, AccountId)>,
    /// entries of the loaded report sets at load: (market, oracle) -> (history length, digest)
    pub ent0: BTreeMap<(u32, AccountId), (u8, H)>,
    /// oracles released by this run's hook (their histories leave every report set, loaded or not)
    pub gone: BTreeSet<AccountId>,
    pub mk: BTreeSet<u32>,
    /// expiry queue groups known now (loaded or created): u -> (prev, next, accounts)
    pub exp: BTreeMap<u64, (Option<u64>, Option<u64>, BTreeSet<AccountId>)>,
    /// groups present at load
    pub exp0: BTreeSet<u64>,
    /// partial-state snapshots at load (completeness guards)
    pub bonds0: BTreeMap<AccountId, u128>,
    pub unb0: BTreeMap<AccountId, u64>,
    pub reps0: BTreeSet<(MarketId, AccountId)>,
    pub hist0: BTreeSet<(MarketId, AccountId)>,
}

fn opt0(x: u64) -> Option<u64> {
    if x == 0 {
        None
    } else {
        Some(x)
    }
}

/// witness section (after the exception sub-trees): oglob, ostk, orm, orep, ohist (samples of loaded entries), omk, oexp
pub(super) fn load(sl: &mut Sl, s: &mut ChainState, r: &mut Rd, b: &mut Buf) -> Result<(), u32> {
    // oglob
    match bad!(r.u8()) {
        0 => {}
        1 => {
            if bad!(r.bool()) {
                let fs = bad!(r.u8());
                let nonce = bad!(r.u64());
                let head = opt0(bad!(r.u64()));
                let tail = opt0(bad!(r.u64()));
                if fs > 1 || head.is_some() != tail.is_some() || !oglob_present(fs, nonce, head) {
                    return Err(ST_SL_BADWIT);
                }
                oglob_leaf(b, fs, nonce, head, tail);
                sl.check(b, true)?;
                s.funding_source = if fs == 1 { FundingSourceKind::AggregatedExternal } else { FundingSourceKind::BondedMedianTwap };
                s.oracle_slash_nonce = nonce;
                sl.o.glob = Some((fs, nonce, head, tail));
            } else {
                oglob_kid(b);
                sl.absent(b)?;
                sl.o.glob = Some((0, 0, None, None));
            }
        }
        _ => return Err(ST_SL_BADWIT),
    }
    // ostk
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_ACCOUNTS {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let id = AccountId(bad!(r.h32()));
        if id == pseudo_oracle() || !sl.o.stk.insert(id) {
            return Err(ST_SL_BADWIT);
        }
        if bad!(r.bool()) {
            let bond = if bad!(r.bool()) { Some(bad!(r.u128())) } else { None };
            let unl = if bad!(r.bool()) { Some(bad!(r.u64())) } else { None };
            if (bond.is_none() && unl.is_none()) || unl == Some(0) {
                return Err(ST_SL_BADWIT);
            }
            ostk_leaf(b, &id, bond, unl);
            sl.check(b, true)?;
            if let Some(v) = bond {
                s.oracle_bonds.insert(id, v);
            }
            if let Some(u) = unl {
                s.oracle_unbonding.insert(id, u);
            }
        } else {
            ostk_kid(b, &id);
            sl.absent(b)?;
        }
        sl.o.unb.insert(id, s.oracle_unbonding.get(&id).copied());
    }
    // orm
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_ACCOUNTS {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let id = AccountId(bad!(r.h32()));
        let k = bad!(r.u16()) as usize;
        if k > SL_MAX_ORACLE_MKTS || sl.o.rm.contains_key(&id) {
            return Err(ST_SL_BADWIT);
        }
        let mut v: Vec<u32> = Vec::with_capacity(k);
        for _ in 0..k {
            let m = bad!(r.u32());
            if v.last().is_some_and(|x| *x >= m) {
                return Err(ST_SL_BADWIT);
            }
            v.push(m);
        }
        if k == 0 {
            orm_kid(b, &id);
            sl.absent(b)?;
        } else {
            orm_leaf(b, &id, &v);
            sl.check(b, true)?;
        }
        sl.o.rm.insert(id, v);
    }
    // orep
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_MARKETS {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let m = bad!(r.u32());
        let k = bad!(r.u16()) as usize;
        if k > SL_MAX_REPORTERS || sl.o.rep.contains_key(&m) {
            return Err(ST_SL_BADWIT);
        }
        let mut es: Vec<OrepE> = Vec::with_capacity(k);
        for _ in 0..k {
            let o = AccountId(bad!(r.h32()));
            let p = if bad!(r.bool()) { Some(bad!(r.i64())) } else { None };
            let bd = bad!(r.bool());
            let hn = bad!(r.u8());
            let dg = bad!(r.h32());
            if o == pseudo_oracle() || es.last().is_some_and(|x| x.0 >= o) || hn as usize > HIST_MAX || (p.is_none() && hn == 0) {
                return Err(ST_SL_BADWIT);
            }
            es.push((o, p, bd, hn, dg));
        }
        if k == 0 {
            orep_kid(b, m);
            sl.absent(b)?;
        } else {
            orep_leaf(b, m, &es);
            sl.check(b, true)?;
        }
        let mid = MarketId(m);
        let pseudo = s.oracle_reports.remove(&(mid, pseudo_oracle())).is_some();
        let orc = es.iter().any(|e| e.1.is_some() && e.2);
        // the market's mkx: `oracled` bit (loaded as the stand-in reporter) is the same fact
        if sl.markets.get(&m) == Some(&true) && pseudo != orc {
            return Err(ST_SL_BADWIT);
        }
        for (o, p, bd, hn, dg) in &es {
            if let Some(p) = p {
                s.oracle_reports.insert((mid, *o), *p);
            }
            sl.o.ent0.insert((m, *o), (*hn, *dg));
            if sl.o.stk.contains(o) {
                if s.oracle_bonds.contains_key(o) != *bd {
                    return Err(ST_SL_BADWIT);
                }
            } else if *bd {
                // a reporter whose ostk: is not loaded: its bond presence only (the value is read by nobody but a
                // slash of it / its expiry, which load its ostk:)
                s.oracle_bonds.insert(*o, crate::types::ORACLE_BOND_PERP);
            }
        }
        sl.o.rep.insert(m, orc);
    }
    // ohist: the samples of entries of LOADED report sets, checked against the entry (absent entry: no samples)
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_ACCOUNTS {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let m = bad!(r.u32());
        let id = AccountId(bad!(r.h32()));
        let k = bad!(r.u8()) as usize;
        if k > HIST_MAX || !sl.o.rep.contains_key(&m) || !sl.o.hist.insert((m, id)) {
            return Err(ST_SL_BADWIT);
        }
        let mut q: VecDeque<ReportSample> = VecDeque::with_capacity(k);
        for _ in 0..k {
            q.push_back(ReportSample { height: bad!(r.u64()), price: bad!(r.i64()), seq: bad!(r.u64()) });
        }
        let (hn, dg) = sl.o.ent0.get(&(m, id)).copied().unwrap_or((0, hist_digest(None)));
        if hn as usize != k || dg != hist_digest(Some(&q)) {
            return Err(ST_SL_BADWIT);
        }
        if k > 0 {
            s.oracle_report_history.insert((MarketId(m), id), q);
        }
    }
    // omk
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_MARKETS {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let m = bad!(r.u32());
        if !sl.o.mk.insert(m) {
            return Err(ST_SL_BADWIT);
        }
        let mid = MarketId(m);
        if bad!(r.bool()) {
            if bad!(r.bool()) {
                s.oracle_configs.insert(mid, OracleConfig { deviation_bps: bad!(r.u64()), twap_window: bad!(r.u64()), slash_reward_bps: bad!(r.u64()) });
            }
            if bad!(r.bool()) {
                s.funding_index_twap.insert(mid, bad!(r.i64()));
            }
            if bad!(r.bool()) {
                s.last_funding_height.insert(mid, bad!(r.u64()));
            }
            for (cap, fq) in [(OTW_MAX, false), (FTW_MAX, true)] {
                let k = bad!(r.u16()) as usize;
                if k > cap {
                    return Err(ST_SL_BADWIT);
                }
                let mut q: VecDeque<TwapSample> = VecDeque::with_capacity(k);
                for _ in 0..k {
                    q.push_back(TwapSample { seq: bad!(r.u64()), height: bad!(r.u64()), median: bad!(r.i64()) });
                }
                if k > 0 {
                    if fq {
                        s.funding_twap.insert(mid, q);
                    } else {
                        s.oracle_twap.insert(mid, q);
                    }
                }
            }
            if !omk_present(s, mid) {
                return Err(ST_SL_BADWIT);
            }
            omk_leaf(b, s, mid);
            sl.check(b, true)?;
        } else {
            omk_kid(b, m);
            sl.absent(b)?;
        }
    }
    // oexp
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_ACCOUNTS {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let u = bad!(r.u64());
        if u == 0 || sl.o.exp.contains_key(&u) || sl.o.exp0.contains(&u) {
            return Err(ST_SL_BADWIT);
        }
        if bad!(r.bool()) {
            let prev = opt0(bad!(r.u64()));
            let next = opt0(bad!(r.u64()));
            let k = bad!(r.u32()) as usize;
            if k == 0 || k > SL_MAX_UNSTAKES {
                return Err(ST_SL_BADWIT);
            }
            let mut ids: BTreeSet<AccountId> = BTreeSet::new();
            let mut last: Option<AccountId> = None;
            for _ in 0..k {
                let a = AccountId(bad!(r.h32()));
                if last.is_some_and(|x| x >= a) {
                    return Err(ST_SL_BADWIT);
                }
                last = Some(a);
                ids.insert(a);
            }
            oexp_leaf(b, u, prev, next, &ids);
            sl.check(b, true)?;
            sl.o.exp.insert(u, (prev, next, ids));
            sl.o.exp0.insert(u);
        } else {
            oexp_kid(b, u);
            sl.absent(b)?;
            // proven absent: known empty (never re-created except as a new tail, see sync)
            sl.o.exp0.insert(u);
        }
    }
    sl.o.bonds0 = s.oracle_bonds.clone();
    sl.o.unb0 = s.oracle_unbonding.clone();
    sl.o.reps0 = s.oracle_reports.keys().copied().collect();
    sl.o.hist0 = s.oracle_report_history.keys().copied().collect();
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// guards
// ------------------------------------------------------------------------------------------------
type G = Result<(), Result<Need, u32>>;
fn nd(n: Need) -> Result<(), Result<Need, u32>> {
    Err(Ok(n))
}
fn need_stk(sl: &Sl, a: &AccountId) -> G {
    if !sl.o.stk.contains(a) {
        return nd(Need::Ostk(*a));
    }
    Ok(())
}
/// Stake / Unstake: the author's bond record (Stake's PERP debit and commit bond: run loop `bonded`); an Unstake that
/// starts an unbonding also reads the size of this height's expiry group (R20-M2 bound): `oglob:` and, when the group
/// exists (it is the queue's tail), the group
pub(super) fn pre_stake(sl: &Sl, s: &ChainState, a: &AccountId, unstake: bool) -> G {
    need_stk(sl, a)?;
    if unstake && s.oracle_bonds.contains_key(a) && !s.oracle_unbonding.contains_key(a) {
        let Some(g) = sl.o.glob else { return nd(Need::Oglob) };
        let u = s.height.saturating_add(crate::types::ORACLE_UNBOND_HEIGHTS);
        if g.3 == Some(u) && !sl.o.exp.contains_key(&u) {
            return nd(Need::Oexp(u));
        }
    }
    Ok(())
}
/// Report: bond gate, market gate (present / spot), MARK_CAP gate; then what apply_report reads
pub(super) fn pre_report(sl: &Sl, s: &ChainState, a: &AccountId, market: u32, price: Price) -> G {
    need_stk(sl, a)?;
    if !s.oracle_bonds.contains_key(a) {
        return Ok(());
    }
    let Some(present) = sl.markets.get(&market) else { return nd(Need::Market(market)) };
    let Some(p) = s.markets.get(&MarketId(market)).filter(|_| *present) else { return Ok(()) };
    if p.spot_only || price.unsigned_abs() >= crate::types::MARK_CAP.unsigned_abs() || price == 0 {
        return Ok(());
    }
    // funding-rate market: settle_funding_peg (external ring, peg clock, rate transfer over every holder)
    if p.funding_rate {
        return Err(Err(ST_SL_UNSUPPORTED));
    }
    let Some(g) = sl.o.glob else { return nd(Need::Oglob) };
    // AggregatedExternal: the funding index reads the external ring (not committed: ExtPrice is unsupported)
    if g.0 != 0 {
        return Err(Err(ST_SL_UNSUPPORTED));
    }
    if !sl.o.rep.contains_key(&market) {
        return nd(Need::Orep(market));
    }
    if !sl.o.hist.contains(&(market, *a)) {
        return nd(Need::Ohist(market, *a));
    }
    if !sl.o.rm.contains_key(a) {
        return nd(Need::Orm(*a));
    }
    if !sl.o.mk.contains(&market) {
        return nd(Need::Omk(market));
    }
    Ok(())
}
/// the entries of a LOADED report set now: reports from the partial state (complete for the market), histories from the
/// partial state where loaded, else as at load unless the oracle was released by the hook (prune removes them)
pub(super) fn entries_now(sl: &Sl, s: &ChainState, m: u32) -> Vec<OrepE> {
    let mid = MarketId(m);
    let mut ks: BTreeSet<AccountId> = s.oracle_reports.range((mid, AMIN)..=(mid, AMAX)).map(|((_, o), _)| *o).collect();
    ks.extend(s.oracle_report_history.range((mid, AMIN)..=(mid, AMAX)).filter(|(_, q)| !q.is_empty()).map(|((_, o), _)| *o));
    ks.extend(sl.o.ent0.range((m, AMIN)..=(m, AMAX)).filter(|((_, o), (n, _))| *n > 0 && !sl.o.hist.contains(&(m, *o)) && !sl.o.gone.contains(o)).map(|((_, o), _)| *o));
    ks.remove(&pseudo_oracle());
    ks.into_iter()
        .filter_map(|o| {
            let (hn, dg) = if sl.o.hist.contains(&(m, o)) || sl.o.gone.contains(&o) {
                let q = s.oracle_report_history.get(&(mid, o));
                (q.map(|q| q.len()).unwrap_or(0) as u8, hist_digest(q))
            } else {
                sl.o.ent0.get(&(m, o)).copied().unwrap_or((0, hist_digest(None)))
            };
            let p = s.oracle_reports.get(&(mid, o)).copied();
            if p.is_none() && hn == 0 {
                None
            } else {
                Some((o, p, s.oracle_bonds.contains_key(&o), hn, dg))
            }
        })
        .collect()
}
/// the markets an account has an entry in now: the loaded list, with the membership in every LOADED report set taken
/// from its entries now (any other membership cannot have changed: `post`)
pub(super) fn orm_now(sl: &Sl, s: &ChainState, a: &AccountId) -> BTreeSet<u32> {
    let mut v: BTreeSet<u32> = sl.o.rm.get(a).map(|x| x.iter().copied().collect()).unwrap_or_default();
    for m in sl.o.rep.keys() {
        if entries_now(sl, s, *m).iter().any(|e| e.0 == *a) {
            v.insert(*m);
        } else {
            v.remove(m);
        }
    }
    v
}
/// stateless rules (code 19, like SL_MAX_POS): a Report that would add an entry to a full report set or a market to a
/// full `orm:` list (inputs loaded by pre_report); an Unstake that would put more than SL_MAX_UNSTAKES oracles into this
/// height's expiry group (R20-M2; inputs loaded by pre_stake)
pub(super) fn cap_ok(sl: &Sl, s: &ChainState, op: &crate::BatchOp, a: &AccountId) -> bool {
    match *op {
        crate::BatchOp::Unstake { .. } => {
            if !(sl.o.stk.contains(a) && s.oracle_bonds.contains_key(a) && !s.oracle_unbonding.contains_key(a)) {
                return true;
            }
            let u = s.height.saturating_add(crate::types::ORACLE_UNBOND_HEIGHTS);
            sl.o.exp.get(&u).map(|g| g.2.len()).unwrap_or(0) < SL_MAX_UNSTAKES
        }
        crate::BatchOp::Report { market, price, .. } => {
            let mid = MarketId(market);
            let gated = sl.o.stk.contains(a)
                && s.oracle_bonds.contains_key(a)
                && s.markets.get(&mid).is_some_and(|p| !p.spot_only && !p.funding_rate)
                && price != 0
                && price.unsigned_abs() < crate::types::MARK_CAP.unsigned_abs()
                && sl.o.rep.contains_key(&market)
                && sl.o.rm.contains_key(a);
            if !gated {
                return true;
            }
            let es = entries_now(sl, s, market);
            if !es.iter().any(|e| e.0 == *a) && es.len() >= SL_MAX_REPORTERS {
                return false;
            }
            let now = orm_now(sl, s, a);
            now.contains(&market) || now.len() < SL_MAX_ORACLE_MKTS
        }
        _ => true,
    }
}
/// height hook (eager expiry, R19-I2): `oglob:` and every queue group up to the new height, each listed oracle's `ostk:`
/// and account record (its bond returns to its PERP balance); the rest (orm / orep, markets whose `oracled` changes,
/// pglob / pexc, the group after the last released one) by `post` and the run loop's guards after the prune. Returns
/// the oracles the prune releases (bonded + unlock <= height): their entries -- reports and histories -- leave every
/// report set
pub(super) fn hook_pre(sl: &Sl, s: &ChainState) -> Result<BTreeSet<AccountId>, Result<Need, u32>> {
    let Some(g) = sl.o.glob else { return Err(Ok(Need::Oglob)) };
    let mut cur = g.2;
    let mut gone = BTreeSet::new();
    while let Some(u) = cur {
        if u > s.height {
            break;
        }
        let Some(grp) = sl.o.exp.get(&u) else { return Err(Ok(Need::Oexp(u))) };
        for a in &grp.2 {
            need_stk(sl, a)?;
            if !sl.accts.contains_key(a) {
                return Err(Ok(Need::Account(*a)));
            }
            if s.oracle_bonds.contains_key(a) {
                gone.insert(*a);
            }
        }
        cur = grp.1;
    }
    Ok(gone)
}
pub(super) fn set_gone(sl: &mut Sl, gone: BTreeSet<AccountId>) {
    sl.o.gone.extend(gone);
}
/// post-unit (and post-hook) completeness of the oracle records + the expiry queue update
pub(super) fn post(sl: &mut Sl, s: &ChainState) -> G {
    let ps = pseudo_oracle();
    // (a) a bond / unbonding of an account whose ostk: is not loaded never changes
    let ids: BTreeSet<AccountId> = s.oracle_bonds.keys().chain(s.oracle_unbonding.keys()).chain(sl.o.bonds0.keys()).chain(sl.o.unb0.keys()).copied().collect();
    for a in &ids {
        if *a == ps || sl.o.stk.contains(a) {
            continue;
        }
        if s.oracle_bonds.get(a) != sl.o.bonds0.get(a) || s.oracle_unbonding.get(a) != sl.o.unb0.get(a) {
            return nd(Need::Ostk(*a));
        }
    }
    // (b) a bond that appeared / disappeared rewrites the `bonded` flag of every entry of the oracle (and, released by
    // the hook, removes them): its orm: list with every report set of it (one record per market, R20-M1)
    for a in &sl.o.stk {
        if s.oracle_bonds.contains_key(a) != sl.o.bonds0.contains_key(a) {
            let Some(l) = sl.o.rm.get(a) else { return nd(Need::Orm(*a)) };
            for m in l {
                if !sl.o.rep.contains_key(m) {
                    return nd(Need::Orep(*m));
                }
            }
        }
    }
    // (c) reports / histories exist in the partial state only inside loaded report sets (histories: loaded samples);
    // an entry that appeared / disappeared needs the oracle's orm:
    let mut pairs: BTreeSet<(MarketId, AccountId)> = s.oracle_reports.keys().chain(s.oracle_report_history.keys()).chain(sl.o.reps0.iter()).chain(sl.o.hist0.iter()).copied().collect();
    pairs.retain(|(_, a)| *a != ps);
    for (m, a) in &pairs {
        if !sl.o.rep.contains_key(&m.0) {
            return nd(Need::Orep(m.0));
        }
        if s.oracle_report_history.contains_key(&(*m, *a)) && !sl.o.hist.contains(&(m.0, *a)) {
            return nd(Need::Ohist(m.0, *a));
        }
    }
    for m in sl.o.rep.keys() {
        let now: BTreeSet<AccountId> = entries_now(sl, s, *m).into_iter().map(|e| e.0).collect();
        let was: BTreeSet<AccountId> = sl.o.ent0.range((*m, AMIN)..=(*m, AMAX)).map(|((_, o), _)| *o).collect();
        for a in now.symmetric_difference(&was) {
            if !sl.o.rm.contains_key(a) {
                return nd(Need::Orm(*a));
            }
        }
    }
    // (d) market-level oracle state exists in the partial state only for loaded omk: records
    let oms: BTreeSet<MarketId> = s.oracle_configs.keys().chain(s.funding_index_twap.keys()).chain(s.last_funding_height.keys()).chain(s.oracle_twap.keys()).chain(s.funding_twap.keys()).copied().collect();
    for m in oms {
        if !sl.o.mk.contains(&m.0) {
            return nd(Need::Omk(m.0));
        }
    }
    // (e) a report set whose `oracled` fact changed rewrites the market's mkx: leaf
    for (m, o0) in &sl.o.rep {
        if oracled(s, MarketId(*m)) != *o0 && !sl.markets.contains_key(m) {
            return nd(Need::Market(*m));
        }
    }
    // the funding source / slash nonce move only with oglob: loaded
    if sl.o.glob.is_none() && (s.funding_source as u8 != 0 || s.oracle_slash_nonce != 0) {
        return nd(Need::Oglob);
    }
    sync(sl, s)
}
/// expiry queue: move every loaded oracle whose unlock height changed (append at the tail, unlink emptied groups)
fn sync(sl: &mut Sl, s: &ChainState) -> G {
    let ch: Vec<(AccountId, Option<u64>, Option<u64>)> = sl
        .o
        .unb
        .iter()
        .filter_map(|(a, u0)| {
            let u1 = s.oracle_unbonding.get(a).copied();
            if u1 != *u0 {
                Some((*a, *u0, u1))
            } else {
                None
            }
        })
        .collect();
    if ch.is_empty() {
        return Ok(());
    }
    let Some(mut g) = sl.o.glob else { return nd(Need::Oglob) };
    for (a, old, new) in ch {
        if let Some(u) = old {
            let Some(grp) = sl.o.exp.get_mut(&u) else { return nd(Need::Oexp(u)) };
            if !grp.2.remove(&a) {
                return Err(Err(ST_SL_BADWIT));
            }
            if grp.2.is_empty() {
                let (p, n) = (grp.0, grp.1);
                if let Some(p) = p {
                    let Some(gp) = sl.o.exp.get_mut(&p) else { return nd(Need::Oexp(p)) };
                    gp.1 = n;
                } else {
                    g.2 = n;
                }
                if let Some(n) = n {
                    let Some(gn) = sl.o.exp.get_mut(&n) else { return nd(Need::Oexp(n)) };
                    gn.0 = p;
                } else {
                    g.3 = p;
                }
                sl.o.exp.remove(&u);
            }
        }
        if let Some(u) = new {
            if u == 0 {
                return Err(Err(ST_SL_UNSUPPORTED));
            }
            if let Some(grp) = sl.o.exp.get_mut(&u) {
                grp.2.insert(a);
            } else {
                match g.3 {
                    // the group exists (it is the tail) but was not loaded
                    Some(t) if t == u => return nd(Need::Oexp(t)),
                    // a group in the middle of the queue: never in a bound image (unlock = height + 256, heights
                    // ascending); its existence would need a proof
                    Some(t) if t > u => return Err(Err(ST_SL_UNSUPPORTED)),
                    Some(t) => {
                        let Some(gt) = sl.o.exp.get_mut(&t) else { return nd(Need::Oexp(t)) };
                        gt.1 = Some(u);
                        let mut ids = BTreeSet::new();
                        ids.insert(a);
                        sl.o.exp.insert(u, (Some(t), None, ids));
                    }
                    None => {
                        let mut ids = BTreeSet::new();
                        ids.insert(a);
                        sl.o.exp.insert(u, (None, None, ids));
                        g.2 = Some(u);
                    }
                }
                g.3 = Some(u);
            }
        }
        sl.o.unb.insert(a, new);
    }
    sl.o.glob = Some(g);
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// end root
// ------------------------------------------------------------------------------------------------
pub(super) fn end(sl: &Sl, s: &ChainState, puts: &mut Vec<(H, H)>, dels: &mut Vec<H>) {
    let mut b = Buf::new();
    if let Some((_, _, head, tail)) = sl.o.glob {
        let fs = s.funding_source as u8;
        if oglob_present(fs, s.oracle_slash_nonce, head) {
            oglob_leaf(&mut b, fs, s.oracle_slash_nonce, head, tail);
            puts.push(kh(&b));
        } else {
            oglob_kid(&mut b);
            dels.push(kid_key(&b));
        }
    }
    for a in &sl.o.stk {
        let (bd, u) = (s.oracle_bonds.get(a).copied(), s.oracle_unbonding.get(a).copied());
        if bd.is_none() && u.is_none() {
            ostk_kid(&mut b, a);
            dels.push(kid_key(&b));
        } else {
            ostk_leaf(&mut b, a, bd, u);
            puts.push(kh(&b));
        }
    }
    for a in sl.o.rm.keys() {
        let v: Vec<u32> = orm_now(sl, s, a).into_iter().collect();
        if v.is_empty() {
            orm_kid(&mut b, a);
            dels.push(kid_key(&b));
        } else {
            orm_leaf(&mut b, a, &v);
            puts.push(kh(&b));
        }
    }
    for m in sl.o.rep.keys() {
        let es = entries_now(sl, s, *m);
        if es.is_empty() {
            orep_kid(&mut b, *m);
            dels.push(kid_key(&b));
        } else {
            orep_leaf(&mut b, *m, &es);
            puts.push(kh(&b));
        }
    }
    for m in &sl.o.mk {
        if omk_present(s, MarketId(*m)) {
            omk_leaf(&mut b, s, MarketId(*m));
            puts.push(kh(&b));
        } else {
            omk_kid(&mut b, *m);
            dels.push(kid_key(&b));
        }
    }
    for (u, (p, n, ids)) in &sl.o.exp {
        oexp_leaf(&mut b, *u, *p, *n, ids);
        puts.push(kh(&b));
    }
    for u in &sl.o.exp0 {
        if !sl.o.exp.contains_key(u) {
            oexp_kid(&mut b, *u);
            dels.push(kid_key(&b));
        }
    }
}

// ------------------------------------------------------------------------------------------------
// operator (host): witness section for the oracle needs
// ------------------------------------------------------------------------------------------------
#[derive(Default)]
pub struct ONeeds {
    pub glob: bool,
    pub stk: BTreeSet<AccountId>,
    pub rm: BTreeSet<AccountId>,
    pub rep: BTreeSet<u32>,
    pub hist: BTreeSet<(u32, AccountId)>,
    pub mk: BTreeSet<u32>,
    pub exp: BTreeSet<u64>,
}
impl ONeeds {
    pub fn add(&mut self, n: &Need) -> bool {
        match *n {
            Need::Oglob => self.glob = true,
            Need::Ostk(a) => {
                self.stk.insert(a);
            }
            Need::Orm(a) => {
                self.rm.insert(a);
            }
            Need::Orep(m) => {
                self.rep.insert(m);
            }
            Need::Ohist(m, a) => {
                self.hist.insert((m, a));
            }
            Need::Omk(m) => {
                self.mk.insert(m);
            }
            Need::Oexp(u) => {
                self.exp.insert(u);
            }
            _ => return false,
        }
        true
    }
}
/// append the section; `keys` gets every key whose path the tree must expand. `t_drop`: adversarial knob (drop the
/// first entry of every list record: 1 orep, 2 orm, 3 oexp)
pub fn build(s: &ChainState, n: &ONeeds, rec: &mut Vec<u8>, keys: &mut BTreeSet<H>, t_drop: u8) {
    let mut b = Buf::new();
    let g = oexp_groups(s);
    if n.glob {
        rec.push(1);
        let fs = s.funding_source as u8;
        let head = g.keys().next().copied();
        if oglob_present(fs, s.oracle_slash_nonce, head) {
            rec.push(1);
            rec.push(fs);
            rec.extend_from_slice(&s.oracle_slash_nonce.to_le_bytes());
            rec.extend_from_slice(&head.unwrap_or(0).to_le_bytes());
            rec.extend_from_slice(&g.keys().next_back().copied().unwrap_or(0).to_le_bytes());
        } else {
            rec.push(0);
        }
        oglob_kid(&mut b);
        keys.insert(kid_key(&b));
    } else {
        rec.push(0);
    }
    rec.extend_from_slice(&(n.stk.len() as u16).to_le_bytes());
    for a in &n.stk {
        rec.extend_from_slice(&a.0);
        let (bd, u) = (s.oracle_bonds.get(a), s.oracle_unbonding.get(a));
        if bd.is_none() && u.is_none() {
            rec.push(0);
        } else {
            rec.push(1);
            rec.push(bd.is_some() as u8);
            if let Some(v) = bd {
                rec.extend_from_slice(&v.to_le_bytes());
            }
            rec.push(u.is_some() as u8);
            if let Some(v) = u {
                rec.extend_from_slice(&v.to_le_bytes());
            }
        }
        ostk_kid(&mut b, a);
        keys.insert(kid_key(&b));
    }
    rec.extend_from_slice(&(n.rm.len() as u16).to_le_bytes());
    for a in &n.rm {
        let mut v = orm_of(s, a);
        if t_drop == 2 && !v.is_empty() {
            v.remove(0);
        }
        rec.extend_from_slice(&a.0);
        rec.extend_from_slice(&(v.len() as u16).to_le_bytes());
        for m in &v {
            rec.extend_from_slice(&m.to_le_bytes());
        }
        orm_kid(&mut b, a);
        keys.insert(kid_key(&b));
    }
    let reps: BTreeSet<u32> = n.rep.iter().copied().chain(n.hist.iter().map(|x| x.0)).collect();
    rec.extend_from_slice(&(reps.len() as u16).to_le_bytes());
    for m in &reps {
        let mut es = orep_of(s, *m);
        if t_drop == 1 && !es.is_empty() {
            es.remove(0);
        }
        rec.extend_from_slice(&m.to_le_bytes());
        rec.extend_from_slice(&(es.len() as u16).to_le_bytes());
        for (o, p, bd, hn, dg) in &es {
            rec.extend_from_slice(&o.0);
            rec.push(p.is_some() as u8);
            if let Some(p) = p {
                rec.extend_from_slice(&p.to_le_bytes());
            }
            rec.push(*bd as u8);
            rec.push(*hn);
            rec.extend_from_slice(dg);
        }
        orep_kid(&mut b, *m);
        keys.insert(kid_key(&b));
    }
    rec.extend_from_slice(&(n.hist.len() as u16).to_le_bytes());
    for (m, a) in &n.hist {
        rec.extend_from_slice(&m.to_le_bytes());
        rec.extend_from_slice(&a.0);
        let q = s.oracle_report_history.get(&(MarketId(*m), *a));
        rec.push(q.map(|q| q.len()).unwrap_or(0) as u8);
        for x in q.into_iter().flatten() {
            rec.extend_from_slice(&x.height.to_le_bytes());
            rec.extend_from_slice(&x.price.to_le_bytes());
            rec.extend_from_slice(&x.seq.to_le_bytes());
        }
    }
    rec.extend_from_slice(&(n.mk.len() as u16).to_le_bytes());
    for m in &n.mk {
        let mid = MarketId(*m);
        rec.extend_from_slice(&m.to_le_bytes());
        if omk_present(s, mid) {
            rec.push(1);
            match s.oracle_configs.get(&mid) {
                Some(c) => {
                    rec.push(1);
                    rec.extend_from_slice(&c.deviation_bps.to_le_bytes());
                    rec.extend_from_slice(&c.twap_window.to_le_bytes());
                    rec.extend_from_slice(&c.slash_reward_bps.to_le_bytes());
                }
                None => rec.push(0),
            }
            match s.funding_index_twap.get(&mid) {
                Some(v) => {
                    rec.push(1);
                    rec.extend_from_slice(&v.to_le_bytes());
                }
                None => rec.push(0),
            }
            match s.last_funding_height.get(&mid) {
                Some(v) => {
                    rec.push(1);
                    rec.extend_from_slice(&v.to_le_bytes());
                }
                None => rec.push(0),
            }
            for q in [s.oracle_twap.get(&mid), s.funding_twap.get(&mid)] {
                rec.extend_from_slice(&(q.map(|q| q.len()).unwrap_or(0) as u16).to_le_bytes());
                for x in q.into_iter().flatten() {
                    rec.extend_from_slice(&x.seq.to_le_bytes());
                    rec.extend_from_slice(&x.height.to_le_bytes());
                    rec.extend_from_slice(&x.median.to_le_bytes());
                }
            }
        } else {
            rec.push(0);
        }
        omk_kid(&mut b, *m);
        keys.insert(kid_key(&b));
    }
    rec.extend_from_slice(&(n.exp.len() as u16).to_le_bytes());
    for u in &n.exp {
        rec.extend_from_slice(&u.to_le_bytes());
        match g.get(u) {
            Some(ids) => {
                let (p, nx) = nbr(&g, *u);
                rec.push(1);
                rec.extend_from_slice(&p.unwrap_or(0).to_le_bytes());
                rec.extend_from_slice(&nx.unwrap_or(0).to_le_bytes());
                let skip = (t_drop == 3) as usize;
                rec.extend_from_slice(&((ids.len() - skip.min(ids.len())) as u32).to_le_bytes());
                for a in ids.iter().skip(skip) {
                    rec.extend_from_slice(&a.0);
                }
            }
            None => rec.push(0),
        }
        oexp_kid(&mut b, *u);
        keys.insert(kid_key(&b));
    }
}
