//! Loop round 21: the stateless ADL remainder (design docs/rv-stateless-guest.md §12.2, round-21 form).
//!
//! The book-path ADL takes ONE counterparty per unit: the opposite-sign holder first in the order |qty| descending,
//! AccountId ascending (a mark-independent rank; engine.rs `liquidate_book_path`). The stateless image commits that
//! order as a RANK SUB-TREE per (market, sign): a compact SMT (the MNWIT-S tree's shape, `PTree`) whose keys are NOT
//! hashed but the rank itself, so the tree's leftmost leaf is the ADL pick:
//!
//!   rank key  = BE(u64::MAX - |qty|) (8 bytes) || AccountId[0..24]   (bit order = rank order)
//!   rank leaf = sha256("~R1:" || key || AccountId)                    (tag-5 leaf: key + id, both verified)
//!   adlr:<m>:<sign>   :<sub-tree root hex>                            MNWIT-S leaf, absent = no holder of that sign
//!
//! sign 0 = long (qty > 0), 1 = short. Every non-insurance account with a non-zero position is in exactly one tree of
//! the market (insurance is never an ADL candidate). The leaves are a pure function of the session state, so the
//! reference root stays `s_root(session state)` and the migration commits them like every other leaf.
//!
//! Guest:
//!  * ADL pick (run loop, unit that reached the remainder: engine flag SL_ADL_REACHED + SL_ADL_SIDE): the opposite
//!    tree as of unit start (maintained through the previous units) must expose its leftmost leaf (verified) and that
//!    holder's full record must be loaded; the engine then ranks the LOADED holders -- each one is in the tree under
//!    its current key, so none ranks before the leftmost leaf: the engine's pick = the session's (also checked on the
//!    fill). Empty tree = no candidate anywhere.
//!  * Maintenance (post-unit): a dirty account whose (sign, |qty|) changed in a market moves in the trees (remove the
//!    old key, insert the new one); paths are supplied on demand (Need::AdlKey), the leftmost path after removals by
//!    Need::AdlTop(k) = the first k start keys.
//!  * End root: every loaded tree's root into its `adlr:` leaf (put / delete).
//! Assumption (R21-I2): two holders with the same |qty| never share a 24-byte AccountId prefix (ids are 32-byte
//! hashes / keys; a 192-bit prefix collision is not reachable).
use super::*;

pub const LONG: u8 = 0;
pub const SHORT: u8 = 1;

pub fn sgn(q: i64) -> u8 {
    if q > 0 {
        LONG
    } else {
        SHORT
    }
}
pub fn rkey(qabs: u64, a: &AccountId) -> H {
    let mut k = [0u8; 32];
    k[..8].copy_from_slice(&(u64::MAX - qabs).to_be_bytes());
    k[8..].copy_from_slice(&a.0[..24]);
    k
}
pub fn rleaf(k: &H, a: &AccountId) -> H {
    let mut h = Sha256::new();
    h.update(b"~R1:");
    h.update(k);
    h.update(a.0);
    h.finalize().into()
}
pub fn adlr_kid(b: &mut Buf, m: u32, sd: u8) {
    b.n = 0;
    let _ = write!(b, "adlr:{}:{}", m, sd);
    mark(b);
}
pub fn adlr_leaf(b: &mut Buf, m: u32, sd: u8, root: &H) {
    adlr_kid(b, m, sd);
    let _ = write!(b, ":");
    hexw(b, root);
}
/// (market, sign) -> sorted (key, leaf hash, account) of the session state
pub fn sets(s: &ChainState) -> BTreeMap<(u32, u8), Vec<(H, H, AccountId)>> {
    let mut out: BTreeMap<(u32, u8), Vec<(H, H, AccountId)>> = BTreeMap::new();
    for (id, a) in s.accounts.iter() {
        if *id == INSURANCE_ACCOUNT {
            continue;
        }
        for (m, p) in a.positions.iter() {
            if p.qty == 0 {
                continue;
            }
            let k = rkey(p.qty.unsigned_abs(), id);
            out.entry((m.0, sgn(p.qty))).or_default().push((k, rleaf(&k, id), *id));
        }
    }
    for v in out.values_mut() {
        v.sort_unstable_by(|x, y| x.0.cmp(&y.0));
    }
    out
}
pub fn leaves(s: &ChainState, push: &mut dyn FnMut(&Buf)) {
    let mut b = Buf::new();
    for ((m, sd), v) in sets(s) {
        let kv: Vec<(H, H)> = v.iter().map(|x| (x.0, x.1)).collect();
        adlr_leaf(&mut b, m, sd, &root_of_sorted(&kv));
        push(&b);
    }
}

/// the guest's loaded rank trees
#[derive(Default)]
pub struct Adl {
    /// (market, sign) -> (present at load, sub-tree)
    pub t: BTreeMap<(u32, u8), (bool, PTree)>,
    /// (market, sign) -> verified leaf key -> account (tag-5 leaves and keys inserted in the segment)
    pub ids: BTreeMap<(u32, u8), BTreeMap<H, AccountId>>,
    /// the current tree entry of every loaded full account's position: (account, market) -> (sign, |qty|)
    pub cur: BTreeMap<(AccountId, u32), (u8, u64)>,
    /// keys removed per tree in the segment (bounds the leftmost-path need, AdlTop)
    pub removed: BTreeMap<(u32, u8), u16>,
    /// stats: rank leaf hashes computed (decode of tag-5 leaves, removal checks, insertions)
    pub hashes: u64,
}

type G = Result<(), Result<Need, u32>>;

/// loader section (after the oracle section): n, then per tree (m u32, sign u8, present u8, [root h32], sub-tree)
pub(super) fn load(sl: &mut Sl, s: &ChainState, r: &mut Rd, b: &mut Buf) -> Result<(), u32> {
    let n = bad!(r.u16()) as usize;
    if n > 2 * SL_MAX_MARKETS {
        return Err(ST_SL_BADWIT);
    }
    let mut seen = sl.t.nodes.len() + sl.xt.values().map(|x| x.nodes.len()).sum::<usize>();
    let mut last: Option<(u32, u8)> = None;
    for _ in 0..n {
        let m = bad!(r.u32());
        let sd = bad!(r.u8());
        if sd > SHORT || last.is_some_and(|l| l >= (m, sd)) {
            return Err(ST_SL_BADWIT);
        }
        last = Some((m, sd));
        let present = bad!(r.bool());
        let root = if present {
            let h = bad!(r.h32());
            adlr_leaf(b, m, sd, &h);
            sl.check(b, true)?;
            h
        } else {
            adlr_kid(b, m, sd);
            sl.absent(b)?;
            EMPTY
        };
        let mut st = bad!(PTree::decode_raw(r, SL_MAX_TREE_NODES.saturating_sub(seen)));
        seen += st.nodes.len();
        if seen > SL_MAX_TREE_NODES || st.root_hash() != root {
            return Err(ST_SL_BADWIT);
        }
        sl.adl.hashes += st.rids.len() as u64;
        let ids: BTreeMap<H, AccountId> = core::mem::take(&mut st.rids).into_iter().map(|(k, a)| (k, AccountId(a))).collect();
        sl.adl.ids.insert((m, sd), ids);
        sl.adl.t.insert((m, sd), (present, st));
    }
    // the start entries of every loaded full account (insurance: never in a tree)
    for (a, rec) in sl.accts.iter() {
        if *a == INSURANCE_ACCOUNT || rec.light.is_some() {
            continue;
        }
        if let Some(acc) = s.accounts.get(a) {
            for (m, p) in acc.positions.iter() {
                if p.qty != 0 {
                    sl.adl.cur.insert((*a, m.0), (sgn(p.qty), p.qty.unsigned_abs()));
                }
            }
        }
    }
    Ok(())
}

/// the leftmost leaf of a tree: Ok(None) = empty, Ok(Some(key)) = a verified leaf, Err = an unexpanded / unverified
/// part lies on the leftmost path
fn leftmost(t: &PTree) -> Result<Option<H>, ()> {
    let mut p = t.root;
    loop {
        match p {
            P::E => return Ok(None),
            P::O(_) => return Err(()),
            P::L(k, _, v) => return if v { Ok(Some(k)) } else { Err(()) },
            P::N(i) => {
                let [a, b] = t.nodes[i as usize].ch;
                p = if a == P::E { b } else { a };
            }
        }
    }
}

/// ADL pick check for a unit that reached the remainder in market m against holders of sign sd (the tree as of unit
/// start): returns the session's counterparty (None: no opposite holder at all)
pub(super) fn pick(sl: &Sl, s: &ChainState, m: u32, sd: u8) -> Result<Option<AccountId>, Result<Need, u32>> {
    let Some((_, t)) = sl.adl.t.get(&(m, sd)) else { return Err(Ok(Need::Adl(m, sd))) };
    let k = match leftmost(t) {
        Ok(None) => return Ok(None),
        Ok(Some(k)) => k,
        Err(()) => return Err(Ok(Need::AdlTop(m, sd, sl.adl.removed.get(&(m, sd)).copied().unwrap_or(0).saturating_add(1)))),
    };
    let Some(a) = sl.adl.ids.get(&(m, sd)).and_then(|x| x.get(&k)).copied() else { return Err(Err(ST_SL_BADWIT)) };
    match sl.accts.get(&a) {
        Some(r) if r.light.is_none() => {}
        _ => return Err(Ok(Need::Account(a))),
    }
    // the tree is current as of unit start: the loaded holder's entry then (this unit's maintenance has not run; its
    // ADL fill may already have moved the position) is the key's, else the witness contradicts itself
    let _ = s;
    match sl.adl.cur.get(&(a, m)) {
        Some((sd2, q)) if *sd2 == sd && rkey(*q, &a) == k => Ok(Some(a)),
        _ => Err(Err(ST_SL_BADWIT)),
    }
}

/// post-unit maintenance: every dirty non-insurance account's changed (sign, |qty|) moves in the rank trees
pub(super) fn maint(sl: &mut Sl, s: &ChainState, dirty: &[AccountId]) -> G {
    for a in dirty {
        if *a == INSURANCE_ACCOUNT {
            continue;
        }
        let Some(acc) = s.accounts.get(a) else {
            // an account with no record has no position; its old entries (if any) go
            let ms: Vec<u32> = sl.adl.cur.range((*a, 0)..=(*a, u32::MAX)).map(|((_, m), _)| *m).collect();
            for m in ms {
                mv(sl, a, m, None)?;
            }
            continue;
        };
        let mut ms: BTreeSet<u32> = sl.adl.cur.range((*a, 0)..=(*a, u32::MAX)).map(|((_, m), _)| *m).collect();
        ms.extend(acc.positions.iter().filter(|(_, p)| p.qty != 0).map(|(m, _)| m.0));
        for m in ms {
            let now = acc.positions.get(&MarketId(m)).filter(|p| p.qty != 0).map(|p| (sgn(p.qty), p.qty.unsigned_abs()));
            if sl.adl.cur.get(&(*a, m)).copied() != now {
                mv(sl, a, m, now)?;
            }
        }
    }
    Ok(())
}
fn mv(sl: &mut Sl, a: &AccountId, m: u32, now: Option<(u8, u64)>) -> G {
    let was = sl.adl.cur.get(&(*a, m)).copied();
    sl.adl.hashes += was.is_some() as u64 + now.is_some() as u64;
    if let Some((sd, q)) = was {
        let k = rkey(q, a);
        let Some((_, t)) = sl.adl.t.get_mut(&(m, sd)) else { return Err(Ok(Need::Adl(m, sd))) };
        match t.get(&k) {
            Look::Present(h) if h == rleaf(&k, a) => {}
            Look::Unknown => return Err(Ok(Need::AdlKey(m, sd, k))),
            _ => return Err(Err(ST_SL_BADWIT)),
        }
        t.mark_verified(&k);
        t.remove(&k).map_err(|_| Ok(Need::AdlKey(m, sd, k)))?;
        if let Some(x) = sl.adl.ids.get_mut(&(m, sd)) {
            x.remove(&k);
        }
        *sl.adl.removed.entry((m, sd)).or_insert(0) += 1;
    }
    if let Some((sd, q)) = now {
        let k = rkey(q, a);
        let Some((_, t)) = sl.adl.t.get_mut(&(m, sd)) else { return Err(Ok(Need::Adl(m, sd))) };
        match t.get(&k) {
            Look::Absent => {}
            Look::Unknown => return Err(Ok(Need::AdlKey(m, sd, k))),
            // R21-I2: a present key here is another holder with the same |qty| and id prefix (not reachable)
            Look::Present(_) => return Err(Err(ST_SL_UNSUPPORTED)),
        }
        t.set(k, rleaf(&k, a)).map_err(|_| Ok(Need::AdlKey(m, sd, k)))?;
        sl.adl.ids.entry((m, sd)).or_default().insert(k, *a);
        sl.adl.cur.insert((*a, m), (sd, q));
    } else {
        sl.adl.cur.remove(&(*a, m));
    }
    Ok(())
}

/// end root: every loaded tree's root into its `adlr:` leaf
pub(super) fn end(sl: &mut Sl, puts: &mut Vec<(H, H)>, dels: &mut Vec<H>) {
    let mut b = Buf::new();
    for ((m, sd), (present, t)) in sl.adl.t.iter_mut() {
        let r = t.root_hash();
        if r != EMPTY {
            adlr_leaf(&mut b, *m, *sd, &r);
            puts.push(kh(&b));
        } else if *present {
            adlr_kid(&mut b, *m, *sd);
            dels.push(kid_key(&b));
        }
    }
}

// ------------------------------------------------------------------------------------------------
// builder (operator)
// ------------------------------------------------------------------------------------------------
#[derive(Default)]
pub struct ANeeds {
    pub trees: BTreeMap<(u32, u8), (u16, BTreeSet<H>)>,
}
impl ANeeds {
    pub fn add(&mut self, n: &Need) -> bool {
        match *n {
            Need::Adl(m, sd) => {
                self.trees.entry((m, sd)).or_default();
            }
            Need::AdlTop(m, sd, k) => {
                let e = self.trees.entry((m, sd)).or_default();
                e.0 = e.0.max(k);
            }
            Need::AdlKey(m, sd, k) => {
                self.trees.entry((m, sd)).or_default().1.insert(k);
            }
            _ => return false,
        }
        true
    }
}
/// `t_drop` (tests): 1 = send the leftmost leaf unverified (tag 2), 2 = hide the leftmost path behind its root hash,
/// 3 = the sub-tree without its leftmost holder under the honest `adlr:` root, 4 = the same with its own root as the
/// `adlr:` value (a forged leaf)
pub fn build(s: &ChainState, n: &ANeeds, rec: &mut Vec<u8>, keys: &mut BTreeSet<H>, t_drop: u8) {
    let mut b = Buf::new();
    let all = if n.trees.is_empty() { BTreeMap::new() } else { sets(s) };
    rec.extend_from_slice(&(n.trees.len() as u16).to_le_bytes());
    for ((m, sd), (top, ks)) in &n.trees {
        let mut v = all.get(&(*m, *sd)).cloned().unwrap_or_default();
        rec.extend_from_slice(&m.to_le_bytes());
        rec.push(*sd);
        let kv: Vec<(H, H)> = v.iter().map(|x| (x.0, x.1)).collect();
        if (t_drop == 3 || t_drop == 4) && v.len() > 1 {
            v.remove(0);
        }
        let kv = if t_drop == 4 { v.iter().map(|x| (x.0, x.1)).collect() } else { kv };
        if kv.is_empty() {
            rec.push(0);
        } else {
            rec.push(1);
            rec.extend_from_slice(&root_of_sorted(&kv));
        }
        let kv: Vec<(H, H)> = v.iter().map(|x| (x.0, x.1)).collect();
        adlr_kid(&mut b, *m, *sd);
        keys.insert(kid_key(&b));
        let k = (*top).max(1) as usize;
        let mut pk: BTreeSet<H> = v.iter().take(k).map(|x| x.0).collect();
        let mut kk: BTreeSet<H> = ks.clone();
        kk.extend(pk.iter().copied());
        if t_drop == 2 {
            if let Some(f) = v.first() {
                kk.remove(&f.0);
                pk.remove(&f.0);
            }
        }
        let kk: Vec<H> = kk.into_iter().collect();
        let ids: Vec<AccountId> = v.iter().map(|x| x.2).collect();
        emit_rtree(&kv, &ids, rec, 0, kv.len(), 0, &kk, false, &pk, t_drop == 1);
    }
}
/// as `emit_tree`, over raw-keyed rank leaves: a verified leaf is tag 5 (key + account id)
#[allow(clippy::too_many_arguments)]
fn emit_rtree(leaves: &[(H, H)], ids: &[AccountId], o: &mut Vec<u8>, lo: usize, hi: usize, d: usize, keys: &[H], sib: bool, pk: &BTreeSet<H>, unv_first: bool) {
    match hi - lo {
        0 => o.push(0),
        1 => {
            // every emitted rank leaf is verified (tag 5 is as long as tag 2): a leaf sent unverified for its own key
            // could later be lifted by a collapse onto another key's path and block an insertion there (round-21 first
            // regression: operator need loops on AdlKey)
            let _ = (sib, keys, pk);
            let verified = !(unv_first && lo == 0);
            if verified {
                o.push(5);
                o.extend_from_slice(&leaves[lo].0);
                o.extend_from_slice(&ids[lo].0);
            } else {
                o.push(2);
                o.extend_from_slice(&leaves[lo].0);
                o.extend_from_slice(&leaves[lo].1);
            }
        }
        _ => {
            let mid = lo + leaves[lo..hi].partition_point(|(k, _)| kbit(k, d) == 0);
            if keys.is_empty() && !sib {
                o.push(1);
                o.extend_from_slice(&range_hash(leaves, lo, hi, d));
                return;
            }
            let km = keys.partition_point(|k| kbit(k, d) == 0);
            o.push(3);
            emit_rtree(leaves, ids, o, lo, mid, d + 1, &keys[..km], !keys.is_empty() && km == 0, pk, unv_first);
            emit_rtree(leaves, ids, o, mid, hi, d + 1, &keys[km..], !keys.is_empty() && km == keys.len(), pk, unv_first);
        }
    }
}
