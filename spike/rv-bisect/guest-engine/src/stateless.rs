//! Loop round 14 (R4-H1 production direction): STATELESS (witness-fed) guest prototype, feature `stateless`.
//!
//! Design: docs/rv-stateless-guest.md. The session guest keeps the whole engine state in guest memory
//! between heights (hence MAX_STATE_ACCOUNTS / MAX_STATE_MARKETS). Here a segment's guest receives only
//! the leaves its units touch, with MNWIT-S inclusion / exclusion proofs (a pruned compact SMT) against
//! the segment's start root, runs the units on that partial state with completeness guards, and
//! recomputes the end root from the updated leaves + the pruned tree. No session, no global caps.
//!
//! MNWIT-S = MNWIT1 (same tree, same key / leaf / node hashing, same acct: pos: ord: band: meta: leaf
//! strings, + prop: cmt: gnon: with `govwit`) plus the state the session kept only in memory:
//!   glob:0:<seq>:<height>                                   engine cursors
//!   cseq:<acct hex>:<last client_seq>                       seen_client_seq (absent = 0)
//!   apos:<acct hex>:<flags>:<m>,<m>,...                     map membership (bit0 Account entry, bit1 PERP
//!                                                           entry, bit2 W entry) + markets with a position
//!   mkx:<m>:<spot 0|1>:<funding 0|1>:<symbol hex>:<last_index>:<oracled 0|1>
//!                                                           MarketParams fields MNWIT1 does not commit + the two
//!                                                           oracle facts the fill path's mark rule reads
//!                                                           (last_index[m] != 0; a bonded reporter for m exists)
//!   lvl:<m>:<side>:<price>:<n>:<sha256(ids FIFO) hex>       one price level (live order ids, FIFO)
//!   bmp:<m>:<side>:<d>:<prefix hex>:<256-bit map hex>       price-level trie (fanout 256, depth 8 over the
//!                                                           order-preserving biased price u = p ^ 2^63)
//!   aord:<acct hex>:<n>:<sha256(entries by id) hex>         the account's live orders (id, market, side, price)
//! A kid is the text before the value part (as MNWIT1). Every *_kid() below is the identity prefix.
//!
//! Scope of the prototype: Deposit, Place (cross / isolated, limit / market, GTC / IOC; spot and perp
//! markets), Cancel, fills (one per unit, STP cancel-maker-continue). Every other op, funding-rate
//! markets and the height hook -> ST_SL_UNSUPPORTED (see the design doc "what remains").
use crate::account::{Account, Position};
use crate::engine::{Engine, RejectReason};
use crate::state::ChainState;
use crate::types::*;
use crate::wit::{self, Buf, H, EMPTY};
use crate::Order;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::fmt::Write;
use sha2::{Digest, Sha256};

pub const SL_MAGIC: u32 = 0x4D4E_5357; // "MNSW"
/// malformed witness, a record that does not verify against the tree, root mismatch, duplicates
pub const ST_SL_BADWIT: u32 = 12;
/// a unit needed state the witness did not supply (or a tree path / node it did not expand)
pub const ST_SL_MISSING: u32 = 13;
/// op kind / market kind / feature not covered by the prototype
pub const ST_SL_UNSUPPORTED: u32 = 14;
/// R14-H2 fix: the witness's claimed start root is not the chain's last good end root (main.rs keeps it in the carried
/// memory: the rollup builds s0(h) on the final memory of h-1)
pub const ST_SL_BADROOT: u32 = 15;
/// per-segment touched-set limits (the ONLY caps; consensus constants of the stateless image)
/// round 14 review (R14-M3): ~2 SHA-256 compressions per node hash -> <= ~2e9 steps of tree hashing
pub const SL_MAX_TREE_NODES: usize = 1 << 18;
/// orders loaded in total (all levels), R14-M3
pub const SL_MAX_ORDERS: usize = 1 << 16;
/// witness bytes (main.rs refuses more before reading), R14-M3
pub const SL_MAX_WIT_BYTES: usize = 1 << 24;
pub const SL_MAX_ACCOUNTS: usize = 4096;
pub const SL_MAX_LEVELS: usize = 4096;
pub const SL_MAX_LEVEL_ORDERS: usize = 4096;
pub const SL_MAX_BMP: usize = 16384;
pub const SL_MAX_MARKETS: usize = 256;
/// R14-H1: per-account exposure cap (markets with a position or a live order); also the apos: bound
pub const SL_MAX_POS: usize = 64;

// ------------------------------------------------------------------------------------------------
// leaf strings (extension kinds)
// ------------------------------------------------------------------------------------------------
fn hexw(b: &mut Buf, x: &[u8]) {
    const HX: &[u8; 16] = b"0123456789abcdef";
    for c in x {
        let s = [HX[(c >> 4) as usize], HX[(c & 15) as usize]];
        let _ = b.write_str(core::str::from_utf8(&s).unwrap());
    }
}
fn mark(b: &mut Buf) {
    b.kid = b.n;
}
pub fn glob_leaf(b: &mut Buf, seq: u64, height: u64) {
    b.n = 0;
    let _ = write!(b, "glob:0");
    mark(b);
    let _ = write!(b, ":{}:{}", seq, height);
}
pub fn cseq_kid(b: &mut Buf, id: &AccountId) {
    b.n = 0;
    let _ = write!(b, "cseq:");
    hexw(b, &id.0);
    mark(b);
}
pub fn cseq_leaf(b: &mut Buf, id: &AccountId, n: u64) {
    cseq_kid(b, id);
    let _ = write!(b, ":{}", n);
}
pub fn apos_kid(b: &mut Buf, id: &AccountId) {
    b.n = 0;
    let _ = write!(b, "apos:");
    hexw(b, &id.0);
    mark(b);
}
/// flags: bit0 Account entry, bit1 perp_balances entry, bit2 withdrawn_total entry
pub fn apos_leaf(b: &mut Buf, id: &AccountId, flags: u8, mkts: &[u32]) {
    apos_kid(b, id);
    let _ = write!(b, ":{}:", flags);
    for (i, m) in mkts.iter().enumerate() {
        let _ = write!(b, "{}{}", if i > 0 { "," } else { "" }, m);
    }
}
pub fn mkx_kid(b: &mut Buf, m: MarketId) {
    b.n = 0;
    let _ = write!(b, "mkx:{}", m.0);
    mark(b);
}
pub fn mkx_leaf(b: &mut Buf, m: MarketId, p: &MarketParams, last_index: Price, oracled: bool) {
    mkx_kid(b, m);
    let _ = write!(b, ":{}:{}:", p.spot_only as u8, p.funding_rate as u8);
    hexw(b, &p.symbol);
    let _ = write!(b, ":{}:{}", last_index, oracled as u8);
}
/// the fill path's oracle predicate (state.rs apply_fill_pair: a bonded reporter has a report for m)
pub fn oracled(s: &ChainState, m: MarketId) -> bool {
    s.oracle_reports.keys().any(|(mm, o)| *mm == m && s.oracle_bonds.contains_key(o))
}
/// stand-in reporter the loader inserts for an `oracled` market (oracle_reports / bonds are not
/// committed: only the predicate above is, and nothing on the prototype's paths reads more)
pub fn pseudo_oracle() -> AccountId {
    AccountId(crate::types::sha256(b"MNSW pseudo oracle"))
}
pub fn lvl_kid(b: &mut Buf, m: MarketId, side: u8, price: Price) {
    b.n = 0;
    let _ = write!(b, "lvl:{}:{}:{}", m.0, side, price);
    mark(b);
}
pub fn ids_digest(ids: &[OrderId]) -> H {
    let mut h = Sha256::new();
    for id in ids {
        h.update(id.0);
    }
    h.finalize().into()
}
pub fn lvl_leaf(b: &mut Buf, m: MarketId, side: u8, price: Price, ids: &[OrderId]) {
    lvl_kid(b, m, side, price);
    let _ = write!(b, ":{}:", ids.len());
    hexw(b, &ids_digest(ids));
}
pub fn bmp_kid(b: &mut Buf, m: MarketId, side: u8, d: u8, prefix: u64) {
    b.n = 0;
    let _ = write!(b, "bmp:{}:{}:{}:", m.0, side, d);
    let pb = prefix.to_be_bytes();
    hexw(b, &pb[8 - d as usize..]);
    mark(b);
}
pub fn bmp_leaf(b: &mut Buf, m: MarketId, side: u8, d: u8, prefix: u64, map: &[u8; 32]) {
    bmp_kid(b, m, side, d, prefix);
    let _ = write!(b, ":");
    hexw(b, map);
}
pub fn aord_kid(b: &mut Buf, id: &AccountId) {
    b.n = 0;
    let _ = write!(b, "aord:");
    hexw(b, &id.0);
    mark(b);
}
/// entries sorted by order id: (id, market, side, price)
pub type AordE = (OrderId, u32, u8, Price);
pub fn aord_digest(es: &[AordE]) -> H {
    let mut h = Sha256::new();
    for (id, m, s, p) in es {
        h.update(id.0);
        h.update(m.to_le_bytes());
        h.update([*s]);
        h.update(p.to_le_bytes());
    }
    h.finalize().into()
}
pub fn aord_leaf(b: &mut Buf, id: &AccountId, es: &[AordE]) {
    aord_kid(b, id);
    let _ = write!(b, ":{}:", es.len());
    hexw(b, &aord_digest(es));
}
fn kh(b: &Buf) -> (H, H) {
    wit::key_and_hash(b)
}
fn kid_key(b: &Buf) -> H {
    wit::key_of(&b.b[..b.kid])
}

/// order-preserving biased price
#[inline]
pub fn ubias(p: Price) -> u64 {
    (p as u64) ^ (1u64 << 63)
}
#[inline]
pub fn unbias(u: u64) -> Price {
    (u ^ (1u64 << 63)) as i64
}
/// prefix of `u` at trie depth d (top d bytes, right-aligned)
#[inline]
pub fn pfx(u: u64, d: u8) -> u64 {
    if d == 0 {
        0
    } else {
        u >> (8 * (8 - d as u32))
    }
}
#[inline]
fn byte_at(u: u64, d: u8) -> u8 {
    (u >> (8 * (7 - d as u32))) as u8
}
#[inline]
fn mbit(map: &[u8; 32], c: u8) -> bool {
    (map[(c >> 3) as usize] >> (7 - (c & 7))) & 1 == 1
}
#[inline]
fn mset(map: &mut [u8; 32], c: u8, v: bool) {
    let m = 1u8 << (7 - (c & 7));
    if v {
        map[(c >> 3) as usize] |= m
    } else {
        map[(c >> 3) as usize] &= !m
    }
}

// ------------------------------------------------------------------------------------------------
// reference (session side / operator): every MNWIT-S leaf of a full state
// ------------------------------------------------------------------------------------------------
fn sides(s: Side) -> u8 {
    s.as_u8()
}
/// The FULL leaf set (key, leaf hash) of a state (MNWIT1 leaves + extension leaves), unsorted.
pub fn s_leaves(s: &ChainState) -> Vec<(H, H)> {
    let mut out = Vec::new();
    s_leaves_with(s, &mut |b: &Buf| out.push(kh(b)));
    out
}
/// (key, leaf hash, leaf string) of every MNWIT-S leaf (debug / tests)
pub fn s_leaf_strings(s: &ChainState) -> Vec<(H, H, alloc::string::String)> {
    let mut out = Vec::new();
    s_leaves_with(s, &mut |b: &Buf| {
        let (k, lh) = kh(b);
        out.push((k, lh, alloc::string::String::from(core::str::from_utf8(b.as_bytes()).unwrap())))
    });
    out
}
fn s_leaves_with(s: &ChainState, push: &mut dyn FnMut(&Buf)) {
    let mut b = Buf::new();
    let ids: BTreeSet<AccountId> = s.accounts.keys().chain(s.perp_balances.keys()).chain(s.withdrawn_total.keys()).copied().collect();
    for id in &ids {
        let a = s.accounts.get(id);
        wit::acct_leaf(&mut b, id, a.map(|a| a.collateral).unwrap_or(0), s.perp_balances.get(id).copied().unwrap_or(0), s.withdrawn_total.get(id).copied().unwrap_or(0));
        push(&b);
        let flags = a.is_some() as u8 | (s.perp_balances.contains_key(id) as u8) << 1 | (s.withdrawn_total.contains_key(id) as u8) << 2;
        let mk: Vec<u32> = a.map(|a| a.positions.keys().map(|m| m.0).collect()).unwrap_or_default();
        apos_leaf(&mut b, id, flags, &mk);
        push(&b);
        if let Some(a) = a {
            for (m, p) in &a.positions {
                wit::pos_leaf(&mut b, id, *m, p.qty, p.entry_price, p.isolated, a.isolated_margin.get(m).copied().unwrap_or(0));
                push(&b);
            }
        }
    }
    for (id, n) in &s.seen_client_seq {
        cseq_leaf(&mut b, id, *n);
        push(&b);
    }
    let mut aord: BTreeMap<AccountId, Vec<AordE>> = BTreeMap::new();
    for (m, book) in &s.books {
        for o in book.live_orders() {
            wit::ord_leaf(&mut b, o);
            push(&b);
            aord.entry(o.account).or_default().push((o.id, m.0, sides(o.side), o.price));
        }
        let mut bm: BTreeMap<(u8, u8, u64), [u8; 32]> = BTreeMap::new();
        for (side, price, ids) in book.sl_levels() {
            let sd = sides(side);
            lvl_leaf(&mut b, *m, sd, price, &ids);
            push(&b);
            let u = ubias(price);
            for d in 0..8u8 {
                mset(bm.entry((sd, d, pfx(u, d))).or_insert([0; 32]), byte_at(u, d), true);
            }
        }
        for ((sd, d, p), map) in &bm {
            bmp_leaf(&mut b, *m, *sd, *d, *p, map);
            push(&b);
        }
    }
    for (id, mut es) in aord {
        es.sort_by(|x, y| x.0.cmp(&y.0));
        aord_leaf(&mut b, &id, &es);
        push(&b);
    }
    for (m, p) in &s.markets {
        wit::band_leaf(&mut b, *m, p);
        push(&b);
        wit::meta_leaf(&mut b, *m, p, s.marks.get(m).copied().unwrap_or(0));
        push(&b);
        mkx_leaf(&mut b, *m, p, s.last_index.get(m).copied().unwrap_or(0), oracled(s, *m));
        push(&b);
    }
    glob_leaf(&mut b, s.seq, s.height);
    push(&b);
    #[cfg(feature = "govwit")]
    {
        for (id, p) in &s.proposals {
            wit::prop_leaf(&mut b, *id, p);
            push(&b);
        }
        for (h, e) in &s.commits {
            wit::cmt_leaf(&mut b, h, e);
            push(&b);
        }
        for (a, n) in &s.seen_gov_nonces {
            wit::gnon_leaf(&mut b, a, *n);
            push(&b);
        }
    }
}
/// MNWIT-S root of a full state (reference).
pub fn s_root(s: &ChainState) -> H {
    let mut t = wit::Smt::new();
    for (k, lh) in s_leaves(s) {
        t.set(k, lh);
    }
    t.root()
}

// ------------------------------------------------------------------------------------------------
// pruned compact SMT (multiproof)
// ------------------------------------------------------------------------------------------------
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P {
    E,
    /// unexpanded subtree (hash only)
    O(H),
    /// leaf (key, leaf hash, key verified). R14-C1 fix: a hash-only leaf (tag 2) carries an UNVERIFIED key --
    /// the path fixes only its first d bits and the root only its hash -- so it may serve for hashing, for a
    /// canonical collapse (lift) and for an inclusion check (the caller recomputes the leaf hash from its own
    /// record, which binds hex(key)), but never as an exclusion witness, an insertion split point, an update or
    /// a deletion target. A verified leaf (tag 4: kid + rest of the leaf string, key and hash recomputed) and a
    /// leaf whose inclusion was checked are verified.
    L(H, H, bool),
    N(u32),
}
pub enum Look {
    Present(H),
    Absent,
    Unknown,
}
#[derive(Clone, Debug)]
struct PN {
    ch: [P; 2],
    h: Option<H>,
}
pub struct PTree {
    nodes: Vec<PN>,
    pub root: P,
    pub node_hashes: u64,
}
#[inline]
fn kbit(k: &H, d: usize) -> usize {
    ((k[d >> 3] >> (7 - (d & 7))) & 1) as usize
}
impl PTree {
    /// Preorder decode: tag 0 E, 1 O(h32), 2 L(key32, lh32) unverified, 3 N(left, right), 4 L verified (kid u16 +
    /// bytes, rest u16 + bytes; key = key_of(kid), hash = leaf_hash(key, kid || rest)). Rejects (None): bad tags,
    /// depth > 256, > SL_MAX_TREE_NODES nodes, a leaf whose key is not on its path, non-canonical
    /// nodes N(E,E) / N(E,L) / N(L,E). O(EMPTY) is read as E.
    pub fn decode(r: &mut Rd) -> Option<PTree> {
        let mut t = PTree { nodes: Vec::new(), root: P::E, node_hashes: 0 };
        let mut path = [0u8; 32];
        t.root = t.dec(r, 0, &mut path)?;
        Some(t)
    }
    fn dec(&mut self, r: &mut Rd, d: usize, path: &mut [u8; 32]) -> Option<P> {
        if self.nodes.len() > SL_MAX_TREE_NODES {
            return None;
        }
        match r.u8()? {
            0 => Some(P::E),
            1 => {
                let h = r.h32()?;
                Some(if h == EMPTY { P::E } else { P::O(h) })
            }
            2 => {
                let k = r.h32()?;
                let lh = r.h32()?;
                for i in 0..d {
                    if kbit(&k, i) != kbit(path, i) {
                        return None;
                    }
                }
                Some(P::L(k, lh, false))
            }
            4 => {
                let kl = r.u16()? as usize;
                if kl == 0 || kl > 384 {
                    return None;
                }
                let kid = r.take(kl)?;
                let rl = r.u16()? as usize;
                if rl > 384 {
                    return None;
                }
                let rest = r.take(rl)?;
                let k = wit::key_of(kid);
                let mut h = Sha256::new();
                h.update(b"~L1:");
                h.update(wit::hex32(&k));
                h.update(b":");
                h.update(kid);
                h.update(rest);
                let lh: H = h.finalize().into();
                for i in 0..d {
                    if kbit(&k, i) != kbit(path, i) {
                        return None;
                    }
                }
                Some(P::L(k, lh, true))
            }
            3 => {
                if d >= 256 {
                    return None;
                }
                let idx = self.nodes.len() as u32;
                self.nodes.push(PN { ch: [P::E, P::E], h: None });
                let m = 1u8 << (7 - (d & 7));
                path[d >> 3] &= !m;
                let a = self.dec(r, d + 1, path)?;
                path[d >> 3] |= m;
                let b = self.dec(r, d + 1, path)?;
                path[d >> 3] &= !m;
                match (a, b) {
                    (P::E, P::E) | (P::E, P::L(..)) | (P::L(..), P::E) => return None,
                    _ => {}
                }
                self.nodes[idx as usize].ch = [a, b];
                Some(P::N(idx))
            }
            _ => None,
        }
    }
    fn hash_of(&mut self, p: P) -> H {
        match p {
            P::E => EMPTY,
            P::O(h) => h,
            P::L(_, lh, _) => lh,
            P::N(i) => {
                if let Some(h) = self.nodes[i as usize].h {
                    return h;
                }
                let [a, b] = self.nodes[i as usize].ch;
                let ha = self.hash_of(a);
                let hb = self.hash_of(b);
                let h = wit::node_hash(&ha, &hb);
                self.node_hashes += 1;
                self.nodes[i as usize].h = Some(h);
                h
            }
        }
    }
    pub fn root_hash(&mut self) -> H {
        let r = self.root;
        self.hash_of(r)
    }
    pub fn get(&self, key: &H) -> Look {
        let mut p = self.root;
        let mut d = 0;
        loop {
            match p {
                P::E => return Look::Absent,
                P::O(_) => return Look::Unknown,
                // an unverified leaf proves nothing about other keys (R14-C1)
                P::L(k, lh, v) => return if &k == key { Look::Present(lh) } else if v { Look::Absent } else { Look::Unknown },
                P::N(i) => {
                    p = self.nodes[i as usize].ch[kbit(key, d)];
                    d += 1;
                }
            }
        }
    }
    /// depth a NEW leaf would get (W2 rule); Ok(None) = present; Err = path not expanded
    pub fn insert_depth(&self, key: &H) -> Result<Option<usize>, ()> {
        let mut p = self.root;
        let mut d = 0;
        loop {
            match p {
                P::E => return Ok(Some(d)),
                P::O(_) => return Err(()),
                P::L(k2, _, v) => {
                    if !v {
                        return Err(());
                    }
                    if &k2 == key {
                        return Ok(None);
                    }
                    let mut c = d;
                    while c < 256 && kbit(&k2, c) == kbit(key, c) {
                        c += 1;
                    }
                    return Ok(Some(c + 1));
                }
                P::N(i) => {
                    p = self.nodes[i as usize].ch[kbit(key, d)];
                    d += 1;
                }
            }
        }
    }
    /// R14-C1: after an inclusion check recomputed the leaf hash from a record, the leaf's key is verified
    pub fn mark_verified(&mut self, key: &H) {
        let mut p = self.root;
        let mut d = 0;
        let mut slot: Option<(u32, usize)> = None;
        loop {
            match p {
                P::L(k, lh, false) if &k == key => {
                    match slot {
                        None => self.root = P::L(k, lh, true),
                        Some((i, b)) => self.nodes[i as usize].ch[b] = P::L(k, lh, true),
                    }
                    return;
                }
                P::N(i) => {
                    let b = kbit(key, d);
                    slot = Some((i, b));
                    p = self.nodes[i as usize].ch[b];
                    d += 1;
                }
                _ => return,
            }
        }
    }
    fn new_node(&mut self, ch: [P; 2]) -> P {
        self.nodes.push(PN { ch, h: None });
        P::N((self.nodes.len() - 1) as u32)
    }
    pub fn set(&mut self, key: H, lh: H) -> Result<(), ()> {
        let r = self.root;
        self.root = self.ins(r, 0, &key, &lh)?;
        Ok(())
    }
    fn ins(&mut self, p: P, d: usize, key: &H, lh: &H) -> Result<P, ()> {
        match p {
            P::E => Ok(P::L(*key, *lh, true)),
            P::O(_) => Err(()),
            P::L(_, _, false) => Err(()),
            P::L(k2, lh2, true) => {
                if &k2 == key {
                    Ok(P::L(k2, *lh, true))
                } else {
                    Ok(self.split(d, (k2, lh2), (*key, *lh)))
                }
            }
            P::N(i) => {
                let b = kbit(key, d);
                let c = self.nodes[i as usize].ch[b];
                let c2 = self.ins(c, d + 1, key, lh)?;
                self.nodes[i as usize].ch[b] = c2;
                self.nodes[i as usize].h = None;
                Ok(p)
            }
        }
    }
    fn split(&mut self, d: usize, a: (H, H), b: (H, H)) -> P {
        let ba = kbit(&a.0, d);
        let bb = kbit(&b.0, d);
        let mut ch = [P::E, P::E];
        if ba != bb {
            ch[ba] = P::L(a.0, a.1, true);
            ch[bb] = P::L(b.0, b.1, true);
        } else {
            ch[ba] = self.split(d + 1, a, b);
        }
        self.new_node(ch)
    }
    /// Remove `key` (no-op if absent). Err when the path is not expanded or when the canonical
    /// collapse would need to know whether an unexpanded sibling is a single leaf.
    pub fn remove(&mut self, key: &H) -> Result<(), ()> {
        let r = self.root;
        self.root = self.del(r, 0, key)?.0;
        Ok(())
    }
    /// (new subtree, changed)
    fn del(&mut self, p: P, d: usize, key: &H) -> Result<(P, bool), ()> {
        match p {
            P::E => Ok((P::E, false)),
            P::O(_) => Err(()),
            P::L(_, _, false) => Err(()),
            P::L(k, _, true) => Ok(if &k == key { (P::E, true) } else { (p, false) }),
            P::N(i) => {
                let b = kbit(key, d);
                let c = self.nodes[i as usize].ch[b];
                let (c2, changed) = self.del(c, d + 1, key)?;
                if !changed {
                    return Ok((p, false));
                }
                // round 14 fix (first slfuzz run): invalidate even when the child stays the same node
                // (a deeper deletion changed its hash)
                self.nodes[i as usize].ch[b] = c2;
                self.nodes[i as usize].h = None;
                match self.nodes[i as usize].ch {
                    [P::E, P::E] => Ok((P::E, true)),
                    [P::L(k, h, v), P::E] | [P::E, P::L(k, h, v)] => Ok((P::L(k, h, v), true)),
                    // a lone unexpanded sibling may be a single (collapsed) leaf: unknown shape
                    [P::O(_), P::E] | [P::E, P::O(_)] => Err(()),
                    _ => Ok((p, true)),
                }
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------
// witness reader
// ------------------------------------------------------------------------------------------------
pub struct Rd<'a> {
    pub b: &'a [u8],
    pub i: usize,
}
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.i..self.i.checked_add(n)?)?;
        self.i += n;
        Some(s)
    }
    pub fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    pub fn i64(&mut self) -> Option<i64> {
        Some(self.u64()? as i64)
    }
    pub fn u128(&mut self) -> Option<u128> {
        Some(u128::from_le_bytes(self.take(16)?.try_into().ok()?))
    }
    pub fn i128(&mut self) -> Option<i128> {
        Some(self.u128()? as i128)
    }
    pub fn h32(&mut self) -> Option<H> {
        self.take(32)?.try_into().ok()
    }
    pub fn bool(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
}

// ------------------------------------------------------------------------------------------------
// what the guest found missing (the operator adds it and retries; a challenger reads it as fraud)
// ------------------------------------------------------------------------------------------------
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Need {
    Account(AccountId),
    Market(u32),
    Aord(AccountId),
    /// the order id: its level (if it exists) or its exclusion proof
    Order(OrderId),
    Level(u32, u8, Price),
    Bmp(u32, u8, u8, u64),
    /// a tree path (insertion / deletion / depth rule) for this MNWIT-S key
    Path(H),
}

/// Result of a stateless segment run.
pub struct SlOut {
    pub status: u32,
    pub start_root: H,
    pub end_root: H,
    pub applied: u32,
    pub rejected: u32,
    pub fills: u32,
    pub need: Option<Need>,
    /// stats
    pub leaves_verified: u32,
    pub tree_nodes: u32,
    pub node_hashes: u64,
    pub leaf_hashes: u64,
    /// the end-root update set (debug / tests): puts (key, leaf hash) and deletions
    pub puts: Vec<(H, H)>,
    pub dels: Vec<H>,
}

struct AcctRec {
    present: bool,
    /// markets of the start positions (pos leaves to delete if closed)
    start_pos: Vec<MarketId>,
}
#[derive(Clone)]
struct Bm {
    map: [u8; 32],
    dirty: bool,
}

struct Sl {
    t: PTree,
    accts: BTreeMap<AccountId, AcctRec>,
    markets: BTreeMap<u32, bool>,
    /// known (complete) levels: present?
    levels: BTreeMap<(u32, u8, Price), bool>,
    bmp: BTreeMap<(u32, u8, u8, u64), Bm>,
    aord: BTreeMap<AccountId, (BTreeMap<OrderId, (u32, u8, Price)>, bool)>,
    /// every order loaded or created in the segment -> (market, side, price, account)
    oloc: BTreeMap<OrderId, (u32, u8, Price, AccountId)>,
    /// order ids proven absent at segment start
    ordx: BTreeSet<OrderId>,
    verified: u32,
    leaf_hashes: u64,
}

macro_rules! bad {
    ($e:expr) => {
        match $e {
            Some(v) => v,
            None => return Err(ST_SL_BADWIT),
        }
    };
}

impl Sl {
    fn check(&mut self, b: &Buf, present: bool) -> Result<(), u32> {
        let (k, lh) = kh(b);
        self.leaf_hashes += 1;
        self.verified += 1;
        match (self.t.get(&k), present) {
            (Look::Present(h), true) if h == lh => {
                self.t.mark_verified(&k);
                Ok(())
            }
            (Look::Absent, false) => Ok(()),
            _ => Err(ST_SL_BADWIT),
        }
    }
    fn absent(&mut self, b: &Buf) -> Result<(), u32> {
        let k = kid_key(b);
        self.verified += 1;
        match self.t.get(&k) {
            Look::Absent => Ok(()),
            _ => Err(ST_SL_BADWIT),
        }
    }
}

fn read_params(r: &mut Rd) -> Option<MarketParams> {
    let mut symbol = [0u8; 16];
    symbol.copy_from_slice(r.take(16)?);
    Some(MarketParams {
        symbol,
        tick_size: r.i64()?,
        im_bps: r.u64()?,
        mm_bps: r.u64()?,
        taker_fee_bps: r.u64()?,
        keeper_reward_bps: r.u64()?,
        delisted: r.bool()?,
        spot_only: r.bool()?,
        funding_rate: r.bool()?,
        usd_per_unit: r.u64()?,
        funding_cap_bps: r.u64()?,
        min_price: r.i64()?,
        max_price: r.i64()?,
    })
}

/// Load + verify the witness into a partial ChainState.
fn load(w: &[u8]) -> Result<(Sl, ChainState, H), u32> {
    let mut r = Rd { b: w, i: 0 };
    if bad!(r.u32()) != SL_MAGIC {
        return Err(ST_SL_BADWIT);
    }
    let claimed = bad!(r.h32());
    let mut t = bad!(PTree::decode(&mut r));
    if t.root_hash() != claimed {
        return Err(ST_SL_BADWIT);
    }
    let tree_nodes = t.nodes.len();
    let _ = tree_nodes;
    let mut sl = Sl {
        t,
        accts: BTreeMap::new(),
        markets: BTreeMap::new(),
        levels: BTreeMap::new(),
        bmp: BTreeMap::new(),
        aord: BTreeMap::new(),
        oloc: BTreeMap::new(),
        ordx: BTreeSet::new(),
        verified: 0,
        leaf_hashes: 0,
    };
    let mut s = ChainState::default();
    let mut b = Buf::new();
    // glob (always)
    s.seq = bad!(r.u64());
    s.height = bad!(r.u64());
    glob_leaf(&mut b, s.seq, s.height);
    sl.check(&b, true)?;
    // markets
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_MARKETS {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let present = bad!(r.bool());
        let m = MarketId(bad!(r.u32()));
        if sl.markets.insert(m.0, present).is_some() {
            return Err(ST_SL_BADWIT);
        }
        if present {
            let p = bad!(read_params(&mut r));
            let mk = bad!(r.i64());
            let li = bad!(r.i64());
            let orc = bad!(r.bool());
            wit::band_leaf(&mut b, m, &p);
            sl.check(&b, true)?;
            wit::meta_leaf(&mut b, m, &p, mk);
            sl.check(&b, true)?;
            mkx_leaf(&mut b, m, &p, li, orc);
            sl.check(&b, true)?;
            s.markets.insert(m, p);
            if mk != 0 {
                s.marks.insert(m, mk);
            }
            if li != 0 {
                s.last_index.insert(m, li);
            }
            if orc {
                s.oracle_bonds.insert(pseudo_oracle(), 1);
                s.oracle_reports.insert((m, pseudo_oracle()), 0);
            }
        } else {
            wit::band_leaf(&mut b, m, &genesis_params());
            sl.absent(&b)?;
            wit::meta_leaf(&mut b, m, &genesis_params(), 0);
            sl.absent(&b)?;
            mkx_kid(&mut b, m);
            sl.absent(&b)?;
        }
    }
    // accounts
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_ACCOUNTS {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let present = bad!(r.bool());
        let id = AccountId(bad!(r.h32()));
        if sl.accts.contains_key(&id) {
            return Err(ST_SL_BADWIT);
        }
        let mut start_pos = Vec::new();
        if present {
            let flags = bad!(r.u8());
            if flags & !7 != 0 || flags == 0 {
                return Err(ST_SL_BADWIT);
            }
            let coll = bad!(r.i128());
            let perp = bad!(r.u128());
            let wd = bad!(r.i128());
            let cseq = bad!(r.u64());
            let np = bad!(r.u8()) as usize;
            if np > SL_MAX_POS {
                return Err(ST_SL_BADWIT);
            }
            wit::acct_leaf(&mut b, &id, coll, perp, wd);
            sl.check(&b, true)?;
            if cseq > 0 {
                cseq_leaf(&mut b, &id, cseq);
                sl.check(&b, true)?;
                s.seen_client_seq.insert(id, cseq);
            } else {
                cseq_kid(&mut b, &id);
                sl.absent(&b)?;
            }
            let mut a = Account::new(id);
            a.collateral = coll;
            let mut mk = Vec::new();
            for _ in 0..np {
                let m = MarketId(bad!(r.u32()));
                let qty = bad!(r.i64());
                let entry = bad!(r.i64());
                let iso = bad!(r.bool());
                let bucket = bad!(r.i128());
                if mk.last().is_some_and(|x| *x >= m.0) || qty == 0 {
                    return Err(ST_SL_BADWIT);
                }
                mk.push(m.0);
                wit::pos_leaf(&mut b, &id, m, qty, entry, iso, bucket);
                sl.check(&b, true)?;
                a.positions.insert(m, Position { market: m, qty, entry_price: entry, isolated: iso });
                if bucket != 0 {
                    a.isolated_margin.insert(m, bucket);
                }
                start_pos.push(m);
            }
            if flags & 1 == 0 && np > 0 {
                return Err(ST_SL_BADWIT);
            }
            apos_leaf(&mut b, &id, flags, &mk);
            sl.check(&b, true)?;
            if flags & 1 != 0 {
                s.put_account(id, a);
            } else if coll != 0 {
                return Err(ST_SL_BADWIT);
            }
            if flags & 2 != 0 {
                s.perp_balances.insert(id, perp);
            } else if perp != 0 {
                return Err(ST_SL_BADWIT);
            }
            if flags & 4 != 0 {
                s.withdrawn_total.insert(id, wd);
            } else if wd != 0 {
                return Err(ST_SL_BADWIT);
            }
        } else {
            wit::acct_leaf(&mut b, &id, 0, 0, 0);
            sl.absent(&b)?;
            apos_kid(&mut b, &id);
            sl.absent(&b)?;
            cseq_kid(&mut b, &id);
            sl.absent(&b)?;
        }
        sl.accts.insert(id, AcctRec { present, start_pos });
    }
    // aord
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_ACCOUNTS {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let id = AccountId(bad!(r.h32()));
        let k = bad!(r.u16()) as usize;
        if k > MAX_LIVE_ORDERS_PER_ACCOUNT || sl.aord.contains_key(&id) {
            return Err(ST_SL_BADWIT);
        }
        let mut es: Vec<AordE> = Vec::with_capacity(k);
        for _ in 0..k {
            let e = (OrderId(bad!(r.h32())), bad!(r.u32()), bad!(r.u8()), bad!(r.i64()));
            if es.last().is_some_and(|x| x.0 >= e.0) || e.2 > 1 {
                return Err(ST_SL_BADWIT);
            }
            es.push(e);
        }
        if k == 0 {
            aord_kid(&mut b, &id);
            sl.absent(&b)?;
        } else {
            aord_leaf(&mut b, &id, &es);
            sl.check(&b, true)?;
        }
        sl.aord.insert(id, (es.iter().map(|(o, m, sd, p)| (*o, (*m, *sd, *p))).collect(), false));
    }
    // bitmap nodes
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_BMP {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let m = bad!(r.u32());
        let sd = bad!(r.u8());
        let d = bad!(r.u8());
        let prefix = bad!(r.u64());
        let present = bad!(r.bool());
        if sd > 1 || d > 7 || (d < 8 && d > 0 && prefix >> (8 * d as u32) != 0) || (d == 0 && prefix != 0) {
            return Err(ST_SL_BADWIT);
        }
        let mut map = [0u8; 32];
        if present {
            map = bad!(r.h32());
            if map == [0u8; 32] {
                return Err(ST_SL_BADWIT);
            }
            bmp_leaf(&mut b, MarketId(m), sd, d, prefix, &map);
            sl.check(&b, true)?;
        } else {
            bmp_kid(&mut b, MarketId(m), sd, d, prefix);
            sl.absent(&b)?;
        }
        if sl.bmp.insert((m, sd, d, prefix), Bm { map, dirty: false }).is_some() {
            return Err(ST_SL_BADWIT);
        }
    }
    // levels (complete: every live order of the level, FIFO)
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_LEVELS {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let m = MarketId(bad!(r.u32()));
        let sd = bad!(r.u8());
        let price = bad!(r.i64());
        let side = bad!(Side::from_u8(sd));
        let k = bad!(r.u16()) as usize;
        if k == 0 || k > SL_MAX_LEVEL_ORDERS || sl.levels.contains_key(&(m.0, sd, price)) {
            return Err(ST_SL_BADWIT);
        }
        let mut ids = Vec::with_capacity(k);
        if sl.oloc.len() + k > SL_MAX_ORDERS {
            return Err(ST_SL_BADWIT);
        }
        for _ in 0..k {
            let o = Order {
                id: OrderId(bad!(r.h32())),
                account: AccountId(bad!(r.h32())),
                market: m,
                side,
                typ: bad!(OrderType::from_u8(bad!(r.u8()))),
                tif: bad!(TimeInForce::from_u8(bad!(r.u8()))),
                price,
                qty: bad!(r.u64()),
                remaining: bad!(r.u64()),
                seq: bad!(r.u64()),
                isolated: bad!(r.bool()),
                margin_left: bad!(r.u64()),
            };
            if o.remaining == 0 || sl.oloc.contains_key(&o.id) {
                return Err(ST_SL_BADWIT);
            }
            wit::ord_leaf(&mut b, &o);
            sl.check(&b, true)?;
            sl.oloc.insert(o.id, (m.0, sd, price, o.account));
            ids.push(o.id);
            s.book_mut(m).sl_restore(o);
        }
        lvl_leaf(&mut b, m, sd, price, &ids);
        sl.leaf_hashes += k as u64 / 2; // ids digest (64 B per 2 ids ~ one compression each)
        sl.check(&b, true)?;
        sl.levels.insert((m.0, sd, price), true);
    }
    // order ids proven absent
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_LEVEL_ORDERS {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let oid = OrderId(bad!(r.h32()));
        if sl.oloc.contains_key(&oid) || !sl.ordx.insert(oid) {
            return Err(ST_SL_BADWIT);
        }
        let k = wit::ord_key(&oid);
        sl.verified += 1;
        if !matches!(sl.t.get(&k), Look::Absent) {
            return Err(ST_SL_BADWIT);
        }
    }
    if r.i != w.len() {
        return Err(ST_SL_BADWIT);
    }
    let _ = s.take_dirty();
    // the session's books carry the peek log; start empty
    Ok((sl, s, claimed))
}

// ------------------------------------------------------------------------------------------------
// guards
// ------------------------------------------------------------------------------------------------
fn need_acct(sl: &Sl, s: &ChainState, a: &AccountId) -> Result<(), Need> {
    if !sl.accts.contains_key(a) {
        return Err(Need::Account(*a));
    }
    // markets of its positions (snapshot / risk read their params + marks)
    if let Some(ac) = s.accounts.get(a) {
        for m in ac.positions.keys() {
            if !sl.markets.contains_key(&m.0) {
                return Err(Need::Market(m.0));
            }
        }
    }
    Ok(())
}
fn need_aord_full(sl: &Sl, a: &AccountId) -> Result<(), Need> {
    let Some((es, _)) = sl.aord.get(a) else { return Err(Need::Aord(*a)) };
    for (oid, (m, sd, p)) in es {
        if !sl.levels.contains_key(&(*m, *sd, *p)) {
            let _ = oid;
            return Err(Need::Level(*m, *sd, *p));
        }
        if !sl.markets.contains_key(m) {
            return Err(Need::Market(*m));
        }
    }
    Ok(())
}
fn bmp_get<'a>(sl: &'a Sl, m: u32, sd: u8, d: u8, prefix: u64) -> Result<&'a Bm, Need> {
    sl.bmp.get(&(m, sd, d, prefix)).ok_or(Need::Bmp(m, sd, d, prefix))
}
/// Is the level at `price` present per the trie (the full book at unit start)?
fn trie_has(sl: &Sl, m: u32, sd: u8, price: Price) -> Result<bool, Need> {
    let u = ubias(price);
    for d in 0..8u8 {
        let bm = bmp_get(sl, m, sd, d, pfx(u, d))?;
        if !mbit(&bm.map, byte_at(u, d)) {
            return Ok(false);
        }
    }
    Ok(true)
}
/// Walk check: every non-empty level of side `sd` (per the trie at unit start) that is better than
/// or equal to `frontier` (None = the whole side) must be a known (complete) level.
fn walk_check(sl: &Sl, m: u32, sd: u8, frontier: Option<Price>) -> Result<(), Need> {
    // bids: best = highest u (children high -> low); asks: lowest first
    let fu = frontier.map(ubias);
    fn go(sl: &Sl, m: u32, sd: u8, d: u8, prefix: u64, fu: Option<u64>) -> Result<bool, Need> {
        let map = bmp_get(sl, m, sd, d, prefix)?.map;
        let order: &mut dyn Iterator<Item = u16> = if sd == 0 { &mut (0..256u16).rev() } else { &mut (0..256u16) };
        for c in order {
            let c = c as u8;
            if !mbit(&map, c) {
                continue;
            }
            let np = (prefix << 8) | c as u64;
            // smallest / largest u under this child vs the frontier: prune when entirely worse
            let shift = 8 * (7 - d as u32);
            let lo = np << shift;
            let hi = lo | ((1u64 << shift) - 1).wrapping_add(if shift == 64 { 0 } else { 0 });
            let hi = if shift == 0 { lo } else { hi };
            if let Some(f) = fu {
                let worse = if sd == 0 { hi < f } else { lo > f };
                if worse {
                    return Ok(false); // ordered: everything after is worse too
                }
            }
            if d == 7 {
                let q = unbias(np);
                if !sl.levels.contains_key(&(m, sd, q)) {
                    return Err(Need::Level(m, sd, q));
                }
            } else if !go(sl, m, sd, d + 1, np, fu)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    go(sl, m, sd, 0, 0, fu).map(|_| ())
}
/// set / clear the trie bits of one level (all 8 path nodes must be loaded)
fn trie_set(sl: &mut Sl, m: u32, sd: u8, price: Price, v: bool) -> Result<(), Need> {
    let u = ubias(price);
    for d in 0..8u8 {
        bmp_get(sl, m, sd, d, pfx(u, d))?;
    }
    if v {
        for d in 0..8u8 {
            let bm = sl.bmp.get_mut(&(m, sd, d, pfx(u, d))).unwrap();
            mset(&mut bm.map, byte_at(u, d), true);
            bm.dirty = true;
        }
    } else {
        for d in (0..8u8).rev() {
            let bm = sl.bmp.get_mut(&(m, sd, d, pfx(u, d))).unwrap();
            mset(&mut bm.map, byte_at(u, d), false);
            bm.dirty = true;
            if bm.map != [0u8; 32] {
                break;
            }
        }
    }
    Ok(())
}

/// pre-unit guards (reads)
fn pre(sl: &Sl, s: &ChainState, op: &crate::BatchOp, author: AccountId) -> Result<(), Result<Need, u32>> {
    use crate::BatchOp::*;
    match *op {
        Deposit { .. } => need_acct(sl, s, &author).map_err(Ok)?,
        Place { market, .. } => {
            need_acct(sl, s, &author).map_err(Ok)?;
            match sl.markets.get(&market) {
                None => return Err(Ok(Need::Market(market))),
                Some(true) if s.markets.get(&MarketId(market)).is_some_and(|p| p.funding_rate) => return Err(Err(ST_SL_UNSUPPORTED)),
                _ => {}
            }
            need_acct(sl, s, &INSURANCE_ACCOUNT).map_err(Ok)?;
            need_aord_full(sl, &author).map_err(Ok)?;
            // R14-M1 rule input: the own-side level a GTC limit may join must be known (or absent per the trie), so
            // the level-size rule below never depends on which extra records the witness carries
            if let Place { side, typ: OrderType::Limit, tif: TimeInForce::Gtc, price, .. } = *op {
                if price != 0 && !sl.levels.contains_key(&(market, side.as_u8(), price)) {
                    match trie_has(sl, market, side.as_u8(), price) {
                        Err(n) => return Err(Ok(n)),
                        Ok(true) => return Err(Ok(Need::Level(market, side.as_u8(), price))),
                        Ok(false) => {}
                    }
                }
            }
            // resting_open_im walks every book of the state and reads its market's params
            for m in s.books.keys() {
                if !sl.markets.contains_key(&m.0) {
                    return Err(Ok(Need::Market(m.0)));
                }
            }
            // a funding-rate market anywhere in the author's exposure reads global OI: unsupported
            for m in sl.markets.keys() {
                if s.markets.get(&MarketId(*m)).is_some_and(|p| p.funding_rate) && s.accounts.get(&author).is_some_and(|a| a.positions.contains_key(&MarketId(*m))) {
                    return Err(Err(ST_SL_UNSUPPORTED));
                }
            }
        }
        Cancel { client_seq, market, .. } => {
            need_acct(sl, s, &author).map_err(Ok)?;
            if !sl.aord.contains_key(&author) {
                return Err(Ok(Need::Aord(author)));
            }
            let oid = order_id(author, MarketId(market), client_seq);
            if !sl.oloc.contains_key(&oid) && !sl.ordx.contains(&oid) {
                return Err(Ok(Need::Order(oid)));
            }
        }
        _ => return Err(Err(ST_SL_UNSUPPORTED)),
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// the stateless segment run
// ------------------------------------------------------------------------------------------------
/// Run one segment statelessly: `rd` = the MNP1/MNP2 batch words (flags must be 0), `wit` = the witness
/// bytes. Events as `run_segment`. Status 0 => end_root is the MNWIT-S root after the segment.
/// `expect`: the chain's last good end root (None = not bound: host tests of other properties, non-prod first run).
pub fn run_stateless(rd: &mut dyn FnMut(u32) -> u32, wit_bytes: &[u8], expect: Option<&H>, ev: &mut dyn FnMut(u32)) -> SlOut {
    let mut out = SlOut { status: 0, start_root: EMPTY, end_root: EMPTY, applied: 0, rejected: 0, fills: 0, need: None, leaves_verified: 0, tree_nodes: 0, node_hashes: 0, leaf_hashes: 0, puts: Vec::new(), dels: Vec::new() };
    out.status = crate::check_header_seg(rd, true);
    if out.status != crate::ST_OK {
        return out;
    }
    let (mut sl, s, claimed) = match load(wit_bytes) {
        Ok(x) => x,
        Err(st) => {
            out.status = st;
            return out;
        }
    };
    out.start_root = claimed;
    out.tree_nodes = sl.t.nodes.len() as u32;
    if expect.is_some_and(|e| *e != claimed) {
        out.status = ST_SL_BADROOT;
        return out;
    }
    let mut eng = Engine { state: s };
    let n_acc = rd(1);
    let n_ops = rd(2);
    let mut accts: Vec<AccountId> = Vec::with_capacity(n_acc as usize);
    for a in 0..n_acc {
        let mut id = [0u8; 32];
        for k in 0..8 {
            id[k * 4..k * 4 + 4].copy_from_slice(&rd(4 + a * 8 + k as u32).to_le_bytes());
        }
        accts.push(AccountId(id));
    }
    let base = 4 + n_acc * 8;
    let v2 = rd(0) == crate::MAGIC2;
    let uid_base = base + 8 * n_ops;
    let ext = if v2 { crate::Ext { base: uid_base + 8 * n_ops, n: rd(uid_base + 8 * n_ops) } } else { crate::Ext::NONE };
    let fin = |out: &mut SlOut, sl: &Sl, st: u32, need: Option<Need>| {
        out.status = st;
        out.need = need;
        out.leaves_verified = sl.verified;
        out.node_hashes = sl.t.node_hashes;
        out.leaf_hashes = sl.leaf_hashes;
    };
    for i in 0..n_ops {
        let mut ow = [0u32; 8];
        for (k, x) in ow.iter_mut().enumerate() {
            *x = rd(base + i * 8 + k as u32);
        }
        let seq = eng.state.seq;
        let acct_of = |a: u32| accts.get(a as usize).copied().filter(|id| *id != INSURANCE_ACCOUNT);
        let op = crate::decode_op(&ow);
        let author = op.signer().and_then(acct_of);
        if let Some(a) = author {
            if let Err(e) = pre(&sl, &eng.state, &op, a) {
                match e {
                    Ok(n) => fin(&mut out, &sl, ST_SL_MISSING, Some(n)),
                    Err(st) => fin(&mut out, &sl, st, None),
                }
                return out;
            }
            // round 14 consensus rules of the stateless image (no global caps; per-account / per-level bounds that keep
            // every record loadable -- R14-H1 / R14-M1). Inputs are fully loaded (pre), so the outcome does not depend
            // on extra witness records.
            if let crate::BatchOp::Place { market, side, typ, tif, price, .. } = op {
                let m = MarketId(market);
                let st = &eng.state;
                let has = st.accounts.get(&a).is_some_and(|x| x.positions.contains_key(&m)) || st.books.get(&m).is_some_and(|b| b.live_orders_of(a).next().is_some());
                let mut expo: BTreeSet<u32> = st.accounts.get(&a).map(|x| x.positions.keys().map(|k| k.0).collect()).unwrap_or_default();
                if let Some((es, _)) = sl.aord.get(&a) {
                    expo.extend(es.values().map(|e| e.0));
                }
                let lvl_full = typ == OrderType::Limit
                    && tif == TimeInForce::Gtc
                    && st.books.get(&m).and_then(|b| b.sl_level(side, price)).is_some_and(|v| v.len() >= SL_MAX_LEVEL_ORDERS);
                if (!has && expo.len() >= SL_MAX_POS) || lvl_full {
                    out.rejected += 1;
                    ev(crate::STATE_CAP_CODE);
                    continue;
                }
            }
            // W2 depth rule on the MNWIT-S tree (keys the unit may create)
            let mut keys: Vec<H> = Vec::new();
            match op {
                crate::BatchOp::Deposit { .. } if !eng.state.accounts.contains_key(&a) => keys.push(wit::acct_key(&a)),
                crate::BatchOp::Place { market, client_seq, .. } => {
                    if !eng.state.accounts.contains_key(&a) {
                        keys.push(wit::acct_key(&a));
                    }
                    keys.push(wit::ord_key(&order_id(a, MarketId(market), client_seq)));
                    if !eng.state.accounts.get(&a).is_some_and(|x| x.positions.contains_key(&MarketId(market))) {
                        keys.push(wit::pos_key(&a, MarketId(market)));
                    }
                }
                _ => {}
            }
            let mut deep = false;
            for k in &keys {
                match sl.t.insert_depth(k) {
                    Ok(Some(dd)) if dd > wit::MAX_WIT_DEPTH => deep = true,
                    Ok(_) => {}
                    Err(()) => {
                        fin(&mut out, &sl, ST_SL_MISSING, Some(Need::Path(*k)));
                        return out;
                    }
                }
            }
            if deep {
                out.rejected += 1;
                ev(crate::WIT_DEPTH_CODE);
                continue;
            }
        } else if !matches!(op, crate::BatchOp::Deposit { .. } | crate::BatchOp::Place { .. } | crate::BatchOp::Cancel { .. } | crate::BatchOp::Bad) {
            fin(&mut out, &sl, ST_SL_UNSUPPORTED, None);
            return out;
        }
        for b in eng.state.books.values_mut() {
            b.peeks.0.clear();
        }
        let res = crate::dispatch(&mut eng, &op, &accts, crate::Uid { v2, at: uid_base + i * 8 }, seq, &ext, rd, false);
        // ---- post-unit guards (on the outcome, applied or rolled back) ----
        let post = (|| -> Result<(), Need> {
            // walk check
            for (m, b) in &eng.state.books {
                if let Some((ts, last)) = b.peeks.0.last() {
                    walk_check(&sl, m.0, ts.opposite().as_u8(), *last)?;
                }
            }
            let d = eng.state.take_dirty();
            // every account the unit wrote (incl. rolled-back journals) must be loaded
            for a in &d.accounts {
                if !sl.accts.contains_key(a) {
                    return Err(Need::Account(*a));
                }
            }
            for m in &d.markets {
                if !sl.markets.contains_key(&m.0) {
                    return Err(Need::Market(m.0));
                }
            }
            // touched orders -> levels; new resting orders: their level must be known or absent per the trie
            let mut lv: BTreeSet<(u32, u8, Price)> = BTreeSet::new();
            for (m, oid) in &d.orders {
                let loc = match sl.oloc.get(oid) {
                    Some(l) => Some(*l),
                    None => eng.state.books.get(m).and_then(|b| b.get(*oid)).map(|o| (m.0, o.side.as_u8(), o.price, o.account)),
                };
                let Some((mm, sd, p, acc)) = loc else { continue };
                if !sl.levels.contains_key(&(mm, sd, p)) {
                    if trie_has(&sl, mm, sd, p)? {
                        return Err(Need::Level(mm, sd, p));
                    }
                    sl.levels.insert((mm, sd, p), false);
                }
                lv.insert((mm, sd, p));
                let live_now = eng.state.books.get(m).and_then(|b| b.get(*oid)).is_some_and(|o| o.remaining > 0);
                let ent = sl.aord.get(&acc).ok_or(Need::Aord(acc))?;
                if ent.0.contains_key(oid) != live_now {
                    let e = sl.aord.get_mut(&acc).unwrap();
                    if live_now {
                        e.0.insert(*oid, (mm, sd, p));
                    } else {
                        e.0.remove(oid);
                    }
                    e.1 = true;
                }
                sl.oloc.entry(*oid).or_insert((mm, sd, p, acc));
            }
            for (mm, sd, p) in lv {
                let now = eng.state.books.get(&MarketId(mm)).and_then(|b| b.sl_level(Side::from_u8(sd).unwrap(), p)).is_some();
                let was = sl.levels[&(mm, sd, p)];
                if now != was {
                    trie_set(&mut sl, mm, sd, p, now)?;
                    sl.levels.insert((mm, sd, p), now);
                }
            }
            Ok(())
        })();
        if let Err(n) = post {
            fin(&mut out, &sl, ST_SL_MISSING, Some(n));
            return out;
        }
        match res {
            Ok(fills) => {
                eng.state.seq += 1;
                out.applied += 1;
                out.fills += fills.len() as u32;
                ev(crate::EV_APPLIED | fills.len() as u32);
                for f in &fills {
                    ev(u32::from_le_bytes([f.maker_id.0[0], f.maker_id.0[1], f.maker_id.0[2], f.maker_id.0[3]]));
                    ev(u32::from_le_bytes([f.taker_id.0[0], f.taker_id.0[1], f.taker_id.0[2], f.taker_id.0[3]]));
                    ev(f.price as u32);
                    ev((f.price >> 32) as u32);
                    ev(f.qty as u32);
                    ev((f.qty >> 32) as u32);
                }
            }
            Err(r) => {
                out.rejected += 1;
                ev(crate::reason_code(&r));
            }
        }
        let _: Option<RejectReason> = None;
    }
    // ---- end root: re-derive every loaded / created leaf, then update the pruned tree ----
    match end_root(&mut sl, &eng.state, &mut out.puts, &mut out.dels) {
        Ok(r) => {
            out.end_root = r;
            fin(&mut out, &sl, crate::ST_OK, None);
        }
        Err(n) => fin(&mut out, &sl, ST_SL_MISSING, Some(n)),
    }
    out
}

fn end_root(sl: &mut Sl, s: &ChainState, dbg_puts: &mut Vec<(H, H)>, dbg_dels: &mut Vec<H>) -> Result<H, Need> {
    let mut puts: Vec<(H, H)> = Vec::new();
    let mut dels: Vec<H> = Vec::new();
    let mut b = Buf::new();
    // accounts
    for (id, rec) in &sl.accts {
        let a = s.accounts.get(id);
        let flags = a.is_some() as u8 | (s.perp_balances.contains_key(id) as u8) << 1 | (s.withdrawn_total.contains_key(id) as u8) << 2;
        if flags != 0 {
            wit::acct_leaf(&mut b, id, a.map(|a| a.collateral).unwrap_or(0), s.perp_balances.get(id).copied().unwrap_or(0), s.withdrawn_total.get(id).copied().unwrap_or(0));
            puts.push(kh(&b));
            let mk: Vec<u32> = a.map(|a| a.positions.keys().map(|m| m.0).collect()).unwrap_or_default();
            apos_leaf(&mut b, id, flags, &mk);
            puts.push(kh(&b));
        } else {
            wit::acct_leaf(&mut b, id, 0, 0, 0);
            dels.push(kid_key(&b));
            apos_kid(&mut b, id);
            dels.push(kid_key(&b));
        }
        if let Some(a) = a {
            for (m, p) in &a.positions {
                wit::pos_leaf(&mut b, id, *m, p.qty, p.entry_price, p.isolated, a.isolated_margin.get(m).copied().unwrap_or(0));
                puts.push(kh(&b));
            }
        }
        for m in &rec.start_pos {
            if !a.is_some_and(|a| a.positions.contains_key(m)) {
                dels.push(wit::pos_key(id, *m));
            }
        }
        match s.seen_client_seq.get(id) {
            Some(n) => {
                cseq_leaf(&mut b, id, *n);
                puts.push(kh(&b));
            }
            None => {
                cseq_kid(&mut b, id);
                dels.push(kid_key(&b));
            }
        }
        let _ = rec.present;
    }
    // markets (present ones: the mark may move)
    for (m, present) in &sl.markets {
        if *present {
            let p = &s.markets[&MarketId(*m)];
            wit::band_leaf(&mut b, MarketId(*m), p);
            puts.push(kh(&b));
            wit::meta_leaf(&mut b, MarketId(*m), p, s.marks.get(&MarketId(*m)).copied().unwrap_or(0));
            puts.push(kh(&b));
            mkx_leaf(&mut b, MarketId(*m), p, s.last_index.get(&MarketId(*m)).copied().unwrap_or(0), oracled(s, MarketId(*m)));
            puts.push(kh(&b));
        }
    }
    // orders
    for (oid, (m, _, _, _)) in &sl.oloc {
        match s.books.get(&MarketId(*m)).and_then(|bk| bk.get(*oid)).filter(|o| o.remaining > 0) {
            Some(o) => {
                wit::ord_leaf(&mut b, o);
                puts.push(kh(&b));
            }
            None => dels.push(wit::ord_key(oid)),
        }
    }
    // levels
    for ((m, sd, p), _) in &sl.levels {
        match s.books.get(&MarketId(*m)).and_then(|bk| bk.sl_level(Side::from_u8(*sd).unwrap(), *p)) {
            Some(ids) => {
                lvl_leaf(&mut b, MarketId(*m), *sd, *p, &ids);
                sl.leaf_hashes += ids.len() as u64 / 2;
                puts.push(kh(&b));
            }
            None => {
                lvl_kid(&mut b, MarketId(*m), *sd, *p);
                dels.push(kid_key(&b));
            }
        }
    }
    // trie nodes
    for ((m, sd, d, pf), bm) in &sl.bmp {
        if bm.dirty {
            if bm.map == [0u8; 32] {
                bmp_kid(&mut b, MarketId(*m), *sd, *d, *pf);
                dels.push(kid_key(&b));
            } else {
                bmp_leaf(&mut b, MarketId(*m), *sd, *d, *pf, &bm.map);
                puts.push(kh(&b));
            }
        }
    }
    // account order sets
    for (id, (es, dirty)) in &sl.aord {
        if *dirty {
            if es.is_empty() {
                aord_kid(&mut b, id);
                dels.push(kid_key(&b));
            } else {
                let v: Vec<AordE> = es.iter().map(|(o, (m, sd, p))| (*o, *m, *sd, *p)).collect();
                aord_leaf(&mut b, id, &v);
                puts.push(kh(&b));
            }
        }
    }
    glob_leaf(&mut b, s.seq, s.height);
    puts.push(kh(&b));
    sl.leaf_hashes += puts.len() as u64 + dels.len() as u64;
    if cfg!(not(target_arch = "riscv32")) {
        dbg_puts.clone_from(&puts);
        dbg_dels.clone_from(&dels);
    }
    for (k, lh) in puts {
        sl.t.set(k, lh).map_err(|_| Need::Path(k))?;
    }
    for k in dels {
        sl.t.remove(&k).map_err(|_| Need::Path(k))?;
    }
    Ok(sl.t.root_hash())
}

// ------------------------------------------------------------------------------------------------
// operator side (host): build a witness from the FULL start state for a set of needs
// ------------------------------------------------------------------------------------------------
pub struct WitBuilder<'a> {
    pub s: &'a ChainState,
    /// sorted (key, leaf hash) of the full MNWIT-S leaf set
    pub leaves: Vec<(H, H)>,
    /// leaf strings (kid length, bytes), parallel to `leaves` (verified-leaf form, R14-C1)
    pub strs: Vec<(usize, Vec<u8>)>,
    pub root: H,
}
fn put_params(o: &mut Vec<u8>, p: &MarketParams) {
    o.extend_from_slice(&p.symbol);
    o.extend_from_slice(&p.tick_size.to_le_bytes());
    for v in [p.im_bps, p.mm_bps, p.taker_fee_bps, p.keeper_reward_bps] {
        o.extend_from_slice(&v.to_le_bytes());
    }
    o.push(p.delisted as u8);
    o.push(p.spot_only as u8);
    o.push(p.funding_rate as u8);
    o.extend_from_slice(&p.usd_per_unit.to_le_bytes());
    o.extend_from_slice(&p.funding_cap_bps.to_le_bytes());
    o.extend_from_slice(&p.min_price.to_le_bytes());
    o.extend_from_slice(&p.max_price.to_le_bytes());
}
impl<'a> WitBuilder<'a> {
    pub fn new(s: &'a ChainState) -> Self {
        let mut all: Vec<(H, H, usize, Vec<u8>)> = Vec::new();
        s_leaves_with(s, &mut |b: &Buf| {
            let (k, lh) = kh(b);
            all.push((k, lh, b.kid, b.as_bytes().to_vec()))
        });
        all.sort_by(|x, y| x.0.cmp(&y.0));
        let mut t = wit::Smt::new();
        for (k, lh, _, _) in &all {
            t.set(*k, *lh);
        }
        let root = t.root();
        let leaves = all.iter().map(|x| (x.0, x.1)).collect();
        let strs = all.into_iter().map(|x| (x.2, x.3)).collect();
        WitBuilder { s, leaves, strs, root }
    }
    fn level_of(&self, oid: &OrderId) -> Option<(u32, u8, Price)> {
        for (m, b) in &self.s.books {
            if let Some(o) = b.get(*oid).filter(|o| o.remaining > 0) {
                return Some((m.0, o.side.as_u8(), o.price));
            }
        }
        None
    }
    /// Close the need set (a level brings its trie path; an order its level) and serialize.
    pub fn build(&self, needs: &BTreeSet<Need>) -> Vec<u8> {
        let s = self.s;
        let mut accts: BTreeSet<AccountId> = BTreeSet::new();
        let mut mkts: BTreeSet<u32> = BTreeSet::new();
        let mut aord: BTreeSet<AccountId> = BTreeSet::new();
        let mut levels: BTreeSet<(u32, u8, Price)> = BTreeSet::new();
        let mut bmps: BTreeSet<(u32, u8, u8, u64)> = BTreeSet::new();
        let mut ordx: BTreeSet<OrderId> = BTreeSet::new();
        let mut paths: BTreeSet<H> = BTreeSet::new();
        for n in needs {
            match *n {
                Need::Account(a) => {
                    accts.insert(a);
                }
                Need::Market(m) => {
                    mkts.insert(m);
                }
                Need::Aord(a) => {
                    aord.insert(a);
                }
                Need::Order(o) => match self.level_of(&o) {
                    Some(l) => {
                        levels.insert(l);
                    }
                    None => {
                        ordx.insert(o);
                    }
                },
                Need::Level(m, sd, p) => {
                    levels.insert((m, sd, p));
                    mkts.insert(m);
                }
                Need::Bmp(m, sd, d, p) => {
                    bmps.insert((m, sd, d, p));
                }
                Need::Path(k) => {
                    paths.insert(k);
                }
            }
        }
        // a level brings its full trie path (bitmap updates) -- only for levels that exist
        let mut lv2 = BTreeSet::new();
        for (m, sd, p) in &levels {
            let side = Side::from_u8(*sd).unwrap();
            if s.books.get(&MarketId(*m)).and_then(|b| b.sl_level(side, *p)).is_some() {
                lv2.insert((*m, *sd, *p));
            }
            let u = ubias(*p);
            for d in 0..8u8 {
                bmps.insert((*m, *sd, d, pfx(u, d)));
            }
            mkts.insert(*m);
        }
        let levels = lv2;
        // collect the keys to expand and serialize records
        let mut keys: BTreeSet<H> = paths;
        let mut b = Buf::new();
        let mut o: Vec<u8> = Vec::new();
        o.extend_from_slice(&SL_MAGIC.to_le_bytes());
        o.extend_from_slice(&self.root);
        let mut rec: Vec<u8> = Vec::new();
        rec.extend_from_slice(&s.seq.to_le_bytes());
        rec.extend_from_slice(&s.height.to_le_bytes());
        glob_leaf(&mut b, s.seq, s.height);
        keys.insert(kid_key(&b));
        rec.extend_from_slice(&(mkts.len() as u16).to_le_bytes());
        for m in &mkts {
            let mid = MarketId(*m);
            match s.markets.get(&mid) {
                Some(p) => {
                    rec.push(1);
                    rec.extend_from_slice(&m.to_le_bytes());
                    put_params(&mut rec, p);
                    rec.extend_from_slice(&s.marks.get(&mid).copied().unwrap_or(0).to_le_bytes());
                    rec.extend_from_slice(&s.last_index.get(&mid).copied().unwrap_or(0).to_le_bytes());
                    rec.push(oracled(s, mid) as u8);
                }
                None => {
                    rec.push(0);
                    rec.extend_from_slice(&m.to_le_bytes());
                }
            }
            for k in wit::market_keys(mid) {
                keys.insert(k);
            }
            mkx_kid(&mut b, mid);
            keys.insert(kid_key(&b));
        }
        rec.extend_from_slice(&(accts.len() as u16).to_le_bytes());
        for id in &accts {
            let a = s.accounts.get(id);
            let flags = a.is_some() as u8 | (s.perp_balances.contains_key(id) as u8) << 1 | (s.withdrawn_total.contains_key(id) as u8) << 2;
            keys.insert(wit::acct_key(id));
            apos_kid(&mut b, id);
            keys.insert(kid_key(&b));
            cseq_kid(&mut b, id);
            keys.insert(kid_key(&b));
            if flags == 0 {
                rec.push(0);
                rec.extend_from_slice(&id.0);
                continue;
            }
            rec.push(1);
            rec.extend_from_slice(&id.0);
            rec.push(flags);
            rec.extend_from_slice(&a.map(|a| a.collateral).unwrap_or(0).to_le_bytes());
            rec.extend_from_slice(&s.perp_balances.get(id).copied().unwrap_or(0).to_le_bytes());
            rec.extend_from_slice(&s.withdrawn_total.get(id).copied().unwrap_or(0).to_le_bytes());
            rec.extend_from_slice(&s.seen_client_seq.get(id).copied().unwrap_or(0).to_le_bytes());
            let np = a.map(|a| a.positions.len()).unwrap_or(0);
            rec.push(np as u8);
            if let Some(a) = a {
                for (m, p) in &a.positions {
                    rec.extend_from_slice(&m.0.to_le_bytes());
                    rec.extend_from_slice(&p.qty.to_le_bytes());
                    rec.extend_from_slice(&p.entry_price.to_le_bytes());
                    rec.push(p.isolated as u8);
                    rec.extend_from_slice(&a.isolated_margin.get(m).copied().unwrap_or(0).to_le_bytes());
                    keys.insert(wit::pos_key(id, *m));
                }
            }
        }
        rec.extend_from_slice(&(aord.len() as u16).to_le_bytes());
        for id in &aord {
            let mut es: Vec<AordE> = Vec::new();
            for (m, bk) in &s.books {
                for o2 in bk.live_orders_of(*id) {
                    es.push((o2.id, m.0, o2.side.as_u8(), o2.price));
                }
            }
            es.sort_by(|x, y| x.0.cmp(&y.0));
            rec.extend_from_slice(&id.0);
            rec.extend_from_slice(&(es.len() as u16).to_le_bytes());
            for (oid, m, sd, p) in &es {
                rec.extend_from_slice(&oid.0);
                rec.extend_from_slice(&m.to_le_bytes());
                rec.push(*sd);
                rec.extend_from_slice(&p.to_le_bytes());
            }
            aord_kid(&mut b, id);
            keys.insert(kid_key(&b));
        }
        // bitmap nodes (present = in the full trie)
        let mut full_bm: BTreeMap<(u32, u8, u8, u64), [u8; 32]> = BTreeMap::new();
        for (m, bk) in &s.books {
            for (side, price, _) in bk.sl_levels() {
                let u = ubias(price);
                for d in 0..8u8 {
                    mset(full_bm.entry((m.0, side.as_u8(), d, pfx(u, d))).or_insert([0; 32]), byte_at(u, d), true);
                }
            }
        }
        rec.extend_from_slice(&(bmps.len() as u16).to_le_bytes());
        for (m, sd, d, p) in &bmps {
            rec.extend_from_slice(&m.to_le_bytes());
            rec.push(*sd);
            rec.push(*d);
            rec.extend_from_slice(&p.to_le_bytes());
            match full_bm.get(&(*m, *sd, *d, *p)) {
                Some(map) => {
                    rec.push(1);
                    rec.extend_from_slice(map);
                }
                None => rec.push(0),
            }
            bmp_kid(&mut b, MarketId(*m), *sd, *d, *p);
            keys.insert(kid_key(&b));
        }
        rec.extend_from_slice(&(levels.len() as u16).to_le_bytes());
        for (m, sd, p) in &levels {
            let bk = &s.books[&MarketId(*m)];
            let ids = bk.sl_level(Side::from_u8(*sd).unwrap(), *p).unwrap();
            rec.extend_from_slice(&m.to_le_bytes());
            rec.push(*sd);
            rec.extend_from_slice(&p.to_le_bytes());
            rec.extend_from_slice(&(ids.len() as u16).to_le_bytes());
            for id in &ids {
                let o2 = bk.get(*id).unwrap();
                rec.extend_from_slice(&o2.id.0);
                rec.extend_from_slice(&o2.account.0);
                rec.push(o2.typ.as_u8());
                rec.push(o2.tif.as_u8());
                rec.extend_from_slice(&o2.qty.to_le_bytes());
                rec.extend_from_slice(&o2.remaining.to_le_bytes());
                rec.extend_from_slice(&o2.seq.to_le_bytes());
                rec.push(o2.isolated as u8);
                rec.extend_from_slice(&o2.margin_left.to_le_bytes());
                keys.insert(wit::ord_key(id));
            }
            lvl_kid(&mut b, MarketId(*m), *sd, *p);
            keys.insert(kid_key(&b));
        }
        rec.extend_from_slice(&(ordx.len() as u16).to_le_bytes());
        for oid in &ordx {
            rec.extend_from_slice(&oid.0);
            keys.insert(wit::ord_key(oid));
        }
        let keys: Vec<H> = keys.into_iter().collect();
        self.tree(&mut o, 0, self.leaves.len(), 0, &keys, false);
        o.extend_from_slice(&rec);
        o
    }
    fn range_hash(&self, lo: usize, hi: usize, d: usize) -> H {
        match hi - lo {
            0 => EMPTY,
            1 => self.leaves[lo].1,
            _ => {
                let mid = lo + self.leaves[lo..hi].partition_point(|(k, _)| kbit(k, d) == 0);
                let a = self.range_hash(lo, mid, d + 1);
                let b = self.range_hash(mid, hi, d + 1);
                wit::node_hash(&a, &b)
            }
        }
    }
    /// preorder pruned tree over leaves[lo..hi) at depth d; `keys` = sorted keys whose paths to expand.
    /// A single leaf is always emitted as L (never hidden in an O). `sib`: this subtree is the sibling
    /// of an expanded path -> expand one more level, so a later deletion on the path can prove the
    /// sibling is an internal node (no collapse) instead of an opaque hash (ambiguous -> missing).
    fn tree(&self, o: &mut Vec<u8>, lo: usize, hi: usize, d: usize, keys: &[H], sib: bool) {
        match hi - lo {
            0 => o.push(0),
            1 => {
                // a key whose path ends at ANOTHER leaf needs that leaf verified (exclusion / split, R14-C1);
                // so does a single-leaf sibling of a path: a deletion on the path may lift it to where a later
                // insertion must split it
                if sib || keys.iter().any(|k| *k != self.leaves[lo].0) {
                    let (kl, st) = &self.strs[lo];
                    o.push(4);
                    o.extend_from_slice(&(*kl as u16).to_le_bytes());
                    o.extend_from_slice(&st[..*kl]);
                    o.extend_from_slice(&((st.len() - kl) as u16).to_le_bytes());
                    o.extend_from_slice(&st[*kl..]);
                } else {
                    o.push(2);
                    o.extend_from_slice(&self.leaves[lo].0);
                    o.extend_from_slice(&self.leaves[lo].1);
                }
            }
            _ => {
                let mid = lo + self.leaves[lo..hi].partition_point(|(k, _)| kbit(k, d) == 0);
                if keys.is_empty() && !sib {
                    o.push(1);
                    o.extend_from_slice(&self.range_hash(lo, hi, d));
                    return;
                }
                let km = keys.partition_point(|k| kbit(k, d) == 0);
                o.push(3);
                self.tree(o, lo, mid, d + 1, &keys[..km], !keys.is_empty() && km == 0);
                self.tree(o, mid, hi, d + 1, &keys[km..], !keys.is_empty() && km == keys.len());
            }
        }
    }
}
