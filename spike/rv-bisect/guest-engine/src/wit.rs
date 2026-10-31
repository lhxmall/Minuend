//! MNWIT1 — incremental witness commitment (spike proposal, NOT the fix/47-all consensus format).
//!
//! A compact sparse Merkle tree (binary, MSB-first over a 256-bit key) whose leaves are the SAME
//! strings upstream `minuend_state::wit_leaves` produces (`acct:`, `pos:`, `ord:`, `band:`, `meta:`;
//! `adr:`/`adrx:`/`dep:`/`obond:` follow the same rule but are not modelled by the pilot).
//! Spec (docs/rv-dispute-design.md §7.3):
//!   kid(leaf)  = identity prefix of the leaf string: `acct:<hex id>`, `pos:<hex id>:<market>`,
//!                `ord:<hex order id>`, `band:<market>`, `meta:<market>` (adr:<addr>, adrx:<hex>,
//!                dep:<b64>, obond:<hex>)
//!   key        = sha256("~K1:" || kid)                       (32 bytes; path = bits MSB first)
//!   leaf hash  = sha256("~L1:" || hex(key) || ":" || leaf)   (hex lowercase, 64 chars)
//!   node hash  = sha256("~N1:" || b64(left) || b64(right))   (b64 = standard base64, 44 chars)
//!   EMPTY      = 32 zero bytes (b64 "AAAA…A="); an empty subtree is EMPTY, a subtree holding
//!                exactly ONE leaf is that leaf's hash (collapsed, at the shallowest depth),
//!                any other subtree is node(left, right). Root of the empty tree = EMPTY.
//! The shape (hence the root) is a pure function of the leaf set: independent of insertion
//! history. Only paths of touched leaves are rehashed per unit.
use crate::account::Account;
use crate::state::ChainState;
use crate::types::*;
use crate::Order;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;
use sha2::{Digest, Sha256};

pub type H = [u8; 32];
pub const EMPTY: H = [0u8; 32];

/// Loop round 2 (W2): consensus bound on the proof depth (number of siblings) of any leaf a
/// *checked* insertion creates. A unit that would insert an `acct:` key (new account), its order's
/// `ord:` key, or its own `pos:` key for the order's market (account without a position there) at a
/// depth > MAX_WIT_DEPTH is rejected (event code `WIT_DEPTH_CODE`) before it executes; the depth an
/// insertion gets is 1 + the common-prefix length with the closest existing key (or the depth of the
/// empty slot it fills). Pushing a key past 64 bits needs ~2^64 / n work against the n existing keys
/// and only gets the grinder's own unit rejected; making an *unchecked* side-effect insertion (a
/// maker's first `pos:` leaf at a fill) or a victim's future key deep needs a targeted 2^64 preimage
/// prefix. The AA verifier therefore unrolls exactly MAX_WIT_DEPTH levels (docs §7.5).
#[cfg(not(feature = "depth8"))]
pub const MAX_WIT_DEPTH: usize = 64;
/// test build: small bound so grinding on a laptop exercises the rule
#[cfg(feature = "depth8")]
pub const MAX_WIT_DEPTH: usize = 8;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub fn b64_32(h: &H) -> [u8; 44] {
    let mut o = [b'='; 44];
    let mut k = 0;
    let mut i = 0;
    while i + 3 <= 32 {
        let n = ((h[i] as u32) << 16) | ((h[i + 1] as u32) << 8) | h[i + 2] as u32;
        o[k] = B64[(n >> 18) as usize & 63];
        o[k + 1] = B64[(n >> 12) as usize & 63];
        o[k + 2] = B64[(n >> 6) as usize & 63];
        o[k + 3] = B64[n as usize & 63];
        i += 3;
        k += 4;
    }
    let n = ((h[30] as u32) << 16) | ((h[31] as u32) << 8);
    o[40] = B64[(n >> 18) as usize & 63];
    o[41] = B64[(n >> 12) as usize & 63];
    o[42] = B64[(n >> 6) as usize & 63];
    o
}
const HEX: &[u8; 16] = b"0123456789abcdef";
pub fn hex32(b: &[u8; 32]) -> [u8; 64] {
    let mut o = [0u8; 64];
    for i in 0..32 {
        o[2 * i] = HEX[(b[i] >> 4) as usize];
        o[2 * i + 1] = HEX[(b[i] & 15) as usize];
    }
    o
}

/// Fixed stack buffer for one leaf string (no heap per leaf).
pub struct Buf {
    pub b: [u8; 384],
    pub n: usize,
    /// length of the identity prefix (kid)
    pub kid: usize,
}
impl Buf {
    pub fn new() -> Self {
        Buf { b: [0; 384], n: 0, kid: 0 }
    }
    fn raw(&mut self, s: &[u8]) {
        self.b[self.n..self.n + s.len()].copy_from_slice(s);
        self.n += s.len();
    }
    fn hex(&mut self, b: &[u8; 32]) {
        let h = hex32(b);
        self.raw(&h);
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.b[..self.n]
    }
    fn mark_kid(&mut self) {
        self.kid = self.n;
    }
}
impl Write for Buf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.raw(s.as_bytes());
        Ok(())
    }
}

// ---- leaf strings: byte-identical to minuend_state::wit_leaves @ 20326c0 ----
pub fn acct_leaf(b: &mut Buf, id: &AccountId, collateral: Usd, perp: u128, w: i128) {
    b.n = 0;
    b.raw(b"acct:");
    b.hex(&id.0);
    b.mark_kid();
    let _ = write!(b, ":{}:{}:{}", collateral, perp, w);
}
pub fn pos_leaf(b: &mut Buf, id: &AccountId, m: MarketId, qty: i64, entry: Price, isolated: bool, bucket: Usd) {
    b.n = 0;
    b.raw(b"pos:");
    b.hex(&id.0);
    let _ = write!(b, ":{}", m.0);
    b.mark_kid();
    let _ = write!(b, ":{}:{}:{}:{}", qty, entry, if isolated { 1 } else { 0 }, bucket);
}
pub fn ord_leaf(b: &mut Buf, o: &Order) {
    b.n = 0;
    b.raw(b"ord:");
    b.hex(&o.id.0);
    b.mark_kid();
    let _ = write!(b, ":{}:{}:{}:{}:{}:", o.market.0, o.side.as_u8(), o.price, o.seq, o.remaining);
    b.hex(&o.account.0);
    let _ = write!(b, ":{}:{}", if o.isolated { 1 } else { 0 }, o.margin_left);
}
pub fn band_leaf(b: &mut Buf, m: MarketId, p: &MarketParams) {
    b.n = 0;
    let _ = write!(b, "band:{}", m.0);
    b.mark_kid();
    let _ = write!(b, ":{}:{}", p.min_price, p.max_price);
}
pub fn meta_leaf(b: &mut Buf, m: MarketId, p: &MarketParams, mark: Price) {
    b.n = 0;
    let _ = write!(b, "meta:{}", m.0);
    b.mark_kid();
    let _ = write!(
        b,
        ":{}:{}:{}:{}:{}:{}:{}:{}:{}",
        p.tick_size,
        p.im_bps,
        p.mm_bps,
        p.taker_fee_bps,
        p.keeper_reward_bps,
        if p.delisted { 1 } else { 0 },
        mark,
        p.usd_per_unit,
        p.funding_cap_bps
    );
}

pub fn key_of(kid: &[u8]) -> H {
    let mut h = Sha256::new();
    h.update(b"~K1:");
    h.update(kid);
    h.finalize().into()
}
pub fn leaf_hash(key: &H, leaf: &[u8]) -> H {
    let mut h = Sha256::new();
    h.update(b"~L1:");
    h.update(hex32(key));
    h.update(b":");
    h.update(leaf);
    h.finalize().into()
}
pub fn node_hash(l: &H, r: &H) -> H {
    let mut h = Sha256::new();
    h.update(b"~N1:");
    h.update(b64_32(l));
    h.update(b64_32(r));
    h.finalize().into()
}
/// MNWIT1 keys of the kids a unit can create (W2 depth rule).
pub fn acct_key(id: &AccountId) -> H {
    let mut b = Buf::new();
    acct_leaf(&mut b, id, 0, 0, 0);
    key_of(&b.b[..b.kid])
}
pub fn pos_key(id: &AccountId, m: MarketId) -> H {
    let mut b = Buf::new();
    pos_leaf(&mut b, id, m, 0, 0, false, 0);
    key_of(&b.b[..b.kid])
}
pub fn ord_key(oid: &OrderId) -> H {
    let mut b = Buf::new();
    b.raw(b"ord:");
    b.hex(&oid.0);
    b.mark_kid();
    key_of(&b.b[..b.kid])
}

/// (key, leaf hash) of the leaf in `b`.
pub fn key_and_hash(b: &Buf) -> (H, H) {
    let k = key_of(&b.b[..b.kid]);
    (k, leaf_hash(&k, b.as_bytes()))
}

// ---- compact sparse Merkle tree (arena) ----
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum R {
    E,
    L(u32),
    N(u32),
}
#[derive(Clone, Debug)]
struct Leaf {
    key: H,
    lh: H,
}
#[derive(Clone, Debug)]
struct Node {
    ch: [R; 2],
    h: H,
    dirty: bool,
}
#[derive(Clone, Debug)]
pub struct Smt {
    root: R,
    leaves: Vec<Leaf>,
    nodes: Vec<Node>,
    free_l: Vec<u32>,
    free_n: Vec<u32>,
    /// number of leaves
    pub count: u32,
    /// node hashes computed (stats)
    pub node_hashes: u64,
}
#[inline]
fn bit(k: &H, d: usize) -> usize {
    ((k[d >> 3] >> (7 - (d & 7))) & 1) as usize
}
impl Default for Smt {
    fn default() -> Self {
        Self::new()
    }
}
impl Smt {
    pub fn new() -> Self {
        Smt { root: R::E, leaves: Vec::new(), nodes: Vec::new(), free_l: Vec::new(), free_n: Vec::new(), count: 0, node_hashes: 0 }
    }
    fn new_leaf(&mut self, key: H, lh: H) -> u32 {
        self.count += 1;
        if let Some(i) = self.free_l.pop() {
            self.leaves[i as usize] = Leaf { key, lh };
            i
        } else {
            self.leaves.push(Leaf { key, lh });
            (self.leaves.len() - 1) as u32
        }
    }
    fn new_node(&mut self, ch: [R; 2]) -> u32 {
        let n = Node { ch, h: EMPTY, dirty: true };
        if let Some(i) = self.free_n.pop() {
            self.nodes[i as usize] = n;
            i
        } else {
            self.nodes.push(n);
            (self.nodes.len() - 1) as u32
        }
    }
    pub fn get(&self, key: &H) -> Option<H> {
        let mut r = self.root;
        let mut d = 0;
        loop {
            match r {
                R::E => return None,
                R::L(i) => {
                    let l = &self.leaves[i as usize];
                    return if &l.key == key { Some(l.lh) } else { None };
                }
                R::N(n) => {
                    r = self.nodes[n as usize].ch[bit(key, d)];
                    d += 1;
                }
            }
        }
    }
    /// Depth (proof length) a NEW leaf with `key` would get if inserted now; None if the key is
    /// already present (an update does not change the shape).
    pub fn insert_depth(&self, key: &H) -> Option<usize> {
        let mut r = self.root;
        let mut d = 0;
        loop {
            match r {
                R::E => return Some(d),
                R::L(i) => {
                    let k2 = &self.leaves[i as usize].key;
                    if k2 == key {
                        return None;
                    }
                    let mut c = d;
                    while c < 256 && bit(k2, c) == bit(key, c) {
                        c += 1;
                    }
                    return Some(c + 1);
                }
                R::N(n) => {
                    r = self.nodes[n as usize].ch[bit(key, d)];
                    d += 1;
                }
            }
        }
    }
    /// Max depth over all leaves (stats / tests).
    pub fn max_depth(&self) -> usize {
        fn go(t: &Smt, r: R, d: usize) -> usize {
            match r {
                R::E => 0,
                R::L(_) => d,
                R::N(n) => {
                    let [a, b] = t.nodes[n as usize].ch;
                    go(t, a, d + 1).max(go(t, b, d + 1))
                }
            }
        }
        go(self, self.root, 0)
    }
    /// Insert or update. No-op (no dirty path) when the leaf hash is unchanged.
    pub fn set(&mut self, key: H, lh: H) {
        if self.get(&key) == Some(lh) {
            return;
        }
        let r = self.root;
        self.root = self.ins(r, 0, &key, &lh);
    }
    fn ins(&mut self, r: R, d: usize, key: &H, lh: &H) -> R {
        match r {
            R::E => R::L(self.new_leaf(*key, *lh)),
            R::L(i) => {
                if &self.leaves[i as usize].key == key {
                    self.leaves[i as usize].lh = *lh;
                    R::L(i)
                } else {
                    let j = self.new_leaf(*key, *lh);
                    self.split(d, i, j)
                }
            }
            R::N(n) => {
                let b = bit(key, d);
                let c = self.nodes[n as usize].ch[b];
                let c2 = self.ins(c, d + 1, key, lh);
                let nd = &mut self.nodes[n as usize];
                nd.ch[b] = c2;
                nd.dirty = true;
                R::N(n)
            }
        }
    }
    fn split(&mut self, d: usize, old: u32, new: u32) -> R {
        assert!(d < 256, "key collision");
        let bo = bit(&self.leaves[old as usize].key, d);
        let bn = bit(&self.leaves[new as usize].key, d);
        let mut ch = [R::E, R::E];
        if bo != bn {
            ch[bo] = R::L(old);
            ch[bn] = R::L(new);
        } else {
            ch[bo] = self.split(d + 1, old, new);
        }
        R::N(self.new_node(ch))
    }
    pub fn remove(&mut self, key: &H) {
        if self.get(key).is_none() {
            return;
        }
        let r = self.root;
        self.root = self.del(r, 0, key);
    }
    fn del(&mut self, r: R, d: usize, key: &H) -> R {
        match r {
            R::E => R::E,
            R::L(i) => {
                if &self.leaves[i as usize].key == key {
                    self.free_l.push(i);
                    self.count -= 1;
                    R::E
                } else {
                    r
                }
            }
            R::N(n) => {
                let b = bit(key, d);
                let c = self.nodes[n as usize].ch[b];
                let c2 = self.del(c, d + 1, key);
                let nd = &mut self.nodes[n as usize];
                nd.ch[b] = c2;
                nd.dirty = true;
                // keep the shape canonical: a subtree with one leaf collapses to that leaf
                match nd.ch {
                    [R::E, R::E] => {
                        self.free_n.push(n);
                        R::E
                    }
                    [R::L(x), R::E] | [R::E, R::L(x)] => {
                        self.free_n.push(n);
                        R::L(x)
                    }
                    _ => R::N(n),
                }
            }
        }
    }
    fn hash_of(&mut self, r: R) -> H {
        match r {
            R::E => EMPTY,
            R::L(i) => self.leaves[i as usize].lh,
            R::N(n) => {
                if self.nodes[n as usize].dirty {
                    let [a, b] = self.nodes[n as usize].ch;
                    let ha = self.hash_of(a);
                    let hb = self.hash_of(b);
                    self.nodes[n as usize].h = node_hash(&ha, &hb);
                    self.nodes[n as usize].dirty = false;
                    self.node_hashes += 1;
                }
                self.nodes[n as usize].h
            }
        }
    }
    /// Recompute only dirty paths and return the root.
    pub fn root(&mut self) -> H {
        let r = self.root;
        self.hash_of(r)
    }
}

/// Keys touched since the last commit (filled by the state's mutation hooks).
#[derive(Clone, Debug, Default)]
pub struct WitDirty {
    pub accounts: BTreeSet<AccountId>,
    pub orders: BTreeSet<(MarketId, OrderId)>,
    pub markets: BTreeSet<MarketId>,
}
impl WitDirty {
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty() && self.orders.is_empty() && self.markets.is_empty()
    }
}

/// Incremental commitment over a ChainState.
#[derive(Clone, Debug, Default)]
pub struct Wit {
    pub smt: Smt,
    /// markets with a `pos:` leaf per account (to delete closed positions)
    pos_index: BTreeMap<AccountId, Vec<MarketId>>,
    /// leaves rehashed (stats)
    pub leaf_updates: u64,
}

fn put(smt: &mut Smt, b: &Buf, n: &mut u64) {
    let (k, lh) = key_and_hash(b);
    smt.set(k, lh);
    *n += 1;
}

impl Wit {
    pub fn from_state(s: &ChainState) -> Self {
        let mut w = Wit::default();
        let mut d = WitDirty::default();
        d.accounts.extend(s.accounts.keys().copied());
        for (m, book) in &s.books {
            for o in book.live_orders() {
                d.orders.insert((*m, o.id));
            }
        }
        d.markets.extend(s.markets.keys().copied());
        w.apply(s, &d);
        w
    }
    /// Re-derive the leaves of every dirty key from `s` and update the tree.
    pub fn apply(&mut self, s: &ChainState, d: &WitDirty) {
        let mut b = Buf::new();
        for id in &d.accounts {
            let old = self.pos_index.remove(id).unwrap_or_default();
            match s.accounts.get(id) {
                // PILOT: perp_balances / withdrawn_total are not modelled (always 0 here); upstream
                // also gives an acct: leaf to ids that only hold PERP or W.
                Some(a) => {
                    acct_leaf(&mut b, id, a.collateral, 0, 0);
                    put(&mut self.smt, &b, &mut self.leaf_updates);
                    let cur = self.put_positions(&mut b, a);
                    for m in old.iter().filter(|m| !cur.contains(m)) {
                        pos_leaf(&mut b, id, *m, 0, 0, false, 0);
                        self.smt.remove(&key_of(&b.b[..b.kid]));
                    }
                    if !cur.is_empty() {
                        self.pos_index.insert(*id, cur);
                    }
                }
                None => {
                    acct_leaf(&mut b, id, 0, 0, 0);
                    self.smt.remove(&key_of(&b.b[..b.kid]));
                    for m in &old {
                        pos_leaf(&mut b, id, *m, 0, 0, false, 0);
                        self.smt.remove(&key_of(&b.b[..b.kid]));
                    }
                }
            }
        }
        for (m, oid) in &d.orders {
            match s.books.get(m).and_then(|bk| bk.get(*oid)).filter(|o| o.remaining > 0) {
                Some(o) => {
                    ord_leaf(&mut b, o);
                    put(&mut self.smt, &b, &mut self.leaf_updates);
                }
                None => {
                    b.n = 0;
                    b.raw(b"ord:");
                    b.hex(&oid.0);
                    b.mark_kid();
                    self.smt.remove(&key_of(&b.b[..b.kid]));
                }
            }
        }
        for m in &d.markets {
            match s.markets.get(m) {
                Some(p) => {
                    band_leaf(&mut b, *m, p);
                    put(&mut self.smt, &b, &mut self.leaf_updates);
                    meta_leaf(&mut b, *m, p, s.marks.get(m).copied().unwrap_or(0));
                    put(&mut self.smt, &b, &mut self.leaf_updates);
                }
                None => {
                    band_leaf(&mut b, *m, &crate::types::genesis_params());
                    self.smt.remove(&key_of(&b.b[..b.kid]));
                    meta_leaf(&mut b, *m, &crate::types::genesis_params(), 0);
                    self.smt.remove(&key_of(&b.b[..b.kid]));
                }
            }
        }
    }
    fn put_positions(&mut self, b: &mut Buf, a: &Account) -> Vec<MarketId> {
        let mut cur = Vec::new();
        for (m, p) in &a.positions {
            let bucket = a.isolated_margin.get(m).copied().unwrap_or(0);
            pos_leaf(b, &a.id, *m, p.qty, p.entry_price, p.isolated, bucket);
            put(&mut self.smt, b, &mut self.leaf_updates);
            cur.push(*m);
        }
        cur
    }
    /// Per-unit commit: drain the state's dirty set, update touched leaves, return the root.
    pub fn commit(&mut self, s: &mut ChainState) -> H {
        let d = core::mem::take(&mut s.wit_dirty);
        if !d.is_empty() {
            self.apply(s, &d);
        }
        self.smt.root()
    }
    pub fn root(&mut self) -> H {
        self.smt.root()
    }
}

/// Every leaf string of the pilot's state (unsorted), for from-scratch references.
pub fn all_leaves(s: &ChainState) -> Vec<String> {
    let mut out = Vec::new();
    let mut b = Buf::new();
    let mut push = |b: &Buf| out.push(String::from(core::str::from_utf8(b.as_bytes()).unwrap()));
    for (id, a) in &s.accounts {
        acct_leaf(&mut b, id, a.collateral, 0, 0);
        push(&b);
        for (m, p) in &a.positions {
            pos_leaf(&mut b, id, *m, p.qty, p.entry_price, p.isolated, a.isolated_margin.get(m).copied().unwrap_or(0));
            push(&b);
        }
    }
    for book in s.books.values() {
        for o in book.live_orders() {
            ord_leaf(&mut b, o);
            push(&b);
        }
    }
    for (m, p) in &s.markets {
        band_leaf(&mut b, *m, p);
        push(&b);
        meta_leaf(&mut b, *m, p, s.marks.get(m).copied().unwrap_or(0));
        push(&b);
    }
    out
}

/// Legacy (fix/47-all) witness root over the pilot's leaves: sort + `~:end` sentinel +
/// Obyte merkle (base64 string domain). Used only to measure the per-unit cost being replaced.
pub fn legacy_root(s: &ChainState) -> H {
    let mut leaves = all_leaves(s);
    leaves.push(String::from("~:end"));
    leaves.sort();
    let mut level: Vec<[u8; 44]> = leaves.iter().map(|l| b64_32(&Sha256::digest(l.as_bytes()).into())).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let j = if i + 1 < level.len() { i + 1 } else { i };
            let mut h = Sha256::new();
            h.update(level[i]);
            h.update(level[j]);
            next.push(b64_32(&h.finalize().into()));
            i += 2;
        }
        level = next;
    }
    // return the raw digest behind the base64 root
    let mut out = [0u8; 32];
    b64_decode_32(&level[0], &mut out);
    out
}
fn b64_decode_32(s: &[u8; 44], out: &mut [u8; 32]) {
    let v = |c: u8| B64.iter().position(|&x| x == c).unwrap_or(0) as u32;
    let mut k = 0;
    for q in 0..11 {
        let n = (v(s[4 * q]) << 18) | (v(s[4 * q + 1]) << 12) | (v(s[4 * q + 2]) << 6) | v(s[4 * q + 3]);
        for (t, sh) in [16, 8, 0].iter().enumerate() {
            if k + t < 32 {
                out[k + t] = (n >> sh) as u8;
            }
        }
        k += 3;
    }
}
