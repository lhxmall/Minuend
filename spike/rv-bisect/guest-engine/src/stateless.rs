//! Loop round 14 (R4-H1 production direction): STATELESS (witness-fed) guest prototype, feature `stateless`.
//!
//! Design: docs/rv-stateless-guest.md. The session guest keeps the whole engine state in guest memory
//! between heights (hence MAX_STATE_ACCOUNTS / MAX_STATE_MARKETS). Here a segment's guest receives only
//! the leaves its units touch, with MNWIT-S inclusion / exclusion proofs (a pruned compact SMT) against
//! the segment's start root, runs the units on that partial state with completeness guards, and
//! recomputes the end root from the updated leaves + the pruned tree. No session; global caps on the aggregate
//! leaf gcnt:0 (round 22).
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
/// round 17: set by the engine when a liquidation enters its ADL remainder (engine.rs liquidate_book_path); cleared
/// before every stateless unit, checked after it -- whatever the unit's result (an ADL fill, no candidate among the
/// loaded holders, or an error of the ADL leg): the unit is unsupported (design §12.2)
pub static mut SL_ADL_REACHED: bool = false;
/// R14-H2 fix: the witness's claimed start root is not the chain's last good end root (main.rs keeps it in the carried
/// memory: the rollup builds s0(h) on the final memory of h-1)
pub const ST_SL_BADROOT: u32 = 15;
/// round 15 (R15-M1): a migration snapshot violates a per-object bound of the stateless image (a price level with more
/// than SL_MAX_LEVEL_ORDERS orders, an account with more than SL_MAX_POS markets of exposure): such an object could
/// never be loaded afterwards (its market / account would halt), so the migration is refused
pub const ST_SL_MIG_BOUNDS: u32 = 16;
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
/// round 16: per-account bound of live commits (revealed ones count until their TTL, as in the session); a Commit by an
/// account at the bound is refused (code 19) -- keeps the `acmt:` record loadable (the session's global
/// MAX_STATE_COMMITS cap does not exist in the stateless image)
pub const SL_MAX_ACMT: usize = 64;
/// round 22 (R16-I3 / R17-I3): the GLOBAL caps of the stateless lineage -- the session's `state_cap_ok` totals (account
/// map, PERP ledger ids: one `cap` for both; markets; oracle bonds) enforced on the aggregate leaf `gcnt:0`, kept by
/// delta (design §5). Consensus constants of the lineage; the production values lift the session's memory bounds
/// (MAX_STATE_ACCOUNTS 256 / MAX_STATE_MARKETS 16 / MAX_STATE_ORACLES 32). R22-M1: the Account map / PERP ledger is
/// NOT capped in production (`u64::MAX`): ids are never removed upstream, so a hard cap is a permanent lockout of new
/// users that costs an attacker only one dust Deposit per slot (the session's 256 has the same flaw, pilot limit);
/// listings (burned fee) and oracle bonds (bonded PERP) are capped. The counts are still kept (export precondition,
/// R16-I2: a lineage state fits the session image iff its counts are within the session's caps). The session's
/// Round 23 (R22-I2 / R16-I1): commits expire EAGERLY (per-TTL groups `cexp:<u>`, the height hook deletes the expired
/// `cmt:` leaves), so the live-commit count is a fifth `gcnt:0` field and the session's MAX_STATE_COMMITS rule runs on
/// it (`commits`). R23-M1: in production the lineage does NOT cap the total (`u64::MAX`; the session's 1024 would be a
/// renewable global commit-reveal lockout for 1024 x COMMIT_BOND_PERP of bonded PERP and 1024 unit fees per
/// COMMIT_TTL_HEIGHTS heights). R23-H1: the total must still bound the hook -- a run that fails (status != 0) leaves the
/// root but counts as a height, so the next hook can drop up to COMMIT_TTL_HEIGHTS + 1 groups, i.e. EVERY live commit,
/// and a commit set larger than the loader's record bounds would make that height unprovable (lineage halt). Production:
/// `commits` = SL_MAX_CMT_LIVE (4096, 4x the session: the lockout cost) with the commit record sections bounded by
/// SL_MAX_CMT_RECS = 2 x that (every expiring record + owner index, plus the units' own); `commit_group` = 1024 per TTL
/// height bounds the normal one-step hook. With the session's values (host tests) both images agree (the session never
/// holds more than 1024 commits, so the group bound never binds there). The per-account SL_MAX_ACMT bound stays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlCaps {
    pub accounts: u64,
    pub markets: u64,
    pub oracles: u64,
    /// round 23: live commits (the session's MAX_STATE_COMMITS)
    pub commits: u64,
    /// round 23 (R23-M1): live commits per TTL height (one expiry group)
    pub commit_group: u64,
}
pub const SL_CAPS_PROD: SlCaps = SlCaps { accounts: u64::MAX, markets: 1 << 16, oracles: 1 << 12, commits: SL_MAX_CMT_LIVE as u64, commit_group: crate::MAX_STATE_COMMITS as u64 };
/// round 23 (R23-H1): the production bound on live commits = what one hook can always expire
pub const SL_MAX_CMT_LIVE: usize = 4096;
/// round 23 (R23-H1): loader bound of the commit index / single commit record sections (u16 counts)
pub const SL_MAX_CMT_RECS: usize = 2 * SL_MAX_CMT_LIVE;
const _: () = assert!(SL_CAPS_PROD.commits as usize <= SL_MAX_CMT_LIVE && SL_MAX_CMT_RECS <= u16::MAX as usize && SL_CAPS_PROD.commit_group as usize <= SL_MAX_CEXP && SL_MAX_CMT_LIVE <= SL_MAX_CEXP);
/// round 23: a Commit's TTL is in the live range the engine accepts (height, height + COMMIT_TTL_HEIGHTS]
fn ttl_ok(s: &ChainState, ttl: u64) -> bool {
    ttl > s.height && ttl <= s.height.saturating_add(COMMIT_TTL_HEIGHTS)
}
/// round 23: the size of TTL group u now (loaded group + the commits created in the run)
fn cexp_now(sl: &Sl, s: &ChainState, u: u64) -> u64 {
    let g0 = sl.cx.get(&u).map(|g| g.len()).unwrap_or(0) as u64;
    g0 + s.commits.iter().filter(|(h, e)| e.ttl_height == u && !sl.cmt0.contains(*h)).count() as u64
}
/// round 23: loader bound of one expiry group `cexp:<u>` (hashes) and of the groups one witness may carry
pub const SL_MAX_CEXP: usize = 4096;
pub const SL_MAX_CEXP_GROUPS: usize = 64;
/// the lineage's caps (the guest never writes it; host tests set the session's values to compare the two images at
/// the caps)
pub static mut SL_CAPS: SlCaps = SL_CAPS_PROD;
fn sl_caps() -> SlCaps {
    unsafe { SL_CAPS }
}

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
/// round 15: digest of an account's position markets (ascending ids, u32 LE each)
pub fn apos_digest(mkts: &[u32]) -> H {
    let mut h = Sha256::new();
    for m in mkts {
        h.update(m.to_le_bytes());
    }
    h.finalize().into()
}
/// `apos:<id>:<flags>:<npos>:<sha256(markets)>` -- fixed length. flags: bit0 Account entry, bit1 perp_balances
/// entry, bit2 withdrawn_total entry. Round 15 (R15-H1): the round-14 form listed the markets in decimal and
/// overflowed the 384-byte leaf buffer (guest panic) for an account with many positions in high market ids; the
/// digest form also lets a LIGHT record (R14-M2) verify the leaf without the position records.
pub fn apos_leaf_d(b: &mut Buf, id: &AccountId, flags: u8, npos: u32, dg: &H) {
    apos_kid(b, id);
    let _ = write!(b, ":{}:{}:", flags, npos);
    hexw(b, dg);
}
pub fn apos_leaf(b: &mut Buf, id: &AccountId, flags: u8, mkts: &[u32]) {
    apos_leaf_d(b, id, flags, mkts.len() as u32, &apos_digest(mkts));
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
fn idw(b: &mut Buf, x: Option<OrderId>) {
    match x {
        Some(o) => hexw(b, &o.0),
        None => {
            let _ = write!(b, "-");
        }
    }
}
/// round 16 (linked-FIFO levels): `lvl:<m>:<side>:<price>:<head id>:<tail id>` -- the level's ends only; the FIFO is
/// the chain of `olk:` links, so a level is never loaded whole (round 14/15: `:<n>:<sha256(ids)>`, whole-level loads,
/// the 4096-order level cap R14-M1 and the migration bound R15-M1)
pub fn lvl_leaf(b: &mut Buf, m: MarketId, side: u8, price: Price, head: OrderId, tail: OrderId) {
    lvl_kid(b, m, side, price);
    let _ = write!(b, ":");
    hexw(b, &head.0);
    let _ = write!(b, ":");
    hexw(b, &tail.0);
}
pub fn olk_kid(b: &mut Buf, id: &OrderId) {
    b.n = 0;
    let _ = write!(b, "olk:");
    hexw(b, &id.0);
    mark(b);
}
/// round 16: `olk:<order id>:<prev id | ->:<next id | ->` -- a live order's FIFO neighbours in its level
pub fn olk_leaf(b: &mut Buf, id: &OrderId, prev: Option<OrderId>, next: Option<OrderId>) {
    olk_kid(b, id);
    let _ = write!(b, ":");
    idw(b, prev);
    let _ = write!(b, ":");
    idw(b, next);
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
pub fn wdl_kid(b: &mut Buf, id: &AccountId) {
    b.n = 0;
    let _ = write!(b, "wdl:");
    hexw(b, &id.0);
    mark(b);
}
/// round 15: an account's withdrawal records (nonce, amount, pending, height), sorted by nonce (<= 64)
pub type WdlE = (u64, i128, bool, u64);
pub fn wdl_digest(es: &[WdlE]) -> H {
    let mut h = Sha256::new();
    for (n, a, p, ht) in es {
        h.update(n.to_le_bytes());
        h.update(a.to_le_bytes());
        h.update([*p as u8]);
        h.update(ht.to_le_bytes());
    }
    h.finalize().into()
}
/// `wdl:<id>:<n>:<sha256(entries)>` (absent = no withdrawal record). Session state never holds an expired record
/// (commit_height prunes); the stateless image reads only live records (height + REPLAY_WINDOW > height) and rewrites
/// the leaf only when the unit changed the live set (lazy pruning on touch; see design §11).
pub fn wdl_leaf(b: &mut Buf, id: &AccountId, es: &[WdlE]) {
    wdl_kid(b, id);
    let _ = write!(b, ":{}:", es.len());
    hexw(b, &wdl_digest(es));
}
fn wdl_of(s: &ChainState, id: &AccountId) -> Vec<WdlE> {
    s.withdrawals.range((*id, 0)..=(*id, u64::MAX)).map(|((_, n), w)| (*n, w.amount, w.pending, w.height)).collect()
}
// ---- round 16: PERP ledger / listing / commit-reveal leaves ----
pub fn perp_kid(b: &mut Buf) {
    b.n = 0;
    let _ = write!(b, "perp:0");
    mark(b);
}
/// `perp:0:<perp_supply>:<perp_burned>:<next_market_id>` (always present): the PERP ledger aggregates and the
/// market-id cursor (GovDeposit / GovWithdraw / CreateMarket read them; the session kept them only in memory)
pub fn perp_leaf(b: &mut Buf, supply: u128, burned: u128, next_market: u32) {
    perp_kid(b);
    let _ = write!(b, ":{}:{}:{}", supply, burned, next_market);
}
pub fn gcnt_kid(b: &mut Buf) {
    b.n = 0;
    let _ = write!(b, "gcnt:0");
    mark(b);
}
/// round 22: `gcnt:0:<accounts>:<PERP ids>:<markets>:<oracle bonds>:<commits>` (always present): the sizes of the
/// session maps its global caps count (`accounts`, `perp_balances`, `markets`, `oracle_bonds`; round 23: `commits`)
pub const GCNT_N: usize = 5;
pub type Gcnt = [u64; GCNT_N];
pub fn gcnt_leaf(b: &mut Buf, g: &Gcnt) {
    gcnt_kid(b);
    let _ = write!(b, ":{}:{}:{}:{}:{}", g[0], g[1], g[2], g[3], g[4]);
}
/// reference counts of a full state
pub fn gcnt_of(s: &ChainState) -> Gcnt {
    [s.accounts.len() as u64, s.perp_balances.len() as u64, s.markets.len() as u64, s.oracle_bonds.len() as u64, s.commits.len() as u64]
}
// ---- round 23: eager commit expiry (R16-I1 / R22-I2) ----
pub fn cexp_kid(b: &mut Buf, u: u64) {
    b.n = 0;
    let _ = write!(b, "cexp:{}", u);
    mark(b);
}
pub fn cexp_digest(hs: &[H]) -> H {
    let mut h = Sha256::new();
    for x in hs {
        h.update(x);
    }
    h.finalize().into()
}
/// round 23: `cexp:<u>:<n>:<sha256(commit hashes ascending)>` (absent = no live commit with ttl_height u): the expiry
/// group of TTL height u. Every live commit has ttl in [height, height + COMMIT_TTL_HEIGHTS] (Commit's TTL rule, the
/// height only grows, the hook drops ttl < height), so one hook from h0 to h1 > h0 reads at most
/// COMMIT_TTL_HEIGHTS + 1 groups (u in [h0, min(h1, h0 + COMMIT_TTL_HEIGHTS + 1))) -- no queue is needed
pub fn cexp_leaf(b: &mut Buf, u: u64, hs: &[H]) {
    cexp_kid(b, u);
    let _ = write!(b, ":{}:", hs.len());
    hexw(b, &cexp_digest(hs));
}
/// the expiry groups of a full state (hashes ascending: BTreeMap order)
pub fn cexp_groups(s: &ChainState) -> BTreeMap<u64, Vec<H>> {
    let mut g: BTreeMap<u64, Vec<H>> = BTreeMap::new();
    for (h, e) in &s.commits {
        g.entry(e.ttl_height).or_default().push(*h);
    }
    g
}
pub fn xsrc_kid(b: &mut Buf, id: &AccountId) {
    b.n = 0;
    let _ = write!(b, "xsrc:");
    hexw(b, &id.0);
    mark(b);
}
/// `xsrc:<id>:1`: membership in `external_sources` (a funding-market creator may push external prices)
pub fn xsrc_leaf(b: &mut Buf, id: &AccountId) {
    xsrc_kid(b, id);
    let _ = write!(b, ":1");
}
pub fn acmt_kid(b: &mut Buf, id: &AccountId) {
    b.n = 0;
    let _ = write!(b, "acmt:");
    hexw(b, &id.0);
    mark(b);
}
/// round 16: an account's commits (commit hash, ttl height), sorted by hash
pub type AcmtE = (H, u64);
pub fn acmt_digest(es: &[AcmtE]) -> H {
    let mut h = Sha256::new();
    for (c, t) in es {
        h.update(c);
        h.update(t.to_le_bytes());
    }
    h.finalize().into()
}
/// `acmt:<id>:<n>:<sha256(entries)>` (absent = no commit): the per-account commit index the commit-bond rule
/// (R7-M2: live commits of the author) and Commit's pending count read. Lazy expiry like `wdl:` (an entry is live
/// while ttl >= height); bounded per account by SL_MAX_ACMT (stateless rule).
pub fn acmt_leaf(b: &mut Buf, id: &AccountId, es: &[AcmtE]) {
    acmt_kid(b, id);
    let _ = write!(b, ":{}:", es.len());
    hexw(b, &acmt_digest(es));
}
pub fn acmt_of(s: &ChainState, id: &AccountId) -> Vec<AcmtE> {
    s.commits.iter().filter(|(_, e)| e.account == *id).map(|(h, e)| (*h, e.ttl_height)).collect()
}
// ---- loop round 18: governance (design §12.3, round-18 form) ----
/// one exception entry of an account: (proposal id, snapshot weight, voted)
pub type PexcE = (u64, u128, bool);
/// round 19 (R18-M1 fix): one exception entry lives in its proposal's exception sub-tree (a compact SMT of the same
/// form as MNWIT-S) as the leaf `pxe:<pid>:<acct>` -> `:<weight>:<voted>`; the sub-tree root is a field of `pglob:0`, so
/// a Finalize drops the whole sub-tree with the proposal's `pglob:` entry (O(1)) and no exception holder is loaded.
pub fn pxe_kid(b: &mut Buf, pid: u64, id: &AccountId) {
    b.n = 0;
    let _ = write!(b, "pxe:{}:", pid);
    hexw(b, &id.0);
    mark(b);
}
pub fn pxe_leaf(b: &mut Buf, pid: u64, id: &AccountId, w: u128, voted: bool) {
    pxe_kid(b, pid, id);
    let _ = write!(b, ":{}:{}", w, voted as u8);
}
/// (key, leaf hash, kid length, leaf string) of every leaf of each live proposal's exception sub-tree (reference),
/// sorted by key
pub fn pxe_sets(s: &ChainState, all: &BTreeMap<AccountId, Vec<PexcE>>) -> BTreeMap<u64, Vec<(H, H, usize, Vec<u8>)>> {
    let mut out: BTreeMap<u64, Vec<(H, H, usize, Vec<u8>)>> = s.proposals.keys().map(|k| (*k, Vec::new())).collect();
    let mut b = Buf::new();
    for (a, es) in all {
        for (pid, w, v) in es {
            pxe_leaf(&mut b, *pid, a, *w, *v);
            let (k, lh) = kh(&b);
            out.get_mut(pid).unwrap().push((k, lh, b.kid, b.as_bytes().to_vec()));
        }
    }
    for v in out.values_mut() {
        v.sort_by(|x, y| x.0.cmp(&y.0));
    }
    out
}
/// the exception list of `a` over the proposals of `s` (reference AND guest: in the stateless image the proposals map
/// is complete -- every live proposal is loaded with `pglob:` -- and their snapshot / voter sets hold `a` iff the
/// session's do, for every account whose `pexc:` record is loaded)
pub fn pexc_of(s: &ChainState, a: &AccountId) -> Vec<PexcE> {
    let bal = s.perp_balances.get(a).copied().unwrap_or(0);
    let mut v = Vec::new();
    for (id, p) in &s.proposals {
        let w = p.weight_snapshot.get(a).copied().unwrap_or(0);
        let voted = p.voted.contains(a);
        if voted || w != bal {
            v.push((*id, w, voted));
        }
    }
    v
}
/// every account's exception list (reference): candidates = voters, snapshot members, non-zero PERP holders
pub fn pexc_all(s: &ChainState) -> BTreeMap<AccountId, Vec<PexcE>> {
    let mut out = BTreeMap::new();
    if s.proposals.is_empty() {
        return out;
    }
    let mut cand: BTreeSet<AccountId> = s.perp_balances.iter().filter(|(_, b)| **b != 0).map(|(a, _)| *a).collect();
    for p in s.proposals.values() {
        cand.extend(p.voted.iter().copied());
        cand.extend(p.weight_snapshot.keys().copied());
    }
    for a in cand {
        let v = pexc_of(s, &a);
        if !v.is_empty() {
            out.insert(a, v);
        }
    }
    out
}
pub fn pglob_kid(b: &mut Buf) {
    b.n = 0;
    let _ = write!(b, "pglob:0");
    mark(b);
}
/// `pglob:0:<next proposal id>:<non-zero PERP holders>:<n live>:<sha256((id u64, xroot) by id)>` (always present):
/// the proposal cursor, the live-proposal set (cap 64) with each proposal's exception sub-tree root (round 19; round 18
/// carried an exception count here and per-account `pexc:` leaves), and the snapshot size a new proposal records
pub fn pglob_leaf(b: &mut Buf, next: u64, holders: u64, es: &[(u64, H)]) {
    pglob_kid(b);
    let mut h = Sha256::new();
    for (id, x) in es {
        h.update(id.to_le_bytes());
        h.update(x);
    }
    let d: H = h.finalize().into();
    let _ = write!(b, ":{}:{}:{}:", next, holders, es.len());
    hexw(b, &d);
}
pub fn perp_holders(s: &ChainState) -> u64 {
    s.perp_balances.values().filter(|b| **b != 0).count() as u64
}
/// (id, exception sub-tree root) of every live proposal (reference)
pub fn pglob_entries(s: &ChainState, all: &BTreeMap<AccountId, Vec<PexcE>>) -> Vec<(u64, H)> {
    pxe_sets(s, all)
        .into_iter()
        .map(|(id, v)| {
            let kv: Vec<(H, H)> = v.iter().map(|x| (x.0, x.1)).collect();
            (id, root_of_sorted(&kv))
        })
        .collect()
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
    let wids: BTreeSet<AccountId> = s.withdrawals.keys().map(|(a, _)| *a).collect();
    for id in &wids {
        wdl_leaf(&mut b, id, &wdl_of(s, id));
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
            lvl_leaf(&mut b, *m, sd, price, ids[0], ids[ids.len() - 1]);
            push(&b);
            for (k, id) in ids.iter().enumerate() {
                olk_leaf(&mut b, id, if k > 0 { Some(ids[k - 1]) } else { None }, ids.get(k + 1).copied());
                push(&b);
            }
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
    // round 16
    perp_leaf(&mut b, s.perp_supply, s.perp_burned, s.next_market_id);
    push(&b);
    // round 22
    gcnt_leaf(&mut b, &gcnt_of(s));
    push(&b);
    for id in &s.external_sources {
        xsrc_leaf(&mut b, id);
        push(&b);
    }
    #[cfg(feature = "govwit")]
    {
        let cids: BTreeSet<AccountId> = s.commits.values().map(|e| e.account).collect();
        for id in &cids {
            acmt_leaf(&mut b, id, &acmt_of(s, id));
            push(&b);
        }
        for (id, p) in &s.proposals {
            wit::prop_leaf(&mut b, *id, p);
            push(&b);
        }
        // round 18
        let all = pexc_all(s);
        pglob_leaf(&mut b, s.next_proposal_id, perp_holders(s), &pglob_entries(s, &all));
        push(&b);
        for (h, e) in &s.commits {
            wit::cmt_leaf(&mut b, h, e);
            push(&b);
        }
        // round 23: expiry groups
        for (u, hs) in &cexp_groups(s) {
            cexp_leaf(&mut b, *u, hs);
            push(&b);
        }
        for (a, n) in &s.seen_gov_nonces {
            wit::gnon_leaf(&mut b, a, *n);
            push(&b);
        }
    }
    // round 20: oracle leaves
    ora::leaves(s, push);
    // round 21: ADL rank sub-tree roots
    adl::leaves(s, push);
}
/// MNWIT-S root of a full state (reference). Round 16 (step 4): bulk build over the sorted leaf set -- one hash per
/// internal node of the compact tree (a single-leaf subtree is the leaf) instead of an incremental `Smt::set` per leaf
/// (path re-hash per insertion, ~depth x more node hashes); the guest's migration run computes its root this way.
pub fn s_root(s: &ChainState) -> H {
    let mut v = s_leaves(s);
    v.sort_unstable_by(|x, y| x.0.cmp(&y.0));
    v.dedup_by(|a, b| a.0 == b.0);
    root_of_sorted(&v)
}
/// compact-SMT root of sorted, distinct (key, leaf hash) pairs (same tree as wit::Smt)
pub fn root_of_sorted(v: &[(H, H)]) -> H {
    fn go(v: &[(H, H)], d: usize) -> H {
        match v.len() {
            0 => EMPTY,
            1 => v[0].1,
            _ => {
                let mid = v.partition_point(|(k, _)| kbit(k, d) == 0);
                let a = go(&v[..mid], d + 1);
                let b = go(&v[mid..], d + 1);
                wit::node_hash(&a, &b)
            }
        }
    }
    go(v, 0)
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
    /// round 21: the (key, account) of every tag-5 leaf of a rank sub-tree (adl.rs)
    pub rids: Vec<(H, [u8; 32])>,
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
        Self::decode_lim(r, SL_MAX_TREE_NODES)
    }
    /// round 19 (R19-L1): decode with a node budget -- the proposals' exception sub-trees share SL_MAX_TREE_NODES
    /// with the MNWIT-S tree (one heap bound for every tree of a witness)
    pub fn decode_lim(r: &mut Rd, lim: usize) -> Option<PTree> {
        let mut t = PTree { nodes: Vec::new(), root: P::E, node_hashes: 0, rids: Vec::new() };
        let mut path = [0u8; 32];
        t.root = t.dec(r, 0, &mut path, lim, false)?;
        Some(t)
    }
    /// round 21: a rank sub-tree (adl.rs): raw keys (not hashes of a kid), verified leaves as tag 5 = key32 + account
    /// id32 with key[8..32] == id[0..24] and leaf hash sha256("~R1:" || key || id). Tag 4 is not accepted here, tag 5
    /// nowhere else
    pub fn decode_raw(r: &mut Rd, lim: usize) -> Option<PTree> {
        let mut t = PTree { nodes: Vec::new(), root: P::E, node_hashes: 0, rids: Vec::new() };
        let mut path = [0u8; 32];
        t.root = t.dec(r, 0, &mut path, lim, true)?;
        Some(t)
    }
    fn dec(&mut self, r: &mut Rd, d: usize, path: &mut [u8; 32], lim: usize, raw: bool) -> Option<P> {
        if self.nodes.len() > lim {
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
            5 if raw => {
                let k = r.h32()?;
                let id = r.h32()?;
                if k[8..] != id[..24] {
                    return None;
                }
                for i in 0..d {
                    if kbit(&k, i) != kbit(path, i) {
                        return None;
                    }
                }
                self.rids.push((k, id));
                Some(P::L(k, adl::rleaf(&k, &AccountId(id)), true))
            }
            4 if !raw => {
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
                let a = self.dec(r, d + 1, path, lim, raw)?;
                path[d >> 3] |= m;
                let b = self.dec(r, d + 1, path, lim, raw)?;
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
    /// round 15 (R14-M2): the insurance account's LIGHT record (acct: leaf + apos: digest, no positions) -- all a
    /// Place's fee leg reads; Account(INSURANCE) (the full record) wins when both are needed
    Light(AccountId),
    Market(u32),
    Aord(AccountId),
    /// the order id: its level (if it exists) or its exclusion proof
    Order(OrderId),
    Level(u32, u8, Price),
    Bmp(u32, u8, u8, u64),
    /// a tree path (insertion / deletion / depth rule) for this MNWIT-S key
    Path(H),
    /// round 15: an account's withdrawal records (`wdl:`, present or proven absent)
    Wdl(AccountId),
    /// round 16: the `perp:0` record (PERP supply / burned, next market id)
    Perp,
    /// round 16: an account's governance nonce watermark (`gnon:`, present or proven absent)
    Gnon(AccountId),
    /// round 16: an account's `external_sources` membership (`xsrc:`)
    Xsrc(AccountId),
    /// round 16: an account's commit index (`acmt:`) with its commits' `cmt:` records
    Acmt(AccountId),
    /// round 16: one commit hash's `cmt:` record (present or proven absent)
    Cmt(H),
    /// round 18: `pglob:0` with every live proposal's `prop:` record
    Pglob,
    /// round 18: an account's exception list -- with its account record; round 19: its `pxe:` entry (present or proven
    /// absent) in every live proposal's exception sub-tree (brings `pglob:`)
    Pexc(AccountId),
    /// round 20 (oracle, §12.1): `oglob:0` (funding source, slash nonce, expiry queue ends; present or proven absent)
    Oglob,
    /// round 20: an account's bond record `ostk:` (present or proven absent)
    Ostk(AccountId),
    /// round 20: an oracle's market list `orm:` (present or proven absent)
    Orm(AccountId),
    /// round 20: a market's report set `orep:` (present or proven absent)
    Orep(u32),
    /// round 20: an oracle's report history in a market `ohist:` (present or proven absent)
    Ohist(u32, AccountId),
    /// round 20: a market's oracle config / TWAP rings / funding clock `omk:` (present or proven absent)
    Omk(u32),
    /// round 20: the expiry queue group of an unlock height `oexp:` (present or proven absent)
    Oexp(u64),
    /// round 21: the rank sub-tree of (market, sign) with its `adlr:` leaf (present or proven absent), leftmost path
    Adl(u32, u8),
    /// round 21: the leftmost path through the first k start keys of a rank sub-tree (after removals)
    AdlTop(u32, u8, u16),
    /// round 21: a rank sub-tree path to this key (removal / insertion)
    AdlKey(u32, u8, H),
    /// round 22: the `gcnt:0` record (global cap counts)
    Gcnt,
    /// round 23: the expiry group `cexp:<u>` of TTL height u (present or proven absent)
    Cexp(u64),
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
    /// round 22: membership flags at load (apos: bit0 Account entry, bit1 PERP entry; 0 = proven absent)
    f0: u8,
    /// markets of the start positions (pos leaves to delete if closed)
    start_pos: Vec<MarketId>,
    /// round 15 (R14-M2): a light record (insurance only): start flags, position count, position-market digest.
    /// Its positions are NOT in the partial state; the end root keeps its apos: leaf and touches no pos: / cseq:.
    light: Option<(u8, u32, H)>,
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
    /// round 15: loaded withdrawal record sets: account -> live records at load (what the ChainState holds)
    wdl: BTreeMap<AccountId, Vec<WdlE>>,
    /// round 16: `perp:0` loaded
    perp: bool,
    /// round 16: loaded gov nonce watermarks (0 = proven absent)
    gnon: BTreeMap<AccountId, u64>,
    /// round 16: loaded `external_sources` memberships
    xsrc: BTreeMap<AccountId, bool>,
    /// round 16: loaded commit indexes: account -> live entries at load (what the ChainState holds)
    acmt: BTreeMap<AccountId, Vec<AcmtE>>,
    /// round 16: commit hashes whose `cmt:` record was loaded (present, expired or proven absent)
    cmts: BTreeSet<H>,
    /// round 16: commit hashes in the partial state at load (live)
    cmt0: BTreeSet<H>,
    /// round 23: loaded commit indexes as committed (every entry, also the ones expiring at this run's hook)
    acmt_all: BTreeMap<AccountId, Vec<AcmtE>>,
    /// round 23: loaded single `cmt:` records that expire at this run's hook (ttl < the run's height)
    cmtx: BTreeMap<H, crate::state::CommitEntry>,
    /// round 23: loaded expiry groups: TTL height -> hashes at load (empty = proven absent)
    cx: BTreeMap<u64, Vec<H>>,
    /// round 18: `pglob:0` loaded: (non-zero PERP holders at load, live proposal -> exception sub-tree root at load)
    pglob: Option<(u64, BTreeMap<u64, H>)>,
    /// round 19: the loaded exception sub-tree of every live proposal (pruned to the loaded accounts' paths)
    xt: BTreeMap<u64, PTree>,
    /// round 18: loaded exception lists (as loaded)
    pexc: BTreeMap<AccountId, Vec<PexcE>>,
    /// round 18: proposal -> (voters at load, snapshot size, voters in the partial state at load); a proposal created in
    /// the segment gets (0, holders at creation, 0)
    pcnt: BTreeMap<u64, (usize, usize, usize)>,
    /// round 18: PERP balance at load of every loaded account
    bal0: BTreeMap<AccountId, u128>,
    /// round 20: the loaded oracle records (ora.rs)
    o: ora::Ora,
    /// round 21: the loaded rank sub-trees (adl.rs)
    adl: adl::Adl,
    /// round 22: `gcnt:0` loaded (the counts at load)
    gcnt: Option<Gcnt>,
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
/// round 20: the stateless oracle (design §12.1)
pub mod ora;
/// round 21: the stateless ADL remainder (design §12.2, rank sub-trees)
pub mod adl;
/// round 21: set by the engine with SL_ADL_REACHED: (market, sign of the ADL candidates: 0 long, 1 short)
pub static mut SL_ADL_SIDE: (u32, u8) = (0, 0);
/// round 20: set by state.rs when a unit reaches a funding transfer / the funding-rate peg (O(holders), R19-I1): the
/// unit is unsupported (cleared before every stateless unit, checked after it)
pub static mut SL_FUNDING_REACHED: bool = false;

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
fn load(w: &[u8], height: Option<u64>) -> Result<(Sl, ChainState, H), u32> {
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
        wdl: BTreeMap::new(),
        perp: false,
        gnon: BTreeMap::new(),
        xsrc: BTreeMap::new(),
        acmt: BTreeMap::new(),
        cmts: BTreeSet::new(),
        cmt0: BTreeSet::new(),
        acmt_all: BTreeMap::new(),
        cmtx: BTreeMap::new(),
        cx: BTreeMap::new(),
        pglob: None,
        xt: BTreeMap::new(),
        pexc: BTreeMap::new(),
        pcnt: BTreeMap::new(),
        bal0: BTreeMap::new(),
        o: ora::Ora::default(),
        adl: adl::Adl::default(),
        gcnt: None,
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
    sl.o.h0 = s.height;
    // round 15 height hook (lazy): a bound run (prod: run number = rollup height, like the session's bind_height)
    // moves the engine height first; every height-dependent record read below (withdrawal expiry) is filtered at
    // the new height, and nothing else is pruned eagerly (design §11 item 2)
    if let Some(h) = height {
        if h > s.height {
            s.height = h;
        }
    }
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
        let kind = bad!(r.u8());
        let id = AccountId(bad!(r.h32()));
        if sl.accts.contains_key(&id) || kind > 2 {
            return Err(ST_SL_BADWIT);
        }
        let present = kind != 0;
        let mut start_pos = Vec::new();
        let mut f0 = 0u8;
        if kind == 2 {
            // round 15 (R14-M2) light record: ONLY the insurance account (its positions are read by no supported op;
            // a light record of any other account would hide positions from risk checks)
            if id != INSURANCE_ACCOUNT {
                return Err(ST_SL_BADWIT);
            }
            let flags = bad!(r.u8());
            if flags & !7 != 0 || flags == 0 {
                return Err(ST_SL_BADWIT);
            }
            let coll = bad!(r.i128());
            let perp = bad!(r.u128());
            let wd = bad!(r.i128());
            let npos = bad!(r.u32());
            let dg = bad!(r.h32());
            if (flags & 1 == 0 && (npos > 0 || coll != 0)) || (flags & 2 == 0 && perp != 0) || (flags & 4 == 0 && wd != 0) {
                return Err(ST_SL_BADWIT);
            }
            wit::acct_leaf(&mut b, &id, coll, perp, wd);
            sl.check(&b, true)?;
            apos_leaf_d(&mut b, &id, flags, npos, &dg);
            sl.check(&b, true)?;
            if flags & 1 != 0 {
                let mut a = Account::new(id);
                a.collateral = coll;
                s.put_account(id, a);
            }
            if flags & 2 != 0 {
                s.perp_balances.insert(id, perp);
            }
            if flags & 4 != 0 {
                s.withdrawn_total.insert(id, wd);
            }
            sl.accts.insert(id, AcctRec { present: true, f0: flags, start_pos, light: Some((flags, npos, dg)) });
            continue;
        }
        if present {
            let flags = bad!(r.u8());
            if flags & !7 != 0 || flags == 0 {
                return Err(ST_SL_BADWIT);
            }
            f0 = flags;
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
        sl.accts.insert(id, AcctRec { present, f0, start_pos, light: None });
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
    // levels (round 16, linked FIFO): the level's ends (head, tail) + SOME of its live orders, each with its FIFO links
    // (prev, next), sorted by seq (= FIFO order within a level: an order rests at its placement unit, seqs grow)
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_LEVELS {
        return Err(ST_SL_BADWIT);
    }
    let oid_opt = |x: H| if x == [0u8; 32] { None } else { Some(OrderId(x)) };
    for _ in 0..n {
        let m = MarketId(bad!(r.u32()));
        let sd = bad!(r.u8());
        let price = bad!(r.i64());
        let side = bad!(Side::from_u8(sd));
        let head = OrderId(bad!(r.h32()));
        let tail = OrderId(bad!(r.h32()));
        let k = bad!(r.u16()) as usize;
        if k > SL_MAX_LEVEL_ORDERS || sl.levels.contains_key(&(m.0, sd, price)) || head.0 == [0u8; 32] || tail.0 == [0u8; 32] {
            return Err(ST_SL_BADWIT);
        }
        if sl.oloc.len() + k > SL_MAX_ORDERS {
            return Err(ST_SL_BADWIT);
        }
        lvl_leaf(&mut b, m, sd, price, head, tail);
        sl.check(&b, true)?;
        let mut los: Vec<(OrderId, Option<OrderId>, Option<OrderId>, u64)> = Vec::with_capacity(k);
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
            let prev = oid_opt(bad!(r.h32()));
            let next = oid_opt(bad!(r.h32()));
            if o.remaining == 0 || sl.oloc.contains_key(&o.id) || los.last().is_some_and(|x| x.3 >= o.seq) {
                return Err(ST_SL_BADWIT);
            }
            // the ends: no prev <=> the head, no next <=> the tail
            if (prev.is_none() != (o.id == head)) || (next.is_none() != (o.id == tail)) {
                return Err(ST_SL_BADWIT);
            }
            wit::ord_leaf(&mut b, &o);
            sl.check(&b, true)?;
            olk_leaf(&mut b, &o.id, prev, next);
            sl.check(&b, true)?;
            sl.oloc.insert(o.id, (m.0, sd, price, o.account));
            los.push((o.id, prev, next, o.seq));
            s.book_mut(m).sl_restore(o);
        }
        // a link between two loaded orders must agree with their (seq = FIFO) order
        for (i, (_, _, nx, _)) in los.iter().enumerate() {
            if let Some(q) = nx {
                if let Some(jq) = los.iter().position(|x| x.0 == *q) {
                    if jq <= i || los[jq].1 != Some(los[i].0) {
                        return Err(ST_SL_BADWIT);
                    }
                }
            }
        }
        let bk = s.book_mut(m);
        bk.sl.lv.insert((sd, price), (Some(head), Some(tail)));
        for (id, p, nx, _) in &los {
            bk.sl.lk.insert(*id, (*p, *nx));
        }
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
    // round 15: withdrawal record sets (n = 0: proven absent)
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_ACCOUNTS {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let id = AccountId(bad!(r.h32()));
        let k = bad!(r.u8()) as usize;
        if k > MAX_PENDING_WITHDRAWALS_PER_ACCOUNT || sl.wdl.contains_key(&id) {
            return Err(ST_SL_BADWIT);
        }
        let mut es: Vec<WdlE> = Vec::with_capacity(k);
        for _ in 0..k {
            let e = (bad!(r.u64()), bad!(r.i128()), bad!(r.bool()), bad!(r.u64()));
            if es.last().is_some_and(|x| x.0 >= e.0) {
                return Err(ST_SL_BADWIT);
            }
            es.push(e);
        }
        if k == 0 {
            wdl_kid(&mut b, &id);
            sl.absent(&b)?;
        } else {
            wdl_leaf(&mut b, &id, &es);
            sl.check(&b, true)?;
        }
        let live: Vec<WdlE> = es.into_iter().filter(|e| e.3.saturating_add(REPLAY_WINDOW) > s.height).collect();
        for e in &live {
            s.withdrawals.insert((id, e.0), crate::types::Withdrawal { amount: e.1, pending: e.2, height: e.3 });
        }
        sl.wdl.insert(id, live);
    }
    // ---- round 16 sections ----
    // perp:0 (u8 flag: loaded)
    match bad!(r.u8()) {
        0 => {}
        1 => {
            s.perp_supply = bad!(r.u128());
            s.perp_burned = bad!(r.u128());
            s.next_market_id = bad!(r.u32());
            perp_leaf(&mut b, s.perp_supply, s.perp_burned, s.next_market_id);
            sl.check(&b, true)?;
            sl.perp = true;
        }
        _ => return Err(ST_SL_BADWIT),
    }
    // gov nonce watermarks (0 = proven absent)
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_ACCOUNTS {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let id = AccountId(bad!(r.h32()));
        let v = bad!(r.u64());
        if sl.gnon.insert(id, v).is_some() {
            return Err(ST_SL_BADWIT);
        }
        if v == 0 {
            wit::gnon_kid(&mut b, &id);
            sl.absent(&b)?;
        } else {
            wit::gnon_leaf(&mut b, &id, v);
            sl.check(&b, true)?;
            s.seen_gov_nonces.insert(id, v);
        }
    }
    // external_sources memberships
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_ACCOUNTS {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let id = AccountId(bad!(r.h32()));
        let present = bad!(r.bool());
        if sl.xsrc.insert(id, present).is_some() {
            return Err(ST_SL_BADWIT);
        }
        if present {
            xsrc_leaf(&mut b, &id);
            sl.check(&b, true)?;
            s.external_sources.insert(id);
        } else {
            xsrc_kid(&mut b, &id);
            sl.absent(&b)?;
        }
    }
    // commit indexes: entries {hash, ttl, commit_unit, commit_height, revealed}; a live entry (ttl >= height) is checked
    // against its cmt: leaf and enters the state; one expiring at this run's hook (round 23: eager expiry -- the only
    // non-live entries a committed index can hold) is covered by the digest here; its cmt: record comes from the
    // single-record section (cmtx) and the index is rewritten without it (end root)
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_CMT_RECS {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let id = AccountId(bad!(r.h32()));
        let k = bad!(r.u8()) as usize;
        if k > SL_MAX_ACMT || sl.acmt.contains_key(&id) {
            return Err(ST_SL_BADWIT);
        }
        let mut es: Vec<AcmtE> = Vec::with_capacity(k);
        let mut live: Vec<AcmtE> = Vec::new();
        for _ in 0..k {
            let h = bad!(r.h32());
            let ttl = bad!(r.u64());
            let e = crate::state::CommitEntry { account: id, commit_unit: bad!(r.h32()), commit_height: bad!(r.u64()), ttl_height: ttl, revealed: bad!(r.bool()) };
            if es.last().is_some_and(|x| x.0 >= h) {
                return Err(ST_SL_BADWIT);
            }
            es.push((h, ttl));
            if ttl >= s.height {
                if !sl.cmts.insert(h) {
                    return Err(ST_SL_BADWIT);
                }
                wit::cmt_leaf(&mut b, &h, &e);
                sl.check(&b, true)?;
                s.commits.insert(h, e);
                live.push((h, ttl));
            }
        }
        if k == 0 {
            acmt_kid(&mut b, &id);
            sl.absent(&b)?;
        } else {
            acmt_leaf(&mut b, &id, &es);
            sl.check(&b, true)?;
        }
        sl.acmt.insert(id, live);
        sl.acmt_all.insert(id, es);
    }
    // single commit records by hash (present: the full entry; absent proven)
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_CMT_RECS {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let h = bad!(r.h32());
        if !sl.cmts.insert(h) {
            return Err(ST_SL_BADWIT);
        }
        if bad!(r.bool()) {
            let e = crate::state::CommitEntry { account: AccountId(bad!(r.h32())), commit_unit: bad!(r.h32()), commit_height: bad!(r.u64()), ttl_height: bad!(r.u64()), revealed: bad!(r.bool()) };
            wit::cmt_leaf(&mut b, &h, &e);
            sl.check(&b, true)?;
            // an expired commit reads as absent (the session pruned it at its TTL); round 23: it expires at this run's
            // hook (eager expiry: the only non-live record a committed tree holds) -> its leaf is deleted (end root)
            if e.ttl_height >= s.height {
                s.commits.insert(h, e);
            } else {
                sl.cmtx.insert(h, e);
            }
        } else {
            wit::cmt_kid(&mut b, &h);
            sl.absent(&b)?;
        }
    }
    // round 18: governance -- pglob:0 + every live proposal; exception lists
    if bad!(r.bool()) {
        let next = bad!(r.u64());
        let holders = bad!(r.u64());
        let n = bad!(r.u8()) as usize;
        if n > 64 {
            return Err(ST_SL_BADWIT);
        }
        let mut es: Vec<(u64, H)> = Vec::with_capacity(n);
        let mut cnt: BTreeMap<u64, (usize, usize)> = BTreeMap::new();
        for _ in 0..n {
            let id = bad!(r.u64());
            let nx = bad!(r.h32());
            if es.last().is_some_and(|x| x.0 >= id) {
                return Err(ST_SL_BADWIT);
            }
            es.push((id, nx));
            let creator = AccountId(bad!(r.h32()));
            let market = MarketId(bad!(r.u32()));
            let key = bad!(ParamKey::from_u8(bad!(r.u8())));
            let value = bad!(r.u64());
            let created_seq = bad!(r.u64());
            let deadline_seq = bad!(r.u64());
            let supply_at_create = bad!(r.u128());
            let yes = bad!(r.u128());
            let no = bad!(r.u128());
            let vn = bad!(r.u32()) as usize;
            let sn = bad!(r.u32()) as usize;
            let p = crate::state::Proposal {
                creator,
                market,
                key,
                value,
                created_seq,
                deadline_seq,
                supply_at_create,
                yes,
                no,
                voted: BTreeSet::new(),
                weight_snapshot: BTreeMap::new(),
            };
            wit::prop_leaf_n(&mut b, id, &p, vn, sn);
            sl.check(&b, true)?;
            s.proposals.insert(id, p);
            cnt.insert(id, (vn, sn));
        }
        pglob_leaf(&mut b, next, holders, &es);
        sl.check(&b, true)?;
        s.next_proposal_id = next;
        sl.pglob = Some((holders, es.iter().copied().collect()));
        for (id, (vn, sn)) in cnt {
            sl.pcnt.insert(id, (vn, sn, 0));
        }
    }
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_ACCOUNTS {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let id = AccountId(bad!(r.h32()));
        let k = bad!(r.u8()) as usize;
        // the account's balance is an input of every entry-less pair: its record must be loaded
        if k > 64 || sl.pexc.contains_key(&id) || !sl.accts.contains_key(&id) {
            return Err(ST_SL_BADWIT);
        }
        let mut es: Vec<PexcE> = Vec::with_capacity(k);
        for _ in 0..k {
            let pid = bad!(r.u64());
            let wt = bad!(r.u128());
            let v = bad!(r.bool());
            if es.last().is_some_and(|x| x.0 >= pid) || !s.proposals.contains_key(&pid) {
                return Err(ST_SL_BADWIT);
            }
            es.push((pid, wt, v));
        }
        sl.pexc.insert(id, es);
    }
    // a loaded exception list needs the complete proposal set (an entry-less pair means "weight = balance, no vote"
    // only against the live set)
    if !sl.pexc.is_empty() && sl.pglob.is_none() {
        return Err(ST_SL_BADWIT);
    }
    // round 19 (R18-M1 fix): every live proposal's exception sub-tree, pruned to the loaded accounts' paths; each loaded
    // list must match it exactly: a listed entry is a member (leaf hash recomputed), an unlisted pair proven absent
    if let Some((_, xr)) = &sl.pglob {
        // R19-L1: one node budget for the MNWIT-S tree and every sub-tree
        let mut seen = sl.t.nodes.len();
        for (pid, x) in xr {
            let mut st = bad!(PTree::decode_lim(&mut r, SL_MAX_TREE_NODES.saturating_sub(seen)));
            seen += st.nodes.len();
            if seen > SL_MAX_TREE_NODES || st.root_hash() != *x {
                return Err(ST_SL_BADWIT);
            }
            for (a, es) in &sl.pexc {
                match es.iter().find(|e| e.0 == *pid) {
                    Some(e) => {
                        pxe_leaf(&mut b, *pid, a, e.1, e.2);
                        let (k, lh) = kh(&b);
                        match st.get(&k) {
                            Look::Present(h) if h == lh => st.mark_verified(&k),
                            _ => return Err(ST_SL_BADWIT),
                        }
                    }
                    None => {
                        pxe_kid(&mut b, *pid, a);
                        if !matches!(st.get(&kid_key(&b)), Look::Absent) {
                            return Err(ST_SL_BADWIT);
                        }
                    }
                }
            }
            sl.xt.insert(*pid, st);
        }
    }
    // the partial proposals hold, for every account with a loaded exception list, exactly the session's snapshot
    // weight (non-zero only, like the session's copy) and vote membership
    for (a, es) in &sl.pexc {
        let bal = s.perp_balances.get(a).copied().unwrap_or(0);
        for (id, p) in s.proposals.iter_mut() {
            let (wt, v) = es.iter().find(|e| e.0 == *id).map(|e| (e.1, e.2)).unwrap_or((bal, false));
            if wt != 0 {
                p.weight_snapshot.insert(*a, wt);
            }
            if v {
                p.voted.insert(*a);
            }
        }
    }
    for (id, p) in &s.proposals {
        if let Some(c) = sl.pcnt.get_mut(id) {
            c.2 = p.voted.len();
            // a forged count below the loaded voters is not a session state
            if c.0 < c.2 {
                return Err(ST_SL_BADWIT);
            }
        }
    }
    for a in sl.accts.keys() {
        sl.bal0.insert(*a, s.perp_balances.get(a).copied().unwrap_or(0));
    }
    // round 20: oracle records
    ora::load(&mut sl, &mut s, &mut r, &mut b)?;
    // round 21: rank sub-trees
    adl::load(&mut sl, &s, &mut r, &mut b)?;
    // round 22: gcnt:0 (u8 flag: loaded)
    match bad!(r.u8()) {
        0 => {}
        1 => {
            let mut g: Gcnt = [0; GCNT_N];
            for x in g.iter_mut() {
                *x = bad!(r.u64());
            }
            gcnt_leaf(&mut b, &g);
            sl.check(&b, true)?;
            sl.gcnt = Some(g);
        }
        _ => return Err(ST_SL_BADWIT),
    }
    // round 23: commit expiry groups (n = 0: proven absent)
    let n = bad!(r.u16()) as usize;
    if n > SL_MAX_CEXP_GROUPS {
        return Err(ST_SL_BADWIT);
    }
    for _ in 0..n {
        let u = bad!(r.u64());
        let k = bad!(r.u16()) as usize;
        if k > SL_MAX_CEXP || sl.cx.contains_key(&u) {
            return Err(ST_SL_BADWIT);
        }
        let mut hs: Vec<H> = Vec::with_capacity(k);
        for _ in 0..k {
            let h = bad!(r.h32());
            if hs.last().is_some_and(|x| *x >= h) {
                return Err(ST_SL_BADWIT);
            }
            hs.push(h);
        }
        if k == 0 {
            cexp_kid(&mut b, u);
            sl.absent(&b)?;
        } else {
            cexp_leaf(&mut b, u, &hs);
            sl.check(&b, true)?;
        }
        sl.cx.insert(u, hs);
    }
    if r.i != w.len() {
        return Err(ST_SL_BADWIT);
    }
    sl.cmt0 = s.commits.keys().copied().collect();
    // round 16: every loaded book is a partial book (the walk checks its FIFO links)
    for bk in s.books.values_mut() {
        bk.sl.on = true;
    }
    let _ = s.take_dirty();
    // the session's books carry the peek log; start empty
    Ok((sl, s, claimed))
}

// ------------------------------------------------------------------------------------------------
// guards
// ------------------------------------------------------------------------------------------------
fn need_acct(sl: &Sl, s: &ChainState, a: &AccountId) -> Result<(), Need> {
    match sl.accts.get(a) {
        None => return Err(Need::Account(*a)),
        // a light record has no positions loaded: a full read needs the full record
        Some(r) if r.light.is_some() => return Err(Need::Account(*a)),
        _ => {}
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
    for (oid, (m, _sd, _p)) in es {
        // round 16: the order itself (with its level's ends and its links), not its whole level
        if !sl.oloc.contains_key(oid) {
            return Err(Need::Order(*oid));
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
fn walk_check(sl: &Sl, bk: &crate::book::OrderBook, m: u32, sd: u8, frontier: Option<Price>) -> Result<(), Need> {
    // bids: best = highest u (children high -> low); asks: lowest first
    let fu = frontier.map(ubias);
    // round 16: the levels the walk examined (their heads were checked by the book, OrderBook::sl_ok / sl_drained)
    let seen: BTreeSet<u64> = bk.peeks.0.iter().filter_map(|(_, p)| p.map(ubias)).collect();
    fn go(sl: &Sl, bk: &crate::book::OrderBook, seen: &BTreeSet<u64>, m: u32, sd: u8, d: u8, prefix: u64, fu: Option<u64>) -> Result<bool, Need> {
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
                // round 16 (linked FIFO): a level strictly better than the frontier that the walk never examined looked
                // empty in memory: it must really be empty (its whole start chain loaded and gone)
                if fu != Some(np) && !seen.contains(&np) {
                    let mut x = bk.sl.lv.get(&(sd, q)).and_then(|e| e.0);
                    while let Some(o) = x {
                        match bk.sl.lk.get(&o) {
                            Some(&(_, nx)) if !bk.get(o).is_some_and(|z| z.remaining > 0) => x = nx,
                            _ => return Err(Need::Order(o)),
                        }
                    }
                }
            } else if !go(sl, bk, seen, m, sd, d + 1, np, fu)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    go(sl, bk, &seen, m, sd, 0, 0, fu).map(|_| ())
}
/// round 16: is the level non-empty now? Its start chain minus the orders gone in this segment (an order that was not
/// loaded is live: nothing in the segment could remove it), plus the live orders created in the segment.
fn lvl_live(bk: &crate::book::OrderBook, sd: u8, p: Price) -> bool {
    let live = |o: &OrderId| bk.get(*o).is_some_and(|z| z.remaining > 0);
    let mut x = bk.sl.lv.get(&(sd, p)).and_then(|e| e.0);
    while let Some(o) = x {
        match bk.sl.lk.get(&o) {
            None => return true,
            Some(&(_, nx)) => {
                if live(&o) {
                    return true;
                }
                x = nx;
            }
        }
    }
    bk.sl_mem_level(Side::from_u8(sd).unwrap(), p).iter().any(|id| !bk.sl.lk.contains_key(id) && live(id))
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

fn need_acmt(sl: &Sl, a: &AccountId) -> Result<(), Result<Need, u32>> {
    if cfg!(not(feature = "govwit")) {
        return Err(Err(ST_SL_UNSUPPORTED));
    }
    if !sl.acmt.contains_key(a) {
        return Err(Ok(Need::Acmt(*a)));
    }
    Ok(())
}
/// pre-unit guards (reads). `x`: round 16 -- the commit hash of a Commit / the commit_ref of a Reveal (from the ext area)
fn pre(sl: &Sl, s: &ChainState, op: &crate::BatchOp, author: AccountId, x: Option<H>) -> Result<(), Result<Need, u32>> {
    use crate::BatchOp::*;
    match *op {
        // ---- round 16: PERP ledger ops, listings, commit-reveal ----
        GovDeposit { .. } => {
            need_acct(sl, s, &author).map_err(Ok)?;
            if !sl.perp {
                return Err(Ok(Need::Perp));
            }
        }
        GovWithdraw { .. } => {
            if cfg!(not(feature = "govwit")) {
                return Err(Err(ST_SL_UNSUPPORTED));
            }
            need_acct(sl, s, &author).map_err(Ok)?;
            if !sl.perp {
                return Err(Ok(Need::Perp));
            }
            if !sl.gnon.contains_key(&author) {
                return Err(Ok(Need::Gnon(author)));
            }
            // R7-M2 commit bond: the author's live commits
            need_acmt(sl, &author)?;
        }
        CreateMarket { .. } => {
            need_acct(sl, s, &author).map_err(Ok)?;
            if !sl.perp {
                return Err(Ok(Need::Perp));
            }
            need_acmt(sl, &author)?;
            // the new market id: proven absent (its band: / meta: / mkx: keys are created)
            if !sl.markets.contains_key(&s.next_market_id) {
                return Err(Ok(Need::Market(s.next_market_id)));
            }
            // a funding-rate listing adds the creator to external_sources
            if !sl.xsrc.contains_key(&author) {
                return Err(Ok(Need::Xsrc(author)));
            }
        }
        Commit { .. } => {
            // bond: the author's PERP balance and live commits; pending count; the hash's existence
            need_acct(sl, s, &author).map_err(Ok)?;
            need_acmt(sl, &author)?;
            if let Some(h) = x {
                if !sl.cmts.contains(&h) {
                    return Err(Ok(Need::Cmt(h)));
                }
            }
        }
        Reveal { .. } => {
            if cfg!(not(feature = "govwit")) {
                return Err(Err(ST_SL_UNSUPPORTED));
            }
            if let Some(h) = x {
                if !sl.cmts.contains(&h) {
                    return Err(Ok(Need::Cmt(h)));
                }
            }
        }
        Deposit { .. } => need_acct(sl, s, &author).map_err(Ok)?,
        Place { market, .. } => {
            need_acct(sl, s, &author).map_err(Ok)?;
            match sl.markets.get(&market) {
                None => return Err(Ok(Need::Market(market))),
                Some(true) if s.markets.get(&MarketId(market)).is_some_and(|p| p.funding_rate) => return Err(Err(ST_SL_UNSUPPORTED)),
                _ => {}
            }
            // the fee leg reads / writes only the insurance collateral: a light record suffices (R14-M2)
            if !sl.accts.contains_key(&INSURANCE_ACCOUNT) {
                return Err(Ok(Need::Light(INSURANCE_ACCOUNT)));
            }
            need_aord_full(sl, &author).map_err(Ok)?;
            // (round 16: the R14-M1 level-size rule and its own-side level input are gone with linked-FIFO levels)
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
        Withdraw { .. } => {
            // round 15: debit + snapshot read the author's positions; resting_open_im walks every book (params) and
            // the author's live orders; the nonce / pending-count rules read the author's withdrawal records
            need_acct(sl, s, &author).map_err(Ok)?;
            if !sl.wdl.contains_key(&author) {
                return Err(Ok(Need::Wdl(author)));
            }
            need_aord_full(sl, &author).map_err(Ok)?;
            for m in s.books.keys() {
                if !sl.markets.contains_key(&m.0) {
                    return Err(Ok(Need::Market(m.0)));
                }
            }
            if s.accounts.get(&author).is_some_and(|a| a.positions.keys().any(|m| s.markets.get(m).is_some_and(|p| p.funding_rate))) {
                return Err(Err(ST_SL_UNSUPPORTED));
            }
        }
        // round 17: book-path liquidation; the target's reads are checked by liq_pre (needs the batch's account table)
        Liquidate { .. } => need_acct(sl, s, &author).map_err(Ok)?,
        // ---- round 18: governance ----
        // create: the live count (cap 64) and the next id (pglob: + every live proposal), the market (present or
        // absent), the creator's PERP balance (its record), the supply (perp:0); the snapshot size comes from pglob:
        CreateProposal { market, .. } => {
            need_acct(sl, s, &author).map_err(Ok)?;
            need_gov(sl, None)?;
            if !sl.perp {
                return Err(Ok(Need::Perp));
            }
            if !sl.markets.contains_key(&market) {
                return Err(Ok(Need::Market(market)));
            }
        }
        // vote: the proposal (or its absence: every live one is loaded), the voter's snapshot weight / vote (pexc:
        // + the record's balance); the R6-H2 zero-voter rule reads the proposal's counts (run loop)
        Vote { .. } => {
            need_acct(sl, s, &author).map_err(Ok)?;
            need_gov(sl, Some(&author))?;
        }
        // finalize: the proposal and its market (params rewritten when it passes); round 19 (R18-M1 fix): the proposal's
        // exception sub-tree goes with its pglob: entry, no exception holder is read
        Finalize { id, .. } => {
            need_gov(sl, None)?;
            if let Some(p) = s.proposals.get(&id) {
                if !sl.markets.contains_key(&p.market.0) {
                    return Err(Ok(Need::Market(p.market.0)));
                }
            }
        }
        // ---- round 20: oracle (§12.1) ----
        Stake { .. } => ora::pre_stake(sl, s, &author, false)?,
        Unstake { .. } => ora::pre_stake(sl, s, &author, true)?,
        Report { market, price, .. } => ora::pre_report(sl, s, &author, market, price)?,
        // round 20 (step 3): the challenger's record (reward), perp:0 (burn); the target's reads: run loop (pre_slash)
        Slash { .. } => {
            need_acct(sl, s, &author).map_err(Ok)?;
            if !sl.perp {
                return Err(Ok(Need::Perp));
            }
        }
        _ => return Err(Err(ST_SL_UNSUPPORTED)),
    }
    Ok(())
}

/// round 18: `pglob:` (+ every live proposal) loaded, and the exception list of `a`
fn need_gov(sl: &Sl, a: Option<&AccountId>) -> Result<(), Result<Need, u32>> {
    if sl.pglob.is_none() {
        return Err(Ok(Need::Pglob));
    }
    if let Some(a) = a {
        if !sl.pexc.contains_key(a) {
            return Err(Ok(Need::Pexc(*a)));
        }
    }
    Ok(())
}
/// round 18: non-zero PERP holders now (pglob count at load + the loaded accounts' transitions)
fn holders_now(sl: &Sl, s: &ChainState) -> u64 {
    let h0 = sl.pglob.as_ref().map(|g| g.0).unwrap_or(0) as i64;
    let mut d = 0i64;
    for (a, b0) in &sl.bal0 {
        let b1 = s.perp_balances.get(a).copied().unwrap_or(0);
        d += (b1 != 0) as i64 - (*b0 != 0) as i64;
    }
    (h0 + d) as u64
}

/// round 22: change of the global counts since load: every map membership that can change belongs to a loaded record
/// (accounts / PERP ids: the loaded account records -- a dirty account is always loaded, a light record's flags never
/// change; markets: the loaded / proven-absent market records -- a listing proves its id absent; bonds: the loaded
/// `ostk:` records -- guard (a) of ora::post)
fn gcnt_delta(sl: &Sl, s: &ChainState) -> [i64; GCNT_N] {
    let mut d = [0i64; GCNT_N];
    for (a, rec) in &sl.accts {
        d[0] += s.accounts.contains_key(a) as i64 - (rec.f0 & 1) as i64;
        d[1] += s.perp_balances.contains_key(a) as i64 - ((rec.f0 >> 1) & 1) as i64;
    }
    for (m, p0) in &sl.markets {
        d[2] += s.markets.contains_key(&MarketId(*m)) as i64 - *p0 as i64;
    }
    for a in &sl.o.stk {
        d[3] += s.oracle_bonds.contains_key(a) as i64 - sl.o.bonds0.contains_key(a) as i64;
    }
    // round 23: commits are created only through loaded records (cmt0 = the live ones at load; a commit is never removed
    // inside a run) and expire only at the hook, as whole loaded groups (cexp_hook)
    d[4] = s.commits.len() as i64 - sl.cmt0.len() as i64 - cexp_gone(sl, s) as i64;
    d
}
/// round 23: commits expired by this run's hook (the loaded groups below the run's height)
fn cexp_gone(sl: &Sl, s: &ChainState) -> usize {
    sl.cx.range(..s.height).map(|(_, g)| g.len()).sum()
}
/// round 23 (R16-I1 / R22-I2): the inputs of the hook's eager commit expiry from the committed height h0 to the run's
/// height: every group u in [h0, min(height, h0 + COMMIT_TTL_HEIGHTS + 1)) (no live commit can have a larger TTL),
/// the `cmt:` record of each of its hashes (ttl must be u) and its owner's commit index
fn cexp_hook(sl: &Sl, s: &ChainState) -> Result<(), Result<Need, u32>> {
    if cfg!(not(feature = "govwit")) {
        return Ok(());
    }
    let h0 = sl.o.h0;
    let end = s.height.min(h0.saturating_add(COMMIT_TTL_HEIGHTS + 1));
    for u in h0..end {
        let Some(g) = sl.cx.get(&u) else { return Err(Ok(Need::Cexp(u))) };
        for h in g {
            let Some(e) = sl.cmtx.get(h) else { return Err(Ok(Need::Cmt(*h))) };
            if e.ttl_height != u {
                return Err(Err(ST_SL_BADWIT));
            }
            if !sl.acmt.contains_key(&e.account) {
                return Err(Ok(Need::Acmt(e.account)));
            }
        }
    }
    Ok(())
}
fn gcnt_add(g: &Gcnt, d: &[i64; GCNT_N]) -> Gcnt {
    let mut o = [0u64; GCNT_N];
    for i in 0..GCNT_N {
        o[i] = (g[i] as i64).wrapping_add(d[i]) as u64;
    }
    o
}
/// round 22: the inputs of the session's global caps for op `o` with author `a` (the session's `state_cap_ok` runs on
/// the op and on a Reveal's inner op, with the author): the author's membership (its record / `ostk:`) and, for a
/// non-member, `gcnt:0`
fn gcap_pre(sl: &Sl, s: &ChainState, o: &crate::BatchOp, a: &AccountId) -> Result<(), Result<Need, u32>> {
    use crate::BatchOp as B;
    let member = match *o {
        B::Deposit { .. } | B::Liquidate { .. } | B::GovDeposit { .. } | B::GovWithdraw { .. } | B::Slash { .. } => {
            if !sl.accts.contains_key(a) {
                return Err(Ok(Need::Account(*a)));
            }
            if matches!(o, B::Deposit { .. } | B::Liquidate { .. }) {
                s.accounts.contains_key(a)
            } else {
                s.perp_balances.contains_key(a)
            }
        }
        B::CreateMarket { .. } => false,
        // round 23: the session's MAX_STATE_COMMITS (every Commit reads the count) and the per-TTL group bound (R23-M1:
        // the group of a valid TTL)
        B::Commit { ttl, .. } => {
            if ttl_ok(s, ttl) && !sl.cx.contains_key(&ttl) {
                return Err(Ok(Need::Cexp(ttl)));
            }
            false
        }
        B::Stake { .. } => {
            if !sl.o.stk.contains(a) {
                return Err(Ok(Need::Ostk(*a)));
            }
            s.oracle_bonds.contains_key(a)
        }
        _ => return Ok(()),
    };
    if !member && sl.gcnt.is_none() {
        return Err(Ok(Need::Gcnt));
    }
    Ok(())
}
/// round 22: the session's global caps (`state_cap_ok`) on the counts now (gcap_pre loaded the inputs)
fn gcap_ok(sl: &Sl, s: &ChainState, o: &crate::BatchOp, a: &AccountId) -> bool {
    use crate::BatchOp as B;
    let c = sl_caps();
    let now = |i: usize| -> u64 {
        let g0 = sl.gcnt.unwrap_or([0; GCNT_N]);
        gcnt_add(&g0, &gcnt_delta(sl, s))[i]
    };
    match *o {
        B::Deposit { .. } | B::Liquidate { .. } => s.accounts.contains_key(a) || now(0) < c.accounts,
        B::GovDeposit { .. } | B::GovWithdraw { .. } | B::Slash { .. } => s.perp_balances.contains_key(a) || now(1) < c.accounts,
        B::CreateMarket { .. } => now(2) < c.markets,
        B::Commit { ttl, .. } => now(4) < c.commits && (!ttl_ok(s, ttl) || cexp_now(sl, s, ttl) < c.commit_group),
        B::Stake { .. } => s.oracle_bonds.contains_key(a) || now(3) < c.oracles,
        _ => true,
    }
}

/// round 17 (stateless liquidation, book path): the reads of `liquidate_inner` / `liquidate_book_path` for target `t`
/// in market `m` -- the target's full record and its position markets (snapshot / isolated_risk), the market, its order
/// set (the IOC's cancel-maker STP and refunds), the insurance light record (fee leg), and a proof of the R7-H1 dust
/// check's input (`first_maker_qty`: the first live maker of another account on the opposite side, liq_first_maker).
/// A funding-rate market (off-book close + ADL over all holders) is unsupported. The ADL remainder (book fills nothing)
/// is detected after the unit (run loop); round 21: checked against the rank sub-tree of the candidates' sign (adl.rs).
fn liq_pre(sl: &Sl, s: &ChainState, t: &AccountId, m: u32) -> Result<(), Result<Need, u32>> {
    need_acct(sl, s, t).map_err(Ok)?;
    match sl.markets.get(&m) {
        None => return Err(Ok(Need::Market(m))),
        Some(true) if s.markets.get(&MarketId(m)).is_some_and(|p| p.funding_rate) => return Err(Err(ST_SL_UNSUPPORTED)),
        _ => {}
    }
    if !sl.accts.contains_key(&INSURANCE_ACCOUNT) {
        return Err(Ok(Need::Light(INSURANCE_ACCOUNT)));
    }
    let Some(pos) = s.accounts.get(t).and_then(|a| a.positions.get(&MarketId(m))) else { return Ok(()) };
    if pos.qty == 0 {
        return Ok(());
    }
    need_aord_full(sl, t).map_err(Ok)?;
    // resting_open_im-style reads are not made by the liquidation; the IOC walks the opposite side (walk check after
    // the unit) and the dust check scans it from the best level skipping the target's own orders
    let sd = if pos.qty > 0 { Side::Bid.as_u8() } else { Side::Ask.as_u8() };
    liq_first_maker(sl, s.books.get(&MarketId(m)), m, sd, t).map_err(Ok)
}
/// round 17: prove the in-memory `first_maker_qty` scan of side `sd` equals the full book's: every level in price
/// priority (trie as of unit start) up to the first one holding a live order of another account than `t` is known,
/// and its start FIFO chain up to that order is loaded (skipped orders: gone or `t`'s own); orders created in the
/// segment follow the start chain, as in memory
fn liq_first_maker(sl: &Sl, bk: Option<&crate::book::OrderBook>, m: u32, sd: u8, t: &AccountId) -> Result<(), Need> {
    fn go(sl: &Sl, bk: Option<&crate::book::OrderBook>, m: u32, sd: u8, d: u8, prefix: u64, t: &AccountId) -> Result<bool, Need> {
        let map = bmp_get(sl, m, sd, d, prefix)?.map;
        let order: &mut dyn Iterator<Item = u16> = if sd == 0 { &mut (0..256u16).rev() } else { &mut (0..256u16) };
        for c in order {
            let c = c as u8;
            if !mbit(&map, c) {
                continue;
            }
            let np = (prefix << 8) | c as u64;
            if d < 7 {
                if go(sl, bk, m, sd, d + 1, np, t)? {
                    return Ok(true);
                }
                continue;
            }
            let q = unbias(np);
            if !sl.levels.contains_key(&(m, sd, q)) {
                return Err(Need::Level(m, sd, q));
            }
            let Some(bk) = bk else { continue };
            let other = |o: &OrderId| bk.get(*o).is_some_and(|z| z.remaining > 0 && z.account != *t);
            let mut x = bk.sl.lv.get(&(sd, q)).and_then(|e| e.0);
            while let Some(o) = x {
                match bk.sl.lk.get(&o) {
                    None => return Err(Need::Order(o)),
                    Some(&(_, nx)) => {
                        if other(&o) {
                            return Ok(true);
                        }
                        x = nx;
                    }
                }
            }
            if bk.sl_mem_level(Side::from_u8(sd).unwrap(), q).iter().any(|id| !bk.sl.lk.contains_key(id) && other(id)) {
                return Ok(true);
            }
        }
        Ok(false)
    }
    go(sl, bk, m, sd, 0, 0, t).map(|_| ())
}

// ------------------------------------------------------------------------------------------------
// the stateless segment run
// ------------------------------------------------------------------------------------------------
/// Run one segment statelessly: `rd` = the MNP1/MNP2 batch words (flags must be 0), `wit` = the witness
/// bytes. Events as `run_segment`. Status 0 => end_root is the MNWIT-S root after the segment.
/// `expect`: the chain's last good end root (None = not bound: host tests of other properties, non-prod first run).
/// `height`: round 15 height hook -- Some(run number) in a bound (prod) image: the engine height moves to it before the
/// units (when greater), as the session's `commit_height` with lazy pruning (withdrawal records expire on read).
pub fn run_stateless(rd: &mut dyn FnMut(u32) -> u32, wit_bytes: &[u8], expect: Option<&H>, height: Option<u64>, ev: &mut dyn FnMut(u32)) -> SlOut {
    let mut out = SlOut { status: 0, start_root: EMPTY, end_root: EMPTY, applied: 0, rejected: 0, fills: 0, need: None, leaves_verified: 0, tree_nodes: 0, node_hashes: 0, leaf_hashes: 0, puts: Vec::new(), dels: Vec::new() };
    out.status = crate::check_header_seg(rd, true);
    if out.status != crate::ST_OK {
        return out;
    }
    let (mut sl, s, claimed) = match load(wit_bytes, height) {
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
        // round 21: + the exception sub-trees and the rank sub-trees (node hashes) and the rank leaf hashes
        out.node_hashes = sl.t.node_hashes + sl.xt.values().map(|x| x.node_hashes).sum::<u64>() + sl.adl.t.values().map(|x| x.1.node_hashes).sum::<u64>();
        out.leaf_hashes = sl.leaf_hashes + sl.adl.hashes;
    };
    // round 20 (R19-I2): the eager oracle expiry of the session's height hook (commit_height -> prune_oracle_unbonding)
    // when the run moved the height: the queue groups up to the new height are loaded with their oracles, the prune
    // runs on the partial state, then the same completeness guards as after a unit (dirty accounts, PERP balance ->
    // pglob / exception list, oracle records, queue update)
    if eng.state.height > sl.o.h0 {
        let hk = (|| -> Result<(), Result<Need, u32>> {
            // round 23: the eager commit expiry of the same hook (prune_commits): the loader already reads the expiring
            // commits as absent; their groups, records and owners' indexes must be loaded so the end root deletes them
            cexp_hook(&sl, &eng.state)?;
            let gone = ora::hook_pre(&sl, &eng.state)?;
            ora::set_gone(&mut sl, gone);
            let h = eng.state.height;
            eng.state.prune_oracle_unbonding(h);
            let d = eng.state.take_dirty();
            for a in &d.accounts {
                if !sl.accts.contains_key(a) {
                    return Err(Ok(Need::Account(*a)));
                }
            }
            for (a, b0) in &sl.bal0 {
                if eng.state.perp_balances.get(a).copied().unwrap_or(0) != *b0 {
                    if sl.pglob.is_none() {
                        return Err(Ok(Need::Pglob));
                    }
                    if !sl.pexc.contains_key(a) {
                        return Err(Ok(Need::Pexc(*a)));
                    }
                }
            }
            // round 21: the prune moves no position; rank maintenance on its dirty accounts anyway (no-op)
            let da: Vec<AccountId> = d.accounts.iter().copied().collect();
            adl::maint(&mut sl, &eng.state, &da)?;
            ora::post(&mut sl, &eng.state)
        })();
        if let Err(e) = hk {
            match e {
                Ok(n) => fin(&mut out, &sl, ST_SL_MISSING, Some(n)),
                Err(st) => fin(&mut out, &sl, st, None),
            }
            return out;
        }
    }
    for i in 0..n_ops {
        let mut ow = [0u32; 8];
        for (k, x) in ow.iter_mut().enumerate() {
            *x = rd(base + i * 8 + k as u32);
        }
        let seq = eng.state.seq;
        let acct_of = |a: u32| accts.get(a as usize).copied().filter(|id| *id != INSURANCE_ACCOUNT);
        let op = crate::decode_op(&ow);
        let author = op.signer().and_then(acct_of);
        // round 18: the SetSeq test fixture (proposal deadlines are 20 000 applied units away) -- glob: only; refused in
        // prod exactly like the session (run_segment: BadAccount; neither applied nor seq-advancing when it succeeds)
        if let crate::BatchOp::SetSeq { seq: x } = op {
            if !cfg!(feature = "prod") && x >= eng.state.seq {
                eng.state.seq = x;
                ev(crate::EV_SEQ);
            } else {
                out.rejected += 1;
                ev(crate::reason_code(&RejectReason::BadAccount));
            }
            continue;
        }
        // round 16: the commit hash of a Commit / commit_ref + inner op of a Reveal (ext area; unreadable -> the
        // engine refuses the unit, nothing to load)
        let id32 = |e: &[u32]| -> H {
            let mut h = [0u8; 32];
            for k in 0..8 {
                h[4 * k..4 * k + 4].copy_from_slice(&e[k].to_le_bytes());
            }
            h
        };
        let (x, inner) = match op {
            crate::BatchOp::Commit { ext: off, .. } => (ext.read(rd, off, crate::EXT_COMMIT_LEN).map(|e| id32(&e)), None),
            crate::BatchOp::Reveal { ext: off, .. } => match ext.read(rd, off, crate::EXT_REVEAL_LEN) {
                Some(e) => {
                    let mut iw = [0u32; 8];
                    iw.copy_from_slice(&e[16..24]);
                    (Some(id32(&e[0..8])), Some(crate::decode_op(&iw)))
                }
                None => (None, None),
            },
            _ => (None, None),
        };
        if let Some(a) = author {
            // a Reveal's inner op (signed by the same author; any other signer / kind is refused by the engine before
            // it runs) reads what it would read at top level
            // (kinds the engine never runs as an inner op -- encode_op None: Deposit / GovDeposit / Commit / Reveal /
            // fixtures -- and foreign signers are refused before anything is read)
            let runs_inner = |io: &crate::BatchOp| {
                io.signer().and_then(acct_of) == Some(a)
                    && !matches!(io, crate::BatchOp::Deposit { .. } | crate::BatchOp::GovDeposit { .. } | crate::BatchOp::Commit { .. } | crate::BatchOp::Reveal { .. } | crate::BatchOp::SetHeight { .. } | crate::BatchOp::SetSeq { .. } | crate::BatchOp::Bad)
            };
            // the per-account rules below (commit bond, zero GovWithdraw) read the author's record and live commits for
            // the op AND the inner op whatever its signer (the session's state_cap_ok runs on both with the author)
            let bonded = |o: &crate::BatchOp| matches!(o, crate::BatchOp::GovWithdraw { .. } | crate::BatchOp::CreateMarket { .. } | crate::BatchOp::Stake { .. } | crate::BatchOp::Commit { .. });
            // the inner op runs only if reveal_begin consumes the commit (inner kind / signer, encoding hash == commit_ref,
            // commit live, the author's, not revealed, its unit a parent): decided on the loaded commit record (pre(op)
            // required it) -- an inner op that never runs reads nothing (e.g. a foreign commit's Stake: BadCommit)
            let mut reveal_runs = |st: &ChainState| -> bool {
                let (Some(io), crate::BatchOp::Reveal { ext: off, .. }) = (inner, op) else { return false };
                if !runs_inner(&io) {
                    return false;
                }
                let Some(e) = ext.read(rd, off, crate::EXT_REVEAL_LEN) else { return false };
                let Some(cr) = x else { return false };
                let Some(ent) = st.commits.get(&cr) else { return false };
                if ent.revealed || ent.account != a || st.height > ent.ttl_height {
                    return false;
                }
                let parents = [id32(&e[24..32]), id32(&e[32..40])];
                if !parents.iter().any(|p| *p != [0u8; 32] && *p == ent.commit_unit) {
                    return false;
                }
                let Some(enc) = crate::encode_op(&io, &accts, &ext, rd) else { return false };
                let mut h = Sha256::new();
                h.update(&enc);
                h.update(id32(&e[8..16]));
                let hh: H = h.finalize().into();
                hh == cr
            };
            let runs = reveal_runs(&eng.state);
            let pr = pre(&sl, &eng.state, &op, a, x)
                .and_then(|_| match inner {
                    // the W2 depth keys of an inner op (any kind / signer; the session's wit_depth_ok runs on it with the
                    // author) depend on the author's record and, for a listing, on the next market id
                    Some(io) => {
                        need_acct(&sl, &eng.state, &a).map_err(Ok)?;
                        if matches!(io, crate::BatchOp::CreateMarket { .. }) && !sl.perp {
                            return Err(Ok(Need::Perp));
                        }
                        Ok(())
                    }
                    None => Ok(()),
                })
                .and_then(|_| match inner {
                    // round 17: a revealed Liquidate has no target guard here (liq_pre runs on the op only)
                    Some(crate::BatchOp::Liquidate { .. }) if runs => Err(Err(ST_SL_UNSUPPORTED)),
                    // round 20: likewise a revealed Slash (its target guard runs on the op only)
                    Some(crate::BatchOp::Slash { .. }) if runs => Err(Err(ST_SL_UNSUPPORTED)),
                    Some(io) if runs => pre(&sl, &eng.state, &io, a, None),
                    _ => Ok(()),
                })
                .and_then(|_| {
                    if bonded(&op) || inner.is_some_and(|io| bonded(&io)) {
                        need_acct(&sl, &eng.state, &a).map_err(Ok)?;
                        need_acmt(&sl, &a)?;
                    }
                    // round 18: the session's R6-H2 zero-voter rule (state_cap_ok) runs on a Reveal's inner Vote too,
                    // whether or not the inner op runs: its inputs (the proposal, the author's weight / vote) are loaded
                    let vote = |o: &crate::BatchOp| matches!(o, crate::BatchOp::Vote { .. });
                    if vote(&op) || inner.is_some_and(|io| vote(&io)) {
                        need_acct(&sl, &eng.state, &a).map_err(Ok)?;
                        need_gov(&sl, Some(&a))?;
                    }
                    Ok(())
                });
            // round 22: the global caps' inputs (op and inner op, author a)
            let pr = pr.and_then(|_| {
                gcap_pre(&sl, &eng.state, &op, &a)?;
                match inner {
                    Some(io) => gcap_pre(&sl, &eng.state, &io, &a),
                    None => Ok(()),
                }
            });
            // round 17: the liquidation target's reads (the target index is resolved like dispatch does)
            let pr = pr.and_then(|_| match op {
                crate::BatchOp::Liquidate { target, market, .. } => {
                    let t = if target == crate::LIQ_TARGET_INSURANCE { Some(INSURANCE_ACCOUNT) } else { accts.get(target as usize).copied() };
                    match t {
                        Some(t) if t != a && t != INSURANCE_ACCOUNT => liq_pre(&sl, &eng.state, &t, market),
                        _ => Ok(()),
                    }
                }
                // round 20: the slashed oracle's reads (target from the batch table, as dispatch)
                crate::BatchOp::Slash { target, market, .. } => match accts.get(target as usize) {
                    Some(t) => ora::pre_slash(&sl, &eng.state, t, market),
                    None => Ok(()),
                },
                _ => Ok(()),
            });
            if let Err(e) = pr {
                match e {
                    Ok(n) => fin(&mut out, &sl, ST_SL_MISSING, Some(n)),
                    Err(st) => fin(&mut out, &sl, st, None),
                }
                return out;
            }
            // round 14 consensus rules of the stateless image (no global caps; per-account / per-level bounds that keep
            // every record loadable -- R14-H1 / R14-M1). Inputs are fully loaded (pre), so the outcome does not depend
            // on extra witness records.
            // round 16: the session's per-account rules of state_cap_ok (not its global caps): the R7-M2 commit bond
            // and the R7-M1 zero GovWithdraw by an id without a PERP entry -- on the op and on a Reveal's inner op;
            // plus the stateless bound on live commits per account (SL_MAX_ACMT)
            {
                let st = &eng.state;
                let live = st.commits.values().filter(|e| e.account == a).count();
                let bal = st.perp_balances.get(&a).copied().unwrap_or(0);
                let rule_ok = |o: &crate::BatchOp| -> bool {
                    if !crate::commit_bond_ok(o, || bal, || live) {
                        return false;
                    }
                    match *o {
                        crate::BatchOp::GovWithdraw { amount: 0, .. } => st.perp_balances.contains_key(&a),
                        crate::BatchOp::Commit { .. } => live < SL_MAX_ACMT,
                        // round 18: R6-H2 (session state_cap_ok) on the proposal's counts
                        crate::BatchOp::Vote { id, .. } => match st.proposals.get(&id) {
                            Some(p) => {
                                let (vn0, sn, pv0) = sl.pcnt.get(&id).copied().unwrap_or((0, 0, 0));
                                let vn = vn0 + p.voted.len() - pv0;
                                p.weight_snapshot.contains_key(&a) || p.voted.contains(&a) || vn < sn + crate::MAX_ZERO_VOTERS
                            }
                            None => true,
                        },
                        _ => true,
                    }
                };
                // round 20: the stateless oracle bounds (SL_MAX_REPORTERS / SL_MAX_ORACLE_MKTS)
                let rule_ok = |o: &crate::BatchOp| rule_ok(o) && ora::cap_ok(&sl, st, o, &a);
                // round 22: the session's global caps (R16-I3 / R17-I3) on gcnt:0 + the deltas
                let rule_ok = |o: &crate::BatchOp| rule_ok(o) && gcap_ok(&sl, st, o, &a);
                if !rule_ok(&op) || inner.is_some_and(|io| !rule_ok(&io)) {
                    out.rejected += 1;
                    ev(crate::STATE_CAP_CODE);
                    continue;
                }
            }
            let place_op = match (op, inner) {
                (crate::BatchOp::Reveal { .. }, Some(io)) if io.signer().and_then(acct_of) == Some(a) => io,
                _ => op,
            };
            if let crate::BatchOp::Place { market, side, typ, tif, price, .. } = place_op {
                let m = MarketId(market);
                let st = &eng.state;
                let has = st.accounts.get(&a).is_some_and(|x| x.positions.contains_key(&m)) || st.books.get(&m).is_some_and(|b| b.live_orders_of(a).next().is_some());
                let mut expo: BTreeSet<u32> = st.accounts.get(&a).map(|x| x.positions.keys().map(|k| k.0).collect()).unwrap_or_default();
                if let Some((es, _)) = sl.aord.get(&a) {
                    expo.extend(es.values().map(|e| e.0));
                }
                let _ = (side, typ, tif, price);
                if !has && expo.len() >= SL_MAX_POS {
                    out.rejected += 1;
                    ev(crate::STATE_CAP_CODE);
                    continue;
                }
            }
            // W2 depth rule on the MNWIT-S tree (keys the unit may create); round 16: + GovDeposit / CreateMarket and a
            // Reveal's inner op (the session's wit_depth_ok runs on both with the author)
            let mut keys: Vec<H> = Vec::new();
            for o in core::iter::once(op).chain(inner) {
                let st = &eng.state;
                match o {
                    crate::BatchOp::Deposit { .. } if !st.accounts.contains_key(&a) => keys.push(wit::acct_key(&a)),
                    // round 17: a keeper reward may create the caller's acct: key (session wit_depth_ok)
                    crate::BatchOp::Liquidate { .. } if !st.accounts.contains_key(&a) => keys.push(wit::acct_key(&a)),
                    crate::BatchOp::Place { market, client_seq, .. } => {
                        if !st.accounts.contains_key(&a) {
                            keys.push(wit::acct_key(&a));
                        }
                        keys.push(wit::ord_key(&order_id(a, MarketId(market), client_seq)));
                        if !st.accounts.get(&a).is_some_and(|x| x.positions.contains_key(&MarketId(market))) {
                            keys.push(wit::pos_key(&a, MarketId(market)));
                        }
                    }
                    crate::BatchOp::GovDeposit { .. } if !st.accounts.contains_key(&a) && !st.perp_balances.contains_key(&a) && !st.withdrawn_total.contains_key(&a) => keys.push(wit::acct_key(&a)),
                    // round 20: a slash reward may create the challenger's acct: key (session wit_depth_ok)
                    crate::BatchOp::Slash { .. } if !st.accounts.contains_key(&a) && !st.perp_balances.contains_key(&a) && !st.withdrawn_total.contains_key(&a) => keys.push(wit::acct_key(&a)),
                    crate::BatchOp::CreateMarket { .. } => keys.extend(wit::market_keys(MarketId(st.next_market_id))),
                    _ => {}
                }
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
        } else if !matches!(op, crate::BatchOp::Deposit { .. } | crate::BatchOp::Place { .. } | crate::BatchOp::Cancel { .. } | crate::BatchOp::Withdraw { .. } | crate::BatchOp::GovDeposit { .. } | crate::BatchOp::GovWithdraw { .. } | crate::BatchOp::CreateMarket { .. } | crate::BatchOp::Commit { .. } | crate::BatchOp::Reveal { .. } | crate::BatchOp::Liquidate { .. } | crate::BatchOp::CreateProposal { .. } | crate::BatchOp::Vote { .. } | crate::BatchOp::Finalize { .. } | crate::BatchOp::Bad) {
            fin(&mut out, &sl, ST_SL_UNSUPPORTED, None);
            return out;
        }
        for b in eng.state.books.values_mut() {
            b.peeks.0.clear();
            b.sl.short = None;
        }
        unsafe { SL_ADL_REACHED = false };
        unsafe { SL_FUNDING_REACHED = false };
        let res = crate::dispatch(&mut eng, &op, &accts, crate::Uid { v2, at: uid_base + i * 8 }, seq, &ext, rd, false);
        // round 17: a liquidation that reached the ADL remainder picked -- or failed to find, or failed to apply -- its
        // counterparty among the LOADED holders only; the session ranks every opposite holder of the market (design
        // §12.2) -> unsupported, never a status-0 result. Flag from the engine (any result) + the outcome forms
        // (Ok with no fill: the remainder ran; an ADL fill of kind 2) as defence in depth
        let adl = unsafe { SL_ADL_REACHED };
        // round 20: a funding transfer / the funding-rate peg reads every holder of the market (R19-I1)
        if unsafe { SL_FUNDING_REACHED } {
            fin(&mut out, &sl, ST_SL_UNSUPPORTED, None);
            return out;
        }
        // round 21 (design §12.2): the ADL remainder ranks every opposite holder -- the rank sub-tree of the candidates'
        // sign (as of unit start: maintained through the previous units, this unit's maintenance runs below) must show
        // its leftmost leaf with that holder's record loaded; the engine's pick among the loaded holders is then the
        // session's (checked on the fill as defence in depth)
        if adl {
            let (am, asd) = unsafe { SL_ADL_SIDE };
            match adl::pick(&sl, &eng.state, am, asd) {
                Ok(top) => {
                    if let Ok(f) = &res {
                        if f.iter().any(|x| x.kind == 2 && Some(x.maker) != top) {
                            fin(&mut out, &sl, ST_SL_BADWIT, None);
                            return out;
                        }
                    }
                }
                Err(Ok(n)) => {
                    fin(&mut out, &sl, ST_SL_MISSING, Some(n));
                    return out;
                }
                Err(Err(st)) => {
                    fin(&mut out, &sl, st, None);
                    return out;
                }
            }
        }
        if let (crate::BatchOp::Liquidate { .. }, Ok(f)) = (&op, &res) {
            if !adl && (f.is_empty() || f.iter().any(|x| x.kind == 2)) {
                fin(&mut out, &sl, ST_SL_UNSUPPORTED, None);
                return out;
            }
        }
        let mut dirty_accts: Vec<AccountId> = Vec::new();
        // ---- post-unit guards (on the outcome, applied or rolled back) ----
        let post = (|| -> Result<(), Need> {
            // walk check
            for (m, b) in &eng.state.books {
                // round 16: the walk stopped at an order whose FIFO predecessors are not all loaded (or an unknown level)
                if let Some(sh) = b.sl.short {
                    return Err(match sh {
                        crate::book::SlShort::Order(o) => Need::Order(o),
                        crate::book::SlShort::Level(sd, p) => Need::Level(m.0, sd, p),
                    });
                }
                if let Some((ts, last)) = b.peeks.0.last() {
                    walk_check(&sl, b, m.0, ts.opposite().as_u8(), *last)?;
                }
            }
            // round 18: a PERP balance moves only with pglob: (holder count) and the account's exception list loaded; a
            // proposal created by the unit records the snapshot size (non-zero holders now)
            for (a, b0) in &sl.bal0 {
                if eng.state.perp_balances.get(a).copied().unwrap_or(0) != *b0 {
                    if sl.pglob.is_none() {
                        return Err(Need::Pglob);
                    }
                    if !sl.pexc.contains_key(a) {
                        return Err(Need::Pexc(*a));
                    }
                }
            }
            let fresh: Vec<u64> = eng.state.proposals.keys().filter(|id| !sl.pcnt.contains_key(id)).copied().collect();
            if !fresh.is_empty() {
                if sl.pglob.is_none() {
                    return Err(Need::Pglob);
                }
                let h = holders_now(&sl, &eng.state) as usize;
                for id in fresh {
                    sl.pcnt.insert(id, (0, h, 0));
                }
            }
            // round 15: a withdrawal record can only appear for a loaded set (the author's, pre); catch-all
            for (a, _) in eng.state.withdrawals.keys() {
                if !sl.wdl.contains_key(a) {
                    return Err(Need::Wdl(*a));
                }
            }
            // round 16 catch-alls: every governance nonce / external source / commit in the partial state has its
            // record loaded; a commit created in the segment has its author's index loaded; the PERP aggregates move
            // only when `perp:0` is loaded
            for a in eng.state.seen_gov_nonces.keys() {
                if !sl.gnon.contains_key(a) {
                    return Err(Need::Gnon(*a));
                }
            }
            for a in &eng.state.external_sources {
                if !sl.xsrc.contains_key(a) {
                    return Err(Need::Xsrc(*a));
                }
            }
            for (h, e) in &eng.state.commits {
                if !sl.cmts.contains(h) {
                    return Err(Need::Cmt(*h));
                }
                if !sl.cmt0.contains(h) && !sl.acmt.contains_key(&e.account) {
                    return Err(Need::Acmt(e.account));
                }
                // round 23: a created commit joins its TTL's expiry group
                if !sl.cmt0.contains(h) && !sl.cx.contains_key(&e.ttl_height) {
                    return Err(Need::Cexp(e.ttl_height));
                }
            }
            if !sl.perp && (eng.state.perp_supply != 0 || eng.state.perp_burned != 0 || eng.state.next_market_id != 0) {
                return Err(Need::Perp);
            }
            let d = eng.state.take_dirty();
            // every account the unit wrote (incl. rolled-back journals) must be loaded
            for a in &d.accounts {
                if !sl.accts.contains_key(a) {
                    return Err(Need::Account(*a));
                }
            }
            dirty_accts.extend(d.accounts.iter().copied());
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
                    // round 16: proven absent at start -> known, empty ends
                    let bk = eng.state.book_mut(MarketId(mm));
                    bk.sl.on = true;
                    bk.sl.lv.insert((sd, p), (None, None));
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
                let now = eng.state.books.get(&MarketId(mm)).is_some_and(|b| lvl_live(b, sd, p));
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
        // round 20: oracle records + expiry queue
        if let Err(e) = ora::post(&mut sl, &eng.state) {
            match e {
                Ok(n) => fin(&mut out, &sl, ST_SL_MISSING, Some(n)),
                Err(st) => fin(&mut out, &sl, st, None),
            }
            return out;
        }
        // round 21: rank sub-tree maintenance (positions changed by the unit)
        if let Err(e) = adl::maint(&mut sl, &eng.state, &dirty_accts) {
            match e {
                Ok(n) => fin(&mut out, &sl, ST_SL_MISSING, Some(n)),
                Err(st) => fin(&mut out, &sl, st, None),
            }
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
                    // R17-L1 (round 17 collection): the session's MNP1 event mask for liquidation / ADL fills (unit id 0
                    // in MNP1: the taker id is written as LIQ_TAKER_EV); the stateless log must equal the session's
                    ev(if (f.kind == 2 || f.kind == 3) && !v2 {
                        crate::LIQ_TAKER_EV
                    } else {
                        u32::from_le_bytes([f.taker_id.0[0], f.taker_id.0[1], f.taker_id.0[2], f.taker_id.0[3]])
                    });
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
        if let Some((f0, npos, dg)) = rec.light {
            // light record (R14-M2): only the acct: leaf may change; membership / positions must be as loaded
            // (the partial state holds none of its positions), else the full record is needed
            if flags != f0 || a.is_some_and(|a| !a.positions.is_empty() || !a.isolated_margin.is_empty()) {
                return Err(Need::Account(*id));
            }
            wit::acct_leaf(&mut b, id, a.map(|a| a.collateral).unwrap_or(0), s.perp_balances.get(id).copied().unwrap_or(0), s.withdrawn_total.get(id).copied().unwrap_or(0));
            puts.push(kh(&b));
            apos_leaf_d(&mut b, id, flags, npos, &dg);
            puts.push(kh(&b));
            continue;
        }
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
    for m in sl.markets.keys() {
        // round 16: a market created in the segment (loaded as proven absent) is put too
        if let Some(p) = s.markets.get(&MarketId(*m)) {
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
    // levels (round 16, linked FIFO): new ends, and the links of every loaded / created order whose neighbours changed.
    // An order the witness did not load is live (no unit of the segment could reach it); one whose links change (the
    // neighbour of a removed order, a new head, the tail a new order is appended to) must be loaded -> Need::Order.
    let mut by_lvl: BTreeMap<(u32, u8, Price), Vec<OrderId>> = BTreeMap::new();
    for (oid, (m, sd, p, _)) in &sl.oloc {
        by_lvl.entry((*m, *sd, *p)).or_default().push(*oid);
    }
    for (m, sd, p) in sl.levels.keys() {
        let Some(bk) = s.books.get(&MarketId(*m)) else { continue };
        let side = Side::from_u8(*sd).unwrap();
        let live = |o: &OrderId| bk.get(*o).is_some_and(|z| z.remaining > 0);
        let lk = &bk.sl.lk;
        let (h0, t0) = bk.sl.lv.get(&(*sd, *p)).copied().unwrap_or((None, None));
        let news: Vec<OrderId> = bk.sl_mem_level(side, *p).into_iter().filter(|id| !lk.contains_key(id) && live(id)).collect();
        // first order at or after / before x on the start chain that is still live (an unloaded one is live)
        let fwd = |mut x: Option<OrderId>| -> Option<OrderId> {
            while let Some(o) = x {
                match lk.get(&o) {
                    Some(&(_, nx)) if !live(&o) => x = nx,
                    _ => return Some(o),
                }
            }
            None
        };
        let back = |mut x: Option<OrderId>| -> Option<OrderId> {
            while let Some(o) = x {
                match lk.get(&o) {
                    Some(&(pv, _)) if !live(&o) => x = pv,
                    _ => return Some(o),
                }
            }
            None
        };
        let hh = fwd(h0);
        let tt = back(t0);
        let need = |o: Option<OrderId>| -> Result<(), Need> {
            match o {
                Some(x) if !lk.contains_key(&x) => Err(Need::Order(x)),
                _ => Ok(()),
            }
        };
        if hh != h0 {
            need(hh)?;
        }
        if !news.is_empty() {
            need(tt)?;
        }
        for o in by_lvl.get(&(*m, *sd, *p)).map(|v| v.as_slice()).unwrap_or(&[]) {
            let Some(&(pv, nx)) = lk.get(o) else { continue }; // created in the segment: below
            if !live(o) {
                olk_kid(&mut b, o);
                dels.push(kid_key(&b));
                need(back(pv))?;
                need(fwd(nx))?;
            } else {
                let fp = back(pv);
                let fnx = fwd(nx).or_else(|| news.first().copied());
                olk_leaf(&mut b, o, fp, fnx);
                puts.push(kh(&b));
            }
        }
        for (i, o) in news.iter().enumerate() {
            let pv = if i == 0 { tt } else { Some(news[i - 1]) };
            olk_leaf(&mut b, o, pv, news.get(i + 1).copied());
            puts.push(kh(&b));
        }
        match (hh.or(news.first().copied()), news.last().copied().or(tt)) {
            (Some(h), Some(t)) => {
                lvl_leaf(&mut b, MarketId(*m), *sd, *p, h, t);
                puts.push(kh(&b));
            }
            _ => {
                if h0.is_some() {
                    lvl_kid(&mut b, MarketId(*m), *sd, *p);
                    dels.push(kid_key(&b));
                }
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
    // withdrawal record sets: rewritten only when the live set changed (lazy pruning on touch, witness-independent)
    for (id, live0) in &sl.wdl {
        let now = wdl_of(s, id);
        if now != *live0 {
            if now.is_empty() {
                wdl_kid(&mut b, id);
                dels.push(kid_key(&b));
            } else {
                wdl_leaf(&mut b, id, &now);
                puts.push(kh(&b));
            }
        }
    }
    // round 16: PERP aggregates, governance nonces, external sources, commits and commit indexes
    if sl.perp {
        perp_leaf(&mut b, s.perp_supply, s.perp_burned, s.next_market_id);
        puts.push(kh(&b));
    }
    // round 22: the global counts move only with `gcnt:0` loaded; catch-all of gcnt_delta's premise: every id of the
    // partial Account map / PERP ledger has its record loaded, every market of the partial state its market record
    for a in s.accounts.keys().chain(s.perp_balances.keys()) {
        if !sl.accts.contains_key(a) {
            return Err(Need::Account(*a));
        }
    }
    for m in s.markets.keys() {
        if !sl.markets.contains_key(&m.0) {
            return Err(Need::Market(m.0));
        }
    }
    let gd = gcnt_delta(sl, s);
    if gd != [0; GCNT_N] {
        let Some(g0) = sl.gcnt else { return Err(Need::Gcnt) };
        gcnt_leaf(&mut b, &gcnt_add(&g0, &gd));
        puts.push(kh(&b));
    }
    for (id, v0) in &sl.gnon {
        if let Some(v) = s.seen_gov_nonces.get(id) {
            if v != v0 {
                wit::gnon_leaf(&mut b, id, *v);
                puts.push(kh(&b));
            }
        }
    }
    for (id, x0) in &sl.xsrc {
        if !*x0 && s.external_sources.contains(id) {
            xsrc_leaf(&mut b, id);
            puts.push(kh(&b));
        }
    }
    for (h, e) in &s.commits {
        wit::cmt_leaf(&mut b, h, e);
        puts.push(kh(&b));
    }
    // round 23 (R16-I1): eager expiry -- the cmt: records that expired at this run's hook are deleted (a hash re-used
    // by a new commit in the run was just rewritten above)
    for h in sl.cmtx.keys() {
        if !s.commits.contains_key(h) {
            wit::cmt_kid(&mut b, h);
            dels.push(kid_key(&b));
        }
    }
    // the expiry groups: an expired group (u < height) is deleted; a live one gains the commits created in the run
    for (u, g0) in &sl.cx {
        let mut now: Vec<H> = Vec::new();
        if *u >= s.height {
            now.extend_from_slice(g0);
            for (h, e) in &s.commits {
                if e.ttl_height == *u && !sl.cmt0.contains(h) {
                    now.push(*h);
                }
            }
            now.sort_unstable();
        }
        if now != *g0 {
            if now.is_empty() {
                cexp_kid(&mut b, *u);
                dels.push(kid_key(&b));
            } else {
                cexp_leaf(&mut b, *u, &now);
                puts.push(kh(&b));
            }
        }
    }
    for (id, all0) in &sl.acmt_all {
        // round 23: rewritten when the committed entry list changed (a created commit, or entries dropped by the hook's
        // eager expiry); rounds 16-22: lazily, when the live set changed
        let now = acmt_of(s, id);
        if now != *all0 {
            if now.is_empty() {
                acmt_kid(&mut b, id);
                dels.push(kid_key(&b));
            } else {
                acmt_leaf(&mut b, id, &now);
                puts.push(kh(&b));
            }
        }
    }
    // round 18: governance -- exception lists recomputed on the (complete) proposal set; round 19 (R18-M1 fix): each
    // live proposal's exception sub-tree updated at the loaded accounts' keys (a proposal created in the segment starts
    // empty: every exception it can have is a loaded account's), a finalized proposal's sub-tree dropped with its
    // pglob: entry; prop: leaves with their counts, pglob:0
    if sl.pglob.is_some() {
        let now: BTreeMap<AccountId, Vec<PexcE>> = sl.pexc.keys().map(|a| (*a, pexc_of(s, a))).collect();
        let mut es: Vec<(u64, H)> = Vec::with_capacity(s.proposals.len());
        for pid in s.proposals.keys() {
            let mut st = sl.xt.remove(pid).unwrap_or(PTree { nodes: Vec::new(), root: P::E, node_hashes: 0, rids: Vec::new() });
            for (a, l) in &now {
                match l.iter().find(|e| e.0 == *pid) {
                    Some(e) => {
                        pxe_leaf(&mut b, *pid, a, e.1, e.2);
                        let (k, lh) = kh(&b);
                        st.set(k, lh).map_err(|_| Need::Pexc(*a))?;
                    }
                    None => {
                        pxe_kid(&mut b, *pid, a);
                        st.remove(&kid_key(&b)).map_err(|_| Need::Pexc(*a))?;
                    }
                }
            }
            sl.leaf_hashes += now.len() as u64;
            es.push((*pid, st.root_hash()));
            sl.xt.insert(*pid, st);
        }
        for (id, p) in &s.proposals {
            let (vn0, sn, pv0) = sl.pcnt[id];
            wit::prop_leaf_n(&mut b, *id, p, vn0 + p.voted.len() - pv0, sn);
            puts.push(kh(&b));
        }
        for id in sl.pcnt.keys() {
            if !s.proposals.contains_key(id) {
                wit::prop_kid(&mut b, *id);
                dels.push(kid_key(&b));
            }
        }
        pglob_leaf(&mut b, s.next_proposal_id, holders_now(sl, s), &es);
        puts.push(kh(&b));
    }
    // round 20: oracle records
    ora::end(sl, s, &mut puts, &mut dels);
    // round 21: rank sub-tree roots
    adl::end(sl, &mut puts, &mut dels);
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
// round 15: MNWIT-S genesis by migration (session snapshot -> MNWIT-S root)
// ------------------------------------------------------------------------------------------------
/// input word 0 of a migration run; words 1..=n are the session snapshot (snapshot.rs encoding)
pub const SL_MIG_MAGIC: u32 = 0x4D4E_534D; // "MNSM"
pub struct MigOut {
    pub status: u32,
    pub digest: H,
    pub words: u32,
    /// MNWIT-S root of the decoded state (the stateless lineage's start root)
    pub root: H,
    /// the imported lineage's run count (export run number + 1: the migration run is a height of its own)
    pub segs: u32,
}
/// Migration run: accepted only for a fresh stateless lineage (`fresh`) and a snapshot whose digest / length equal the
/// compiled-in expectation (the export digest of the session image, chosen by governance -- the R4-S1 binding).
/// The MNWIT-S root is computed over the whole decoded state; the stateless image then carries it as SL_ROOT.
/// State the MNWIT-S leaf set does not commit (oracle rings / TWAPs / unbonding, proposals' voter sets and weight
/// snapshots, funding clocks) is NOT carried: a production migration needs leaves for it first (design §11).
pub fn migrate(rd: &mut dyn FnMut(u32) -> u32, expect: Option<&(H, u32)>, fresh: bool) -> MigOut {
    let mut o = MigOut { status: crate::ST_OK, digest: EMPTY, words: 0, root: EMPTY, segs: 0 };
    if !fresh {
        o.status = crate::ST_SESSION_LIVE;
        return o;
    }
    let Some((digest, words)) = expect else {
        o.status = crate::ST_IMPORT_LOCKED;
        return o;
    };
    if *words > crate::SNAP_LIMIT {
        o.status = crate::ST_BAD_SNAP;
        return o;
    }
    // round 17: one pass over the snapshot -- the decoder hashes what it reads (SnapR), so the digest is checked after
    // the decode (a decoded state is used only if every word was read and the digest matches; round 16 hashed the
    // words twice), and the decode skips the session's MNWIT1 witness tree (decode_opts build_wit = false)
    let mut rd1 = |i: u32| rd(1 + i);
    let mut r = crate::snapshot::SnapR::new(&mut rd1, *words);
    let dec = crate::snapshot::decode_opts(&mut r, false);
    let full = r.i == *words;
    let d: H = r.digest();
    if d != *digest || !full {
        o.status = crate::ST_BAD_SNAP;
        return o;
    }
    match dec {
        Ok(sess) => {
            debug_assert!(sess.w.is_none());
            let st = &sess.eng.state;
            // R15-M1: every object must stay loadable under the stateless image's per-object bounds
            let mut expo: BTreeMap<AccountId, BTreeSet<u32>> = BTreeMap::new();
            for (id, a) in st.accounts.iter() {
                expo.entry(*id).or_default().extend(a.positions.keys().map(|m| m.0));
            }
            // (round 16: no level-size bound -- linked-FIFO levels are never loaded whole; R15-M1 lifted)
            for (m, bk) in &st.books {
                for od in bk.live_orders() {
                    expo.entry(od.account).or_default().insert(m.0);
                }
            }
            // round 16: an account's commit index must stay loadable (SL_MAX_ACMT)
            let mut nc: BTreeMap<AccountId, usize> = BTreeMap::new();
            for e in st.commits.values() {
                *nc.entry(e.account).or_default() += 1;
            }
            if nc.values().any(|n| *n > SL_MAX_ACMT) {
                o.status = ST_SL_MIG_BOUNDS;
                return o;
            }
            // the insurance account is loaded light (R14-M2): its position count is unbounded
            if expo.iter().any(|(id, e)| *id != INSURANCE_ACCOUNT && e.len() > SL_MAX_POS) {
                o.status = ST_SL_MIG_BOUNDS;
                return o;
            }
            // round 20: oracle objects (orm: / orep: / rings / expiry groups) must stay loadable
            if !ora::mig_ok(st) {
                o.status = ST_SL_MIG_BOUNDS;
                return o;
            }
            // round 22: the migrated state is within the lineage's global caps (gcnt:0 starts at its counts)
            let (g, c) = (gcnt_of(st), sl_caps());
            // round 23: + live commits, and every commit's TTL within [height, height + COMMIT_TTL_HEIGHTS] (the session
            // invariant the bounded eager expiry relies on)
            if g[0] > c.accounts || g[1] > c.accounts || g[2] > c.markets || g[3] > c.oracles || g[4] > c.commits {
                o.status = ST_SL_MIG_BOUNDS;
                return o;
            }
            if st.commits.values().any(|e| e.ttl_height < st.height || e.ttl_height > st.height.saturating_add(COMMIT_TTL_HEIGHTS)) || cexp_groups(st).values().any(|g| g.len() as u64 > c.commit_group) {
                o.status = ST_SL_MIG_BOUNDS;
                return o;
            }
            o.root = s_root(st);
            o.digest = d;
            o.words = *words;
            o.segs = sess.segs + 1;
        }
        _ => o.status = crate::ST_BAD_SNAP,
    }
    o
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
    /// round 16: the run's engine height (height hook) -- a commit index entry is live iff ttl >= it
    pub live_h: core::cell::Cell<u64>,
    /// round 16 (adversarial tests only): send level records WITHOUT their head order (unless needed by id)
    pub t_omit_head: core::cell::Cell<bool>,
    /// round 18 (adversarial tests only): do not add `pglob:` for an exception list
    pub t_omit_pglob: core::cell::Cell<bool>,
    /// round 19 (adversarial tests only): forge every sent exception list against its sub-trees -- 1: drop the first
    /// entry, 2: weight + 1 on the first entry (both: add a fake entry for the first live proposal when the list is empty),
    /// 3: send every listed account as entry-less AND its sub-trees built without its entries (consistent forgery: only
    /// the sub-tree roots bound by `pglob:` tell it apart)
    pub t_pxe: core::cell::Cell<u8>,
    /// round 20 (adversarial tests only): drop the first entry of every sent oracle list record (1 orep, 2 orm, 3 oexp);
    /// 4: forge the first sample of every sent history (its report-set entry honest)
    pub t_odrop: core::cell::Cell<u8>,
    /// round 21 (adversarial tests only): rank sub-trees -- 1 send the leftmost leaf unverified, 2 hide the leftmost path
    pub t_adrop: core::cell::Cell<u8>,
    /// round 22 tests: forged `gcnt:0` counts (see build)
    pub t_gdrop: core::cell::Cell<u8>,
    /// round 23 (adversarial tests only): forged expiry groups -- 1: drop the first hash of every sent present group,
    /// 2: send every present group as absent (n = 0), 3: add a fake hash to every sent group
    pub t_cdrop: core::cell::Cell<u8>,
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
        WitBuilder { s, leaves, strs, root, live_h: core::cell::Cell::new(s.height), t_omit_head: core::cell::Cell::new(false), t_omit_pglob: core::cell::Cell::new(false), t_pxe: core::cell::Cell::new(0), t_odrop: core::cell::Cell::new(0), t_adrop: core::cell::Cell::new(0), t_gdrop: core::cell::Cell::new(0), t_cdrop: core::cell::Cell::new(0) }
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
        let mut lights: BTreeSet<AccountId> = BTreeSet::new();
        let mut wdls: BTreeSet<AccountId> = BTreeSet::new();
        let mut mkts: BTreeSet<u32> = BTreeSet::new();
        let mut aord: BTreeSet<AccountId> = BTreeSet::new();
        let mut levels: BTreeSet<(u32, u8, Price)> = BTreeSet::new();
        let mut bmps: BTreeSet<(u32, u8, u8, u64)> = BTreeSet::new();
        let mut ordx: BTreeSet<OrderId> = BTreeSet::new();
        let mut paths: BTreeSet<H> = BTreeSet::new();
        // round 16: the orders to send per level (a level need sends its head)
        let mut lsel: BTreeMap<(u32, u8, Price), BTreeSet<OrderId>> = BTreeMap::new();
        let mut perp = false;
        let mut gcnt = false;
        let mut cexps: BTreeSet<u64> = BTreeSet::new();
        let mut gnons: BTreeSet<AccountId> = BTreeSet::new();
        let mut xsrcs: BTreeSet<AccountId> = BTreeSet::new();
        let mut acmts: BTreeSet<AccountId> = BTreeSet::new();
        let mut cmts: BTreeSet<H> = BTreeSet::new();
        // round 18
        let mut pglob = false;
        let mut pexcs: BTreeSet<AccountId> = BTreeSet::new();
        let gov_all = if needs.iter().any(|n| matches!(n, Need::Pexc(_) | Need::Pglob)) { pexc_all(s) } else { BTreeMap::new() };
        // round 20: oracle needs
        let mut on = ora::ONeeds::default();
        // round 21: rank sub-tree needs
        let mut an = adl::ANeeds::default();
        for n in needs {
            if on.add(n) || an.add(n) {
                continue;
            }
            match *n {
                Need::Account(a) => {
                    accts.insert(a);
                }
                Need::Light(a) => {
                    lights.insert(a);
                }
                Need::Wdl(a) => {
                    wdls.insert(a);
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
                        lsel.entry(l).or_default().insert(o);
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
                Need::Perp => perp = true,
                Need::Gcnt => gcnt = true,
                Need::Cexp(u) => {
                    cexps.insert(u);
                }
                Need::Gnon(a) => {
                    gnons.insert(a);
                }
                Need::Xsrc(a) => {
                    xsrcs.insert(a);
                }
                Need::Acmt(a) => {
                    acmts.insert(a);
                }
                Need::Cmt(h) => {
                    cmts.insert(h);
                }
                Need::Pglob => pglob = true,
                Need::Pexc(a) => {
                    pexcs.insert(a);
                    accts.insert(a);
                }
                _ => {}
            }
        }
        // an exception list is read against the complete proposal set
        if !pexcs.is_empty() && !self.t_omit_pglob.get() {
            pglob = true;
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
        // round 16: a Path need for a key that EXISTS (a depth-rule key of an object the partial state does not hold, e.g.
        // a revealed inner Place re-using a live order's client_seq) is sent as a verified leaf (tag 4), so the guest
        // sees "exists" instead of an unverified hash-only leaf (which it may not trust, R14-C1)
        let pk: BTreeSet<H> = paths.clone();
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
        let lights: BTreeSet<AccountId> = lights.difference(&accts).copied().collect();
        let all: BTreeSet<(AccountId, bool)> = accts.iter().map(|a| (*a, false)).chain(lights.iter().map(|a| (*a, true))).collect();
        rec.extend_from_slice(&(all.len() as u16).to_le_bytes());
        for (id, light) in &all {
            let id = &*id;
            let a = s.accounts.get(id);
            let flags = a.is_some() as u8 | (s.perp_balances.contains_key(id) as u8) << 1 | (s.withdrawn_total.contains_key(id) as u8) << 2;
            keys.insert(wit::acct_key(id));
            apos_kid(&mut b, id);
            keys.insert(kid_key(&b));
            if *light && flags != 0 {
                rec.push(2);
                rec.extend_from_slice(&id.0);
                rec.push(flags);
                rec.extend_from_slice(&a.map(|a| a.collateral).unwrap_or(0).to_le_bytes());
                rec.extend_from_slice(&s.perp_balances.get(id).copied().unwrap_or(0).to_le_bytes());
                rec.extend_from_slice(&s.withdrawn_total.get(id).copied().unwrap_or(0).to_le_bytes());
                let mk: Vec<u32> = a.map(|a| a.positions.keys().map(|m| m.0).collect()).unwrap_or_default();
                rec.extend_from_slice(&(mk.len() as u32).to_le_bytes());
                rec.extend_from_slice(&apos_digest(&mk));
                continue;
            }
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
            let sel = lsel.get(&(*m, *sd, *p));
            rec.extend_from_slice(&m.to_le_bytes());
            rec.push(*sd);
            rec.extend_from_slice(&p.to_le_bytes());
            rec.extend_from_slice(&ids[0].0);
            rec.extend_from_slice(&ids[ids.len() - 1].0);
            // the head + the selected orders, FIFO order, each with its links
            let pick: Vec<usize> = (0..ids.len()).filter(|k| (*k == 0 && !self.t_omit_head.get()) || sel.is_some_and(|x| x.contains(&ids[*k]))).collect();
            rec.extend_from_slice(&(pick.len() as u16).to_le_bytes());
            for k in pick {
                let id = ids[k];
                let o2 = bk.get(id).unwrap();
                rec.extend_from_slice(&o2.id.0);
                rec.extend_from_slice(&o2.account.0);
                rec.push(o2.typ.as_u8());
                rec.push(o2.tif.as_u8());
                rec.extend_from_slice(&o2.qty.to_le_bytes());
                rec.extend_from_slice(&o2.remaining.to_le_bytes());
                rec.extend_from_slice(&o2.seq.to_le_bytes());
                rec.push(o2.isolated as u8);
                rec.extend_from_slice(&o2.margin_left.to_le_bytes());
                rec.extend_from_slice(&if k > 0 { ids[k - 1].0 } else { [0u8; 32] });
                rec.extend_from_slice(&ids.get(k + 1).map(|x| x.0).unwrap_or([0u8; 32]));
                keys.insert(wit::ord_key(&id));
                olk_kid(&mut b, &id);
                keys.insert(kid_key(&b));
            }
            lvl_kid(&mut b, MarketId(*m), *sd, *p);
            keys.insert(kid_key(&b));
        }
        rec.extend_from_slice(&(ordx.len() as u16).to_le_bytes());
        for oid in &ordx {
            rec.extend_from_slice(&oid.0);
            keys.insert(wit::ord_key(oid));
        }
        rec.extend_from_slice(&(wdls.len() as u16).to_le_bytes());
        for id in &wdls {
            let es = wdl_of(s, id);
            rec.extend_from_slice(&id.0);
            rec.push(es.len() as u8);
            for (n, a, p, h) in &es {
                rec.extend_from_slice(&n.to_le_bytes());
                rec.extend_from_slice(&a.to_le_bytes());
                rec.push(*p as u8);
                rec.extend_from_slice(&h.to_le_bytes());
            }
            wdl_kid(&mut b, id);
            keys.insert(kid_key(&b));
        }
        // ---- round 16 sections ----
        if perp {
            rec.push(1);
            rec.extend_from_slice(&s.perp_supply.to_le_bytes());
            rec.extend_from_slice(&s.perp_burned.to_le_bytes());
            rec.extend_from_slice(&s.next_market_id.to_le_bytes());
            perp_kid(&mut b);
            keys.insert(kid_key(&b));
        } else {
            rec.push(0);
        }
        rec.extend_from_slice(&(gnons.len() as u16).to_le_bytes());
        for id in &gnons {
            rec.extend_from_slice(&id.0);
            rec.extend_from_slice(&s.seen_gov_nonces.get(id).copied().unwrap_or(0).to_le_bytes());
            wit::gnon_kid(&mut b, id);
            keys.insert(kid_key(&b));
        }
        rec.extend_from_slice(&(xsrcs.len() as u16).to_le_bytes());
        for id in &xsrcs {
            rec.extend_from_slice(&id.0);
            rec.push(s.external_sources.contains(id) as u8);
            xsrc_kid(&mut b, id);
            keys.insert(kid_key(&b));
        }
        // the operator's state is the (lazily committed) full state: every listed commit is in s.commits; a hash
        // that is live in a loaded index is not repeated in the single-record section
        let mut in_idx: BTreeSet<H> = BTreeSet::new();
        rec.extend_from_slice(&(acmts.len() as u16).to_le_bytes());
        for id in &acmts {
            let es: Vec<(&H, &crate::state::CommitEntry)> = s.commits.iter().filter(|(_, e)| e.account == *id).collect();
            rec.extend_from_slice(&id.0);
            rec.push(es.len() as u8);
            for (h, e) in &es {
                rec.extend_from_slice(*h);
                rec.extend_from_slice(&e.ttl_height.to_le_bytes());
                rec.extend_from_slice(&e.commit_unit);
                rec.extend_from_slice(&e.commit_height.to_le_bytes());
                rec.push(e.revealed as u8);
                wit::cmt_kid(&mut b, h);
                keys.insert(kid_key(&b));
                if e.ttl_height >= self.live_h.get().max(s.height) {
                    in_idx.insert(**h);
                }
            }
            acmt_kid(&mut b, id);
            keys.insert(kid_key(&b));
        }
        let cmts: Vec<H> = cmts.difference(&in_idx).copied().collect();
        rec.extend_from_slice(&(cmts.len() as u16).to_le_bytes());
        for h in &cmts {
            rec.extend_from_slice(h);
            match s.commits.get(h) {
                Some(e) => {
                    rec.push(1);
                    rec.extend_from_slice(&e.account.0);
                    rec.extend_from_slice(&e.commit_unit);
                    rec.extend_from_slice(&e.commit_height.to_le_bytes());
                    rec.extend_from_slice(&e.ttl_height.to_le_bytes());
                    rec.push(e.revealed as u8);
                }
                None => rec.push(0),
            }
            wit::cmt_kid(&mut b, h);
            keys.insert(kid_key(&b));
        }
        // ---- round 18 sections ----
        if pglob {
            rec.push(1);
            rec.extend_from_slice(&s.next_proposal_id.to_le_bytes());
            rec.extend_from_slice(&perp_holders(s).to_le_bytes());
            rec.push(s.proposals.len() as u8);
            let ent: BTreeMap<u64, H> = pglob_entries(s, &gov_all).into_iter().collect();
            for (id, p) in &s.proposals {
                rec.extend_from_slice(&id.to_le_bytes());
                rec.extend_from_slice(&ent[id]);
                rec.extend_from_slice(&p.creator.0);
                rec.extend_from_slice(&p.market.0.to_le_bytes());
                rec.push(p.key.as_u8());
                rec.extend_from_slice(&p.value.to_le_bytes());
                rec.extend_from_slice(&p.created_seq.to_le_bytes());
                rec.extend_from_slice(&p.deadline_seq.to_le_bytes());
                rec.extend_from_slice(&p.supply_at_create.to_le_bytes());
                rec.extend_from_slice(&p.yes.to_le_bytes());
                rec.extend_from_slice(&p.no.to_le_bytes());
                rec.extend_from_slice(&(p.voted.len() as u32).to_le_bytes());
                rec.extend_from_slice(&(p.weight_snapshot.len() as u32).to_le_bytes());
                wit::prop_kid(&mut b, *id);
                keys.insert(kid_key(&b));
            }
            pglob_kid(&mut b);
            keys.insert(kid_key(&b));
        } else {
            rec.push(0);
        }
        rec.extend_from_slice(&(pexcs.len() as u16).to_le_bytes());
        for id in &pexcs {
            let mut es = gov_all.get(id).cloned().unwrap_or_default();
            match (self.t_pxe.get(), es.is_empty(), s.proposals.keys().next()) {
                (1 | 2, true, Some(pid)) => es.push((*pid, 7, false)),
                (1, false, _) => {
                    es.remove(0);
                }
                (2, false, _) => es[0].1 += 1,
                (3, _, _) => es.clear(),
                _ => {}
            }
            rec.extend_from_slice(&id.0);
            rec.push(es.len() as u8);
            for (pid, w, v) in &es {
                rec.extend_from_slice(&pid.to_le_bytes());
                rec.extend_from_slice(&w.to_le_bytes());
                rec.push(*v as u8);
            }
        }
        // round 19: every live proposal's exception sub-tree, expanded at the loaded accounts' keys
        if pglob {
            let mut forged = gov_all.clone();
            if self.t_pxe.get() == 3 {
                forged.retain(|a, _| !pexcs.contains(a));
            }
            for (pid, v) in pxe_sets(s, &forged) {
                let mut ks: Vec<H> = pexcs
                    .iter()
                    .map(|a| {
                        pxe_kid(&mut b, pid, a);
                        kid_key(&b)
                    })
                    .collect();
                ks.sort();
                let lv: Vec<(H, H)> = v.iter().map(|x| (x.0, x.1)).collect();
                let st: Vec<(usize, Vec<u8>)> = v.into_iter().map(|x| (x.2, x.3)).collect();
                emit_tree(&lv, &st, &mut rec, 0, lv.len(), 0, &ks, false, &BTreeSet::new());
            }
        }
        // round 20: oracle records
        ora::build(s, &on, &mut rec, &mut keys, self.t_odrop.get());
        // round 21: rank sub-trees
        adl::build(s, &an, &mut rec, &mut keys, self.t_adrop.get());
        // round 22: gcnt:0 (`t_gdrop` tests: 1 = accounts - 1, 2 = PERP ids - 1, 3 = markets - 1, 4 = bonds - 1, each
        // with a forged leaf string, i.e. a record that does not verify)
        if gcnt {
            rec.push(1);
            let mut g = gcnt_of(s);
            let t = self.t_gdrop.get();
            if (1..=GCNT_N as u8).contains(&t) {
                g[t as usize - 1] = g[t as usize - 1].wrapping_sub(1);
            }
            for x in g {
                rec.extend_from_slice(&x.to_le_bytes());
            }
            gcnt_kid(&mut b);
            keys.insert(kid_key(&b));
        } else {
            rec.push(0);
        }
        // round 23: commit expiry groups
        let groups = cexp_groups(s);
        rec.extend_from_slice(&(cexps.len() as u16).to_le_bytes());
        let t = self.t_cdrop.get();
        for u in &cexps {
            let mut hs: Vec<H> = groups.get(u).cloned().unwrap_or_default();
            match t {
                1 if !hs.is_empty() => {
                    hs.remove(0);
                }
                2 => hs.clear(),
                3 => {
                    let mut f = [0x5Au8; 32];
                    f[..8].copy_from_slice(&u.to_le_bytes());
                    if !hs.contains(&f) {
                        hs.push(f);
                        hs.sort_unstable();
                    }
                }
                _ => {}
            }
            rec.extend_from_slice(&u.to_le_bytes());
            rec.extend_from_slice(&(hs.len() as u16).to_le_bytes());
            for h in &hs {
                rec.extend_from_slice(h);
            }
            cexp_kid(&mut b, *u);
            keys.insert(kid_key(&b));
        }
        let keys: Vec<H> = keys.into_iter().collect();
        self.tree(&mut o, 0, self.leaves.len(), 0, &keys, false, &pk);
        o.extend_from_slice(&rec);
        o
    }
    fn tree(&self, o: &mut Vec<u8>, lo: usize, hi: usize, d: usize, keys: &[H], sib: bool, pk: &BTreeSet<H>) {
        emit_tree(&self.leaves, &self.strs, o, lo, hi, d, keys, sib, pk)
    }
}
fn range_hash(leaves: &[(H, H)], lo: usize, hi: usize, d: usize) -> H {
    match hi - lo {
        0 => EMPTY,
        1 => leaves[lo].1,
        _ => {
            let mid = lo + leaves[lo..hi].partition_point(|(k, _)| kbit(k, d) == 0);
            let a = range_hash(leaves, lo, mid, d + 1);
            let b = range_hash(leaves, mid, hi, d + 1);
            wit::node_hash(&a, &b)
        }
    }
}
/// preorder pruned tree over leaves[lo..hi) at depth d; `keys` = sorted keys whose paths to expand.
/// A single leaf is always emitted as L (never hidden in an O). `sib`: this subtree is the sibling
/// of an expanded path -> expand one more level, so a later deletion on the path can prove the
/// sibling is an internal node (no collapse) instead of an opaque hash (ambiguous -> missing).
/// (round 19: a free function over any sorted leaf set -- the MNWIT-S tree and the proposals' exception sub-trees)
#[allow(clippy::too_many_arguments)]
fn emit_tree(leaves: &[(H, H)], strs: &[(usize, Vec<u8>)], o: &mut Vec<u8>, lo: usize, hi: usize, d: usize, keys: &[H], sib: bool, pk: &BTreeSet<H>) {
    match hi - lo {
        0 => o.push(0),
        1 => {
            // a key whose path ends at ANOTHER leaf needs that leaf verified (exclusion / split, R14-C1);
            // so does a single-leaf sibling of a path: a deletion on the path may lift it to where a later
            // insertion must split it
            if sib || keys.iter().any(|k| *k != leaves[lo].0) || pk.contains(&leaves[lo].0) {
                let (kl, st) = &strs[lo];
                o.push(4);
                o.extend_from_slice(&(*kl as u16).to_le_bytes());
                o.extend_from_slice(&st[..*kl]);
                o.extend_from_slice(&((st.len() - kl) as u16).to_le_bytes());
                o.extend_from_slice(&st[*kl..]);
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
            emit_tree(leaves, strs, o, lo, mid, d + 1, &keys[..km], !keys.is_empty() && km == 0, pk);
            emit_tree(leaves, strs, o, mid, hi, d + 1, &keys[km..], !keys.is_empty() && km == keys.len(), pk);
        }
    }
}
