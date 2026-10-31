//! Loop round 6 (R4-M3 rest): differential batches for the governance + commit-reveal port --
//! GovDeposit / GovWithdraw, CreateMarket, CreateProposal / Vote / FinalizeProposal (parameter
//! changes, delisting) and Commit / Reveal (inner op through the normal dispatch, parent edge,
//! TTL, pending cap, "rejected = unchanged").
//!
//!   govgen  <seed> <n_ops> <out.bin>   one MNP2 batch (unit ids + extension area)
//!   govfuzz <n> <n_ops>                real vs port: hash + events + per-unit MNWIT1 roots
//!                                      (real scratch / port incremental / port scratch) +
//!                                      snapshot v3 round trip + segment cut / bind check
//!   govedge                            deterministic boundary batches: real vs port + intent
//!
//! The builder steps the REAL engine while it writes the batch (a Reveal names its commit unit as
//! a parent, so the unit ids must be known while building); `run_real_eng_h` re-runs the finished
//! batch from scratch and asserts the unit-id table.
//!
//! Accounts: 1..=3 bonded oracles (fixture), 4..=9 hold 2 x ORACLE_BOND_PERP PERP (fixture bit 27),
//! the rest traders / fresh ids.
use super::*;
use mnpilot::BatchOp as B;

const DOLLAR: i64 = PRICE_SCALE as i64;

pub struct GB {
    pub eng: Engine,
    pub ids: Vec<AccountId>,
    pub parent: minuend_types::UnitId,
    pub ops: Vec<[u32; 8]>,
    pub ext: Vec<u32>,
    pub uids: Vec<[u8; 32]>,
    pub flags: u32,
    /// real event of every op (same codes as the harness)
    pub ev: Vec<u32>,
    /// ids of the units the real engine holds (a Reveal may name any of them as a parent)
    pub ingested: Vec<[u8; 32]>,
}

fn le_words(b: &[u8; 32]) -> [u32; 8] {
    let mut o = [0u32; 8];
    for k in 0..8 {
        o[k] = u32::from_le_bytes(b[4 * k..4 * k + 4].try_into().unwrap());
    }
    o
}

impl GB {
    pub fn new(n_acc: u32, flags: u32) -> Self {
        let ids: Vec<AccountId> = (0..n_acc).map(acct_id).collect();
        let mut eng = Engine::new();
        eng.state.markets.insert(BTC_USD, minuend_types::genesis_params());
        if flags & mnpilot::MARKET2_FLAG != 0 {
            eng.state.markets.insert(MarketId(2), minuend_types::genesis_params());
            eng.state.marks.insert(MarketId(2), 100_000 * PRICE_SCALE as i64);
        }
        real_fixtures(&mut eng, flags, &ids);
        GB { eng, ids, parent: genesis_id(), ops: Vec::new(), ext: Vec::new(), uids: Vec::new(), flags, ev: Vec::new(), ingested: Vec::new() }
    }
    /// append extension words, return their offset
    pub fn put_ext(&mut self, p: &[u32]) -> u32 {
        let off = self.ext.len() as u32;
        self.ext.extend_from_slice(p);
        off
    }
    fn rx(&self) -> impl Fn(u32, u32) -> Option<Vec<u32>> + '_ {
        move |off: u32, len: u32| {
            let (o, l) = (off as usize, len as usize);
            if o + l > self.ext.len() {
                None
            } else {
                Some(self.ext[o..o + l].to_vec())
            }
        }
    }
    /// apply one op (words final, extension already put); returns the real event word
    pub fn op(&mut self, w: [u32; 8]) -> u32 {
        let i = self.ops.len();
        self.ops.push(w);
        let d = mnpilot::decode_op(&w);
        // loop round 7 (R7-M1): the pilot refuses a GovWithdraw of 0 by an id without a PERP ledger entry (also as a
        // Reveal's inner op); the unit never reaches the real engine (event 19, unit id 0)
        if pilot_gov_refused(&self.eng, &d, &self.ids, &self.rx()) {
            self.uids.push([0; 32]);
            self.ev.push(mnpilot::STATE_CAP_CODE);
            return mnpilot::STATE_CAP_CODE;
        }
        let e = match d {
            B::SetHeight { height } => {
                self.uids.push([0; 32]);
                if height >= self.eng.state.height {
                    self.eng.state.height = height;
                    self.eng.state.prune_withdrawals(height);
                    self.eng.state.prune_commits(height);
                    self.eng.state.prune_oracle_unbonding(height);
                    mnpilot::EV_HEIGHT
                } else {
                    2
                }
            }
            B::SetSeq { seq } => {
                self.uids.push([0; 32]);
                if seq >= self.eng.state.seq {
                    self.eng.state.seq = seq;
                    mnpilot::EV_SEQ
                } else {
                    2
                }
            }
            _ => {
                if let B::Deposit { .. } = d {
                    self.eng.state.deposits_allowed.insert((aa_unit(false, i), false));
                }
                if let B::GovDeposit { .. } = d {
                    self.eng.state.deposits_allowed.insert((aa_unit(true, i), true));
                }
                let op = real_op(&w, &self.ids, &self.rx(), i).expect("builder op has an upstream form");
                let parents = match d {
                    B::Reveal { ext, .. } => {
                        let e = (self.rx())(ext, mnpilot::EXT_REVEAL_LEN).unwrap();
                        let mut ps: Vec<minuend_types::UnitId> = [&e[24..32], &e[32..40]]
                            .iter()
                            .map(|x| minuend_types::UnitId(words_id(x)))
                            .filter(|p| p.0 != [0u8; 32])
                            .collect();
                        ps.sort();
                        ps.dedup();
                        ps
                    }
                    _ => vec![self.parent],
                };
                let u = sign_unit(parents, op, &secret(d.signer().unwrap()));
                let id = unit_id(&u);
                self.uids.push(id.0);
                match self.eng.ingest(u) {
                    Ok(evs) => {
                        assert_eq!(evs.len(), 1);
                        self.parent = id;
                        self.ingested.push(id.0);
                        match &evs[0] {
                            ExecEvent::Applied { fills, .. } => EV_APPLIED | fills.len() as u32,
                            ExecEvent::Rejected { reason, .. } => real_reason(reason),
                        }
                    }
                    Err(_) if matches!(d, B::Reveal { .. }) => 2,
                    Err(e) => panic!("builder ingest {}: {:?}", i, e),
                }
            }
        };
        self.ev.push(e);
        e
    }
    pub fn applied(&mut self, w: [u32; 8]) -> bool {
        self.op(w) & EV_APPLIED != 0
    }
    /// the linear parent the next unit would chain on
    pub fn last(&self) -> [u8; 32] {
        self.parent.0
    }
    pub fn words(&self) -> Vec<u32> {
        let mut w = vec![mnpilot::MAGIC2, self.ids.len() as u32, self.ops.len() as u32, self.flags];
        for id in &self.ids {
            w.extend_from_slice(&le_words(&id.0));
        }
        for o in &self.ops {
            w.extend_from_slice(o);
        }
        for u in &self.uids {
            w.extend_from_slice(&le_words(u));
        }
        w.push(self.ext.len() as u32);
        w.extend_from_slice(&self.ext);
        w
    }
    // ---- op helpers ----
    pub fn cseq(&self, a: u32) -> u64 {
        self.eng.state.seen_client_seq.get(&self.ids[a as usize]).copied().unwrap_or(0) + 1
    }
    pub fn w_dep(a: u32, amt: i64) -> [u32; 8] {
        [1 | (a << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, 0, 0]
    }
    pub fn w_place(&self, a: u32, bid: bool, ioc: bool, price: i64, qty: u64, market: u32) -> [u32; 8] {
        let c = self.cseq(a);
        [2 | (a << 8), (!bid) as u32 | ((ioc as u32) << 2), price as u32, (price >> 32) as u32, qty as u32, (qty >> 32) as u32, c as u32, market]
    }
    pub fn w_gdep(a: u32, amt: u64) -> [u32; 8] {
        [14 | (a << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, 0, 0]
    }
    pub fn w_gwd(a: u32, amt: u64, nonce: u64) -> [u32; 8] {
        [15 | (a << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, nonce as u32, (nonce >> 32) as u32]
    }
    pub fn w_market(&mut self, a: u32, l: &[u32; 23]) -> [u32; 8] {
        let off = self.put_ext(l);
        [16 | (a << 8), 0, 0, 0, 0, 0, 0, off]
    }
    pub fn w_prop(a: u32, market: u32, key: u8, value: u64) -> [u32; 8] {
        [17 | (a << 8), market, key as u32, value as u32, (value >> 32) as u32, 0, 0, 0]
    }
    pub fn w_vote(a: u32, id: u64, approve: bool) -> [u32; 8] {
        [18 | (a << 8), id as u32, (id >> 32) as u32, approve as u32, 0, 0, 0, 0]
    }
    pub fn w_fin(a: u32, id: u64) -> [u32; 8] {
        [19 | (a << 8), id as u32, (id >> 32) as u32, 0, 0, 0, 0, 0]
    }
    pub fn w_height(h: u64) -> [u32; 8] {
        [10, h as u32, (h >> 32) as u32, 0, 0, 0, 0, 0]
    }
    pub fn w_seq(s: u64) -> [u32; 8] {
        [22, s as u32, (s >> 32) as u32, 0, 0, 0, 0, 0]
    }
    /// commit hash of `inner` (op words, its extension already put) with `salt` -- the REAL
    /// encoding (minuend_dag::reveal_commit_hash), so the port's own encode_op is checked
    pub fn commit_hash(&self, inner: &[u32; 8], salt: &[u8; 32]) -> [u8; 32] {
        let op = real_op(inner, &self.ids, &self.rx(), self.ops.len()).expect("inner op");
        minuend_dag::reveal_commit_hash(&op, salt)
    }
    pub fn w_commit(&mut self, a: u32, hash: &[u8; 32], ttl: u64) -> [u32; 8] {
        let off = self.put_ext(&le_words(hash));
        [20 | (a << 8), ttl as u32, (ttl >> 32) as u32, 0, 0, 0, 0, off]
    }
    pub fn w_reveal(&mut self, a: u32, commit_ref: &[u8; 32], salt: &[u8; 32], inner: &[u32; 8], p1: [u8; 32], p2: [u8; 32]) -> [u32; 8] {
        let mut p = Vec::with_capacity(40);
        p.extend_from_slice(&le_words(commit_ref));
        p.extend_from_slice(&le_words(salt));
        p.extend_from_slice(inner);
        p.extend_from_slice(&le_words(&p1));
        p.extend_from_slice(&le_words(&p2));
        let off = self.put_ext(&p);
        [21 | (a << 8), 0, 0, 0, 0, 0, 0, off]
    }
}

/// listing words (the 23-word CreateMarket extension)
#[allow(clippy::too_many_arguments)]
pub fn listing(sym: &str, tick: i64, im: u64, mm: u64, fee: u64, keeper: u64, spot: bool, fr: bool, usd: u64, cap: u64, min: i64, max: i64) -> [u32; 23] {
    let mut s = [0u8; 16];
    s[..sym.len().min(16)].copy_from_slice(&sym.as_bytes()[..sym.len().min(16)]);
    let mut l = [0u32; 23];
    for k in 0..4 {
        l[k] = u32::from_le_bytes(s[4 * k..4 * k + 4].try_into().unwrap());
    }
    let mut put = |i: usize, x: u64| {
        l[i] = x as u32;
        l[i + 1] = (x >> 32) as u32;
    };
    put(4, tick as u64);
    put(6, im);
    put(8, mm);
    put(10, fee);
    put(12, keeper);
    put(15, usd);
    put(17, cap);
    put(19, min as u64);
    put(21, max as u64);
    l[14] = spot as u32 | ((fr as u32) << 1);
    l
}
pub fn listing_regular(sym: &str) -> [u32; 23] {
    listing(sym, 1, 1000, 500, 5, 100, false, false, 0, 0, 0, 0)
}
pub fn listing_spot(sym: &str) -> [u32; 23] {
    listing(sym, 1, 10_000, 500, 5, 100, true, false, 0, 0, 50_000 * DOLLAR, 150_000 * DOLLAR)
}
pub fn listing_funding(sym: &str) -> [u32; 23] {
    listing(sym, 1, 100, 50, 5, 10, false, true, 10_000, 10, 0, 0)
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn salt(&mut self) -> [u8; 32] {
        let mut s = [0u8; 32];
        for k in 0..4 {
            s[8 * k..8 * k + 8].copy_from_slice(&self.next().to_le_bytes());
        }
        s
    }
}

/// Loop round 7 (R7-M1): the pilot rule `state_cap_ok` adds below the caps -- a GovWithdraw of 0 by an id that has no
/// PERP ledger entry (upstream: succeeds and inserts a zero balance) is refused with code 19; for a Reveal the inner op
/// is checked with the Reveal's author (as the port does). Mirrored by the builder and by `run_real_eng_h`.
pub fn pilot_gov_refused(eng: &Engine, d: &B, ids: &[AccountId], rx: &dyn Fn(u32, u32) -> Option<Vec<u32>>) -> bool {
    let Some(author) = d.signer().and_then(|a| ids.get(a as usize)) else { return false };
    let zero_new = |x: &B| matches!(x, B::GovWithdraw { amount: 0, .. }) && !eng.state.perp_balances.contains_key(author);
    zero_new(d)
        || match d {
            B::Reveal { ext, .. } => rx(*ext, mnpilot::EXT_REVEAL_LEN).is_some_and(|e| {
                let mut iw = [0u32; 8];
                iw.copy_from_slice(&e[16..24]);
                zero_new(&mnpilot::decode_op(&iw))
            }),
            _ => false,
        }
}

/// A random but mostly-valid inner op for a Reveal by `a` (its extension put first).
fn inner_op(g: &mut GB, rng: &mut Rng, a: u32, n_acc: u32) -> [u32; 8] {
    let mid = 100_000 * DOLLAR;
    let nm = g.eng.state.next_market_id;
    match rng.below(12) {
        0..=3 => {
            let px = mid + (rng.below(21) as i64 - 10) * DOLLAR * 10;
            let m = if rng.below(4) == 0 && nm > 2 { 2 + rng.below((nm - 2) as u64) as u32 } else { 1 };
            g.w_place(a, rng.below(2) == 0, rng.below(3) == 0, px, QTY_SCALE / 1000, m)
        }
        4 => GB::w_gwd(a, rng.below(20_000), rng.below(40)),
        5 => GB::w_prop(a, 1 + rng.below(nm as u64) as u32, rng.below(5) as u8, [0, 600, 900, 1000, 4, 50][rng.below(6) as usize]),
        6 => GB::w_vote(a, 1 + rng.below(g.eng.state.next_proposal_id.max(1)), rng.below(3) != 0),
        7 => [11 | (a << 8), 0, 0, 0, 0, 0, 0, 0],
        8 => [12 | (a << 8), 0, 0, 0, 0, 0, 0, 0],
        9 => {
            let l = if rng.below(2) == 0 { listing_regular("RVL") } else { listing_spot("RVS") };
            g.w_market(a, &l)
        }
        10 => {
            let amt = rng.below(2000) as i64 * USD_SCALE as i64;
            [6 | (a << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, rng.below(30) as u32, 0]
        }
        _ => {
            // forbidden inner kinds / foreign signer (the real engine refuses the unit at ingest)
            match rng.below(3) {
                0 => GB::w_dep(a, 5 * USD_SCALE as i64),
                1 => GB::w_gdep(a, 5),
                _ => [11 | (((a + 1) % n_acc) << 8), 0, 0, 0, 0, 0, 0, 0],
            }
        }
    }
}

pub fn gov_batch(seed: u64, n_ops: u32) -> Vec<u32> {
    gov_build(seed, n_ops).words()
}
pub fn gov_build(seed: u64, n_ops: u32) -> GB {
    gov_build_x(seed, n_ops, false)
}
/// Loop round 7 review (cross-module coverage): `x` adds liquidations, slashes, collateral withdrawals and leveraged
/// IOC trades to the governance mix (proposals change im / mm / fees of the traded market, oracle reports move the
/// mark), so gov x liq x oracle sequences are compared real vs port. x = false draws exactly the govfuzz sequence.
pub fn gov_build_x(seed: u64, n_ops: u32, x: bool) -> GB {
    let mut rng = Rng(seed.wrapping_mul(0xA24B_AED4_963E_E407) | 1);
    let n_acc = 12 + rng.below(6) as u32;
    let flags = mnpilot::ORACLES_FLAG | mnpilot::PERP_FLAG;
    let mut g = GB::new(n_acc, flags);
    let mid = 100_000 * DOLLAR;
    for a in 1..n_acc {
        g.op(GB::w_dep(a, 20_000 * USD_SCALE as i64));
    }
    for o in 1..=3u32 {
        g.op([8 | (o << 8), 0, mid as u32, (mid >> 32) as u32, 0, 0, 0, 1]);
    }
    let mut height = 0u64;
    let mut pending: Vec<(u32, [u8; 32], [u8; 32], [u32; 8], [u8; 32])> = Vec::new(); // (acct, commit, salt, inner, commit uid)
    let mut nonce: Vec<u64> = vec![0; n_acc as usize];
    for _ in 0..n_ops {
        let a = 1 + rng.below((n_acc - 1) as u64) as u32;
        let holder = 4 + rng.below(6) as u32;
        let nm = g.eng.state.next_market_id;
        let np = g.eng.state.next_proposal_id;
        match rng.below(100) {
            0..=7 => {
                let amt = match rng.below(10) {
                    0 => u64::MAX,
                    1 => (minuend_types::PERP_SUPPLY_MAX as u64).saturating_sub(rng.below(3)),
                    _ => rng.below(30_000),
                };
                g.op(GB::w_gdep(a, amt));
            }
            8..=13 => {
                let who = if rng.below(2) == 0 { holder } else { a };
                let n = &mut nonce[who as usize];
                let nn = match rng.below(6) {
                    0 => *n,
                    1 => n.saturating_sub(1),
                    2 => *n + 5,
                    _ => *n + 1,
                };
                let big = rng.below(3) == 0;
                let amt = rng.below(if big { 300_000 } else { 5_000 });
                if g.applied(GB::w_gwd(who, amt, nn)) {
                    *n = nn;
                }
            }
            14..=21 => {
                let mut l = match rng.below(3) {
                    0 => listing_regular("NEWR"),
                    1 => listing_spot("NEWS"),
                    _ => listing_funding("NEWF"),
                };
                if rng.below(4) == 0 {
                    // perturb one field: often illegal
                    let i = 4 + rng.below(19) as usize;
                    l[i] = match rng.below(4) {
                        0 => 0,
                        1 => l[i].wrapping_add(1),
                        2 => u32::MAX,
                        _ => rng.next() as u32,
                    };
                }
                let who = if rng.below(4) == 0 { a } else { holder };
                let w = g.w_market(who, &l);
                g.op(w);
            }
            22..=29 => {
                let m = if rng.below(8) == 0 { nm + 3 } else { 1 + rng.below(nm as u64 - 1) as u32 };
                let key = rng.below(6) as u8;
                let value = if key == 4 && rng.below(4) != 0 {
                    0
                } else {
                    [0u64, 4, 10, 50, 100, 200, 300, 500, 600, 1000, 1200, 2000, 5000, 10_000, 20_000][rng.below(15) as usize]
                };
                let who = if rng.below(3) == 0 { a } else { holder };
                g.op(GB::w_prop(who, m, key, value));
            }
            30..=41 => {
                // mostly an open proposal, voted by the PERP holders (so some pass)
                let open: Vec<u64> = g.eng.state.proposals.keys().copied().collect();
                let id = if rng.below(8) == 0 || open.is_empty() { 1 + rng.below(np + 2) } else { open[rng.below(open.len() as u64) as usize] };
                let who = if rng.below(4) == 0 { a } else { holder };
                g.op(GB::w_vote(who, id, rng.below(5) != 0));
            }
            42..=45 => {
                let s = g.eng.state.seq + if rng.below(3) == 0 { minuend_types::PROPOSAL_DURATION_SEQS } else { 1 + rng.below(30) };
                g.op(GB::w_seq(s));
            }
            46..=50 => {
                let open: Vec<u64> = g.eng.state.proposals.keys().copied().collect();
                let id = if rng.below(5) == 0 || open.is_empty() { 1 + rng.below(np.max(1)) } else { open[rng.below(open.len() as u64) as usize] };
                g.op(GB::w_fin(a, id));
            }
            51..=58 => {
                // trade on any listed market (new listings, delisted ones)
                let m = 1 + rng.below(nm as u64 - 1) as u32;
                let p = g.eng.state.markets.get(&MarketId(m)).copied();
                let px = match p {
                    Some(p) if p.funding_rate => mnpilot::types::encode_funding_price(100 + rng.below(40) as i64),
                    _ => mid + (rng.below(11) as i64 - 5) * DOLLAR * 100,
                };
                let mk = 10 + rng.below((n_acc - 10) as u64) as u32;
                let w1 = g.w_place(mk, true, false, px, QTY_SCALE / 1000, m);
                g.op(w1);
                if rng.below(2) == 0 {
                    let w2 = g.w_place(a, false, rng.below(2) == 0, px, QTY_SCALE / 1000, m);
                    g.op(w2);
                }
            }
            59..=72 => {
                // commit (mostly a correct hash of an inner op this account will reveal later)
                let inner = inner_op(&mut g, &mut rng, a, n_acc);
                let salt = rng.salt();
                let mut hash = g.commit_hash_any(&inner, &salt);
                if rng.below(12) == 0 {
                    hash[0] ^= 1;
                }
                let ttl = match rng.below(10) {
                    0 => height,
                    1 => height + minuend_types::COMMIT_TTL_HEIGHTS + 1,
                    2 => height + minuend_types::COMMIT_TTL_HEIGHTS,
                    _ => height + 1 + rng.below(8),
                };
                let w = g.w_commit(a, &hash, ttl);
                g.op(w);
                let uid = *g.uids.last().unwrap();
                pending.push((a, hash, salt, inner, uid));
            }
            73..=88 if !pending.is_empty() => {
                let k = rng.below(pending.len() as u64) as usize;
                let (ca, hash, salt, inner, cu) = pending[k];
                let who = if rng.below(10) == 0 { a } else { ca };
                let p2 = match rng.below(8) {
                    0 => [0u8; 32],
                    // another unit the engine holds (not the commit): the parent edge fails
                    1 if !g.ingested.is_empty() => g.ingested[rng.below(g.ingested.len() as u64) as usize],
                    _ => cu,
                };
                let mut sl = salt;
                if rng.below(15) == 0 {
                    sl[1] ^= 4;
                }
                let p1 = g.last();
                let w = g.w_reveal(who, &hash, &sl, &inner, p1, p2);
                g.op(w);
                if rng.below(3) != 0 {
                    pending.swap_remove(k);
                }
            }
            89..=94 => {
                height += if rng.below(5) == 0 { 10 + rng.below(20) } else { 1 };
                g.op(GB::w_height(height));
            }
            95..=99 if x => match rng.below(6) {
                0 | 1 => {
                    let t = 1 + rng.below((n_acc - 1) as u64) as u32;
                    let m = if rng.below(4) == 0 { 1 + rng.below(nm as u64 - 1) as u32 } else { 1 };
                    g.op([7 | (a << 8), t, 0, 0, 0, 0, 0, m]);
                }
                2 => {
                    let t = 1 + rng.below(3) as u32;
                    g.op([13 | (holder << 8), t, 0, 0, 0, 0, 0, 1]);
                }
                3 => {
                    let amt = rng.below(25_000) as i64 * USD_SCALE as i64;
                    g.op([6 | (a << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, rng.below(30) as u32, 0]);
                }
                _ => {
                    // a leveraged position on market 1: a resting maker, then an IOC taker of 1-15 x 0.1 BTC
                    let px = mid + (rng.below(5) as i64 - 2) * DOLLAR * 100;
                    let q = QTY_SCALE / 10 * (1 + rng.below(15));
                    let mk = 10 + rng.below((n_acc - 10) as u64) as u32;
                    let w1 = g.w_place(mk, true, false, px, q, 1);
                    g.op(w1);
                    let w2 = g.w_place(a, false, true, px, q, 1);
                    g.op(w2);
                }
            },
            _ => {
                let o = 1 + rng.below(3) as u32;
                let px = mid + (rng.below(21) as i64 - 10) * mid / 10_000;
                g.op([8 | (o << 8), 0, px as u32, (px >> 32) as u32, 0, 0, 0, 1]);
                if rng.below(3) == 0 {
                    g.op([if rng.below(2) == 0 { 11 } else { 12 } | (holder << 8), 0, 0, 0, 0, 0, 0, 0]);
                }
            }
        }
    }
    g
}

impl GB {
    /// commit hash for any inner op incl. forbidden kinds (real encoding; foreign signer fine)
    pub fn commit_hash_any(&self, inner: &[u32; 8], salt: &[u8; 32]) -> [u8; 32] {
        match real_op(inner, &self.ids, &self.rx(), self.ops.len()) {
            Some(op) => minuend_dag::reveal_commit_hash(&op, salt),
            None => [7u8; 32],
        }
    }
}

/// real vs port on one batch: hash, events, applied, per-unit roots (real scratch / port incremental
/// / port scratch), snapshot v3 round trip; plus: the batch cut into segments (session carried,
/// snapshot export+import at one cut) gives the same events and final hash
pub fn check_batch(w: &[u32]) -> Result<(), String> {
    let mut a = Vec::new();
    let (r, _) = run_real_eng_cb(w, &mut |e| a.push(smt_ref::root(&real_pilot_leaves(e))));
    let p = run_port(w);
    let (b, c, wo) = port_roots(w);
    if r.hash != p.hash || r.ev != p.ev || r.applied != p.applied {
        let first_ev = r.ev.iter().zip(&p.ev).position(|(x, y)| x != y);
        return Err(format!("engine: hash {} applied {}/{} first_ev {:?} real {:?} port {:?}", r.hash == p.hash, r.applied, p.applied, first_ev,
            first_ev.map(|i| r.ev[i]), first_ev.map(|i| p.ev[i])));
    }
    if !(a == b && b == c && wo.scratch_ok && a.len() == w[2] as usize) {
        let first_root = a.iter().zip(&b).zip(&c).position(|((x, y), z)| x != y || y != z);
        return Err(format!("roots: first_root {:?} scratch_ok {}", first_root, wo.scratch_ok));
    }
    // snapshot v3 round trip of the final session
    let mut sess: Option<mnpilot::Session> = None;
    let _ = mnpilot::run_segment(&mut |i| w.get(i as usize).copied().unwrap_or(0), &mut |_| {}, &mut |_, _, _| {}, mnpilot::WitMode::Incremental, &mut sess);
    let (d, words) = snap::export_words(sess.as_ref().unwrap());
    let mut imp: Option<mnpilot::Session> = None;
    let io = mnpilot::run_import(&mut |i| words.get(i as usize).copied().unwrap_or(0), &mut imp, Some(&(d, words.len() as u32)));
    let er = sess.as_mut().unwrap().w.as_mut().map(|t| t.root());
    let snap_ok = io.status == 0
        && er == Some(io.root)
        && imp.as_ref().map(|x| mnpilot::state_hash(&x.eng.state) == p.hash).unwrap_or(false)
        // re-export after undoing the import's run count: the identical words
        && imp.as_mut().map(|x| {
            x.segs -= 1;
            snap::export_words(x).0 == d
        }).unwrap_or(false);
    if !snap_ok {
        return Err(format!("snapshot: status {} root {}", io.status, er == Some(io.root)));
    }
    Ok(())
}

/// Segment cut of an MNP2 batch: ops [lo, hi) with their unit ids and the WHOLE extension area
/// (offsets stay valid).
pub fn cut_v2(w: &[u32], lo: usize, hi: usize) -> Vec<u32> {
    let na = w[1] as usize;
    let n = w[2] as usize;
    let base = 4 + 8 * na;
    let eb = base + 16 * n;
    let mut o = vec![mnpilot::MAGIC2, na as u32, (hi - lo) as u32, if lo == 0 { w[3] } else { 0 }];
    o.extend_from_slice(&w[4..base]);
    o.extend_from_slice(&w[base + 8 * lo..base + 8 * hi]);
    o.extend_from_slice(&w[base + 8 * n + 8 * lo..base + 8 * n + 8 * hi]);
    o.extend_from_slice(&w[eb..]);
    o
}

/// the batch as segments on one session (MNWIT1): events concatenate to the whole-batch events and
/// the final hash / root match; one cut also goes through export + import
pub fn check_segments(w: &[u32], cuts: &[usize], snap_at: Option<usize>) -> Result<(), String> {
    let whole = run_port(w);
    let n = w[2] as usize;
    let mut sess: Option<mnpilot::Session> = None;
    let mut ev = Vec::new();
    let mut h = [0u8; 32];
    let mut bounds = vec![0];
    bounds.extend(cuts.iter().copied().filter(|c| *c > 0 && *c < n));
    bounds.push(n);
    bounds.dedup();
    let mut prev_end = None;
    for k in 0..bounds.len() - 1 {
        if Some(bounds[k]) == snap_at && sess.is_some() {
            let (d, words) = snap::export_words(sess.as_ref().unwrap());
            let mut imp: Option<mnpilot::Session> = None;
            let io = mnpilot::run_import(&mut |i| words.get(i as usize).copied().unwrap_or(0), &mut imp, Some(&(d, words.len() as u32)));
            if io.status != 0 {
                return Err(format!("import status {}", io.status));
            }
            sess = imp;
        }
        let sw = cut_v2(w, bounds[k], bounds[k + 1]);
        let (hh, st, wo) = mnpilot::run_segment(&mut |i| sw.get(i as usize).copied().unwrap_or(0), &mut |x| ev.push(x), &mut |_, _, _| {}, mnpilot::WitMode::Incremental, &mut sess);
        if st.status != 0 {
            return Err(format!("segment {} status {}", k, st.status));
        }
        if let Some(pe) = prev_end {
            if wo.start_root != pe {
                return Err(format!("segment {} start root != previous end root", k));
            }
        }
        if !wo.scratch_ok {
            return Err(format!("segment {} scratch", k));
        }
        prev_end = Some(wo.root);
        h = hh;
    }
    if ev != whole.ev || h != whole.hash {
        return Err(format!("segments: ev {} hash {}", ev == whole.ev, h == whole.hash));
    }
    Ok(())
}

pub fn govfuzz(n: u64, ops: u32) -> String {
    govfuzz_x(n, ops, false)
}
pub fn govfuzz_x(n: u64, ops: u32, x: bool) -> String {
    let (mut ok, mut units) = (0u64, 0u64);
    let mut cov: std::collections::BTreeMap<String, u64> = Default::default();
    let mut why = String::new();
    for s in 1..=n {
        let g = gov_build_x(s, ops, x);
        let w = g.words();
        let mut res = check_batch(&w);
        if res.is_ok() {
            let nn = w[2] as usize;
            let c1 = 1 + (s as usize * 7919) % nn.max(2);
            let c2 = (c1 + 1 + (s as usize * 104_729) % nn.max(2)) % nn.max(1);
            res = check_segments(&w, &[c1.min(c2), c1.max(c2)], Some(c1.max(c2)));
        }
        match res {
            Ok(()) => ok += 1,
            Err(e) => {
                println!("GOVMISMATCH seed {} {}", s, e);
                if why.is_empty() {
                    why = format!("seed {} {}", s, e).replace('"', "'");
                }
            }
        }
        units += w[2] as u64;
        let base = 4 + 8 * w[1] as usize;
        for (i, e) in g.ev.iter().enumerate() {
            let k = w[base + 8 * i] & 0xff;
            let name = match k {
                14 => "gdep",
                15 => "gwd",
                16 => "market",
                17 => "prop",
                18 => "vote",
                19 => "final",
                20 => "commit",
                21 => "reveal",
                6 => "wd",
                7 => "liq",
                13 => "slash",
                2 if i > 0 => "place",
                _ => continue,
            };
            let res = if e & EV_APPLIED != 0 { "ok".to_string() } else { format!("{:#x}", e) };
            *cov.entry(format!("{}:{}", name, res)).or_default() += 1;
        }
        // listing / governance effects reached
        let st = &g.eng.state;
        *cov.entry("markets_created".into()).or_default() += (st.next_market_id - 2) as u64;
        *cov.entry("delisted".into()).or_default() += st.markets.values().filter(|p| p.delisted).count() as u64;
        *cov.entry("param_changed".into()).or_default() +=
            st.markets.values().filter(|p| !p.delisted && !p.spot_only && !p.funding_rate && (p.im_bps != 1000 || p.mm_bps != 500 || p.taker_fee_bps != 5 || p.keeper_reward_bps != 100)).count() as u64;
    }
    let cs: Vec<String> = cov.iter().map(|(k, v)| format!("\"{}\":{}", k, v)).collect();
    format!("{{\"seeds\":{},\"match\":{},\"units\":{},\"why\":\"{}\",\"coverage\":{{{}}}}}", n, ok, units, why, cs.join(","))
}

// ---------------------------------------------------------------- govedge
fn expect(name: &str, cond: bool, fails: &mut Vec<String>) {
    if !cond {
        fails.push(name.to_string());
    }
}
const OK: u32 = EV_APPLIED;

/// deterministic boundary batches: real == port (check_batch) and the intended outcome
pub fn govedge() -> String {
    let mut fails: Vec<String> = Vec::new();
    let mut cases = 0;
    let flags = mnpilot::ORACLES_FLAG | mnpilot::PERP_FLAG;
    let run = |name: &str, g: &GB, fails: &mut Vec<String>| {
        if let Err(e) = check_batch(&g.words()) {
            fails.push(format!("{}: diff {}", name, e).replace('"', "'"));
        }
    };
    // 1. quorum boundary: supply 600 000 (fixture) + X held by acct 10 (its only vote): quorum
    //    10 X >= 600 000 + X  <=>  X >= 66 666.67 -> proposal 1 at X = 66 666 fails, proposal 2
    //    (created after one more PERP) at X = 66 667 passes. Deadline edges with a zero-weight voter.
    {
        cases += 1;
        let mut g = GB::new(14, flags);
        g.op(GB::w_gdep(10, 66_666));
        let p1 = g.op(GB::w_prop(4, 1, 0, 1200));
        g.op(GB::w_gdep(10, 1));
        let p2 = g.op(GB::w_prop(4, 1, 1, 600));
        expect("q:prop", p1 == OK && p2 == OK, &mut fails);
        let v1 = g.op(GB::w_vote(10, 1, true));
        let v2 = g.op(GB::w_vote(10, 2, true));
        let v3 = g.op(GB::w_vote(10, 2, true)); // double vote
        expect("q:votes", v1 == OK && v2 == OK && v3 == 7, &mut fails);
        let d1 = g.eng.state.proposals[&1].deadline_seq;
        let d2 = g.eng.state.proposals[&2].deadline_seq;
        expect("q:deadline", d2 == d1 + 2, &mut fails);
        g.op(GB::w_seq(d1 - 1));
        expect("q:vote_before_deadline", g.op(GB::w_vote(11, 1, false)) == OK, &mut fails); // seq d1-1 -> d1
        expect("q:fin_early", g.op(GB::w_fin(4, 2)) == 7, &mut fails); // seq d1 < d2
        expect("q:vote_at_deadline", g.op(GB::w_vote(12, 1, true)) == 7, &mut fails);
        expect("q:fin1", g.op(GB::w_fin(4, 1)) == OK, &mut fails);
        expect("q:p1_no_quorum", g.eng.state.markets[&BTC_USD].im_bps == 1000, &mut fails);
        g.op(GB::w_seq(d2));
        expect("q:fin2", g.op(GB::w_fin(13, 2)) == OK, &mut fails);
        expect("q:p2_applied", g.eng.state.markets[&BTC_USD].mm_bps == 600, &mut fails);
        expect("q:fin_again", g.op(GB::w_fin(4, 2)) == 12, &mut fails);
        run("quorum", &g, &mut fails);
    }
    // 2. pass + apply; weight snapshot at creation; spot fee raise refused; delist blocks trading
    {
        cases += 1;
        let mut g = GB::new(12, flags);
        g.op(GB::w_dep(10, 50_000 * USD_SCALE as i64));
        g.op(GB::w_dep(11, 50_000 * USD_SCALE as i64));
        expect("p:prop", g.op(GB::w_prop(4, 1, 0, 1200)) == OK, &mut fails);
        g.op(GB::w_gdep(10, 500_000)); // after creation: no weight
        expect("p:vote_snapshot", g.op(GB::w_vote(10, 1, false)) == OK, &mut fails);
        expect("p:vote_yes", g.op(GB::w_vote(4, 1, true)) == OK, &mut fails);
        let d = g.eng.state.proposals[&1].deadline_seq;
        expect("p:no_weight", g.eng.state.proposals[&1].no == 0, &mut fails);
        g.op(GB::w_seq(d));
        expect("p:fin", g.op(GB::w_fin(9, 1)) == OK, &mut fails);
        expect("p:applied", g.eng.state.markets[&BTC_USD].im_bps == 1200, &mut fails);
        // spot listing, fee raise refused, lowering ok
        let w = g.w_market(5, &listing_spot("SPOT"));
        expect("p:list_spot", g.op(w) == OK, &mut fails);
        expect("p:spot_fee_raise", g.op(GB::w_prop(5, 2, 2, 6)) == 7, &mut fails);
        expect("p:spot_fee_lower", g.op(GB::w_prop(5, 2, 2, 4)) == OK, &mut fails);
        expect("p:delist_value", g.op(GB::w_prop(5, 1, 4, 1)) == 7, &mut fails);
        expect("p:delist", g.op(GB::w_prop(5, 1, 4, 0)) == OK, &mut fails);
        expect("p:bad_key", g.op(GB::w_prop(5, 1, 5, 0)) == 7, &mut fails);
        expect("p:no_market", g.op(GB::w_prop(5, 9, 0, 1200)) == 10, &mut fails);
        expect("p:illegal_im", g.op(GB::w_prop(5, 1, 0, 400)) == 7, &mut fails);
        expect("p:low_stake", g.op(GB::w_prop(11, 1, 0, 1200)) == 9, &mut fails);
        let px = 100_000 * DOLLAR;
        let w = g.w_place(11, true, false, px, QTY_SCALE / 1000, 1);
        expect("p:place_before_delist", g.op(w) == OK, &mut fails);
        // id 2 = spot fee lower, id 3 = delist (supply at creation 1.09 M -> quorum 109 000)
        for v in [4u32, 5, 6] {
            expect("p:vote_delist", g.op(GB::w_vote(v, 3, true)) == OK, &mut fails);
            expect("p:vote_fee", g.op(GB::w_vote(v, 2, true)) == OK, &mut fails);
        }
        let d = g.eng.state.proposals[&3].deadline_seq;
        g.op(GB::w_seq(d));
        expect("p:fin_delist", g.op(GB::w_fin(9, 3)) == OK && g.eng.state.markets[&BTC_USD].delisted, &mut fails);
        expect("p:fin_fee", g.op(GB::w_fin(9, 2)) == OK && g.eng.state.markets[&MarketId(2)].taker_fee_bps == 4, &mut fails);
        let w = g.w_place(11, true, false, px, QTY_SCALE / 1000, 1);
        expect("p:place_delisted", g.op(w) != OK, &mut fails);
        run("pass", &g, &mut fails);
    }
    // 3. listing fee exact / short; ids allocated; funding listing makes the creator a feed;
    //    64-proposal cap; gov withdraw watermark
    {
        cases += 1;
        let mut g = GB::new(14, flags);
        g.op(GB::w_gdep(12, 10_000));
        g.op(GB::w_gdep(13, 9_999));
        let w = g.w_market(13, &listing_regular("SHORT"));
        expect("l:short", g.op(w) == 9, &mut fails);
        let w = g.w_market(12, &listing_regular("EXACT"));
        expect("l:exact", g.op(w) == OK && g.eng.state.perp_balances[&g.ids[12]] == 0, &mut fails);
        let w = g.w_market(4, &listing_funding("FUND"));
        expect("l:funding", g.op(w) == OK && g.eng.state.external_sources.contains(&g.ids[4]), &mut fails);
        let mut bad = listing_regular("BADTICK");
        bad[4] = 0;
        bad[5] = 0;
        let w = g.w_market(5, &bad);
        expect("l:tick0", g.op(w) == 7, &mut fails);
        let w = g.w_market(5, &listing("BAND", 1, 1000, 500, 5, 100, false, false, 0, 0, 7, 3));
        expect("l:band", g.op(w) == 7, &mut fails);
        let w = g.w_market(5, &listing("SPOTNEG", 1, 10_000, 500, 5, 100, true, false, 0, 0, 0, 100));
        expect("l:spot_floor", g.op(w) == 7, &mut fails);
        expect("l:ids", g.eng.state.next_market_id == 4 && g.eng.state.perp_burned == 20_000, &mut fails);
        // feed on the new funding market
        let fp = mnpilot::types::encode_funding_price(120);
        expect("l:feed", g.op([9 | (4 << 8), 0, fp as u32, (fp >> 32) as u32, 0, 0, 3, 3]) == OK, &mut fails);
        for k in 0..64u64 {
            g.op(GB::w_prop(4 + (k % 6) as u32, 1, 0, 1000 + 10 * (k % 7)));
        }
        expect("l:cap64", g.eng.state.proposals.len() == 64 && g.op(GB::w_prop(4, 1, 0, 1200)) == 7, &mut fails);
        expect("w:gwd_ok", g.op(GB::w_gwd(6, 100, 5)) == OK, &mut fails);
        expect("w:gwd_dup", g.op(GB::w_gwd(6, 100, 5)) == 6, &mut fails);
        expect("w:gwd_low", g.op(GB::w_gwd(6, 100, 4)) == 6, &mut fails);
        expect("w:gwd_insuff_high", g.op(GB::w_gwd(6, 10_000_000, 9)) == 9, &mut fails);
        expect("w:gwd_after_reject", g.op(GB::w_gwd(6, 100, 7)) == OK, &mut fails); // 9 did not advance
        expect("w:gdep_overflow", g.op(GB::w_gdep(7, minuend_types::PERP_SUPPLY_MAX as u64)) == 7, &mut fails);
        run("listing", &g, &mut fails);
    }
    // 4. commit-reveal: TTL bounds, reveal window, parent edge, wrong salt / account, inner reject
    //    keeps the commit, pending cap, prune at the hook, double reveal
    {
        cases += 1;
        let mut g = GB::new(12, flags);
        g.op(GB::w_dep(10, 50_000 * USD_SCALE as i64));
        g.op(GB::w_dep(11, 50_000 * USD_SCALE as i64));
        g.op(GB::w_height(100));
        let px = 100_000 * DOLLAR;
        let salt = [9u8; 32];
        // ttl bounds
        let inner = g.w_place(10, true, false, px, QTY_SCALE / 1000, 1);
        let h = g.commit_hash(&inner, &salt);
        let w = g.w_commit(10, &h, 100);
        expect("c:ttl_now", g.op(w) == 17, &mut fails);
        let w = g.w_commit(10, &h, 117);
        expect("c:ttl_17", g.op(w) == 17, &mut fails);
        let w = g.w_commit(10, &h, 116);
        expect("c:ttl_16", g.op(w) == OK, &mut fails);
        let cu = *g.uids.last().unwrap();
        let w = g.w_commit(11, &h, 110);
        expect("c:dup_hash", g.op(w) == 17, &mut fails);
        // reveal without the commit parent (another unit in between)
        g.op(GB::w_height(101));
        g.op(GB::w_dep(11, USD_SCALE as i64));
        let p1 = g.last();
        let w = g.w_reveal(10, &h, &salt, &inner, p1, [0; 32]);
        expect("c:no_parent", g.op(w) == 17, &mut fails);
        // wrong salt, wrong account (inner signed by 10, revealed by 11: ingest refusal)
        let mut bs = salt;
        bs[0] ^= 1;
        let p1 = g.last();
        let w = g.w_reveal(10, &h, &bs, &inner, p1, cu);
        expect("c:bad_salt", g.op(w) == 17, &mut fails);
        let p1 = g.last();
        let w = g.w_reveal(11, &h, &salt, &inner, p1, cu);
        expect("c:foreign", g.op(w) == 2, &mut fails);
        // a good reveal at height == ttl with the commit as a non-linear parent
        g.op(GB::w_height(116));
        let p1 = g.last();
        let w = g.w_reveal(10, &h, &salt, &inner, p1, cu);
        expect("c:reveal_at_ttl", g.op(w) == OK, &mut fails);
        let p1 = g.last();
        let w = g.w_reveal(10, &h, &salt, &inner, p1, cu);
        expect("c:double", g.op(w) == 17, &mut fails);
        // inner reject keeps the commit: withdraw more than the collateral, then still revealable?
        // (the inner op is fixed by the hash: reveal fails while it is rejected, commit stays)
        let inner2 = GB::w_prop(10, 1, 0, 1200); // 10 holds no PERP -> Insufficient
        let h2 = g.commit_hash(&inner2, &salt);
        let w = g.w_commit(10, &h2, 120);
        g.op(w);
        let cu2 = *g.uids.last().unwrap();
        let p1 = g.last();
        let w = g.w_reveal(10, &h2, &salt, &inner2, p1, cu2);
        expect("c:inner_reject", g.op(w) == 9, &mut fails);
        g.op(GB::w_gdep(10, 1000));
        let p1 = g.last();
        let w = g.w_reveal(10, &h2, &salt, &inner2, p1, cu2);
        expect("c:inner_retry", g.op(w) == OK, &mut fails);
        // expiry: reveal at ttl + 1
        let inner3 = GB::w_vote(10, 1, true);
        let h3 = g.commit_hash(&inner3, &salt);
        let w = g.w_commit(10, &h3, 117);
        g.op(w);
        let cu3 = *g.uids.last().unwrap();
        g.op(GB::w_height(118));
        let p1 = g.last();
        let w = g.w_reveal(10, &h3, &salt, &inner3, p1, cu3);
        expect("c:expired", g.op(w) == 17, &mut fails);
        expect("c:pruned", !g.eng.state.commits.contains_key(&h3), &mut fails);
        // pending cap 8 (unrevealed, unexpired)
        let mut codes = Vec::new();
        for k in 0..9u8 {
            let mut s2 = salt;
            s2[5] = k;
            let hh = g.commit_hash(&inner3, &s2);
            let w = g.w_commit(11, &hh, 125);
            codes.push(g.op(w));
        }
        expect("c:cap8", codes[..8].iter().all(|c| *c == OK) && codes[8] == 17, &mut fails);
        // forbidden inner kinds (ingest refusal) whether or not a commit exists
        let dep = GB::w_dep(10, USD_SCALE as i64);
        let hd = g.commit_hash_any(&dep, &salt);
        let w = g.w_commit(10, &hd, 125);
        g.op(w);
        let cud = *g.uids.last().unwrap();
        let p1 = g.last();
        let w = g.w_reveal(10, &hd, &salt, &dep, p1, cud);
        expect("c:inner_deposit", g.op(w) == 2, &mut fails);
        let p1 = g.last();
        let w = g.w_reveal(10, &[3u8; 32], &salt, &dep, p1, [0; 32]);
        expect("c:inner_deposit_nocommit", g.op(w) == 2, &mut fails);
        // inner CreateMarket (extension inside the reveal) and inner Liquidate-free Withdraw
        let wm = g.w_market(4, &listing_regular("CRMKT"));
        let hm = g.commit_hash(&wm, &salt);
        let w = g.w_commit(4, &hm, 125);
        g.op(w);
        let cum = *g.uids.last().unwrap();
        let p1 = g.last();
        let w = g.w_reveal(4, &hm, &salt, &wm, p1, cum);
        expect("c:inner_market", g.op(w) == OK && g.eng.state.next_market_id == 3, &mut fails);
        run("commit", &g, &mut fails);
    }
    // 5. binding: the hook prunes commits at segment start (prod height rule) -- host session with
    //    bind: a commit with ttl h+1 survives height h+1, is gone at h+2
    {
        cases += 1;
        let mut g = GB::new(12, flags);
        g.op(GB::w_dep(10, 50_000 * USD_SCALE as i64));
        let inner = GB::w_vote(10, 1, true);
        let h = g.commit_hash(&inner, &[1; 32]);
        // engine height 1 (bound run 1): ttl 2
        let w = g.w_commit(10, &h, 2);
        g.op(w);
        let words = g.words();
        let mut sess: Option<mnpilot::Session> = None;
        let o = mnpilot::SegOpt { run_no: None, bind: true };
        let _ = mnpilot::run_segment_n(&mut |i| words.get(i as usize).copied().unwrap_or(0), &mut |_| {}, &mut |_, _, _| {}, mnpilot::WitMode::Incremental, &mut sess, o);
        let s1 = sess.as_ref().unwrap().eng.state.commits.len();
        let empty = vec![mnpilot::MAGIC2, words[1], 0, 0];
        let mut e2 = empty.clone();
        e2.extend_from_slice(&words[4..4 + 8 * words[1] as usize]);
        e2.push(0);
        let _ = mnpilot::run_segment_n(&mut |i| e2.get(i as usize).copied().unwrap_or(0), &mut |_| {}, &mut |_, _, _| {}, mnpilot::WitMode::Incremental, &mut sess, o);
        let s2 = sess.as_ref().unwrap().eng.state.commits.len();
        let _ = mnpilot::run_segment_n(&mut |i| e2.get(i as usize).copied().unwrap_or(0), &mut |_| {}, &mut |_, _, _| {}, mnpilot::WitMode::Incremental, &mut sess, o);
        let s3 = sess.as_ref().unwrap().eng.state.commits.len();
        expect("b:prune_hook", s1 == 1 && s2 == 1 && s3 == 0, &mut fails);
    }
    // 6. malformed extension (port only: no upstream unit): offsets outside the area -> BadAccount
    {
        cases += 1;
        let mut g = GB::new(12, flags);
        g.op(GB::w_dep(10, USD_SCALE as i64));
        let mut w = g.words();
        let base = 4 + 8 * w[1] as usize;
        // turn op 0 into a CreateMarket / Commit / Reveal with an offset past the end
        let ev_of = |w: &[u32]| run_port(w).ev;
        for (k, name) in [(16u32, "x:market"), (20, "x:commit"), (21, "x:reveal")] {
            w[base] = k | (4 << 8);
            w[base + 7] = 1_000_000;
            expect(name, ev_of(&w) == vec![2], &mut fails);
        }
        // MNP1: no extension area at all
        let mut w1 = w.clone();
        w1[0] = mnpilot::MAGIC;
        w1[base + 7] = 0;
        expect("x:mnp1", ev_of(&w1) == vec![2], &mut fails);
    }
    // 7. review R6-H1/H2/H3/M1: the state caps fire exactly at the cap (port; the real engine has
    //    no caps, so only the port's events are checked) and never before
    {
        cases += 1;
        let n_acc = 700u32; // loop round 7: the ledger is filled with real deposits -> snapshot ~256, voters 300..620
        let mut g = GB::new(n_acc, flags);
        g.op(GB::w_gdep(10, 3_000_000));
        let mut codes = Vec::new();
        for k in 0..mnpilot::MAX_STATE_MARKETS as u32 {
            let w = g.w_market(10, &listing_regular(&format!("M{}", k)));
            codes.push(g.op(w));
        }
        // perp ledger: 6 fixture ids + 10 -> fresh ids 11.. by gov deposits up to the cap, then one more
        // (loop round 7, R7-M1: a gov withdraw of 0 by a fresh id no longer adds an id at all, case 8)
        let base_perp = 7u32;
        let fresh_n = mnpilot::MAX_STATE_ACCOUNTS as u32 - base_perp;
        for k in 0..=fresh_n {
            g.op(GB::w_gdep(11 + k, 2_000));
        }
        g.op(GB::w_gdep(10, 1)); // existing id at the cap
        g.op(GB::w_gwd(11 + fresh_n + 1, 5, 1)); // loop round 7: a gov withdraw > 0 by a new id at the cap -> 19
        g.op(GB::w_prop(10, 1, 0, 1200));
        let z0 = g.ops.len();
        let zcap = g.eng.state.proposals[&1].weight_snapshot.len() + mnpilot::MAX_ZERO_VOTERS;
        for k in 0..=zcap as u32 {
            g.op(GB::w_vote(300 + k, 1, true));
        }
        g.op(GB::w_vote(4, 1, true)); // snapshot voter after the zero-weight cap
        let c0 = g.ops.len();
        for k in 0..=mnpilot::MAX_STATE_COMMITS as u32 {
            let a = 270 + k / 8; // 8 pending each (the per-account cap)
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&k.to_le_bytes());
            h[31] = 0xcc;
            let w = g.w_commit(a, &h, 5);
            g.op(w);
        }
        let w = g.words();
        let pe = run_port(&w).ev;
        let base = 4 + 8 * w[1] as usize;
        let kind = |i: usize| w[base + 8 * i] & 0xff;
        let _ = kind;
        let n_mk = mnpilot::MAX_STATE_MARKETS; // BTC + 255 ok, the 256th listing refused
        let mk_ok = pe[1..n_mk].iter().all(|e| *e == OK) && pe[n_mk] == mnpilot::STATE_CAP_CODE;
        expect("cap:markets", mk_ok, &mut fails);
        let p0 = 1 + n_mk;
        let pr = &pe[p0..p0 + fresh_n as usize + 1];
        expect("cap:perp", pr[..fresh_n as usize].iter().all(|e| *e == OK) && pr[fresh_n as usize] == mnpilot::STATE_CAP_CODE, &mut fails);
        expect("cap:perp_existing", pe[p0 + fresh_n as usize + 1] == OK, &mut fails);
        expect("cap:perp_gwd_new", pe[p0 + fresh_n as usize + 2] == mnpilot::STATE_CAP_CODE, &mut fails);
        let zv = &pe[z0..z0 + zcap + 2];
        let zbad = zv[..zcap].iter().position(|e| *e != OK);
        let zname = format!("cap:votes(zcap {} first_bad {:?} code {:?} at_cap {} after {})", zcap, zbad, zbad.map(|i| zv[i]), zv[zcap], zv[zcap + 1]);
        expect(&zname, zbad.is_none() && zv[zcap] == mnpilot::STATE_CAP_CODE && zv[zcap + 1] == OK, &mut fails);
        let cm = &pe[c0..c0 + mnpilot::MAX_STATE_COMMITS + 1];
        expect("cap:commits", cm[..mnpilot::MAX_STATE_COMMITS].iter().all(|e| *e == OK) && cm[mnpilot::MAX_STATE_COMMITS] == mnpilot::STATE_CAP_CODE, &mut fails);
        // nothing else differs from the real engine before the first cap event
        let first19 = pe.iter().position(|e| *e == mnpilot::STATE_CAP_CODE).unwrap_or(pe.len());
        expect("cap:not_early", pe[..first19] == g.ev[..first19], &mut fails);
    }
    // 8. loop round 7 review R7-M1: a gov withdraw of 0 by an id without a PERP ledger entry is refused (code 19) at
    //    any ledger size -- also as a Reveal's inner op -- and adds nothing; by a holder (incl. a zero balance) it
    //    applies; amount > 0 by a fresh id keeps the upstream rejection. PoC of the old behaviour: 249 such units
    //    filled the shared ledger cap, then a slash by a new challenger was refused (code 19).
    {
        cases += 1;
        let mut g = GB::new(16, flags);
        let n0 = g.eng.state.perp_balances.len();
        expect("r7:gwd0_fresh", g.op(GB::w_gwd(12, 0, 1)) == mnpilot::STATE_CAP_CODE, &mut fails);
        let pos = g.op(GB::w_gwd(12, 5, 1));
        expect("r7:gwd_pos_fresh", pos != OK && pos != mnpilot::STATE_CAP_CODE, &mut fails);
        expect("r7:gwd0_holder", g.op(GB::w_gwd(6, 0, 1)) == OK, &mut fails);
        g.op(GB::w_gdep(13, 10_000));
        let w = g.w_market(13, &listing_regular("ZERO")); // 13 now holds exactly 0 PERP (entry kept)
        g.op(w);
        expect("r7:gwd0_zero_balance_holder", g.op(GB::w_gwd(13, 0, 1)) == OK, &mut fails);
        let salt = [7u8; 32];
        let inner = GB::w_gwd(14, 0, 1);
        let h = g.commit_hash(&inner, &salt);
        let w = g.w_commit(14, &h, 5); // height 0: ttl within COMMIT_TTL_HEIGHTS
        expect("r7:commit", g.op(w) == OK, &mut fails);
        let cu = *g.uids.last().unwrap();
        let p1 = g.last();
        let w = g.w_reveal(14, &h, &salt, &inner, p1, cu);
        expect("r7:reveal_inner_gwd0_fresh", g.op(w) == mnpilot::STATE_CAP_CODE, &mut fails);
        let pe = run_port(&g.words());
        expect("r7:port_events", pe.ev == g.ev, &mut fails);
        expect("r7:ledger_unchanged_by_refusals", g.eng.state.perp_balances.len() == n0 + 1, &mut fails);
        run("r7", &g, &mut fails);
    }
    let fj: Vec<String> = fails.iter().map(|f| format!("\"{}\"", f)).collect();
    format!("{{\"cases\":{},\"ok\":{},\"fail\":[{}]}}", cases, fails.is_empty() as u32 * cases, fj.join(","))
}

/// Heap of the governance / commit-reveal state at its caps (host allocator simulation, 64-bit
/// sizes = upper bound of rv32): MAX_STATE_ACCOUNTS PERP ids, MAX_STATE_MARKETS markets, 64
/// proposals each with a full weight snapshot and snapshot + MAX_ZERO_VOTERS voters, MAX_STATE_COMMITS
/// commits.
pub fn govcap() -> String {
    use mnpilot::types::{AccountId as A, MarketId as M};
    heapsim::reset();
    heapsim::ON.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut sess = mnpilot::Session::genesis(0, mnpilot::WitMode::Incremental);
    let id = |i: u32| A(Sha256::digest(format!("govcap-{}", i).as_bytes()).into());
    let mut fails = 0u32;
    {
        let e = &mut sess.eng;
        let mut ok = |r: Result<Vec<mnpilot::Fill>, mnpilot::engine::RejectReason>, e: &mut mnpilot::engine::Engine| {
            if r.is_ok() { e.state.seq += 1 } else { fails += 1 }
        };
        for i in 0..mnpilot::MAX_STATE_ACCOUNTS as u32 {
            let r = e.gov_deposit(id(i), if i == 0 { 10_000_000 } else { 2_000 });
            ok(r, e);
        }
        let l = mnpilot::listing_of(&listing_regular("CAP"));
        for _ in 1..mnpilot::MAX_STATE_MARKETS {
            let r = e.create_market(id(0), &l);
            ok(r, e);
        }
        for k in 0..64u32 {
            let seq = e.state.seq;
            let r = e.create_proposal(id(k + 1), M(1), 0, 1000 + k as u64, seq);
            ok(r, e);
        }
        for p in 1..=64u64 {
            for v in 0..(mnpilot::MAX_STATE_ACCOUNTS + mnpilot::MAX_ZERO_VOTERS) as u32 {
                let seq = e.state.seq;
                let r = e.vote(id(v), p, true, seq);
                ok(r, e);
            }
        }
        for k in 0..mnpilot::MAX_STATE_COMMITS as u32 {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&k.to_le_bytes());
            let r = e.commit_op([1; 32], id(1000 + k / 8), h, 10);
            ok(r, e);
        }
    }
    if let Some(w) = sess.w.as_mut() {
        w.commit(&mut sess.eng.state);
    }
    heapsim::ON.store(false, std::sync::atomic::Ordering::Relaxed);
    let (top, peak, _) = heapsim::read();
    let (_, words, _) = mnpilot::snapshot::export(&sess, false);
    let st = &sess.eng.state;
    format!(
        "{{\"perp_ids\":{},\"markets\":{},\"proposals\":{},\"voted\":{},\"commits\":{},\"rejected_ops\":{},\"leaves\":{},\"sizeclass_highwater\":{},\"peak_live\":{},\"sum_class_peaks\":{},\"snapshot_words\":{}}}",
        st.perp_balances.len(), st.markets.len(), st.proposals.len(), st.proposals.values().map(|p| p.voted.len()).sum::<usize>(), st.commits.len(), fails,
        sess.w.as_ref().map(|w| w.smt.count).unwrap_or(0), top, peak, heapsim::sum_class_peaks(), words
    )
}
