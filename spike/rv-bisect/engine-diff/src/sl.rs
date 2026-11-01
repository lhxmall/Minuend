//! Loop round 14 (R4-H1 production direction): differential + adversarial harness for the STATELESS guest
//! prototype (mnpilot feature `stateless`, guest-engine/src/stateless.rs, docs/rv-stateless-guest.md).
//!
//!   slfuzz <n> <orders> [adv]  : n batches (gen / stress workloads; `adv` = adv_batch edge-value workloads),
//!        cut into segments of random size 1..200. Reference = the session port (MNWIT1 incremental session,
//!        state carried in memory). For every segment the "operator" builds a witness from the FULL
//!        pre-segment state by iterating the guest's Need reports to a fixpoint, then the stateless run must
//!        give status 0, the session's event words, start root = MNWIT-S root of the pre-state and end root
//!        = MNWIT-S root of the session's post-state. Stats: witness bytes, leaves verified, tree nodes,
//!        node / leaf hashes vs the session run's node hashes + leaf updates.
//!   sladv <n> <orders>         : adversarial witness mutations on gen segments (findings/rv-loop-14.md):
//!        omissions (every record class), forged leaves, duplicates, wrong-root proofs, byte flips, extra
//!        records, order-book boundary attacks (omit a better level, drop / reorder a level's orders, hide a
//!        trie node, claim a present node absent), limit overflow. Invariant: status 0 => end root ==
//!        reference and events == reference; extra (valid) records never change the result.
use super::*;
use mnpilot::stateless::{self as sl, Need, WitBuilder};
use std::collections::BTreeSet;

pub struct SegRef {
    pub pre: mnpilot::state::ChainState,
    pub post_root: [u8; 32],
    pub post: mnpilot::state::ChainState,
    pub ev: Vec<u32>,
    pub seg: Vec<u32>,
    pub sess_hashes: u64,
}

/// round 16: session reference for an MNP2 batch (unit ids + extension area), cut with gov::cut_v2
pub fn session_refs_v2(w: &[u32], s: u32) -> Vec<SegRef> {
    let n_acc = w[1];
    let accts: Vec<mnpilot::types::AccountId> = (0..n_acc)
        .map(|a| {
            let mut id = [0u8; 32];
            for k in 0..8 {
                id[k * 4..k * 4 + 4].copy_from_slice(&w[4 + (a * 8) as usize + k].to_le_bytes());
            }
            mnpilot::types::AccountId(id)
        })
        .collect();
    let mut sess = Some(mnpilot::Session::genesis_with(w[3], mnpilot::WitMode::Incremental, &accts));
    let mut out = Vec::new();
    let n = w[2] as usize;
    let mut lo = 0usize;
    while lo < n || (n == 0 && lo == 0) {
        let hi = (lo + s as usize).min(n);
        let mut sw = crate::gov::cut_v2(w, lo, hi);
        sw[3] = 0;
        let pre = sess.as_ref().unwrap().eng.state.clone();
        let h0 = sess.as_ref().unwrap().w.as_ref().map(|x| x.smt.node_hashes + x.leaf_updates).unwrap_or(0);
        let mut ev = Vec::new();
        let (_, st, _) = mnpilot::run_segment(&mut |i| sw.get(i as usize).copied().unwrap_or(0), &mut |x| ev.push(x), &mut |_, _, _| {}, mnpilot::WitMode::Incremental, &mut sess);
        assert_eq!(st.status, 0);
        let s1 = sess.as_ref().unwrap();
        let h1 = s1.w.as_ref().map(|x| x.smt.node_hashes + x.leaf_updates).unwrap_or(0);
        out.push(SegRef { pre, post_root: sl::s_root(&s1.eng.state), post: s1.eng.state.clone(), ev, seg: sw, sess_hashes: h1 - h0 });
        if hi >= n {
            break;
        }
        lo = hi;
    }
    out
}

/// round 16: the 'perp' workload (MNP2, built on the REAL engine by gov::GB): trading on market 1 and on new listings,
/// deposits / withdrawals, gov deposits / withdrawals (nonce variants, 0 by a fresh id, near PERP_SUPPLY_MAX), listings
/// (regular / spot / funding, perturbed), commits (valid / invalid ttl, wrong hash) and reveals of supported inner ops
/// (place, gov withdraw, listing, withdraw) and of forbidden kinds / by a foreign revealer / with a wrong salt or parent.
/// No SetHeight / SetSeq (fixtures, unsupported statelessly); at most 10 listings (the session keeps its 16-market cap).
pub fn perp_batch(seed: u64, n_ops: u32) -> Vec<u32> {
    use crate::gov::{listing_funding, listing_regular, listing_spot, GB};
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let n_acc = 10 + rng.below(6) as u32;
    let mut g = GB::new(n_acc, mnpilot::ORACLES_FLAG | mnpilot::PERP_FLAG);
    let mid = 100_000 * PRICE_SCALE as i64;
    let dollar = PRICE_SCALE as i64;
    for a in 1..n_acc {
        g.op(GB::w_dep(a, 20_000 * USD_SCALE as i64));
    }
    let mut nonce: Vec<u64> = vec![0; n_acc as usize];
    let mut creates = 0u32;
    let mut pending: Vec<(u32, [u8; 32], [u8; 32], [u32; 8], [u8; 32])> = Vec::new();
    let mut n_done = 0u32;
    while n_done < n_ops {
        n_done += 1;
        let a = 1 + rng.below((n_acc - 1) as u64) as u32;
        let holder = 4 + rng.below(6) as u32;
        let nm = g.eng.state.next_market_id;
        match rng.below(100) {
            0..=9 => {
                let amt = match rng.below(10) {
                    0 => u64::MAX,
                    1 => (minuend_types::PERP_SUPPLY_MAX as u64).saturating_sub(rng.below(3)),
                    _ => rng.below(30_000),
                };
                g.op(GB::w_gdep(if rng.below(3) == 0 { holder } else { a }, amt));
            }
            10..=19 => {
                let who = if rng.below(2) == 0 { holder } else { a };
                let n = nonce[who as usize];
                let nn = match rng.below(6) {
                    0 => n,
                    1 => n.saturating_sub(1),
                    2 => n + 5,
                    _ => n + 1,
                };
                let amt = match rng.below(5) {
                    0 => 0,
                    1 => rng.below(300_000),
                    _ => rng.below(5_000),
                };
                if g.applied(GB::w_gwd(who, amt, nn)) {
                    nonce[who as usize] = nn;
                }
            }
            20..=27 if creates < 10 => {
                creates += 1;
                let mut l = match rng.below(3) {
                    0 => listing_regular("SLR"),
                    1 => listing_spot("SLS"),
                    _ => listing_funding("SLF"),
                };
                if rng.below(4) == 0 {
                    let i = 4 + rng.below(19) as usize;
                    l[i] = match rng.below(3) {
                        0 => 0,
                        1 => l[i].wrapping_add(1),
                        _ => u32::MAX,
                    };
                }
                let who = if rng.below(4) == 0 { a } else { holder };
                let w = g.w_market(who, &l);
                g.op(w);
            }
            28..=55 => {
                // trade on market 1 or a non-funding listing
                let m = if rng.below(3) == 0 && nm > 2 { 2 + rng.below((nm - 2) as u64) as u32 } else { 1 };
                if g.eng.state.markets.get(&MarketId(m)).is_some_and(|p| p.funding_rate) {
                    continue;
                }
                let px = mid + (rng.below(11) as i64 - 5) * dollar * 100;
                let mk = 1 + rng.below((n_acc - 1) as u64) as u32;
                let w1 = g.w_place(mk, rng.below(2) == 0, false, px, QTY_SCALE / 1000, m);
                g.op(w1);
                if rng.below(2) == 0 {
                    let w2 = g.w_place(a, rng.below(2) == 0, rng.below(2) == 0, px, QTY_SCALE / 1000, m);
                    g.op(w2);
                }
            }
            56..=60 => {
                let c = g.cseq(a).saturating_sub(1 + rng.below(3));
                let m = if rng.below(3) == 0 && nm > 2 { 2 + rng.below((nm - 2) as u64) as u32 } else { 1 };
                g.op([3 | (a << 8), 0, 0, 0, 0, 0, c as u32, m]);
            }
            61..=64 => {
                g.op(GB::w_dep(a, (1 + rng.below(5_000)) as i64 * USD_SCALE as i64));
            }
            65..=68 => {
                let amt = rng.below(3_000) as i64 * USD_SCALE as i64;
                g.op([6 | (a << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, rng.below(20) as u32, 0]);
            }
            69..=84 => {
                // commit of an inner op this account (mostly) reveals later
                let inner = match rng.below(8) {
                    0..=2 => {
                        let px = mid + (rng.below(11) as i64 - 5) * dollar * 100;
                        g.w_place(a, rng.below(2) == 0, rng.below(2) == 0, px, QTY_SCALE / 1000, 1)
                    }
                    3 => GB::w_gwd(a, rng.below(2_000), nonce[a as usize] + 1),
                    4 if creates < 10 => {
                        creates += 1;
                        g.w_market(a, &listing_regular("SLC"))
                    }
                    5 => {
                        let amt = rng.below(2000) as i64 * USD_SCALE as i64;
                        [6 | (a << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, 100 + rng.below(30) as u32, 0]
                    }
                    _ => match rng.below(3) {
                        0 => GB::w_dep(a, 5 * USD_SCALE as i64),
                        1 => GB::w_gdep(a, 5),
                        _ => [11 | (((a + 1) % n_acc) << 8), 0, 0, 0, 0, 0, 0, 0],
                    },
                };
                let salt = {
                    let mut s = [0u8; 32];
                    for k in 0..4 {
                        s[8 * k..8 * k + 8].copy_from_slice(&rng.next().to_le_bytes());
                    }
                    s
                };
                let mut hash = g.commit_hash_any(&inner, &salt);
                if rng.below(12) == 0 {
                    hash[0] ^= 1;
                }
                let ttl = match rng.below(10) {
                    0 => 0,
                    1 => minuend_types::COMMIT_TTL_HEIGHTS + 1,
                    _ => 1 + rng.below(minuend_types::COMMIT_TTL_HEIGHTS),
                };
                let w = g.w_commit(a, &hash, ttl);
                g.op(w);
                let uid = *g.uids.last().unwrap();
                pending.push((a, hash, salt, inner, uid));
            }
            _ if !pending.is_empty() => {
                let k = rng.below(pending.len() as u64) as usize;
                let (ca, hash, salt, inner, cu) = pending[k];
                let who = if rng.below(10) == 0 { a } else { ca };
                let p2 = if rng.below(8) == 0 { [0u8; 32] } else { cu };
                let mut st = salt;
                if rng.below(15) == 0 {
                    st[1] ^= 4;
                }
                let p1 = g.last();
                let w = g.w_reveal(who, &hash, &st, &inner, p1, p2);
                g.op(w);
                if rng.below(3) != 0 {
                    pending.swap_remove(k);
                }
            }
            _ => {
                g.op(GB::w_dep(a, USD_SCALE as i64));
            }
        }
    }
    g.words()
}

/// session reference: segments (flags zeroed) with pre-states, post MNWIT-S roots and events
pub fn session_refs(w: &[u32], s: u32) -> Vec<SegRef> {
    let n_acc = w[1];
    let accts: Vec<mnpilot::types::AccountId> = (0..n_acc)
        .map(|a| {
            let mut id = [0u8; 32];
            for k in 0..8 {
                id[k * 4..k * 4 + 4].copy_from_slice(&w[4 + (a * 8) as usize + k].to_le_bytes());
            }
            mnpilot::types::AccountId(id)
        })
        .collect();
    let mut sess = Some(mnpilot::Session::genesis_with(w[3], mnpilot::WitMode::Incremental, &accts));
    let mut out = Vec::new();
    for mut sw in seg::split(w, s) {
        sw[3] = 0;
        let pre = sess.as_ref().unwrap().eng.state.clone();
        let h0 = sess.as_ref().unwrap().w.as_ref().map(|x| x.smt.node_hashes + x.leaf_updates).unwrap_or(0);
        let mut ev = Vec::new();
        let (_, st, _) = mnpilot::run_segment(&mut |i| sw.get(i as usize).copied().unwrap_or(0), &mut |x| ev.push(x), &mut |_, _, _| {}, mnpilot::WitMode::Incremental, &mut sess);
        assert_eq!(st.status, 0);
        let s1 = sess.as_ref().unwrap();
        let h1 = s1.w.as_ref().map(|x| x.smt.node_hashes + x.leaf_updates).unwrap_or(0);
        out.push(SegRef { pre, post_root: sl::s_root(&s1.eng.state), post: s1.eng.state.clone(), ev, seg: sw, sess_hashes: h1 - h0 });
    }
    out
}

/// run with the chain binding of main.rs (R14-H2): `expect` = the last good end root (the honest pre-state root)
pub fn run_sl_x(seg: &[u32], wit: &[u8], expect: Option<&[u8; 32]>) -> (sl::SlOut, Vec<u32>) {
    run_sl_xh(seg, wit, expect, None)
}
/// round 15: with the height hook (`height` = the run number of a bound image)
pub fn run_sl_xh(seg: &[u32], wit: &[u8], expect: Option<&[u8; 32]>, height: Option<u64>) -> (sl::SlOut, Vec<u32>) {
    let mut ev = Vec::new();
    let o = sl::run_stateless(&mut |i| seg.get(i as usize).copied().unwrap_or(0), wit, expect, height, &mut |x| ev.push(x));
    (o, ev)
}
pub fn run_sl(seg: &[u32], wit: &[u8]) -> (sl::SlOut, Vec<u32>) {
    run_sl_x(seg, wit, None)
}

/// initial operator guess from the segment's ops (author, own order set, market, insurance)
pub fn guess(seg: &[u32]) -> BTreeSet<Need> {
    let n_acc = seg[1];
    let n_ops = seg[2];
    let id = |a: u32| -> Option<mnpilot::types::AccountId> {
        if a >= n_acc {
            return None;
        }
        let mut x = [0u8; 32];
        for k in 0..8 {
            x[k * 4..k * 4 + 4].copy_from_slice(&seg[4 + (a * 8) as usize + k].to_le_bytes());
        }
        Some(mnpilot::types::AccountId(x))
    };
    let mut n = BTreeSet::new();
    n.insert(Need::Light(mnpilot::types::INSURANCE_ACCOUNT));
    let base = 4 + 8 * n_acc as usize;
    for i in 0..n_ops as usize {
        let mut ow = [0u32; 8];
        ow.copy_from_slice(&seg[base + 8 * i..base + 8 * i + 8]);
        let op = mnpilot::decode_op(&ow);
        if let Some(a) = op.signer().and_then(id) {
            n.insert(Need::Account(a));
            n.insert(Need::Aord(a));
            match op {
                mnpilot::BatchOp::Place { market, .. } => {
                    n.insert(Need::Market(market));
                }
                mnpilot::BatchOp::Cancel { client_seq, market, .. } => {
                    n.insert(Need::Order(mnpilot::types::order_id(a, mnpilot::types::MarketId(market), client_seq)));
                }
                mnpilot::BatchOp::Withdraw { .. } => {
                    n.insert(Need::Wdl(a));
                }
                // round 16
                mnpilot::BatchOp::GovDeposit { .. } => {
                    n.insert(Need::Perp);
                }
                mnpilot::BatchOp::GovWithdraw { .. } => {
                    n.insert(Need::Perp);
                    n.insert(Need::Gnon(a));
                    n.insert(Need::Acmt(a));
                }
                mnpilot::BatchOp::CreateMarket { .. } => {
                    n.insert(Need::Perp);
                    n.insert(Need::Acmt(a));
                    n.insert(Need::Xsrc(a));
                }
                mnpilot::BatchOp::Commit { .. } => {
                    n.insert(Need::Acmt(a));
                }
                _ => {}
            }
        }
    }
    n
}

/// operator fixpoint: Some((needs, witness, out, ev, iterations)) or None (need loop / not converging)
pub fn operate(b: &WitBuilder, seg: &[u32]) -> Result<(BTreeSet<Need>, Vec<u8>, sl::SlOut, Vec<u32>, u32), String> {
    operate_h(b, seg, None)
}
pub fn operate_h(b: &WitBuilder, seg: &[u32], height: Option<u64>) -> Result<(BTreeSet<Need>, Vec<u8>, sl::SlOut, Vec<u32>, u32), String> {
    let mut needs = guess(seg);
    b.live_h.set(height.unwrap_or(0).max(b.s.height));
    for it in 0..20_000u32 {
        let wit = b.build(&needs);
        let (o, ev) = run_sl_xh(seg, &wit, Some(&b.root), height);
        if o.status == sl::ST_SL_MISSING {
            let n = o.need.unwrap();
            if !needs.insert(n) {
                return Err(format!("need loop: {:?} already supplied (iteration {})", n, it));
            }
            continue;
        }
        return Ok((needs, wit, o, ev, it + 1));
    }
    Err("no fixpoint in 20000 iterations".into())
}

/// end-root mismatch diagnosis: wrong puts / deletions and missed changes, as leaf strings
pub fn diag(r: &SegRef, o: &sl::SlOut) -> String {
    use std::collections::BTreeMap;
    let pre: BTreeMap<[u8; 32], ([u8; 32], String)> = sl::s_leaf_strings(&r.pre).into_iter().map(|(k, h, s)| (k, (h, s))).collect();
    let post: BTreeMap<[u8; 32], ([u8; 32], String)> = sl::s_leaf_strings(&r.post).into_iter().map(|(k, h, s)| (k, (h, s))).collect();
    let mut v = Vec::new();
    let name = |k: &[u8; 32]| post.get(k).or(pre.get(k)).map(|x| x.1.clone()).unwrap_or_else(|| format!("?{}", hx(&k[..4])));
    let mut covered = BTreeSet::new();
    for (k, lh) in &o.puts {
        covered.insert(*k);
        if post.get(k).map(|x| x.0) != Some(*lh) {
            v.push(format!("BADPUT {} (post {})", name(k), post.contains_key(k)));
        }
    }
    for k in &o.dels {
        covered.insert(*k);
        if post.contains_key(k) {
            v.push(format!("BADDEL {}", name(k)));
        }
    }
    for (k, (h, st)) in &post {
        if pre.get(k).map(|x| x.0) != Some(*h) && !covered.contains(k) {
            v.push(format!("MISSED+ {}", st));
        }
    }
    for (k, (_, st)) in &pre {
        if !post.contains_key(k) && !covered.contains(k) {
            v.push(format!("MISSED- {}", st));
        }
    }
    v.truncate(12);
    v.join(" | ")
}

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// "ora" workload (round 14): a gen batch whose genesis bonds oracles 1..3 (header bit 26) and whose first ops are
/// three ReportPrice units -> the first segment is unsupported (skipped: session only), every later segment runs
/// statelessly on a pre-state with oracle reports / last_index (the mkx: oracle facts of the fill mark rule).
pub fn ora_batch(seed: u64, ord: u32) -> Vec<u32> {
    let makers = 4 + (seed % 9) as u32;
    let levels = 1 + (seed % 25) as u32;
    let per = 1 + (seed % 3) as u32;
    let mut w = gen(seed, makers, levels, per, ord, seed % 2 == 0).0;
    w[3] = mnpilot::ORACLES_FLAG;
    let base = 4 + 8 * w[1] as usize;
    let mut ins = Vec::new();
    for (k, a) in [1u32, 2, 3].iter().enumerate() {
        let px = MID + (k as i64 - 1) * DOLLAR;
        ins.extend_from_slice(&[8 | (a << 8), 0, px as u32, (px >> 32) as u32, 0, 0, 0, 1]);
    }
    w.splice(base..base, ins);
    w[2] += 3;
    w
}

/// "wd" workload (round 15): a gen batch with Withdraw units spliced into the flow (~1 in 8 units): random trader /
/// maker, amounts from dust (< MIN_WITHDRAW -> Risk) to more than the collateral (Insufficient), full balance, and
/// nonces from a small range (DuplicateNonce), so the stateless withdraw path (wdl: records, R2-E-3 resting IM,
/// pending-count cap) is differentially tested against the session.
pub fn wd_batch(seed: u64, ord: u32) -> Vec<u32> {
    let makers = 4 + (seed % 9) as u32;
    let levels = 1 + (seed % 25) as u32;
    let per = 1 + (seed % 3) as u32;
    let mut w = gen(seed, makers, levels, per, ord, seed % 2 == 0).0;
    let n_acc = w[1];
    let base = 4 + 8 * n_acc as usize;
    let n_ops = w[2] as usize;
    let mut rng = Rng(seed.wrapping_mul(0x2545_F491_4F6C_DD1D) ^ 0x77);
    let mut ops: Vec<[u32; 8]> = (0..n_ops).map(|i| w[base + 8 * i..base + 8 * i + 8].try_into().unwrap()).collect();
    let mut out: Vec<[u32; 8]> = Vec::with_capacity(ops.len() * 9 / 8);
    let mut seq0 = 0u64;
    for o in ops.drain(..) {
        out.push(o);
        if rng.below(8) == 0 {
            let a = rng.below(n_acc as u64) as u32;
            let amt: i64 = match rng.below(6) {
                0 => (USD_SCALE / 2) as i64,                    // dust -> Risk
                1 => 50_000_000 * USD_SCALE as i64,             // above the collateral -> Insufficient
                2 => 0,
                _ => (1 + rng.below(5_000)) as i64 * USD_SCALE as i64,
            };
            let mut nonce = rng.below(12);
            let (a, amt) = if rng.below(2) == 0 {
                // account 0 with fresh nonces: reaches the 64 pending-records cap (Risk) on long batches
                seq0 += 1;
                nonce = 100 + seq0;
                (0, USD_SCALE as i64)
            } else {
                (a, amt)
            };
            out.push([6 | (a << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, nonce as u32, (nonce >> 32) as u32]);
        }
    }
    w.truncate(base);
    w[2] = out.len() as u32;
    for o in &out {
        w.extend_from_slice(o);
    }
    w
}

pub fn slfuzz(n: u64, ord: u32, mode: &str) -> String {
    let adv = mode == "adv";
    let (mut ok, mut segs, mut units, mut bad) = (0u64, 0u64, 0u64, 0u64);
    let (mut wbytes, mut verified, mut nodes, mut hashes, mut sess_hashes, mut iters) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut maxw = 0usize;
    let mut unsupported = 0u64;
    let mut first_bad = String::new();
    for s in 1..=n {
        let w = if adv {
            adv::adv_batch(s, ord)
        } else if mode == "ora" {
            ora_batch(s, ord)
        } else if mode == "wd" {
            wd_batch(s, ord)
        } else if mode == "perp" {
            perp_batch(s, ord)
        } else {
            let makers = 4 + (s % 9) as u32;
            let levels = 1 + (s % 25) as u32;
            let per = 1 + (s % 3) as u32;
            gen(s, makers, levels, per, ord, s % 2 == 0).0
        };
        let mut rng = Rng(s.wrapping_mul(0x51_7CC1_B727_220A) | 1);
        let size = 1 + rng.below(200) as u32;
        let refs = if mode == "perp" { session_refs_v2(&w, size) } else { session_refs(&w, size) };
        let mut batch_ok = true;
        for (k, r) in refs.iter().enumerate() {
            segs += 1;
            units += r.seg[2] as u64;
            let b = WitBuilder::new(&r.pre);
            let res = operate(&b, &r.seg);
            if matches!(&res, Ok((_, _, o, _, _)) if o.status == sl::ST_SL_UNSUPPORTED) {
                unsupported += 1;
                continue;
            }
            let why = match &res {
                Err(e) => Some(e.clone()),
                Ok((_, wit, o, ev, it)) => {
                    wbytes += wit.len() as u64;
                    maxw = maxw.max(wit.len());
                    verified += o.leaves_verified as u64;
                    nodes += o.tree_nodes as u64;
                    hashes += o.node_hashes + o.leaf_hashes;
                    sess_hashes += r.sess_hashes;
                    iters += *it as u64;
                    if o.status != 0 {
                        Some(format!("status {} need {:?}", o.status, o.need))
                    } else if o.start_root != b.root {
                        Some("start root".into())
                    } else if o.end_root != r.post_root {
                        Some(format!("end root {} != {}; {}", hx(&o.end_root), hx(&r.post_root), diag(r, o)))
                    } else if *ev != r.ev {
                        let at = ev.iter().zip(&r.ev).position(|(x, y)| x != y);
                        Some(format!("events differ at {:?} (len {} vs {})", at, ev.len(), r.ev.len()))
                    } else {
                        None
                    }
                }
            };
            if let Some(why) = why {
                bad += 1;
                batch_ok = false;
                if first_bad.is_empty() {
                    first_bad = format!("seed {} seg {} (size {}): {}", s, k, size, why);
                }
                break;
            }
        }
        if batch_ok {
            ok += 1;
        }
    }
    format!(
        "{{\"mode\":\"{}\",\"batches\":{},\"ok\":{},\"bad_segments\":{},\"unsupported_segments\":{},\"segments\":{},\"units\":{},\"witness_bytes\":{},\"max_witness\":{},\"leaves_verified\":{},\"tree_nodes\":{},\"sl_hashes\":{},\"session_hashes\":{},\"operator_iterations\":{},\"first_bad\":\"{}\"}}",
        mode, n, ok, bad, unsupported, segs, units, wbytes, maxw, verified, nodes, hashes, sess_hashes, iters, first_bad
    )
}

// ------------------------------------------------------------------------------------------------
// adversarial witness mutations
// ------------------------------------------------------------------------------------------------
pub struct Adv {
    pub cases: u64,
    pub sound: u64,
    pub unsound: Vec<String>,
    pub counts: std::collections::BTreeMap<String, (u64, u64, u64)>, // name -> (runs, rejected (status!=0), accepted-correct)
}
impl Adv {
    fn rec(&mut self, name: &str, seg: &SegRef, o: &sl::SlOut, ev: &[u32], must_reject: bool) {
        self.cases += 1;
        let e = self.counts.entry(name.to_string()).or_insert((0, 0, 0));
        e.0 += 1;
        if o.status != 0 {
            e.1 += 1;
            if !must_reject || true {
                self.sound += 1;
            }
            return;
        }
        let correct = o.end_root == seg.post_root && ev == seg.ev.as_slice();
        if correct && !must_reject {
            e.2 += 1;
            self.sound += 1;
        } else if correct && must_reject {
            // accepted a witness that should have been refused, but the result is still right: report
            e.2 += 1;
            self.unsound.push(format!("{}: accepted (correct result) but expected refusal", name));
        } else {
            self.unsound.push(format!("{}: status 0 with WRONG result (root ok {}, ev ok {})", name, o.end_root == seg.post_root, ev == seg.ev.as_slice()));
        }
    }
}

/// witness section offsets (parsed back from the builder's layout) so mutations can target records
pub struct Layout {
    pub tree_end: usize,
}
pub fn layout(wit: &[u8]) -> Layout {
    // magic 4 + root 32 + preorder tree
    fn skip(w: &[u8], i: &mut usize) {
        let t = w[*i];
        *i += 1;
        match t {
            0 => {}
            1 => *i += 32,
            2 => *i += 64,
            3 => {
                skip(w, i);
                skip(w, i);
            }
            4 => {
                let kl = u16::from_le_bytes([w[*i], w[*i + 1]]) as usize;
                *i += 2 + kl;
                let rl = u16::from_le_bytes([w[*i], w[*i + 1]]) as usize;
                *i += 2 + rl;
            }
            _ => panic!("tag"),
        }
    }
    let mut i = 36;
    skip(wit, &mut i);
    Layout { tree_end: i }
}

/// A13 helper: the honest witness with its k-th single leaf (tag 2 or 4) replaced by O(leaf hash) -- same root. A
/// lone O sibling left by a deletion may hide a single leaf, which canonical form would lift (PTree::del must refuse).
pub fn leaf_to_opaque(wit: &[u8], k: usize) -> Option<Vec<u8>> {
    fn go(w: &[u8], i: &mut usize, o: &mut Vec<u8>, k: usize, seen: &mut usize) {
        let t = w[*i];
        *i += 1;
        match t {
            0 => o.push(0),
            1 => {
                o.push(1);
                o.extend_from_slice(&w[*i..*i + 32]);
                *i += 32;
            }
            2 | 4 => {
                let (raw, lh) = if t == 2 {
                    let mut lh = [0u8; 32];
                    lh.copy_from_slice(&w[*i + 32..*i + 64]);
                    let raw = w[*i..*i + 64].to_vec();
                    *i += 64;
                    (raw, lh)
                } else {
                    let st = *i;
                    let kl = u16::from_le_bytes([w[*i], w[*i + 1]]) as usize;
                    let kid = w[*i + 2..*i + 2 + kl].to_vec();
                    *i += 2 + kl;
                    let rl = u16::from_le_bytes([w[*i], w[*i + 1]]) as usize;
                    let rest = w[*i + 2..*i + 2 + rl].to_vec();
                    *i += 2 + rl;
                    let key = mnpilot::wit::key_of(&kid);
                    let mut leaf = kid.clone();
                    leaf.extend_from_slice(&rest);
                    (w[st..*i].to_vec(), mnpilot::wit::leaf_hash(&key, &leaf))
                };
                if *seen == k {
                    o.push(1);
                    o.extend_from_slice(&lh);
                } else {
                    o.push(t);
                    o.extend_from_slice(&raw);
                }
                *seen += 1;
            }
            3 => {
                o.push(3);
                go(w, i, o, k, seen);
                go(w, i, o, k, seen);
            }
            _ => panic!("tag"),
        }
    }
    let mut o = wit[..36].to_vec();
    let mut i = 36;
    let mut seen = 0;
    go(wit, &mut i, &mut o, k, &mut seen);
    if k >= seen {
        return None;
    }
    o.extend_from_slice(&wit[i..]);
    Some(o)
}

/// round 15: `sladv <n> <orders> wd` runs the same cases on the withdraw workload (wd_batch)
pub fn sladv_m(n: u64, ord: u32, mode: &str) -> String {
    let mut a = Adv { cases: 0, sound: 0, unsound: Vec::new(), counts: Default::default() };
    let mut done_segs = 0u64;
    for s in 1..=n {
        let makers = 4 + (s % 9) as u32;
        let levels = 1 + (s % 25) as u32;
        let per = 1 + (s % 3) as u32;
        let w = if mode == "wd" { wd_batch(s, ord) } else if mode == "perp" { perp_batch(s, ord) } else { gen(s, makers, levels, per, ord, s % 2 == 0).0 };
        let mut rng = Rng(s.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1);
        let size = 8 + rng.below(64) as u32;
        let refs = if mode == "perp" { session_refs_v2(&w, size) } else { session_refs(&w, size) };
        // previous segment's pre-state (wrong-root attack)
        let mut prev_pre: Option<mnpilot::state::ChainState> = None;
        for r in refs.iter() {
            let b = WitBuilder::new(&r.pre);
            let Ok((needs, wit, o, ev, _)) = operate(&b, &r.seg) else {
                a.unsound.push(format!("seed {}: operator failed", s));
                continue;
            };
            done_segs += 1;
            a.rec("honest", r, &o, &ev, false);
            // A1 omission: drop each supplied need once (status 0 must still be correct)
            for nd in needs.iter() {
                let mut n2 = needs.clone();
                n2.remove(nd);
                let (o2, ev2) = run_sl(&r.seg, &b.build(&n2));
                let kind = match nd {
                    Need::Account(_) => "omit:account",
                    Need::Market(_) => "omit:market",
                    Need::Aord(_) => "omit:aord",
                    Need::Order(_) => "omit:order",
                    Need::Level(..) => "omit:level",
                    Need::Bmp(..) => "omit:bmp",
                    Need::Path(_) => "omit:path",
                    Need::Light(_) => "omit:light",
                    Need::Wdl(_) => "omit:wdl",
                    Need::Perp => "omit:perp",
                    Need::Gnon(_) => "omit:gnon",
                    Need::Xsrc(_) => "omit:xsrc",
                    Need::Acmt(_) => "omit:acmt",
                    Need::Cmt(_) => "omit:cmt",
                };
                a.rec(kind, r, &o2, &ev2, false);
            }
            // A2 extra valid records: every account / market of the pre-state + every level of market 1
            let mut n3 = needs.clone();
            for id in r.pre.accounts.keys().take(40) {
                n3.insert(Need::Account(*id));
                n3.insert(Need::Aord(*id));
                n3.insert(Need::Wdl(*id)); // round 15
            }
            n3.insert(Need::Market(1));
            n3.insert(Need::Market(2));
            n3.insert(Need::Market(77));
            if let Some(bk) = r.pre.books.get(&mnpilot::types::MarketId(1)) {
                for (side, p, _) in bk.sl_levels().into_iter().take(60) {
                    n3.insert(Need::Level(1, side.as_u8(), p));
                }
            }
            let (o3, ev3) = run_sl(&r.seg, &b.build(&n3));
            a.rec("extra:valid", r, &o3, &ev3, false);
            if o3.status != 0 && o.status == 0 {
                a.unsound.push(format!("extra valid records refused: status {} {:?}", o3.status, o3.need));
            }
            // A3 random byte flips in the record area and in the tree area
            let lay = layout(&wit);
            for t in 0..6 {
                let mut w2 = wit.clone();
                let lo = if t % 2 == 0 { lay.tree_end } else { 4 };
                let hi = if t % 2 == 0 { w2.len() } else { lay.tree_end };
                if hi <= lo {
                    continue;
                }
                let i = lo + rng.below((hi - lo) as u64) as usize;
                w2[i] ^= 1 << rng.below(8);
                let (o4, ev4) = run_sl(&r.seg, &w2);
                a.rec(if t % 2 == 0 { "flip:records" } else { "flip:tree" }, r, &o4, &ev4, false);
            }
            // A4 truncated / extended witness
            let (o5, ev5) = run_sl(&r.seg, &wit[..wit.len() - 1]);
            a.rec("truncate", r, &o5, &ev5, true);
            let mut w6 = wit.clone();
            w6.push(0);
            let (o6, ev6) = run_sl(&r.seg, &w6);
            a.rec("trailing", r, &o6, &ev6, true);
            // A5 proof against the wrong root: witness built from the previous segment's pre-state
            if let Some(pp) = &prev_pre {
                let bw = WitBuilder::new(pp);
                let wrong = bw.build(&needs);
                // R14-H2 fix: with the chain binding (expect = honest root) the run must be refused
                let (ob, evb) = run_sl_x(&r.seg, &wrong, Some(&b.root));
                if ob.status != sl::ST_SL_BADROOT && wrong[4..36] != b.root {
                    a.unsound.push(format!("wrong-root with binding: status {}", ob.status));
                }
                a.rec("wrong-root:bound", r, &ob, &evb, wrong[4..36] != b.root);
                let (o7, ev7) = run_sl(&r.seg, &wrong);
                // the guest may accept its own claimed root (status 0) -- the ROLLUP must refuse a start root
                // that is not the previous end root; record whether start_root != reference
                a.cases += 1;
                let e = a.counts.entry("wrong-root".into()).or_insert((0, 0, 0));
                e.0 += 1;
                if o7.status != 0 {
                    e.1 += 1;
                    a.sound += 1;
                } else if o7.start_root != b.root {
                    e.2 += 1;
                    a.sound += 1; // detected by the chain binding (start_root != previous end root)
                } else {
                    a.unsound.push("wrong-root accepted with the right start root".into());
                }
                let _ = ev7;
            }
            // A6 claimed root differs from the tree (operator writes the honest root but a forged tree):
            // forge one account's collateral inside the records (leaf mismatch) -> BADWIT
            if let Some(id) = needs.iter().find_map(|x| if let Need::Account(id) = x { r.pre.accounts.get(id).map(|_| *id) } else { None }) {
                let mut pre2 = r.pre.clone();
                pre2.account_mut(id).collateral += 1_000_000;
                let bf = WitBuilder::new(&pre2);
                let mut forged = bf.build(&needs);
                // keep the forged records but put back the honest root + tree
                let lay_f = layout(&forged);
                let mut wf = wit[..lay.tree_end].to_vec();
                wf.extend_from_slice(&forged[lay_f.tree_end..]);
                let (o8, ev8) = run_sl(&r.seg, &wf);
                a.rec("forge:account", r, &o8, &ev8, true);
                // forged tree + forged root (self-consistent) -> start_root != chain root; with the binding: refused
                let (ob, evb) = run_sl_x(&r.seg, &forged, Some(&b.root));
                a.rec("forge:self-consistent:bound", r, &ob, &evb, true);
                let (o9, _) = run_sl(&r.seg, &forged);
                a.cases += 1;
                let e = a.counts.entry("forge:self-consistent".into()).or_insert((0, 0, 0));
                e.0 += 1;
                if o9.status != 0 || o9.start_root != b.root {
                    e.1 += 1;
                    a.sound += 1;
                } else {
                    a.unsound.push("forged self-consistent witness carries the honest start root".into());
                }
                forged.clear();
            }
            // A16 (round 16): forged round-16 records under the honest tree / root -- PERP aggregates, market-id cursor,
            // gov nonce, external-source membership, commit index (drop / retime an entry) and single commit records
            {
                let mut forges: Vec<(&str, mnpilot::state::ChainState)> = Vec::new();
                if needs.contains(&Need::Perp) {
                    let mut p2 = r.pre.clone();
                    p2.perp_supply += 1;
                    forges.push(("forge16:perp-supply", p2));
                    let mut p2 = r.pre.clone();
                    p2.next_market_id += 1;
                    forges.push(("forge16:next-market", p2));
                }
                for nd in needs.iter() {
                    match *nd {
                        Need::Gnon(id) => {
                            let mut p2 = r.pre.clone();
                            let v = p2.seen_gov_nonces.get(&id).copied().unwrap_or(0);
                            if v > 0 {
                                p2.seen_gov_nonces.insert(id, v - 1);
                            } else {
                                p2.seen_gov_nonces.insert(id, 7);
                            }
                            forges.push(("forge16:gnon", p2));
                        }
                        Need::Xsrc(id) => {
                            let mut p2 = r.pre.clone();
                            if !p2.external_sources.remove(&id) {
                                p2.external_sources.insert(id);
                            }
                            forges.push(("forge16:xsrc", p2));
                        }
                        Need::Acmt(id) => {
                            let hs: Vec<[u8; 32]> = r.pre.commits.iter().filter(|(_, e)| e.account == id).map(|(h, _)| *h).collect();
                            if let Some(h) = hs.first() {
                                let mut p2 = r.pre.clone();
                                p2.commits.remove(h);
                                forges.push(("forge16:acmt-drop", p2));
                                let mut p2 = r.pre.clone();
                                p2.commits.get_mut(h).unwrap().ttl_height += 1;
                                forges.push(("forge16:acmt-ttl", p2));
                                let mut p2 = r.pre.clone();
                                let e = p2.commits.get_mut(h).unwrap();
                                e.revealed = !e.revealed;
                                forges.push(("forge16:acmt-revealed", p2));
                            } else {
                                // claim a commit the account does not have (its index is absent)
                                let mut p2 = r.pre.clone();
                                p2.commits.insert([0x5A; 32], mnpilot::state::CommitEntry { account: id, commit_unit: [1; 32], commit_height: 0, ttl_height: 5, revealed: false });
                                forges.push(("forge16:acmt-add", p2));
                            }
                        }
                        Need::Cmt(h) => {
                            let mut p2 = r.pre.clone();
                            if p2.commits.remove(&h).is_none() {
                                let who = r.pre.accounts.keys().next().copied().unwrap_or(mnpilot::types::INSURANCE_ACCOUNT);
                                p2.commits.insert(h, mnpilot::state::CommitEntry { account: who, commit_unit: [2; 32], commit_height: 0, ttl_height: 9, revealed: false });
                            }
                            forges.push(("forge16:cmt", p2));
                        }
                        _ => {}
                    }
                }
                for (name, p2) in forges.into_iter().take(12) {
                    let bf = WitBuilder::new(&p2);
                    let forged = bf.build(&needs);
                    let lay_f = layout(&forged);
                    let mut wf = wit[..lay.tree_end].to_vec();
                    wf.extend_from_slice(&forged[lay_f.tree_end..]);
                    let (of, evf) = run_sl(&r.seg, &wf);
                    a.rec(name, r, &of, &evf, true);
                }
            }
            // A7 order-book boundary: omit the BEST level of each side of market 1 (keep the trie path)
            if let Some(bk) = r.pre.books.get(&mnpilot::types::MarketId(1)) {
                let lv = bk.sl_levels();
                for sd in [mnpilot::types::Side::Bid, mnpilot::types::Side::Ask] {
                    if let Some((_, p, _)) = lv.iter().find(|x| x.0 == sd) {
                        let key = Need::Level(1, sd.as_u8(), *p);
                        if needs.contains(&key) {
                            let mut n2 = needs.clone();
                            n2.remove(&key);
                            let (ox, evx) = run_sl(&r.seg, &b.build(&n2));
                            a.rec("book:omit-best-level", r, &ox, &evx, false);
                        }
                    }
                }
            }
            // A8 order-book: drop the last order of a supplied level / swap the first two (FIFO forgery)
            // done on the serialized witness by rebuilding from a state whose level is altered
            if let Some((m, sd, p)) = needs.iter().find_map(|x| if let Need::Level(m, sd, p) = x { Some((*m, *sd, *p)) } else { None }) {
                let side = mnpilot::types::Side::from_u8(sd).unwrap();
                if let Some(ids) = r.pre.books.get(&mnpilot::types::MarketId(m)).and_then(|bk| bk.sl_level(side, p)) {
                    // drop: cancel the last order in a copy -> records of the copy, honest tree
                    let mut pre2 = r.pre.clone();
                    let last = *ids.last().unwrap();
                    let _ = pre2.book_mut(mnpilot::types::MarketId(m)).cancel(last);
                    let bf = WitBuilder::new(&pre2);
                    let f = bf.build(&needs);
                    let lf = layout(&f);
                    let mut wf = wit[..lay.tree_end].to_vec();
                    wf.extend_from_slice(&f[lf.tree_end..]);
                    let (ox, evx) = run_sl(&r.seg, &wf);
                    a.rec("book:drop-order-in-level", r, &ox, &evx, true);
                    if ids.len() >= 2 {
                        // reorder: re-insert the first order at the back
                        let mut pre3 = r.pre.clone();
                        let bkm = pre3.book_mut(mnpilot::types::MarketId(m));
                        let first = bkm.get(ids[0]).cloned().unwrap();
                        let _ = bkm.cancel(ids[0]);
                        bkm.sl_restore(first);
                        let bf = WitBuilder::new(&pre3);
                        let f = bf.build(&needs);
                        let lf = layout(&f);
                        let mut wf = wit[..lay.tree_end].to_vec();
                        wf.extend_from_slice(&f[lf.tree_end..]);
                        let (ox, evx) = run_sl(&r.seg, &wf);
                        a.rec("book:reorder-fifo", r, &ox, &evx, true);
                    }
                }
            }
            // A9 hide a trie node: claim a present bmp node absent (records of a state without that level)
            if let Some(Need::Level(m, sd, p)) = needs.iter().find(|x| matches!(x, Need::Level(..))).copied() {
                let side = mnpilot::types::Side::from_u8(sd).unwrap();
                if let Some(ids) = r.pre.books.get(&mnpilot::types::MarketId(m)).and_then(|bk| bk.sl_level(side, p)) {
                    let mut pre2 = r.pre.clone();
                    for id in &ids {
                        let _ = pre2.book_mut(mnpilot::types::MarketId(m)).cancel(*id);
                    }
                    let mut n2 = needs.clone();
                    n2.remove(&Need::Level(m, sd, p));
                    let u = sl::ubias(p);
                    for d in 0..8u8 {
                        n2.insert(Need::Bmp(m, sd, d, sl::pfx(u, d)));
                    }
                    let bf = WitBuilder::new(&pre2);
                    let f = bf.build(&n2);
                    let lf = layout(&f);
                    // honest tree for n2 (+ the forged records claiming the level / nodes absent)
                    let honest = b.build(&n2);
                    let lh = layout(&honest);
                    let mut wf = honest[..lh.tree_end].to_vec();
                    wf.extend_from_slice(&f[lf.tree_end..]);
                    let (ox, evx) = run_sl(&r.seg, &wf);
                    a.rec("book:hide-level-in-trie", r, &ox, &evx, true);
                }
            }
            // A17 (round 16, linked FIFO): every level record without its head order (a later order of the level, loaded
            // by id, must never be taken as the head: OrderBook::sl_ok needs its whole predecessor chain); and the
            // islands of a level only (own orders / cancel targets) -- status 0 must still be the reference result
            {
                b.t_omit_head.set(true);
                let wf = b.build(&needs);
                b.t_omit_head.set(false);
                let (ox, evx) = run_sl(&r.seg, &wf);
                a.rec("book:omit-head", r, &ox, &evx, false);
            }
            // A10 duplicate record: the same account twice (patch the count) -> BADWIT
            {
                let one: BTreeSet<Need> = [Need::Account(mnpilot::types::INSURANCE_ACCOUNT)].into_iter().collect();
                let wv = b.build(&one);
                let lv = layout(&wv);
                // records: seq 8, height 8, markets u16 (0), accounts u16 (1) + record
                let mut wd = wv.clone();
                let acc_cnt = lv.tree_end + 16 + 2;
                let rec_start = acc_cnt + 2;
                // the account record runs to the aord count (5 trailing u16 zeros after it: aord, bmp, levels, ordx,
                // wdl -- round 15)
                let rec_end = wv.len() - 10;
                let rec = wv[rec_start..rec_end].to_vec();
                wd[acc_cnt] = 2;
                wd.splice(rec_end..rec_end, rec);
                let (od, evd) = run_sl(&r.seg, &wd);
                a.rec("duplicate:account", r, &od, &evd, true);
            }
            // A11 limits: an account count above SL_MAX_ACCOUNTS -> BADWIT before reading records
            {
                let one: BTreeSet<Need> = BTreeSet::new();
                let wv = b.build(&one);
                let lv = layout(&wv);
                let mut wl = wv.clone();
                let acc_cnt = lv.tree_end + 16 + 2;
                let big = (sl::SL_MAX_ACCOUNTS as u16 + 1).to_le_bytes();
                wl[acc_cnt] = big[0];
                wl[acc_cnt + 1] = big[1];
                let (ol, evl) = run_sl(&r.seg, &wl);
                a.rec("limit:accounts", r, &ol, &evl, true);
            }
            // A12 (R14-C1 PoC): exclusion proof through a hash-only leaf with a forged key. An author X that
            // exists is claimed ABSENT: the records come from a state without X, the tree is the honest one with
            // the deep bits of X's acct: / apos: / cseq: leaf keys flipped (the path only constrains the first d
            // bits; the leaf hash is unchanged, so the root still matches).
            if let Some(x) = needs.iter().find_map(|n| match n {
                Need::Account(id) if *id != mnpilot::types::INSURANCE_ACCOUNT && r.pre.accounts.contains_key(id) => Some(*id),
                _ => None,
            }) {
                let mut pre2 = r.pre.clone();
                pre2.del_account(&x);
                pre2.perp_balances.remove(&x);
                pre2.withdrawn_total.remove(&x);
                pre2.seen_client_seq.remove(&x);
                let f = WitBuilder::new(&pre2).build(&needs);
                let lf = layout(&f);
                let mut tree = wit[..lay.tree_end].to_vec();
                let mut bb = mnpilot::wit::Buf::new();
                let mut ks = vec![mnpilot::wit::acct_key(&x)];
                sl::apos_kid(&mut bb, &x);
                ks.push(mnpilot::wit::key_of(&bb.b[..bb.kid]));
                sl::cseq_kid(&mut bb, &x);
                ks.push(mnpilot::wit::key_of(&bb.b[..bb.kid]));
                let mut flipped = 0;
                for k in &ks {
                    if let Some(i) = tree.windows(33).position(|w| w[0] == 2 && &w[1..] == k) {
                        tree[i + 32] ^= 1;
                        flipped += 1;
                    }
                }
                if flipped >= 2 {
                    tree.extend_from_slice(&f[lf.tree_end..]);
                    let (ox, evx) = run_sl(&r.seg, &tree);
                    a.rec("forge:absent-via-leaf-key", r, &ox, &evx, true);
                }
            }
            // A13: hide each single leaf as an opaque hash (root unchanged); refusals or correct results only
            for k in 0..48 {
                let Some(w13) = leaf_to_opaque(&wit, k) else { break };
                let (ox, evx) = run_sl(&r.seg, &w13);
                a.rec("tree:leaf-as-opaque", r, &ox, &evx, false);
            }
            // round 15 A14 (R14-M2 light record): (a) records of a state where the insurance account holds one more
            // position (count + digest differ), honest tree -> refused; (b) a light record for a user account -> refused
            let ins = mnpilot::types::INSURANCE_ACCOUNT;
            if needs.contains(&Need::Light(ins)) && r.pre.accounts.contains_key(&ins) {
                let mut pre2 = r.pre.clone();
                pre2.account_mut(ins).positions.insert(
                    mnpilot::types::MarketId(4_000_000_001),
                    mnpilot::account::Position { market: mnpilot::types::MarketId(4_000_000_001), qty: 1, entry_price: MID, isolated: false },
                );
                let _ = pre2.take_dirty();
                let f = WitBuilder::new(&pre2).build(&needs);
                let lf = layout(&f);
                let mut wf = wit[..lay.tree_end].to_vec();
                wf.extend_from_slice(&f[lf.tree_end..]);
                let (ox, evx) = run_sl(&r.seg, &wf);
                a.rec("light:forged-digest", r, &ox, &evx, true);
                let mut pre3 = r.pre.clone();
                pre3.account_mut(ins).collateral += 1_000_000;
                let _ = pre3.take_dirty();
                let f = WitBuilder::new(&pre3).build(&needs);
                let lf = layout(&f);
                let mut wf = wit[..lay.tree_end].to_vec();
                wf.extend_from_slice(&f[lf.tree_end..]);
                let (ox, evx) = run_sl(&r.seg, &wf);
                a.rec("light:forged-collateral", r, &ox, &evx, true);
            }
            if let Some(x) = needs.iter().find_map(|n| match n {
                Need::Account(id) if *id != ins && r.pre.accounts.contains_key(id) => Some(*id),
                _ => None,
            }) {
                let mut n2 = needs.clone();
                n2.remove(&Need::Account(x));
                n2.insert(Need::Light(x));
                let (ox, evx) = run_sl(&r.seg, &b.build(&n2));
                a.rec("light:user-account", r, &ox, &evx, true);
            }
            // round 15 A15 (wdl:): drop one record / add a record / claim the set absent, honest tree -> refused
            let wx: Vec<mnpilot::types::AccountId> = needs.iter().filter_map(|n| if let Need::Wdl(id) = n { Some(*id) } else { None }).collect();
            if let Some(x) = wx.iter().find(|x| r.pre.withdrawals.range((**x, 0)..=(**x, u64::MAX)).next().is_some()).or(wx.first()).copied() {
                let mine: Vec<u64> = r.pre.withdrawals.range((x, 0)..=(x, u64::MAX)).map(|((_, n), _)| *n).collect();
                let mut variants: Vec<(&str, mnpilot::state::ChainState)> = Vec::new();
                if let Some(n0) = mine.first() {
                    let mut p2 = r.pre.clone();
                    p2.withdrawals.remove(&(x, *n0));
                    variants.push(("wdl:drop-record", p2));
                    let mut p3 = r.pre.clone();
                    p3.withdrawals.retain(|(a, _), _| *a != x);
                    variants.push(("wdl:claim-absent", p3));
                }
                let mut p4 = r.pre.clone();
                p4.withdrawals.insert((x, 999_999), mnpilot::types::Withdrawal { amount: 1, pending: true, height: r.pre.height });
                variants.push(("wdl:add-record", p4));
                for (nm, p) in variants {
                    let f = WitBuilder::new(&p).build(&needs);
                    let lf = layout(&f);
                    let mut wf = wit[..lay.tree_end].to_vec();
                    wf.extend_from_slice(&f[lf.tree_end..]);
                    let (ox, evx) = run_sl(&r.seg, &wf);
                    a.rec(nm, r, &ox, &evx, true);
                }
            }
            prev_pre = Some(r.pre.clone());
            if done_segs >= 400 {
                break;
            }
        }
    }
    let cs: Vec<String> = a.counts.iter().map(|(k, (r, rej, ok))| format!("\"{}\":[{},{},{}]", k, r, rej, ok)).collect();
    format!(
        "{{\"segments\":{},\"cases\":{},\"sound\":{},\"unsound\":{},\"by_case [runs, refused, accepted-correct]\":{{{}}},\"unsound_first\":{:?}}}",
        done_segs,
        a.cases,
        a.sound,
        a.unsound.len(),
        cs.join(","),
        a.unsound.iter().take(8).collect::<Vec<_>>()
    )
}

/// sldump <seed> <orders> <S> <dir> [adv]: session segments (seg%03d.bin) + stateless inputs (sl%03d.bin:
/// [SL_MAGIC, B, W, batch words, witness bytes packed LE]) + manifest.json (expected events, MNWIT-S roots,
/// witness size) for js/slsteps.js (riscv32im steps per segment, session vs stateless).
pub fn sldump(seed: u64, ord: u32, size: u32, dir: &str, adv: bool) -> String {
    let w = if adv {
        adv::adv_batch(seed, ord)
    } else {
        let makers = 4 + (seed % 9) as u32;
        let levels = 1 + (seed % 25) as u32;
        let per = 1 + (seed % 3) as u32;
        gen(seed, makers, levels, per, ord, seed % 2 == 0).0
    };
    fs::create_dir_all(dir).unwrap();
    let refs = session_refs(&w, size);
    let mut man = Vec::new();
    for (k, r) in refs.iter().enumerate() {
        let b = WitBuilder::new(&r.pre);
        let (needs, wit, o, ev, it) = operate(&b, &r.seg).expect("operator");
        assert!(o.status == 0 && o.end_root == r.post_root && ev == r.ev, "segment {} differs", k);
        // session segment: first keeps the batch's genesis flags
        let mut sw = r.seg.clone();
        if k == 0 {
            sw[3] = w[3];
        }
        write_words(&format!("{}/seg{:03}.bin", dir, k), &sw);
        let mut x = vec![sl::SL_MAGIC, r.seg.len() as u32, wit.len() as u32];
        x.extend_from_slice(&r.seg);
        for c in wit.chunks(4) {
            let mut q = [0u8; 4];
            q[..c.len()].copy_from_slice(c);
            x.push(u32::from_le_bytes(q));
        }
        write_words(&format!("{}/sl{:03}.bin", dir, k), &x);
        man.push(format!(
            "{{\"seg\":\"seg{:03}.bin\",\"sl\":\"sl{:03}.bin\",\"units\":{},\"s_start\":\"{}\",\"s_end\":\"{}\",\"witness_bytes\":{},\"needs\":{},\"iterations\":{},\"leaves_verified\":{},\"tree_nodes\":{},\"ev\":[{}]}}",
            k, k, r.seg[2], hx(&b.root), hx(&r.post_root), wit.len(), needs.len(), it, o.leaves_verified, o.tree_nodes,
            r.ev.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")
        ));
    }
    fs::write(format!("{}/manifest.json", dir), format!("[{}]", man.join(",\n"))).unwrap();
    format!("{{\"segments\":{},\"dir\":\"{}\"}}", refs.len(), dir)
}

/// slcaps (round 14, R14-H1 / R14-M1): the stateless image's per-account exposure cap and per-level size cap.
/// Synthetic pre-state (no session reference: the session image has neither rule): 66 markets; account A holds
/// SL_MAX_POS positions; market 1 has one ask level with SL_MAX_LEVEL_ORDERS orders from 64 makers.
pub fn slcaps() -> String {
    use mnpilot::types::{AccountId as A, MarketId as M, Side};
    let mut s = mnpilot::state::ChainState::genesis();
    let p0 = mnpilot::types::genesis_params();
    for m in 2..=66u32 {
        s.markets.insert(M(m), p0);
        s.marks.insert(M(m), MID);
    }
    let id = |i: u32| A(acct_id(i).0);
    // A = 0: SL_MAX_POS small long positions (cross) in markets 2..
    let mut a = mnpilot::account::Account::new(id(0));
    a.collateral = 1_000_000_000 * USD_SCALE as i128;
    for m in 2..2 + sl::SL_MAX_POS as u32 {
        a.positions.insert(M(m), mnpilot::account::Position { market: M(m), qty: (QTY_SCALE / 100) as i64, entry_price: MID, isolated: false });
    }
    s.put_account(id(0), a);
    // makers 10..74: 64 orders each at one ask price P on market 1
    let px = MID + 5 * DOLLAR;
    let mut n = 0usize;
    'outer: for mk in 10..74u32 {
        let mut acc = mnpilot::account::Account::new(id(mk));
        acc.collateral = 1_000_000_000 * USD_SCALE as i128;
        s.put_account(id(mk), acc);
        for c in 1..=64u64 {
            if n >= sl::SL_MAX_LEVEL_ORDERS {
                break 'outer;
            }
            let oid = mnpilot::types::order_id(id(mk), M(1), c);
            s.book_mut(M(1)).sl_restore(mnpilot::Order {
                id: oid, account: id(mk), market: M(1), side: Side::Ask, typ: mnpilot::types::OrderType::Limit,
                tif: mnpilot::types::TimeInForce::Gtc, price: px, qty: QTY_SCALE / 100, remaining: QTY_SCALE / 100, seq: n as u64,
                isolated: false, margin_left: 0,
            });
            s.seen_client_seq.insert(id(mk), c);
            n += 1;
        }
    }
    for b in [1u32, 2] {
        let mut acc = mnpilot::account::Account::new(id(b));
        acc.collateral = 1_000_000_000 * USD_SCALE as i128;
        s.put_account(id(b), acc);
    }
    let _ = s.take_dirty();
    // ops: (acct index in table, side 0 bid / 1 ask, typ, tif, price, market, client_seq)
    let table = [0u32, 1, 2];
    let op = |ai: u32, side: u32, ioc: bool, price: i64, m: u32, cs: u32| -> [u32; 8] {
        let q = QTY_SCALE / 100;
        [2 | (ai << 8), side | (if ioc { 4 } else { 0 }), price as u32, (price >> 32) as u32, q as u32, (q >> 32) as u32, cs, m]
    };
    let ops = [
        op(0, 0, false, MID - 50 * DOLLAR, 66, 1), // A: new market 66 beyond the exposure cap -> 19
        op(0, 0, false, MID - 50 * DOLLAR, 2, 1),  // A: market 2 (holds a position) -> not 19
        op(1, 1, false, px, 1, 1),                 // B: GTC ask joining the 4096-order level -> rests (round 16: no level cap)
        op(1, 1, false, px + DOLLAR, 1, 2),        // B: next price -> rests
        op(2, 0, true, px, 1, 1),                  // C: IOC bid at P -> one fill with the level head
    ];
    let mut w = vec![mnpilot::MAGIC, table.len() as u32, ops.len() as u32, 0];
    for t in table {
        let x = acct_id(t);
        for k in 0..8 {
            w.push(u32::from_le_bytes(x.0[k * 4..k * 4 + 4].try_into().unwrap()));
        }
    }
    for o in &ops {
        w.extend_from_slice(o);
    }
    let b = WitBuilder::new(&s);
    let (needs, wit, o, ev, it) = match operate(&b, &w) {
        Ok(x) => x,
        Err(e) => return format!("{{\"ok\":false,\"why\":\"{}\"}}", e),
    };
    // event words per unit
    let mut units: Vec<Vec<u32>> = Vec::new();
    let mut k = 0;
    while k < ev.len() {
        let e = ev[k];
        if e & EV_APPLIED != 0 {
            let nf = (e & 0xff) as usize;
            units.push(ev[k..k + 1 + 6 * nf].to_vec());
            k += 1 + 6 * nf;
        } else {
            units.push(vec![e]);
            k += 1;
        }
    }
    let code = |u: &Vec<u32>| if u[0] & EV_APPLIED != 0 { format!("applied/{}", u[0] & 0xff) } else { u[0].to_string() };
    let got: Vec<String> = units.iter().map(code).collect();
    let ok = o.status == 0
        && units.len() == 5
        && units[0] == vec![mnpilot::STATE_CAP_CODE]
        && units[1] != vec![mnpilot::STATE_CAP_CODE]
        && units[2][0] == EV_APPLIED
        && units[3][0] == EV_APPLIED
        && units[4][0] == EV_APPLIED | 1;
    format!(
        "{{\"ok\":{},\"status\":{},\"units\":{:?},\"level_orders\":{},\"needs\":{},\"iterations\":{},\"witness_bytes\":{},\"leaves_verified\":{}}}",
        ok, o.status, got, n, needs.len(), it, wit.len(), o.leaves_verified
    )
}

/// round 15: direct full-state reference for synthetic pre-states (no session image: the stateless image's own
/// rules -- exposure / level caps, depth rule -- are not exercised by the slpoc15 cases). Same unit loop as
/// run_stateless (events: EV_APPLIED | fills + 6 words per fill, or the reason code).
pub fn direct(pre: &mnpilot::state::ChainState, seg: &[u32]) -> (mnpilot::state::ChainState, Vec<u32>) {
    let mut eng = mnpilot::engine::Engine { state: pre.clone() };
    let n_acc = seg[1];
    let n_ops = seg[2];
    let accts: Vec<mnpilot::types::AccountId> = (0..n_acc)
        .map(|a| {
            let mut id = [0u8; 32];
            for k in 0..8 {
                id[k * 4..k * 4 + 4].copy_from_slice(&seg[4 + (a * 8) as usize + k].to_le_bytes());
            }
            mnpilot::types::AccountId(id)
        })
        .collect();
    let base = 4 + 8 * n_acc;
    let uid_base = base + 8 * n_ops;
    let mut ev = Vec::new();
    for i in 0..n_ops {
        let mut ow = [0u32; 8];
        for (k, x) in ow.iter_mut().enumerate() {
            *x = seg[(base + i * 8) as usize + k];
        }
        let seq = eng.state.seq;
        let op = mnpilot::decode_op(&ow);
        let res = mnpilot::dispatch(&mut eng, &op, &accts, mnpilot::Uid { v2: false, at: uid_base + i * 8 }, seq, &mnpilot::Ext::NONE, &mut |j| seg.get(j as usize).copied().unwrap_or(0), false);
        match res {
            Ok(fills) => {
                eng.state.seq += 1;
                ev.push(EV_APPLIED | fills.len() as u32);
                for f in &fills {
                    ev.push(u32::from_le_bytes(f.maker_id.0[..4].try_into().unwrap()));
                    ev.push(u32::from_le_bytes(f.taker_id.0[..4].try_into().unwrap()));
                    ev.push(f.price as u32);
                    ev.push((f.price >> 32) as u32);
                    ev.push(f.qty as u32);
                    ev.push((f.qty >> 32) as u32);
                }
            }
            Err(r) => ev.push(mnpilot::reason_code(&r)),
        }
    }
    let _ = eng.state.take_dirty();
    (eng.state, ev)
}

fn seg_words(table: &[u32], ops: &[[u32; 8]]) -> Vec<u32> {
    let mut w = vec![mnpilot::MAGIC, table.len() as u32, ops.len() as u32, 0];
    for t in table {
        let x = acct_id(*t);
        for k in 0..8 {
            w.push(u32::from_le_bytes(x.0[k * 4..k * 4 + 4].try_into().unwrap()));
        }
    }
    for o in ops {
        w.extend_from_slice(o);
    }
    w
}

/// slpoc15 (round 15 PoCs / regression):
///  P1 R15-H1: account A holds SL_MAX_POS positions in markets with 10-digit ids (4 000 000 000 + k). The round-14
///     `apos:` leaf listed the markets in decimal -> ~780 bytes > the 384-byte leaf buffer: s_root / WitBuilder /
///     the guest's loader and end root panic (index out of bounds; the riscv guest traps) -> every segment that
///     touches A halts. Fixed form (digest): A's Place and Withdraw run with status 0, events + end root = direct.
///  P2 R14-M2: the insurance account holds 100 positions (> SL_MAX_POS, reachable through liquidation / ADL takeovers
///     once markets are unbounded). Round 14: every Place needs the FULL insurance record (np > 64 -> BADWIT: no
///     witness exists, the exchange halts). Fixed: the LIGHT record (acct: + apos: digest) -> status 0, fee credited,
///     end root = direct; a light record for any other account is refused (BADWIT); a light record whose digest /
///     count does not match is refused.
///  P3 withdraw: wdl: records -- duplicate nonce, pending cap, dust, insufficient, R2-E-3 resting IM, exact roots.
type Extra15<'a> = &'a dyn Fn(&mnpilot::state::ChainState, &sl::SlOut, &BTreeSet<Need>) -> bool;
fn check15(name: &str, s: &mnpilot::state::ChainState, seg: &[u32], extra: Extra15) -> String {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (post, ev_ref) = direct(s, seg);
        let b = WitBuilder::new(s);
        let (needs, wit, o, ev, it) = operate(&b, seg)?;
        let root_ok = o.status == 0 && o.end_root == sl::s_root(&post);
        let ok = root_ok && ev == ev_ref && extra(&post, &o, &needs);
        let evs: Vec<String> = ev.iter().map(|e| if e & EV_APPLIED != 0 { format!("applied/{}", e & 0xff) } else { e.to_string() }).take(16).collect();
        Ok::<String, String>(format!(
            "{{\"case\":\"{}\",\"ok\":{},\"status\":{},\"root_ok\":{},\"ev_ok\":{},\"ev\":{:?},\"needs\":{},\"iterations\":{},\"witness_bytes\":{}}}",
            name, ok, o.status, root_ok, ev == ev_ref, evs, needs.len(), it, wit.len()
        ))
    }));
    match r {
        Ok(Ok(l)) => l,
        Ok(Err(e)) => format!("{{\"case\":\"{}\",\"ok\":false,\"why\":\"{}\"}}", name, e),
        Err(_) => format!("{{\"case\":\"{}\",\"ok\":false,\"why\":\"panic\"}}", name),
    }
}

pub fn slpoc15() -> String {
    use mnpilot::types::{AccountId as A, MarketId as M};
    let mut res: Vec<String> = Vec::new();
    let mut all_ok = true;
    let id = |i: u32| A(acct_id(i).0);
    let p0 = mnpilot::types::genesis_params();
    let place = |ai: u32, bid: bool, ioc: bool, price: i64, m: u32, cs: u32| -> [u32; 8] {
        let q = QTY_SCALE / 100;
        [2 | (ai << 8), (if bid { 0 } else { 1 }) | (if ioc { 4 } else { 0 }), price as u32, (price >> 32) as u32, q as u32, (q >> 32) as u32, cs, m]
    };
    let wd = |ai: u32, amt: i64, nonce: u64| -> [u32; 8] { [6 | (ai << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, nonce as u32, (nonce >> 32) as u32] };
    // ---- P1 ----
    {
        let mut s = mnpilot::state::ChainState::genesis();
        let mut a = mnpilot::account::Account::new(id(0));
        a.collateral = 1_000_000_000 * USD_SCALE as i128;
        for k in 0..sl::SL_MAX_POS as u32 {
            let m = 4_000_000_000 + k;
            s.markets.insert(M(m), p0);
            s.marks.insert(M(m), MID);
            a.positions.insert(M(m), mnpilot::account::Position { market: M(m), qty: (QTY_SCALE / 100) as i64, entry_price: MID, isolated: false });
        }
        s.put_account(id(0), a);
        let mut bb = mnpilot::account::Account::new(id(1));
        bb.collateral = 1_000_000_000 * USD_SCALE as i128;
        s.put_account(id(1), bb);
        let _ = s.take_dirty();
        let mut lb = mnpilot::wit::Buf::new();
        let mk: Vec<u32> = (0..sl::SL_MAX_POS as u32).map(|k| 4_000_000_000 + k).collect();
        sl::apos_leaf(&mut lb, &id(0), 1, &mk);
        res.push(format!("{{\"case\":\"P1 apos leaf length (fixed form)\",\"bytes\":{},\"round14_form_bytes\":{}}}", lb.n, 5 + 64 + 3 + mk.iter().map(|m| m.to_string().len() + 1).sum::<usize>() - 1));
        let m0 = 4_000_000_000u32;
        let seg = seg_words(&[0, 1], &[place(0, true, false, MID - 10 * DOLLAR, m0, 1), place(1, false, true, MID - 10 * DOLLAR, m0, 1), wd(0, 5 * USD_SCALE as i64, 1)]);
        let l = check15("P1 R15-H1 64 positions in 10-digit markets: place, taker fill, withdraw", &s, &seg, &|_, _, _| true);
        all_ok &= l.contains("\"ok\":true");
        res.push(l);
    }
    // ---- P2 ----
    {
        let mut s = mnpilot::state::ChainState::genesis();
        let ins = mnpilot::types::INSURANCE_ACCOUNT;
        for k in 0..100u32 {
            let m = 10 + k;
            s.markets.insert(M(m), p0);
            s.marks.insert(M(m), MID);
            s.account_mut(ins).positions.insert(M(m), mnpilot::account::Position { market: M(m), qty: (QTY_SCALE / 100) as i64, entry_price: MID, isolated: false });
        }
        for i in [1u32, 2] {
            let mut a = mnpilot::account::Account::new(id(i));
            a.collateral = 1_000_000_000 * USD_SCALE as i128;
            s.put_account(id(i), a);
        }
        let _ = s.take_dirty();
        let coll0 = s.accounts.get(&ins).unwrap().collateral;
        let seg = seg_words(&[1, 2], &[place(0, true, false, MID, 1, 1), place(1, false, true, MID, 1, 1)]);
        let l = check15("P2 R14-M2 insurance with 100 positions: maker + taker fill (fee to insurance)", &s, &seg, &|post, _, needs| {
            post.accounts.get(&ins).unwrap().collateral > coll0 && needs.contains(&Need::Light(ins)) && !needs.contains(&Need::Account(ins))
        });
        all_ok &= l.contains("\"ok\":true");
        res.push(l);
        // the round-14 behaviour: the full insurance record (> SL_MAX_POS positions) cannot be loaded
        let b = WitBuilder::new(&s);
        let mut n = guess(&seg);
        n.insert(Need::Account(ins));
        let (o, _) = run_sl(&seg, &b.build(&n));
        res.push(format!("{{\"case\":\"P2 full insurance record (round-14 path)\",\"ok\":{},\"status\":{}}}", o.status == sl::ST_SL_BADWIT, o.status));
        all_ok &= o.status == sl::ST_SL_BADWIT;
        // a light record for a non-insurance account (it would hide positions from risk checks) -> BADWIT
        let mut s2 = s.clone();
        s2.account_mut(id(1)).positions.insert(M(10), mnpilot::account::Position { market: M(10), qty: (QTY_SCALE / 100) as i64, entry_price: MID, isolated: false });
        let _ = s2.take_dirty();
        let b2 = WitBuilder::new(&s2);
        let mut n2 = guess(&seg);
        n2.remove(&Need::Account(id(1)));
        n2.insert(Need::Light(id(1)));
        for m in [1u32, 10] {
            n2.insert(Need::Market(m));
        }
        let (o2, _) = run_sl(&seg, &b2.build(&n2));
        res.push(format!("{{\"case\":\"P2 light record of a user account\",\"ok\":{},\"status\":{}}}", o2.status == sl::ST_SL_BADWIT, o2.status));
        all_ok &= o2.status == sl::ST_SL_BADWIT;
        // a light insurance record whose count / digest hides positions: records of a state where insurance has 99
        // positions, honest tree -> BADWIT
        let mut s3 = s.clone();
        s3.account_mut(ins).positions.remove(&M(109));
        let _ = s3.take_dirty();
        let (needs, wit, _, _, _) = operate(&b, &seg).unwrap();
        let f = WitBuilder::new(&s3).build(&needs);
        let (lw, lf) = (layout(&wit), layout(&f));
        let mut wf = wit[..lw.tree_end].to_vec();
        wf.extend_from_slice(&f[lf.tree_end..]);
        let (o3, _) = run_sl(&seg, &wf);
        res.push(format!("{{\"case\":\"P2 light record with a forged position digest\",\"ok\":{},\"status\":{}}}", o3.status == sl::ST_SL_BADWIT, o3.status));
        all_ok &= o3.status == sl::ST_SL_BADWIT;
    }
    // ---- P3 ----
    {
        let mut s = mnpilot::state::ChainState::genesis();
        for i in [1u32, 2, 3] {
            let mut a = mnpilot::account::Account::new(id(i));
            a.collateral = 10_000 * USD_SCALE as i128;
            s.put_account(id(i), a);
        }
        // account 3 already has 63 withdrawal records (one below the pending cap) at this height
        for n in 0..63u64 {
            s.withdrawals.insert((id(3), 1000 + n), mnpilot::types::Withdrawal { amount: USD_SCALE as i128, pending: true, height: s.height });
        }
        s.withdrawn_total.insert(id(3), 63 * USD_SCALE as i128);
        let _ = s.take_dirty();
        let u = USD_SCALE as i64;
        let seg = seg_words(
            &[1, 2, 3],
            &[
                wd(0, 100 * u, 7),                       // ok
                wd(0, 100 * u, 7),                       // duplicate nonce
                wd(0, u / 2, 8),                         // dust -> Risk
                wd(0, 1_000_000 * u, 9),                 // insufficient
                place(1, true, false, MID - DOLLAR, 1, 1), // B rests a bid (reserves IM)
                wd(1, 9_990 * u, 1),                     // B: equity after < resting IM -> Insufficient (R2-E-3)
                wd(2, 0, 1),                             // zero
                wd(2, 10_000 * u, 2),                    // full balance
                wd(0, 1, 10),                            // tiny: amount != collateral -> Risk
                wd(2, 0, 2),                             // dup nonce after a full withdraw
                wd(0, u, 1000),                          // dup of an existing record? (account 1 has none: ok)
                wd(1, u, 2),
                // account 3: one more fits, then the cap
                [6 | (2 << 8), u as u32, (u >> 32) as u32, 0, 0, 0, 5000, 0],
                [6 | (2 << 8), u as u32, (u >> 32) as u32, 0, 0, 0, 5001, 0],
                [6 | (2 << 8), u as u32, (u >> 32) as u32, 0, 0, 0, 1000, 0],
                // dust withdraw re-using an EXISTING record's nonce: DuplicateNonce comes first (reads the record set)
                [6 | (2 << 8), (u / 2) as u32, 0, 0, 0, 0, 1001, 0],
            ],
        );
        let l = check15("P3 withdraw paths (wdl:)", &s, &seg, &|post, o, _| {
            post.withdrawals.range((id(3), 0)..=(id(3), u64::MAX)).count() == 64 && o.applied >= 5
        });
        all_ok &= l.contains("\"ok\":true");
        res.push(l);
        // P6: every single omission from the P3 witness -> refused or the identical result (never status 0 + wrong)
        let (post, ev_ref) = direct(&s, &seg);
        let want = sl::s_root(&post);
        let b = WitBuilder::new(&s);
        let (needs, _, _, _, _) = operate(&b, &seg).unwrap();
        let (mut runs, mut refused, mut wrong) = (0, 0, 0);
        for nd in &needs {
            let mut n2 = needs.clone();
            n2.remove(nd);
            let (o, ev) = run_sl(&seg, &b.build(&n2));
            runs += 1;
            if o.status != 0 {
                refused += 1;
            } else if o.end_root != want || ev != ev_ref {
                wrong += 1;
            }
        }
        all_ok &= wrong == 0;
        res.push(format!("{{\"case\":\"P6 single omissions from the P3 witness\",\"ok\":{},\"runs\":{},\"refused\":{},\"wrong\":{}}}", wrong == 0, runs, refused, wrong));
    }
    // ---- P7 R2-E-3 in stateless withdraw: the author's resting orders exist BEFORE the segment; a withdraw that
    // would leave equity below their resting IM is refused (Insufficient) -- needs the author's order set + levels ----
    {
        let mut s = mnpilot::state::ChainState::genesis();
        let mut a = mnpilot::account::Account::new(id(1));
        a.collateral = 100_000 * USD_SCALE as i128;
        s.put_account(id(1), a);
        // a resting bid of 1 BTC at MID - 10 $ (IM ~ 10 % of ~100 k$)
        s.book_mut(M(1)).sl_restore(mnpilot::Order {
            id: mnpilot::types::order_id(id(1), M(1), 1), account: id(1), market: M(1), side: mnpilot::types::Side::Bid,
            typ: mnpilot::types::OrderType::Limit, tif: mnpilot::types::TimeInForce::Gtc, price: MID - 10 * DOLLAR, qty: QTY_SCALE,
            remaining: QTY_SCALE, seq: 0, isolated: false, margin_left: 0,
        });
        s.seen_client_seq.insert(id(1), 1);
        let _ = s.take_dirty();
        let u = USD_SCALE as i64;
        let seg = seg_words(&[1], &[wd(0, 95_000 * u, 1), wd(0, 50_000 * u, 2)]);
        let l = check15("P7 R2-E-3: withdraw against pre-existing resting IM", &s, &seg, &|_, o, _| o.applied == 1);
        all_ok &= l.contains("\"ok\":true");
        res.push(l);
    }
    // ---- P8 omissions on minimal withdraw segments whose outcome depends on state the catch-all never sees:
    // (a) a dust withdraw re-using an existing nonce (DuplicateNonce before Risk) -- needs the wdl set;
    // (b) the P7 R2-E-3 refusal -- needs the author's resting orders. Every single omission: refused or identical ----
    {
        let u = USD_SCALE as i64;
        let mut sa = mnpilot::state::ChainState::genesis();
        let mut a = mnpilot::account::Account::new(id(1));
        a.collateral = 10_000 * USD_SCALE as i128;
        sa.put_account(id(1), a);
        sa.withdrawals.insert((id(1), 77), mnpilot::types::Withdrawal { amount: USD_SCALE as i128, pending: true, height: sa.height });
        sa.withdrawn_total.insert(id(1), USD_SCALE as i128);
        let _ = sa.take_dirty();
        let mut sb = mnpilot::state::ChainState::genesis();
        let mut b1 = mnpilot::account::Account::new(id(1));
        b1.collateral = 100_000 * USD_SCALE as i128;
        sb.put_account(id(1), b1);
        sb.book_mut(M(1)).sl_restore(mnpilot::Order {
            id: mnpilot::types::order_id(id(1), M(1), 1), account: id(1), market: M(1), side: mnpilot::types::Side::Bid,
            typ: mnpilot::types::OrderType::Limit, tif: mnpilot::types::TimeInForce::Gtc, price: MID - 10 * DOLLAR, qty: QTY_SCALE,
            remaining: QTY_SCALE, seq: 0, isolated: false, margin_left: 0,
        });
        sb.seen_client_seq.insert(id(1), 1);
        let _ = sb.take_dirty();
        for (nm, st, seg) in [("P8a dup-nonce dust", &sa, seg_words(&[1], &[wd(0, u / 2, 77)])), ("P8b resting IM", &sb, seg_words(&[1], &[wd(0, 95_000 * u, 1)]))] {
            let (post, ev_ref) = direct(st, &seg);
            let want = sl::s_root(&post);
            let b = WitBuilder::new(st);
            let (needs, _, o0, ev0, _) = operate(&b, &seg).unwrap();
            let honest = o0.status == 0 && o0.end_root == want && ev0 == ev_ref;
            let (mut runs, mut wrong) = (0, 0);
            for nd in &needs {
                let mut n2 = needs.clone();
                n2.remove(nd);
                let (o, ev) = run_sl(&seg, &b.build(&n2));
                runs += 1;
                if o.status == 0 && (o.end_root != want || ev != ev_ref) {
                    wrong += 1;
                }
            }
            all_ok &= honest && wrong == 0;
            res.push(format!("{{\"case\":\"{} single omissions\",\"ok\":{},\"honest\":{},\"runs\":{},\"wrong\":{},\"ev\":{:?}}}", nm, honest && wrong == 0, honest, runs, wrong, ev_ref));
        }
    }
    // ---- P4 lazy expiry of withdrawal records (stateless chain: a wdl: leaf may still list records older than the
    // replay window; session semantics = pruned) ----
    {
        let mut s = mnpilot::state::ChainState::genesis();
        s.height = 3000;
        for i in [1u32, 2] {
            let mut a = mnpilot::account::Account::new(id(i));
            a.collateral = 10_000 * USD_SCALE as i128;
            s.put_account(id(i), a);
            // expired (100 + 2048 <= 3000) and live records
            s.withdrawals.insert((id(i), 5), mnpilot::types::Withdrawal { amount: USD_SCALE as i128, pending: true, height: 100 });
            s.withdrawals.insert((id(i), 6), mnpilot::types::Withdrawal { amount: USD_SCALE as i128, pending: true, height: 2900 });
            s.withdrawn_total.insert(id(i), 2 * USD_SCALE as i128);
        }
        let _ = s.take_dirty();
        let u = USD_SCALE as i64;
        // account 1 re-uses the expired nonce 5 (session: pruned -> applied) and the live nonce 6 (duplicate)
        let seg = seg_words(&[1, 2], &[wd(0, 2 * u, 5), wd(0, 2 * u, 6)]);
        let mut pre_ref = s.clone();
        pre_ref.withdrawals.remove(&(id(1), 5));
        let (post, ev_ref) = direct(&pre_ref, &seg);
        let b = WitBuilder::new(&s);
        let line = match operate(&b, &seg) {
            Ok((needs, _, o, ev, _)) => {
                let ok1 = o.status == 0 && o.end_root == sl::s_root(&post) && ev == ev_ref && ev.first() == Some(&EV_APPLIED);
                // account 2's set (with its expired record) loaded as an extra record and untouched: no rewrite
                let mut n2 = needs.clone();
                n2.insert(Need::Wdl(id(2)));
                let (o2, ev2) = run_sl(&seg, &b.build(&n2));
                let ok2 = o2.status == 0 && o2.end_root == o.end_root && ev2 == ev;
                all_ok &= ok1 && ok2;
                format!("{{\"case\":\"P4 lazy expiry: expired nonce re-used, live nonce duplicate, untouched extra set unchanged\",\"ok\":{},\"touched_ok\":{},\"extra_untouched_ok\":{},\"status\":{},\"ev\":{:?}}}", ok1 && ok2, ok1, ok2, o.status, ev)
            }
            Err(e) => {
                all_ok = false;
                format!("{{\"case\":\"P4\",\"ok\":false,\"why\":\"{}\"}}", e)
            }
        };
        res.push(line);
    }
    // ---- P5 R15-M1: migration of a session state whose price level exceeds SL_MAX_LEVEL_ORDERS (reachable in the
    // session: 256 accounts x 64 live orders at one price) -> refused (ST_SL_MIG_BOUNDS); at the bound -> accepted ----
    {
        let mk = |n: usize| {
            let mut s = mnpilot::state::ChainState::genesis();
            let px = MID + 5 * DOLLAR;
            let mut k = 0usize;
            'o: for a in 10..80u32 {
                let mut acc = mnpilot::account::Account::new(id(a));
                acc.collateral = 1_000_000_000 * USD_SCALE as i128;
                s.put_account(id(a), acc);
                for c in 1..=64u64 {
                    if k >= n {
                        break 'o;
                    }
                    s.book_mut(M(1)).sl_restore(mnpilot::Order {
                        id: mnpilot::types::order_id(id(a), M(1), c), account: id(a), market: M(1), side: mnpilot::types::Side::Ask,
                        typ: mnpilot::types::OrderType::Limit, tif: mnpilot::types::TimeInForce::Gtc, price: px, qty: QTY_SCALE / 100,
                        remaining: QTY_SCALE / 100, seq: k as u64, isolated: false, margin_left: 0,
                    });
                    s.seen_client_seq.insert(id(a), c);
                    k += 1;
                }
            }
            let _ = s.take_dirty();
            let mut sess = mnpilot::Session::genesis_with(0, mnpilot::WitMode::Off, &[]);
            sess.eng.state = s;
            let (dg, nw, words) = mnpilot::snapshot::export(&sess, true);
            let mut inp = vec![sl::SL_MIG_MAGIC];
            inp.extend_from_slice(&words.unwrap());
            let mo = sl::migrate(&mut |j| inp.get(j as usize).copied().unwrap_or(0), Some(&(dg, nw)), true);
            (mo.status, mo.root == sl::s_root(&sess.eng.state))
        };
        let (st_over, _) = mk(sl::SL_MAX_LEVEL_ORDERS + 1);
        let (st_at, root_at) = mk(sl::SL_MAX_LEVEL_ORDERS);
        // round 16: linked-FIFO levels lift the bound -- both migrate
        let ok = st_over == 0 && st_at == 0 && root_at;
        all_ok &= ok;
        res.push(format!("{{\"case\":\"P5 R15-M1 lifted (round 16): levels of 4097 and 4096 orders both migrate\",\"ok\":{},\"status_over\":{},\"status_at\":{},\"root_at_ok\":{}}}", ok, st_over, st_at, root_at));
    }
    format!("{{\"ok\":{},\"cases\":[{}]}}", all_ok, res.join(",\n"))
}


// ------------------------------------------------------------------------------------------------
// round 15: MNWIT-S genesis by migration + the height hook (lazy withdrawal expiry)
// ------------------------------------------------------------------------------------------------
type WdlSets = std::collections::BTreeMap<mnpilot::types::AccountId, Vec<(u64, i128, bool, u64)>>;
fn wdl_sets(s: &mnpilot::state::ChainState) -> WdlSets {
    let mut m: WdlSets = Default::default();
    for ((a, n), w) in &s.withdrawals {
        m.entry(*a).or_default().push((*n, w.amount, w.pending, w.height));
    }
    m
}
/// the stateless chain's full state: the session state with the COMMITTED withdrawal records (lazy expiry)
fn lazy_state(s: &mnpilot::state::ChainState, committed: &WdlSets) -> mnpilot::state::ChainState {
    let mut st = s.clone();
    st.withdrawals.clear();
    for (a, es) in committed {
        for (n, amt, p, h) in es {
            st.withdrawals.insert((*a, *n), mnpilot::types::Withdrawal { amount: *amt, pending: *p, height: *h });
        }
    }
    st
}

/// slmig <n> <orders> <hstep>: per seed, a `wd` batch cut into segments. The session image (bind_height, run number =
/// height, heights advancing by 1 + rand(hstep)) runs the first half; then an EXPORT snapshot of the session is
/// MIGRATED (stateless::migrate: digest binding, MNWIT-S root over the decoded state) and the stateless image runs
/// the second half with the height hook, chained on the migration root (expect = last end root). Reference per
/// segment: the session at the same run number; the reference root = MNWIT-S root of the session post-state with
/// the lazily committed withdrawal records (a set is rewritten only when its live set changed). Negative checks:
/// migration with a wrong digest / a tampered word / a non-fresh lineage / no compiled digest is refused.
pub fn slmig(n: u64, ord: u32, hstep: u64) -> String {
    let (mut ok, mut segs_run, mut units, mut migs, mut neg_ok, mut expired_seen) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut first_bad = String::new();
    for seed in 1..=n {
        let w = wd_batch(seed, ord);
        let n_acc = w[1];
        let accts: Vec<mnpilot::types::AccountId> = (0..n_acc)
            .map(|a| {
                let mut id = [0u8; 32];
                for k in 0..8 {
                    id[k * 4..k * 4 + 4].copy_from_slice(&w[4 + (a * 8) as usize + k].to_le_bytes());
                }
                mnpilot::types::AccountId(id)
            })
            .collect();
        let mut sess = Some(mnpilot::Session::genesis_with(w[3], mnpilot::WitMode::Incremental, &accts));
        sess.as_mut().unwrap().bind_height = true;
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x5151);
        let size = 20 + rng.below(80) as u32;
        let parts = seg::split(&w, size);
        let cut = (parts.len() / 2).max(1).min(parts.len().saturating_sub(1));
        let mut h: u64 = 0;
        let mut root = [0u8; 32];
        let mut committed: WdlSets = Default::default();
        let mut bad: Option<String> = None;
        for (i, mut sw) in parts.into_iter().enumerate() {
            sw[3] = 0;
            h += 1 + if hstep > 0 { rng.below(hstep) } else { 0 };
            if i == cut {
                // EXPORT (session image) -> MIGRATE (stateless image)
                let (dg, nw, words) = mnpilot::snapshot::export(sess.as_ref().unwrap(), true);
                let words = words.unwrap();
                let mut inp = vec![sl::SL_MIG_MAGIC];
                inp.extend_from_slice(&words);
                let mo = sl::migrate(&mut |j| inp.get(j as usize).copied().unwrap_or(0), Some(&(dg, nw)), true);
                let st = &sess.as_ref().unwrap().eng.state;
                if mo.status != 0 || mo.root != sl::s_root(st) || mo.segs != sess.as_ref().unwrap().segs + 1 {
                    bad = Some(format!("migrate status {} root_ok {}", mo.status, mo.root == sl::s_root(st)));
                    break;
                }
                migs += 1;
                // negatives
                let mut t = inp.clone();
                let k = 1 + rng.below(nw as u64) as usize;
                t[k] ^= 1;
                let m1 = sl::migrate(&mut |j| t.get(j as usize).copied().unwrap_or(0), Some(&(dg, nw)), true);
                let mut dg2 = dg;
                dg2[0] ^= 1;
                let m2 = sl::migrate(&mut |j| inp.get(j as usize).copied().unwrap_or(0), Some(&(dg2, nw)), true);
                let m3 = sl::migrate(&mut |j| inp.get(j as usize).copied().unwrap_or(0), Some(&(dg, nw)), false);
                let m4 = sl::migrate(&mut |j| inp.get(j as usize).copied().unwrap_or(0), None, true);
                if m1.status == mnpilot::ST_BAD_SNAP && m2.status == mnpilot::ST_BAD_SNAP && m3.status == mnpilot::ST_SESSION_LIVE && m4.status == mnpilot::ST_IMPORT_LOCKED {
                    neg_ok += 1;
                } else {
                    bad = Some(format!("migrate negatives {} {} {} {}", m1.status, m2.status, m3.status, m4.status));
                    break;
                }
                root = mo.root;
                committed = wdl_sets(st);
                // the migration run is a rollup height of its own
                h = mo.segs as u64 + if hstep > 0 { rng.below(hstep) } else { 0 };
                h += 1;
            }
            let pre = sess.as_ref().unwrap().eng.state.clone();
            let mut ev = Vec::new();
            let (_, st, _) = mnpilot::run_segment_n(
                &mut |j| sw.get(j as usize).copied().unwrap_or(0),
                &mut |x| ev.push(x),
                &mut |_, _, _| {},
                mnpilot::WitMode::Incremental,
                &mut sess,
                mnpilot::SegOpt { run_no: Some(h as u32), bind: true },
            );
            if st.status != 0 {
                bad = Some(format!("session status {} at seg {}", st.status, i));
                break;
            }
            if i < cut {
                continue;
            }
            segs_run += 1;
            units += sw[2] as u64;
            let post = &sess.as_ref().unwrap().eng.state;
            let full = lazy_state(&pre, &committed);
            let b = WitBuilder::new(&full);
            if b.root != root {
                bad = Some(format!("operator state root != chain root at seg {}", i));
                break;
            }
            let res = operate_h(&b, &sw, Some(h));
            // lazy commitment update: a set is rewritten iff its live set (at the new height) changed
            let live_at = |es: &Vec<(u64, i128, bool, u64)>| -> Vec<(u64, i128, bool, u64)> { es.iter().copied().filter(|e| e.3.saturating_add(mnpilot::types::REPLAY_WINDOW) > h.max(pre.height)).collect() };
            let post_sets = wdl_sets(post);
            let mut keys: BTreeSet<mnpilot::types::AccountId> = committed.keys().copied().collect();
            keys.extend(post_sets.keys().copied());
            for a in keys {
                let c = committed.get(&a).cloned().unwrap_or_default();
                let lv = live_at(&c);
                if lv.len() != c.len() {
                    expired_seen += 1;
                }
                let p = post_sets.get(&a).cloned().unwrap_or_default();
                if p != lv {
                    if p.is_empty() {
                        committed.remove(&a);
                    } else {
                        committed.insert(a, p);
                    }
                }
            }
            let want = sl::s_root(&lazy_state(post, &committed));
            match res {
                Err(e) => {
                    bad = Some(format!("operator: {} at seg {}", e, i));
                    break;
                }
                Ok((_, _, o, evs, _)) => {
                    if o.status != 0 || o.end_root != want || evs != ev {
                        bad = Some(format!("seg {} h {}: status {} {:?} root_ok {} ev_ok {}", i, h, o.status, o.need, o.end_root == want, evs == ev));
                        break;
                    }
                    root = o.end_root;
                }
            }
        }
        match bad {
            None => ok += 1,
            Some(b) => {
                if first_bad.is_empty() {
                    first_bad = format!("seed {}: {}", seed, b);
                }
            }
        }
    }
    format!(
        "{{\"batches\":{},\"ok\":{},\"migrations\":{},\"migration_negatives_ok\":{},\"stateless_segments\":{},\"units\":{},\"sets_with_expired_records_seen\":{},\"first_bad\":\"{}\"}}",
        n, ok, migs, neg_ok, segs_run, units, expired_seen, first_bad
    )
}

/// slmigdump <seed> <orders> <S> <dir>: guest-level migration + height-hook fixture for js/slmig.js. A `wd` batch
/// cut into segments of S units: the session (bind_height) runs the first half; mig.bin = [SL_MIG_MAGIC, export
/// snapshot words], digest.txt = "<export digest hex>:<words>" (the stateless image is built with
/// MNPILOT_IMPORT_DIGEST = that); then sl%03d.bin for the second half at heights segs + 1, segs + 2, ... (what a prod
/// stateless image's SL_RUNS gives after the migration run) with the session reference at the same run numbers.
pub fn slmigdump(seed: u64, ord: u32, size: u32, dir: &str) -> String {
    fs::create_dir_all(dir).unwrap();
    let w = wd_batch(seed, ord);
    let n_acc = w[1];
    let accts: Vec<mnpilot::types::AccountId> = (0..n_acc)
        .map(|a| {
            let mut id = [0u8; 32];
            for k in 0..8 {
                id[k * 4..k * 4 + 4].copy_from_slice(&w[4 + (a * 8) as usize + k].to_le_bytes());
            }
            mnpilot::types::AccountId(id)
        })
        .collect();
    let mut sess = Some(mnpilot::Session::genesis_with(w[3], mnpilot::WitMode::Incremental, &accts));
    sess.as_mut().unwrap().bind_height = true;
    let parts = seg::split(&w, size);
    let cut = (parts.len() / 2).max(1).min(parts.len().saturating_sub(1));
    let mut man = Vec::new();
    let mut root = [0u8; 32];
    let mut committed: WdlSets = Default::default();
    let mut h: u64 = 0;
    let mut mig = String::new();
    for (i, mut sw) in parts.into_iter().enumerate() {
        sw[3] = 0;
        h += 1;
        if i == cut {
            let (dg, nw, words) = mnpilot::snapshot::export(sess.as_ref().unwrap(), true);
            let mut inp = vec![sl::SL_MIG_MAGIC];
            inp.extend_from_slice(&words.unwrap());
            let mo = sl::migrate(&mut |j| inp.get(j as usize).copied().unwrap_or(0), Some(&(dg, nw)), true);
            assert_eq!(mo.status, 0);
            write_words(&format!("{}/mig.bin", dir), &inp);
            fs::write(format!("{}/digest.txt", dir), format!("{}:{}", hx(&dg), nw)).unwrap();
            root = mo.root;
            committed = wdl_sets(&sess.as_ref().unwrap().eng.state);
            h = mo.segs as u64 + 1;
            mig = format!("{{\"mig\":\"mig.bin\",\"words\":{},\"root\":\"{}\",\"segs\":{}}}", nw, hx(&mo.root), mo.segs);
        }
        let pre = sess.as_ref().unwrap().eng.state.clone();
        let mut ev = Vec::new();
        let (_, st, _) = mnpilot::run_segment_n(&mut |j| sw.get(j as usize).copied().unwrap_or(0), &mut |x| ev.push(x), &mut |_, _, _| {}, mnpilot::WitMode::Incremental, &mut sess, mnpilot::SegOpt { run_no: Some(h as u32), bind: true });
        assert_eq!(st.status, 0);
        if i < cut {
            continue;
        }
        let post = &sess.as_ref().unwrap().eng.state;
        let full = lazy_state(&pre, &committed);
        let b = WitBuilder::new(&full);
        assert_eq!(b.root, root);
        let (_, wit, o, evs, _) = operate_h(&b, &sw, Some(h)).expect("operator");
        let post_sets = wdl_sets(post);
        let mut keys: BTreeSet<mnpilot::types::AccountId> = committed.keys().copied().collect();
        keys.extend(post_sets.keys().copied());
        for a in keys {
            let c = committed.get(&a).cloned().unwrap_or_default();
            let lv: Vec<_> = c.iter().copied().filter(|e| e.3.saturating_add(mnpilot::types::REPLAY_WINDOW) > h.max(pre.height)).collect();
            let p = post_sets.get(&a).cloned().unwrap_or_default();
            if p != lv {
                if p.is_empty() {
                    committed.remove(&a);
                } else {
                    committed.insert(a, p);
                }
            }
        }
        let want = sl::s_root(&lazy_state(post, &committed));
        assert!(o.status == 0 && o.end_root == want && evs == ev, "segment {} differs", i);
        let mut x = vec![sl::SL_MAGIC, sw.len() as u32, wit.len() as u32];
        x.extend_from_slice(&sw);
        for c in wit.chunks(4) {
            let mut q = [0u8; 4];
            q[..c.len()].copy_from_slice(c);
            x.push(u32::from_le_bytes(q));
        }
        write_words(&format!("{}/sl{:03}.bin", dir, i), &x);
        man.push(format!(
            "{{\"sl\":\"sl{:03}.bin\",\"height\":{},\"units\":{},\"s_start\":\"{}\",\"s_end\":\"{}\",\"witness_bytes\":{},\"ev\":[{}]}}",
            i, h, sw[2], hx(&root), hx(&want), wit.len(), ev.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")
        ));
        root = want;
    }
    fs::write(format!("{}/manifest.json", dir), format!("{{\"migration\":{},\"segments\":[{}]}}", mig, man.join(",\n"))).unwrap();
    format!("{{\"segments\":{},\"dir\":\"{}\",\"migration\":{}}}", man.len(), dir, mig)
}

/// loop round 16 (step 4): a FULL-SIZE session migration measured natively. `slmigcap n m r orders wd dir`: the
/// `mktcap` whole-state session (n accounts each with a position in every one of m markets, r bonded oracles with
/// 8-deep report rings, `orders` resting bids and `wd` pending withdrawals per account; real engine entry points
/// only) -> export -> host `migrate` (wall time, heapsim peak live bytes during the migration, MNWIT-S leaf count)
/// -> `<dir>/mig.bin` ([SL_MIG_MAGIC, words]) + `<dir>/digest.txt` for the guest-level run (xval/migsail.js on an
/// `embed,prod,stateless` image built with MNPILOT_IMPORT_DIGEST = digest.txt).
pub fn slmigcap(n: u32, m: u32, r: u32, orders: u32, wd: u32, dir: &str) -> String {
    fs::create_dir_all(dir).unwrap();
    let (sess, fails, _why) = crate::snap::mktcap_sess(n, m, r, orders, wd);
    let st = &sess.eng.state;
    let live: usize = st.books.values().map(|b| b.live_orders().count()).sum();
    let pos: usize = st.accounts.values().map(|a| a.positions.len()).sum();
    let maxlvl = st.books.values().flat_map(|b| b.sl_levels().into_iter().map(|(_, _, ids)| ids.len())).max().unwrap_or(0);
    let t0 = std::time::Instant::now();
    let (dg, nw, words) = mnpilot::snapshot::export(&sess, true);
    let t_exp = t0.elapsed().as_secs_f64();
    let mut inp = vec![sl::SL_MIG_MAGIC];
    inp.extend_from_slice(&words.unwrap());
    let leaves = sl::s_leaves(st).len();
    let host_root = sl::s_root(st);
    drop(sess);
    heapsim::reset();
    heapsim::ON.store(true, std::sync::atomic::Ordering::Relaxed);
    let t1 = std::time::Instant::now();
    let mo = sl::migrate(&mut |j| inp.get(j as usize).copied().unwrap_or(0), Some(&(dg, nw)), true);
    let t_mig = t1.elapsed().as_secs_f64();
    heapsim::ON.store(false, std::sync::atomic::Ordering::Relaxed);
    let (top, peak, _) = heapsim::read();
    write_words(&format!("{}/mig.bin", dir), &inp);
    fs::write(format!("{}/digest.txt", dir), format!("{}:{}", hx(&dg), nw)).unwrap();
    fs::write(format!("{}/root.txt", dir), hx(&mo.root)).unwrap();
    format!(
        "{{\"ok\":{},\"status\":{},\"accounts\":{},\"markets\":{},\"oracles\":{},\"live_orders\":{},\"positions\":{},\"max_level_orders\":{},\"rejected_setup_ops\":{},\"snapshot_words\":{},\"mnwits_leaves\":{},\"root\":\"{}\",\"root_eq_host\":{},\"export_s\":{:.3},\"migrate_host_s\":{:.3},\"migrate_heap_peak_live\":{},\"migrate_heap_top\":{}}}",
        mo.status == 0 && mo.root == host_root, mo.status, n, m, r, live, pos, maxlvl, fails, nw, leaves, hx(&mo.root), mo.root == host_root, t_exp, t_mig, peak, top
    )
}

/// round 16: workload coverage of `perp` batches -- per op kind: applied / rejected codes (session reference)
pub fn slperpstat(n: u64, ord: u32) -> String {
    use std::collections::BTreeMap;
    let mut t: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    for s in 1..=n {
        let w = perp_batch(s, ord);
        let refs = session_refs_v2(&w, 1_000_000);
        let ev = &refs[0].ev;
        let base = 4 + 8 * w[1] as usize;
        let mut k = 0usize;
        for i in 0..w[2] as usize {
            let kind = w[base + 8 * i] & 0xff;
            let e = ev[k];
            let tag = if e & mnpilot::EV_APPLIED != 0 { k += 1 + 6 * (e & 0xffff) as usize; "ok".to_string() } else { k += 1; format!("r{}", e) };
            *t.entry(format!("k{}", kind)).or_default().entry(tag).or_default() += 1;
        }
    }
    format!("{:?}", t)
}

/// round 16 debug: for the perp workload, locate the first unit of every segment that is UNSUPPORTED or whose
/// operator does not converge (prefix bisection from the same pre-state); prints the op words and the last need
pub fn sldbg(n: u64, ord: u32, mode: &str) -> String {
    let mut out = Vec::new();
    let cutp = |seg: &[u32], k: usize| -> Vec<u32> {
        if seg[0] == mnpilot::MAGIC2 {
            crate::gov::cut_v2(seg, 0, k)
        } else {
            let base = 4 + 8 * seg[1] as usize;
            let mut v = seg[..base + 8 * k].to_vec();
            v[2] = k as u32;
            v
        }
    };
    for s in 1..=n {
        let w = match mode {
            "perp" => perp_batch(s, ord),
            "wd" => wd_batch(s, ord),
            _ => gen(s, 4 + (s % 9) as u32, 1 + (s % 25) as u32, 1 + (s % 3) as u32, ord, s % 2 == 0).0,
        };
        let mut rng = Rng(s.wrapping_mul(0x51_7CC1_B727_220A) | 1);
        let size = 1 + rng.below(200) as u32;
        let refs = if mode == "perp" { session_refs_v2(&w, size) } else { session_refs(&w, size) };
        for (k, r) in refs.iter().enumerate() {
            let b = WitBuilder::new(&r.pre);
            let res = operate(&b, &r.seg);
            let bad = match &res {
                Err(e) => Some(e.clone()),
                Ok((_, _, o, _, _)) if o.status != 0 => Some(format!("status {}", o.status)),
                _ => None,
            };
            let Some(why) = bad else { continue };
            // bisect the prefix length
            let units = r.seg[2] as usize;
            let mut lo = 0usize;
            let mut hi = units;
            while hi - lo > 1 {
                let mid = (lo + hi) / 2;
                let sw = cutp(&r.seg, mid);
                let ok = matches!(operate(&b, &sw), Ok((_, _, ref o, _, _)) if o.status == 0);
                if ok { lo = mid } else { hi = mid }
            }
            let base = 4 + 8 * r.seg[1] as usize;
            let op: Vec<u32> = r.seg[base + 8 * lo..base + 8 * lo + 8].to_vec();
            let dec = mnpilot::decode_op(&op.clone().try_into().unwrap());
            let sw = cutp(&r.seg, lo + 1);
            let mut last = match operate(&b, &sw) { Ok((nd, _, o, _, _)) => format!("status {} need {:?} needs {}", o.status, o.need, nd.len()), Err(e) => e };
            // round 16: where is the order of an Order need loop in the pre-state
            if let Some(i) = last.find("Order(OrderId([") {
                let t = &last[i + 15..];
                let bytes: Vec<u8> = t[..t.find(']').unwrap_or(0)].split(", ").filter_map(|x| x.trim().parse().ok()).collect();
                if bytes.len() == 32 {
                    let oid = mnpilot::types::OrderId(bytes.try_into().unwrap());
                    let mut whr = String::from("not in pre-state");
                    for (m, bk) in &r.pre.books {
                        for (sd, p, ids) in bk.sl_levels() {
                            if let Some(k) = ids.iter().position(|x| *x == oid) {
                                let o = bk.get(oid).unwrap();
                                whr = format!("m {} side {:?} price {} index {}/{} seq {} acct {:02x}{:02x} prev-seq {:?}", m.0, sd, p, k, ids.len(), o.seq, o.account.0[0], o.account.0[1], if k > 0 { bk.get(ids[k - 1]).map(|x| x.seq) } else { None });
                            }
                        }
                    }
                    last.push_str(&format!(" | order: {}", whr));
                }
            }
            out.push(format!("seed {} seg {} unit {}: {} | op {:?} | {}", s, k, lo, why, dec, last));
            if out.len() >= 20 { return out.join("\n"); }
        }
    }
    out.join("\n")
}
