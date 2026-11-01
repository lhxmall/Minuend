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

/// round 18: the 'gov' workload (MNP2 on the REAL engine, gov::GB): PERP gov deposits / withdrawals by the fixture
/// holders (accounts 4..=9: 100 000 PERP) and others, proposals (valid / risky params, unknown market, delist, by
/// holders and by ids below PROPOSAL_MIN_STAKE), votes (holders, zero-weight ids, repeats, unknown ids, after a balance
/// change: the snapshot weight differs from the balance), SetSeq jumps past the 20 000-seq deadline (and a refused
/// backwards one), finalize (early, late, unknown / finalized id), some trading and deposits.
pub fn gov_batch(seed: u64, n_ops: u32) -> Vec<u32> {
    use crate::gov::GB;
    let mut rng = Rng(seed.wrapping_mul(0xD1B5_4A32_D192_ED03) | 1);
    let n_acc = 10 + rng.below(6) as u32;
    let mut g = GB::new(n_acc, mnpilot::ORACLES_FLAG | mnpilot::PERP_FLAG);
    let mid = 100_000 * PRICE_SCALE as i64;
    let dollar = PRICE_SCALE as i64;
    for a in 1..n_acc {
        g.op(GB::w_dep(a, 20_000 * USD_SCALE as i64));
    }
    let mut nonce: Vec<u64> = vec![0; n_acc as usize];
    let mut n_done = 0u32;
    while n_done < n_ops {
        n_done += 1;
        let a = 1 + rng.below((n_acc - 1) as u64) as u32;
        let holder = 4 + rng.below(6) as u32;
        let next = g.eng.state.next_proposal_id;
        let pid = if next > 1 && rng.below(8) != 0 { 1 + rng.below(next - 1) } else { next + rng.below(2) };
        match rng.below(100) {
            0..=11 => {
                let amt = match rng.below(4) {
                    0 => 1_000 + rng.below(1_000),
                    1 => 0,
                    _ => rng.below(5_000),
                };
                g.op(GB::w_gdep(if rng.below(3) == 0 { holder } else { a }, amt));
            }
            12..=21 => {
                let who = if rng.below(2) == 0 { holder } else { a };
                let bal = g.eng.state.perp_balances.get(&g.ids[who as usize]).copied().unwrap_or(0) as u64;
                let n = nonce[who as usize];
                let nn = if rng.below(8) == 0 { n } else { n + 1 };
                let amt = match rng.below(5) {
                    0 => bal,
                    1 => bal / 2,
                    2 => 0,
                    _ => rng.below(3_000),
                };
                if g.applied(GB::w_gwd(who, amt, nn)) {
                    nonce[who as usize] = nn;
                }
            }
            22..=31 => {
                let who = if rng.below(4) == 0 { a } else { holder };
                let m = match rng.below(8) {
                    0 => 99,
                    1 => 2,
                    _ => 1,
                };
                let (key, value) = match rng.below(6) {
                    0 => (0u8, 500 + rng.below(2_000)),
                    1 => (1u8, 100 + rng.below(800)),
                    2 => (2u8, rng.below(40)),
                    3 => (3u8, rng.below(60)),
                    4 => (4u8, rng.below(2)),
                    _ => (2u8, 100_000),
                };
                g.op(GB::w_prop(who, m, key, value));
            }
            32..=61 => {
                let voter = match rng.below(5) {
                    0 => rng.below(n_acc as u64) as u32,
                    1 => a,
                    _ => holder,
                };
                g.op(GB::w_vote(voter, pid, rng.below(3) != 0));
            }
            62..=66 => {
                let sq = g.eng.state.seq;
                let to = if rng.below(10) == 0 { sq.saturating_sub(1) } else { sq + minuend_types::PROPOSAL_DURATION_SEQS / 2 + rng.below(minuend_types::PROPOSAL_DURATION_SEQS) };
                g.op(GB::w_seq(to));
            }
            67..=77 => {
                g.op(GB::w_fin(a, pid));
            }
            78..=89 => {
                let px = mid + (rng.below(11) as i64 - 5) * dollar * 100;
                let mk = 1 + rng.below((n_acc - 1) as u64) as u32;
                let w1 = g.w_place(mk, rng.below(2) == 0, false, px, QTY_SCALE / 1000, 1);
                g.op(w1);
                if rng.below(2) == 0 {
                    let w2 = g.w_place(a, rng.below(2) == 0, rng.below(2) == 0, px, QTY_SCALE / 1000, 1);
                    g.op(w2);
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
                // round 18
                mnpilot::BatchOp::CreateProposal { market, .. } => {
                    n.insert(Need::Pglob);
                    n.insert(Need::Perp);
                    n.insert(Need::Market(market));
                }
                mnpilot::BatchOp::Vote { .. } => {
                    n.insert(Need::Pexc(a));
                }
                // round 19 (R18-M1 fix): a Finalize reads no exception holder
                mnpilot::BatchOp::Finalize { .. } => {
                    n.insert(Need::Pglob);
                }
                // round 20: oracle
                mnpilot::BatchOp::Stake { .. } | mnpilot::BatchOp::Unstake { .. } => {
                    n.insert(Need::Ostk(a));
                }
                mnpilot::BatchOp::Slash { target, market, .. } => {
                    n.insert(Need::Perp);
                    n.insert(Need::Oglob);
                    n.insert(Need::Market(market));
                    if let Some(t) = id(target) {
                        n.insert(Need::Ostk(t));
                        n.insert(Need::Ohist(market, t));
                        n.insert(Need::Omk(market));
                    }
                }
                mnpilot::BatchOp::Report { market, .. } => {
                    n.insert(Need::Ostk(a));
                    n.insert(Need::Market(market));
                    n.insert(Need::Oglob);
                    n.insert(Need::Orep(market));
                    n.insert(Need::Ohist(market, a));
                    n.insert(Need::Orm(a));
                    n.insert(Need::Omk(market));
                }
                _ => {}
            }
        }
    }
    n
}

/// round 21: an ADVERSARIAL operator fixpoint -- the builder's forge flags as set by the caller, and the needs `deny`
/// rejects are never supplied (the run is then reported as it stands: a refusal)
pub fn operate_deny(b: &WitBuilder, seg: &[u32], deny: &dyn Fn(&Need) -> bool) -> (sl::SlOut, Vec<u32>) {
    operate_deny_h(b, seg, deny, None)
}
/// round 23: with the height hook
pub fn operate_deny_h(b: &WitBuilder, seg: &[u32], deny: &dyn Fn(&Need) -> bool, height: Option<u64>) -> (sl::SlOut, Vec<u32>) {
    let mut needs: BTreeSet<Need> = guess(seg).into_iter().filter(|n| !deny(n)).collect();
    b.live_h.set(height.unwrap_or(0).max(b.s.height));
    let mut last = run_sl_xh(seg, &b.build(&needs), Some(&b.root), height);
    for _ in 0..20_000u32 {
        if last.0.status != sl::ST_SL_MISSING {
            break;
        }
        let n = last.0.need.unwrap();
        if deny(&n) || !needs.insert(n) {
            break;
        }
        last = run_sl_xh(seg, &b.build(&needs), Some(&b.root), height);
    }
    last
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
            // round 23 (operator shortcut, not a guest rule): an expiry group the hook drops brings its records and
            // their owners' indexes at once (the guest would ask for them one by one)
            if let Need::Cexp(u) = n {
                if u < height.unwrap_or(0) {
                    for (h, e) in b.s.commits.iter().filter(|(_, e)| e.ttl_height == u) {
                        needs.insert(Need::Cmt(*h));
                        needs.insert(Need::Acmt(e.account));
                    }
                }
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

/// "liq" workload (round 17): book-path liquidations without the funding-rate market (unsupported in the stateless
/// image). The mark moves by joint oracle reports (segments holding one are unsupported and skipped); thin
/// traders run 5-9x; keepers liquidate holders (the one closest to maintenance half of the time, anyone sometimes,
/// the insurance account / self now and then); dust at the top of the book (R7-H1 skip -> ADL -> unsupported) and
/// deep makers (book fills -> supported). Liquidations whose book IOC fills nothing reach the ADL remainder:
/// the stateless image must report UNSUPPORTED for them, never a status-0 result.
pub fn liq_sl_batch(seed: u64, n_ops: u32) -> Vec<u32> {
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let traders = 6 + rng.below(10) as u32;
    let n_acc = 8 + traders; // 0..=1 keepers, 2..=7 makers, 8.. traders
    let m2 = seed % 3 == 0;
    // bonded oracles 1..=3 (fixture): the unoracled mark freezes after the first fill (state.rs), so the mark moves by
    // oracle reports -- in bursts (3 reports back to back, ~4 % of ops) so that most segments hold none (a segment
    // with a report is unsupported and skipped; the next one starts from the session's post-report state)
    let flags = mnpilot::ORACLES_FLAG | if m2 { mnpilot::MARKET2_FLAG } else { 0 };
    let (ids_real, mut g) = adv::new_gen(n_acc, flags);
    let report = |g: &mut Gen, m: u32, px: i64| {
        for o in 1..=3u32 {
            g.apply([8 | (o << 8), 0, px as u32, (px >> 32) as u32, 0, 0, 0, m]);
        }
    };
    let qs = QTY_SCALE;
    for a in 0..n_acc {
        let usd: i64 = if a >= 8 && (a % 3 == 1) { 1_500 + rng.below(8_000) as i64 } else if a >= 8 { 20_000 + rng.below(200_000) as i64 } else { 5_000_000 };
        let amt = usd * USD_SCALE as i64;
        g.apply([1 | (a << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, 0, 0]);
    }
    let place = |g: &mut Gen, a: u32, bid: bool, mkt: bool, ioc: bool, price: i64, qty: u64, market: u32| {
        let c = g.next_cseq(a);
        let fl = (!bid as u32) | ((mkt as u32) << 1) | ((ioc as u32) << 2);
        g.apply([2 | (a << 8), fl, price as u32, (price >> 32) as u32, qty as u32, (qty >> 32) as u32, c as u32, market]);
    };
    let mark_of = |g: &Gen, m: u32| g.eng.state.marks.get(&mnpilot::types::MarketId(m)).copied().filter(|x| *x > 0).unwrap_or(MID);
    let depth = |g: &mut Gen, rng: &mut Rng, m: u32| {
        let mark = mark_of(g, m);
        for mk in 2..8u32 {
            for l in 1..=3i64 {
                let off = l * mark / 400;
                place(g, mk, true, false, false, mark - off, (1 + rng.below(30)) * qs / 10, m);
                place(g, mk, false, false, false, mark + off, (1 + rng.below(30)) * qs / 10, m);
            }
        }
    };
    report(&mut g, 1, MID);
    if m2 {
        report(&mut g, 2, MID);
    }
    depth(&mut g, &mut rng, 1);
    if m2 {
        depth(&mut g, &mut rng, 2);
    }
    let trend_up = rng.below(2) == 0;
    for _ in 0..n_ops {
        let r = rng.below(100);
        let t = 8 + rng.below(traders as u64) as u32;
        let bid = rng.below(2) == 0;
        let mkt = if m2 && rng.below(4) == 0 { 2 } else { 1 };
        let mark = mark_of(&g, mkt);
        match r {
            0..=24 => {
                let col = g.eng.state.accounts.get(&g.ids[t as usize]).map(|x| x.collateral).unwrap_or(0).max(0) as u128;
                let lev = 5 + rng.below(5) as u128;
                let q_lev = (col * lev * QTY_SCALE as u128 * DOLLAR as u128 / (USD_SCALE as u128 * mark.max(1) as u128)) as u64;
                let q = if t % 3 == 1 && rng.below(3) != 0 { q_lev.max(qs / 1000) } else { (1 + rng.below(60)) * qs / 100 };
                place(&mut g, t, bid, true, true, 0, q, mkt);
            }
            // mark move: a joint oracle report 4..9 % away (mostly with the trend; reports are capped at 10 %)
            25..=28 => {
                let up = if rng.below(10) < 7 { trend_up } else { !trend_up };
                let step = mark * (4 + rng.below(6) as i64) / 100;
                report(&mut g, mkt, if up { mark + step } else { (mark - step).max(10_000 * DOLLAR) });
            }
            // a trade 2..9 % away (a mover rests, a trader crosses it)
            29..=39 => {
                let up = if rng.below(10) < 7 { trend_up } else { !trend_up };
                let step = mark * (2 + rng.below(8) as i64) / 100;
                let px = if up { mark + step } else { (mark - step).max(10_000 * DOLLAR) };
                let mk = 2 + rng.below(6) as u32;
                let q = (1 + rng.below(5)) * qs / 100;
                place(&mut g, mk, !up, false, false, px, q, mkt);
                place(&mut g, t, up, false, true, px, q, mkt);
            }
            40..=62 => {
                let holders: Vec<u32> = (0..n_acc).filter(|&a| g.eng.state.accounts.get(&g.ids[a as usize]).is_some_and(|x| x.positions.contains_key(&mnpilot::types::MarketId(mkt)))).collect();
                let st = &g.eng.state;
                let worst = holders.iter().copied().max_by_key(|&h| {
                    let a = &st.accounts[&g.ids[h as usize]];
                    let sn = a.snapshot(&st.marks, &st.markets);
                    (sn.mm.max(0) * 1_000_000 / sn.equity.max(1), h)
                });
                let target = if let (Some(wt), true) = (worst, rng.below(2) == 0) { wt } else if !holders.is_empty() && rng.below(5) != 0 { holders[rng.below(holders.len() as u64) as usize] } else if rng.below(20) == 0 { mnpilot::LIQ_TARGET_INSURANCE } else { rng.below(n_acc as u64) as u32 };
                let k = if rng.below(10) == 0 && target < n_acc { target } else { rng.below(2) as u32 };
                if rng.below(4) == 0 {
                    let mk = 2 + rng.below(6) as u32;
                    place(&mut g, mk, true, false, false, mark - mark / 1000, qs / 10_000, mkt);
                    place(&mut g, mk, false, false, false, mark + mark / 1000, qs / 10_000, mkt);
                }
                g.apply([7 | (k << 8), target, 0, 0, 0, 0, 0, mkt]);
            }
            63..=77 => depth(&mut g, &mut rng, mkt),
            78..=84 => {
                let amt = (500 + rng.below(20_000) as i64) * USD_SCALE as i64;
                g.apply([1 | (t << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, 0, 0]);
            }
            _ => {
                if let Some(i) = (!g.live.is_empty()).then(|| rng.below(g.live.len() as u64) as usize) {
                    let (ca, cs) = g.live.swap_remove(i);
                    g.apply([3 | (ca << 8), 0, 0, 0, 0, 0, cs as u32, 1]);
                } else {
                    let q = (1 + rng.below(40)) * qs / 100;
                    place(&mut g, t, bid, false, false, mark + if bid { -DOLLAR } else { DOLLAR } * (1 + rng.below(50) as i64), q, mkt);
                }
            }
        }
    }
    adv::batch_words(&ids_real, &g.ops, flags)
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
    let mut liq_units = 0u64; // round 17: Liquidate units inside segments proven with status 0
    let mut gov = [0u64; 6]; // round 18: [create ok, create rej, vote ok, vote rej, finalize ok, finalize rej] proven
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
        } else if mode == "liq" {
            liq_sl_batch(s, ord)
        } else if mode == "gov" {
            gov_batch(s, ord)
        } else {
            let makers = 4 + (s % 9) as u32;
            let levels = 1 + (s % 25) as u32;
            let per = 1 + (s % 3) as u32;
            gen(s, makers, levels, per, ord, s % 2 == 0).0
        };
        let mut rng = Rng(s.wrapping_mul(0x51_7CC1_B727_220A) | 1);
        let size = 1 + rng.below(200) as u32;
        let refs = if mode == "perp" || mode == "gov" { session_refs_v2(&w, size) } else { session_refs(&w, size) };
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
                        let base = 4 + 8 * r.seg[1] as usize;
                        liq_units += (0..r.seg[2] as usize).filter(|k| r.seg[base + 8 * k] & 0xff == 7).count() as u64;
                        // round 18: governance units (create / vote / finalize, applied and rejected) proven with status 0
                        let mut i = 0usize;
                        for k in 0..r.seg[2] as usize {
                            let x = r.ev.get(i).copied().unwrap_or(0);
                            let app = x & mnpilot::EV_APPLIED != 0;
                            i += if app { 1 + 6 * (x & 0xFFFF) as usize } else { 1 };
                            let kd = r.seg[base + 8 * k] & 0xff;
                            if (17..=19).contains(&kd) {
                                gov[(kd - 17) as usize * 2 + (!app) as usize] += 1;
                            }
                        }
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
        "{{\"mode\":\"{}\",\"batches\":{},\"ok\":{},\"bad_segments\":{},\"unsupported_segments\":{},\"segments\":{},\"units\":{},\"witness_bytes\":{},\"max_witness\":{},\"leaves_verified\":{},\"tree_nodes\":{},\"sl_hashes\":{},\"session_hashes\":{},\"operator_iterations\":{},\"liq_units_proven\":{},\"gov_units_proven\":{:?},\"first_bad\":\"{}\"}}",
        mode, n, ok, bad, unsupported, segs, units, wbytes, maxw, verified, nodes, hashes, sess_hashes, iters, liq_units, gov, first_bad
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
        let w = if mode == "wd" { wd_batch(s, ord) } else if mode == "perp" { perp_batch(s, ord) } else if mode == "liq" { liq_sl_batch(s, ord) } else if mode == "gov" { gov_batch(s, ord) } else { gen(s, makers, levels, per, ord, s % 2 == 0).0 };
        let mut rng = Rng(s.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1);
        let size = 8 + rng.below(64) as u32;
        let refs = if mode == "perp" || mode == "gov" { session_refs_v2(&w, size) } else { session_refs(&w, size) };
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
                // round 18: an exception list brings pglob: in the builder; the omission test drops it for real
                b.t_omit_pglob.set(*nd == Need::Pglob);
                let w2 = b.build(&n2);
                b.t_omit_pglob.set(false);
                let (o2, ev2) = run_sl(&r.seg, &w2);
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
                    Need::Pglob => "omit:pglob",
                    Need::Pexc(_) => "omit:pexc",
                    Need::Adl(..) | Need::AdlTop(..) | Need::AdlKey(..) => "omit:adl",
                    Need::Gcnt => "omit:gcnt",
                    _ => "omit:oracle",
                };
                a.rec(kind, r, &o2, &ev2, false);
            }
            // round 19: forged exception lists against the proposals' exception sub-trees (must be refused)
            if needs.iter().any(|n| matches!(n, Need::Pexc(_))) && !r.pre.proposals.is_empty() {
                for (m, kind) in [(1u8, "forge19:pxe-drop"), (2u8, "forge19:pxe-weight"), (3u8, "forge19:pxe-subtree")] {
                    b.t_pxe.set(m);
                    let w2 = b.build(&needs);
                    b.t_pxe.set(0);
                    if w2 == wit {
                        continue; // mode 3 on accounts without entries = the honest witness
                    }
                    let (o2, ev2) = run_sl(&r.seg, &w2);
                    a.rec(kind, r, &o2, &ev2, true);
                }
            }
            // A2 extra valid records: every account / market of the pre-state + every level of market 1
            let mut n3 = needs.clone();
            for id in r.pre.accounts.keys().take(40) {
                n3.insert(Need::Account(*id));
                n3.insert(Need::Aord(*id));
                n3.insert(Need::Wdl(*id)); // round 15
                n3.insert(Need::Pexc(*id)); // round 18 (brings pglob: + every live proposal)
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
                } else if wrong[4..36] == b.root && o7.end_root == r.post_root && ev7 == r.ev {
                    // round 17: the previous segment left the state unchanged (all its units refused / rejected),
                    // so the "wrong" witness IS an honest witness of this pre-state: a correct acceptance
                    e.2 += 1;
                    a.sound += 1;
                } else {
                    a.unsound.push("wrong-root accepted with the right start root".into());
                }
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
                // round 18: an account whose exception list is sent comes with its full record (builder): not this case
                Need::Account(id) if *id != ins && r.pre.accounts.contains_key(id) && !needs.contains(&Need::Pexc(*id)) => Some(*id),
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
            "liq" => liq_sl_batch(s, ord),
            "gov" => gov_batch(s, ord),
            _ => gen(s, 4 + (s % 9) as u32, 1 + (s % 25) as u32, 1 + (s % 3) as u32, ord, s % 2 == 0).0,
        };
        let mut rng = Rng(s.wrapping_mul(0x51_7CC1_B727_220A) | 1);
        let size = 1 + rng.below(200) as u32;
        let refs = if mode == "perp" || mode == "gov" { session_refs_v2(&w, size) } else { session_refs(&w, size) };
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

/// round 21: the `liq` workload's segments whose units reach the ADL remainder (session-side replay with the engine's
/// SL_ADL_REACHED flag): (seed, segment index, reference, (market, candidates' sign) of the first ADL unit)
pub fn adl_segments(n: u64, ord: u32, limit: usize) -> Vec<(u64, usize, SegRef, (u32, u8, u32))> {
    let mut out = Vec::new();
    for s in 1..=n {
        let w = liq_sl_batch(s, ord);
        let mut rng = Rng(s.wrapping_mul(0x51_7CC1_B727_220A) | 1);
        let size = 1 + rng.below(200) as u32;
        for (k, r) in session_refs(&w, size).into_iter().enumerate() {
            let seg = &r.seg;
            let n_acc = seg[1];
            let accts: Vec<mnpilot::types::AccountId> = (0..n_acc)
                .map(|a| {
                    let mut id = [0u8; 32];
                    for q in 0..8 {
                        id[q * 4..q * 4 + 4].copy_from_slice(&seg[4 + (a * 8) as usize + q].to_le_bytes());
                    }
                    mnpilot::types::AccountId(id)
                })
                .collect();
            let base = 4 + 8 * n_acc;
            let mut eng = mnpilot::engine::Engine { state: r.pre.clone() };
            let mut rd = |i: u32| seg.get(i as usize).copied().unwrap_or(0);
            let mut side = None;
            for i in 0..seg[2] {
                let mut ow = [0u32; 8];
                for (q, x) in ow.iter_mut().enumerate() {
                    *x = seg[(base + i * 8) as usize + q];
                }
                let op = mnpilot::decode_op(&ow);
                let seq = eng.state.seq;
                unsafe { sl::SL_ADL_REACHED = false };
                let res = mnpilot::dispatch(&mut eng, &op, &accts, mnpilot::Uid { v2: false, at: base + 8 * seg[2] + i * 8 }, seq, &mnpilot::Ext::NONE, &mut rd, false);
                if unsafe { sl::SL_ADL_REACHED } {
                    let (m, sd) = unsafe { sl::SL_ADL_SIDE };
                    side = Some((m, sd, i));
                    break;
                }
                if res.is_ok() {
                    eng.state.seq += 1;
                }
                let _ = eng.state.take_dirty();
            }
            if let Some(sd) = side {
                out.push((s, k, r, sd));
                if out.len() >= limit {
                    return out;
                }
            }
        }
    }
    out
}

/// round 17 PoC, round-21 semantics (stateless ADL via the rank sub-trees, design §12.2): on the `liq` workload, every
/// segment whose units reach the ADL remainder must now be PROVEN by the honest operator (status 0 = the session's
/// root and events; another refusal, e.g. an oracle report in the segment, is counted apart), and a witness that
/// additionally carries every position holder's record must give the same result or a refusal -- never a different
/// status-0 result. Round 17-20 form: such segments were UNSUPPORTED (14).
pub fn slpoc17(n: u64, ord: u32) -> String {
    let (mut segs_adl, mut proven, mut honest_14, mut extra_refused, mut wrong, mut op_err) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut first_wrong = String::new();
    for (s, k, r, _) in adl_segments(n, ord, usize::MAX) {
        let seg = &r.seg;
        segs_adl += 1;
        let b = WitBuilder::new(&r.pre);
        match operate(&b, seg) {
            Ok((needs, _, o, ev, _)) => {
                if o.status == 0 && o.end_root == r.post_root && ev == r.ev {
                    proven += 1;
                } else if o.status == 0 {
                    wrong += 1;
                    if first_wrong.is_empty() {
                        first_wrong = format!("seed {} seg {}: honest status 0 with a different result", s, k);
                    }
                } else if o.status == sl::ST_SL_UNSUPPORTED {
                    honest_14 += 1;
                }
                let mut nx = needs.clone();
                for (id, a) in r.pre.accounts.iter() {
                    if !a.positions.is_empty() && *id != mnpilot::types::INSURANCE_ACCOUNT {
                        nx.insert(Need::Account(*id));
                    }
                }
                let wf = b.build(&nx);
                let (ox, evx) = run_sl(seg, &wf);
                if ox.status != 0 {
                    extra_refused += 1;
                } else if ox.end_root != r.post_root || evx != r.ev {
                    wrong += 1;
                    if first_wrong.is_empty() {
                        first_wrong = format!("seed {} seg {}: extra-holders witness status 0 with a different result", s, k);
                    }
                }
            }
            Err(e) => {
                op_err += 1;
                if first_wrong.is_empty() {
                    first_wrong = format!("seed {} seg {}: operator {}", s, k, e);
                }
            }
        }
    }
    let ok = wrong == 0 && op_err == 0 && segs_adl > 0 && proven > 0;
    format!(
        "{{\"ok\":{},\"batches\":{},\"segments_reaching_adl\":{},\"proven\":{},\"honest_unsupported\":{},\"extra_holders_refused\":{},\"wrong_status0\":{},\"operator_errors\":{},\"first_wrong\":\"{}\"}}",
        ok, n, segs_adl, proven, honest_14, extra_refused, wrong, op_err, first_wrong
    )
}

/// round 21 PoC (stateless ADL, rank sub-trees): on up to `lim` ADL segments of the `liq` workload --
///  P1 inflation: the pre-state gets `extra` more holders of the candidates' sign in the ADL market (small positions,
///     deep collateral) plus a WHALE (the largest |qty|, a high id) and a TIE (the whale's |qty|, a lower id: the tie
///     goes to the lower id): the stateless run must equal the session (root) with the tie winner as the counterparty,
///     and its witness must not grow with `extra` (rank sub-tree: the leftmost path only);
///  P2 every single omission from the honest witness of a round-21 need (Adl / AdlTop / AdlKey / Account) and the
///     forged sub-trees (t_adrop 1 leftmost leaf unverified, 2 leftmost path hidden, 3 the sub-tree without its top
///     holder under the honest root, 4 the same with its own root as the `adlr:` value, 5 the tree claimed absent with
///     an empty sub-tree: round-22 kill of load-absent-check-off) -> refused or the identical result;
///  P3 the ADL unit ALONE (pre-state replayed to just before it): no opposite holder is loaded for another reason, so
///     only the pick check brings the top holder in (kills a pick that treats an unloaded tree as empty).
pub fn slpoc21(n: u64, ord: u32, lim: usize, extra: u32) -> String {
    use mnpilot::types::{AccountId as A, MarketId as M};
    let segs = adl_segments(n, ord, lim);
    let (mut p1_runs, mut p1_ok, mut p1_skip) = (0u32, 0u32, 0u32);
    let mut p1_first = String::new();
    let (mut wb0_max, mut wb1_max) = (0usize, 0usize);
    let (mut p2_runs, mut p2_ref, mut p2_wrong) = (0u32, 0u32, 0u32);
    let mut p2_first = String::new();
    let mut proven = 0u32;
    let (mut adl_b0, mut adl_b1) = (0usize, 0usize);
    let mut whale_hits = 0u32;
    let mut acc_n = (0usize, 0usize);
    let (mut p3_runs, mut p3_ok) = (0u32, 0u32);
    let (mut p3d_runs, mut p3d_ref, mut p3d_honest) = (0u32, 0u32, 0u32);
    let mut p3_first = String::new();
    for (s, k, r, (m, sd, ui)) in &segs {
        // ---- P3: the ADL unit ALONE (state replayed to just before it): no opposite holder is loaded for any other
        // reason, so only the pick check can bring the top holder in
        {
            let n_acc = r.seg[1] as usize;
            let hdr = |n_ops: u32| -> Vec<u32> {
                let mut w = vec![r.seg[0], r.seg[1], n_ops, r.seg[3]];
                w.extend_from_slice(&r.seg[4..4 + 8 * n_acc]);
                w
            };
            let base = 4 + 8 * n_acc;
            let mut pw = hdr(*ui);
            pw.extend_from_slice(&r.seg[base..base + 8 * *ui as usize]);
            let (st_i, _) = direct(&r.pre, &pw);
            let mut w1 = hdr(1);
            w1.extend_from_slice(&r.seg[base + 8 * *ui as usize..base + 8 * (*ui as usize + 1)]);
            let (post1, ev1) = direct(&st_i, &w1);
            let b3 = WitBuilder::new(&st_i);
            p3_runs += 1;
            match operate(&b3, &w1) {
                Ok((n3, _, o, ev, _)) if o.status == 0 && o.end_root == sl::s_root(&post1) && ev.len() == ev1.len() => {
                    p3_ok += 1;
                    // P3b: forged sub-trees (t_adrop 2 / 3 / 4) COMBINED with a witness that drops the top holder's
                    // record and carries the second one's: a pick that skipped the hidden / dropped top would find a
                    // consistent loaded candidate (the second) -> must still be refused (or identical)
                    let rs = sl::adl::sets(&st_i);
                    if let Some(v) = rs.get(&(*m, *sd)).filter(|v| v.len() >= 2) {
                        let (top, second) = (v[0].2, v[1].2);
                        // P3c: an adversarial operator that never supplies the top holder's record or a path to its key
                        let tk = v[0].0;
                        for t in [2u8, 3, 4, 5, 6] {
                            b3.t_adrop.set(t);
                            let (of, evf) = operate_deny(&b3, &w1, &|n: &Need| matches!(n, Need::Account(a) if *a == top) || matches!(n, Need::AdlKey(_, _, k) if *k == tk));
                            b3.t_adrop.set(0);
                            p2_runs += 1;
                            if of.status != 0 {
                                p2_ref += 1;
                            } else if of.end_root != sl::s_root(&post1) || evf.len() != ev1.len() {
                                p2_wrong += 1;
                                if p2_first.is_empty() {
                                    p2_first = format!("seed {} seg {} unit {}: P3c adversarial operator t_adrop {}", s, k, ui, t);
                                }
                            }
                        }
                        for t in [2u8, 3, 4, 6] {
                            let mut nf = n3.clone();
                            nf.remove(&Need::Account(top));
                            nf.insert(Need::Account(second));
                            b3.t_adrop.set(t);
                            let wf = b3.build(&nf);
                            b3.t_adrop.set(0);
                            p2_runs += 1;
                            let (of, evf) = run_sl_xh(&w1, &wf, Some(&b3.root), None);
                            if of.status != 0 {
                                p2_ref += 1;
                            } else if of.end_root != sl::s_root(&post1) || evf.len() != ev1.len() {
                                p2_wrong += 1;
                                if p2_first.is_empty() {
                                    p2_first = format!("seed {} seg {} unit {}: P3b t_adrop {} without the top holder", s, k, ui, t);
                                }
                            }
                        }
                    }
                }
                Ok((_, _, o, ev, _)) => {
                    if p3_first.is_empty() {
                        p3_first = format!("seed {} seg {} unit {}: status {} root_ok {} ev {:?} want {:?} need {:?}", s, k, ui, o.status, o.end_root == sl::s_root(&post1), ev, ev1, o.need);
                    }
                }
                Err(e) => {
                    if p3_first.is_empty() {
                        p3_first = format!("seed {} seg {} unit {}: operator {}", s, k, ui, e);
                    }
                }
            }
        }
        // ---- P3d (round 22, kills leftmost-skip-stub): the ADL unit alone on its pre-state + a WHALE W (the largest
        // |qty|) and a TIE PAIR (the next |qty|, both above every other holder): W's leaf and the pair lie on the two
        // sides of one node, so removing the pair's winner does not lift W's stub. An adversarial operator that sends W's
        // leaf as an opaque stub (t_adrop 6) / hides its path (2) and never supplies W's record or key must be refused:
        // a pick that skips the stub would ADL the tie winner (status 0, wrong root)
        {
            let n_acc = r.seg[1] as usize;
            let base = 4 + 8 * n_acc;
            let mut pw = vec![r.seg[0], r.seg[1], *ui, r.seg[3]];
            pw.extend_from_slice(&r.seg[4..4 + 8 * n_acc]);
            pw.extend_from_slice(&r.seg[base..base + 8 * *ui as usize]);
            let (mut st_d, _) = direct(&r.pre, &pw);
            let mut w1 = vec![r.seg[0], r.seg[1], 1, r.seg[3]];
            w1.extend_from_slice(&r.seg[4..4 + 8 * n_acc]);
            w1.extend_from_slice(&r.seg[base + 8 * *ui as usize..base + 8 * (*ui as usize + 1)]);
            let topq = st_d.accounts.iter().filter(|(id, _)| **id != mnpilot::types::INSURANCE_ACCOUNT).filter_map(|(_, a)| a.positions.get(&M(*m)).map(|p| p.qty)).filter(|q| *q != 0 && sl::adl::sgn(*q) == *sd).map(|q| q.unsigned_abs()).max().unwrap_or(0);
            let mut put = |i: u32, q: u64| -> A {
                let id = A(acct_id(910_000 + i).0);
                let mut a = mnpilot::account::Account { id, collateral: 1_000_000_000 * USD_SCALE as i128, realized_pnl: 0, positions: Default::default(), isolated_margin: Default::default() };
                let qty = if *sd == 0 { q as i64 } else { -(q as i64) };
                a.positions.insert(M(*m), mnpilot::account::Position { market: M(*m), qty, entry_price: MID, isolated: false });
                st_d.accounts.insert(id, a);
                id
            };
            let wq = topq + 2 * QTY_SCALE;
            let whale = put(0, wq);
            let _ = (put(1, topq + QTY_SCALE), put(2, topq + QTY_SCALE));
            let _ = st_d.take_dirty();
            let rs = sl::adl::sets(&st_d);
            let (post_d, ev_d) = direct(&st_d, &w1);
            let bd = WitBuilder::new(&st_d);
            if let (Some(v), Ok((_, _, o, ev, _))) = (rs.get(&(*m, *sd)), operate(&bd, &w1)) {
                if v[0].2 == whale && o.status == 0 && o.end_root == sl::s_root(&post_d) && ev.len() == ev_d.len() {
                    p3d_honest += 1;
                    let wk = v[0].0;
                    for t in [2u8, 6] {
                        bd.t_adrop.set(t);
                        let (of, evf) = operate_deny(&bd, &w1, &|n: &Need| matches!(n, Need::Account(a) if *a == whale) || matches!(n, Need::AdlKey(_, _, k) if *k == wk));
                        bd.t_adrop.set(0);
                        p3d_runs += 1;
                        p2_runs += 1;
                        if of.status != 0 {
                            p2_ref += 1;
                            p3d_ref += 1;
                        } else if of.end_root != sl::s_root(&post_d) || evf.len() != ev_d.len() {
                            p2_wrong += 1;
                            if p2_first.is_empty() {
                                p2_first = format!("seed {} seg {} unit {}: P3d whale stub t_adrop {}", s, k, ui, t);
                            }
                        }
                    }
                }
            }
        }
        let b0 = WitBuilder::new(&r.pre);
        let (needs, wit0, o0, ev0) = match operate(&b0, &r.seg) {
            Ok((a, b, c, d, _)) => (a, b, c, d),
            Err(e) => {
                p1_skip += 1;
                if p1_first.is_empty() {
                    p1_first = format!("seed {} seg {}: honest operator {}", s, k, e);
                }
                continue;
            }
        };
        if o0.status != 0 {
            if p1_first.is_empty() {
                p1_first = format!("seed {} seg {}: honest status {} need {:?}", s, k, o0.status, o0.need);
            }
            p1_skip += 1;
            continue;
        }
        proven += (o0.end_root == r.post_root && ev0 == r.ev) as u32;
        // ---- P2 ----
        for nd in needs.iter().filter(|x| matches!(x, Need::Adl(..) | Need::AdlTop(..) | Need::AdlKey(..) | Need::Account(_))) {
            let mut n2 = needs.clone();
            n2.remove(nd);
            p2_runs += 1;
            let (o, ev) = run_sl_xh(&r.seg, &b0.build(&n2), Some(&b0.root), None);
            if o.status != 0 {
                p2_ref += 1;
            } else if o.end_root != r.post_root || ev != r.ev {
                p2_wrong += 1;
                if p2_first.is_empty() {
                    p2_first = format!("seed {} seg {}: omit {:?}", s, k, nd);
                }
            }
        }
        for t in [1u8, 2, 3, 4, 5, 6] {
            b0.t_adrop.set(t);
            let w2 = b0.build(&needs);
            b0.t_adrop.set(0);
            if w2 == wit0 {
                continue;
            }
            p2_runs += 1;
            let (o, ev) = run_sl_xh(&r.seg, &w2, Some(&b0.root), None);
            if o.status != 0 {
                p2_ref += 1;
            } else if o.end_root != r.post_root || ev != r.ev {
                p2_wrong += 1;
                if p2_first.is_empty() {
                    p2_first = format!("seed {} seg {}: t_adrop {}", s, k, t);
                }
            }
        }
        // ---- P1 ----
        let mut pre = r.pre.clone();
        let top = pre.accounts.iter().filter(|(id, _)| **id != mnpilot::types::INSURANCE_ACCOUNT).filter_map(|(_, a)| a.positions.get(&M(*m)).map(|p| p.qty)).filter(|q| *q != 0 && (sl::adl::sgn(*q) == *sd)).map(|q| q.unsigned_abs()).max().unwrap_or(0);
        let wq = (top + 7).max(QTY_SCALE);
        let mk = |pre: &mut mnpilot::state::ChainState, i: u32, q: u64| -> A {
            let id = A(acct_id(900_000 + i).0);
            let mut a = mnpilot::account::Account { id, collateral: 1_000_000_000 * USD_SCALE as i128, realized_pnl: 0, positions: Default::default(), isolated_margin: Default::default() };
            let qty = if *sd == 0 { q as i64 } else { -(q as i64) };
            a.positions.insert(M(*m), mnpilot::account::Position { market: M(*m), qty, entry_price: MID, isolated: false });
            pre.accounts.insert(id, a);
            id
        };
        for i in 0..extra {
            mk(&mut pre, i, 1 + (i as u64 % 5));
        }
        let (x, y) = (mk(&mut pre, extra, wq), mk(&mut pre, extra + 1, wq));
        let (lo, hi) = if x < y { (x, y) } else { (y, x) };
        let _ = pre.take_dirty();
        let (post, _) = direct(&pre, &r.seg);
        let b1 = WitBuilder::new(&pre);
        p1_runs += 1;
        match operate(&b1, &r.seg) {
            Ok((n1, w1, o1, _, _)) => {
                let strip = |n: &BTreeSet<Need>| -> BTreeSet<Need> { n.iter().filter(|x| !matches!(x, Need::Adl(..) | Need::AdlTop(..) | Need::AdlKey(..))).copied().collect() };
                adl_b0 = adl_b0.max(wit0.len() - b0.build(&strip(&needs)).len());
                let na = |n: &BTreeSet<Need>| n.iter().filter(|x| matches!(x, Need::Account(_))).count();
                acc_n = acc_n.max((na(&needs), na(&n1)));
                adl_b1 = adl_b1.max(w1.len() - b1.build(&strip(&n1)).len());
                let lo_hit = post.accounts.get(&lo).and_then(|a| a.positions.get(&M(*m))).map(|p| p.qty.unsigned_abs()) != Some(wq);
                let hi_hit = post.accounts.get(&hi).and_then(|a| a.positions.get(&M(*m))).map(|p| p.qty.unsigned_abs()) != Some(wq);
                // the root is the check (the tie goes to the lower id first; a later ADL unit may take the other); the
                // inflated pre-state may also change whether the remainder is reached (whale hits counted apart)
                let good = o1.status == 0 && o1.end_root == sl::s_root(&post);
                whale_hits += (lo_hit || hi_hit) as u32;
                if good {
                    p1_ok += 1;
                    wb0_max = wb0_max.max(wit0.len());
                    wb1_max = wb1_max.max(w1.len());
                } else if p1_first.is_empty() {
                    p1_first = format!("seed {} seg {}: status {} root_ok {} lo_hit {} hi_hit {} need {:?}", s, k, o1.status, o1.end_root == sl::s_root(&post), lo_hit, hi_hit, o1.need);
                }
            }
            Err(e) => {
                if p1_first.is_empty() {
                    p1_first = format!("seed {} seg {}: operator {}", s, k, e);
                }
            }
        }
    }
    let ok = !segs.is_empty() && p1_runs > 0 && p1_ok == p1_runs && whale_hits > 0 && p3_runs > 0 && p3_ok == p3_runs && p2_wrong == 0 && p2_runs > 0 && proven as usize + p1_skip as usize == segs.len() && p3d_honest > 0;
    format!(
        "{{\"ok\":{},\"segments\":{},\"honest_proven\":{},\"skipped_refused\":{},\"P1_inflated_runs\":{},\"P1_ok\":{},\"P1_whale_picked\":{},\"max_account_records_plain_inflated\":{:?},\"extra_holders\":{},\"max_witness_plain\":{},\"max_witness_inflated\":{},\"max_rank_section_plain\":{},\"max_rank_section_inflated\":{},\"P1_first_bad\":\"{}\",\"P2_runs\":{},\"P2_refused\":{},\"P2_wrong\":{},\"P2_first_wrong\":\"{}\",\"P3_single_unit_runs\":{},\"P3_ok\":{},\"P3_first_bad\":\"{}\",\"P3d_honest_proven\":{},\"P3d_forged_runs\":{},\"P3d_refused\":{}}}",
        ok, segs.len(), proven, p1_skip, p1_runs, p1_ok, whale_hits, acc_n, extra, wb0_max, wb1_max, adl_b0, adl_b1, p1_first, p2_runs, p2_ref, p2_wrong, p2_first, p3_runs, p3_ok, p3_first, p3d_honest, p3d_runs, p3d_ref
    )
}

/// round 17 debug: for one (seed, mode) batch, the first segment whose stateless status-0 events differ from the
/// session's -> the unit, its op, both unit event slices, and the pre-state facts of the liquidation target / book
pub fn sldiff(seed: u64, ord: u32, mode: &str) -> String {
    let w = match mode {
        "liq" => liq_sl_batch(seed, ord),
        "perp" => perp_batch(seed, ord),
        "wd" => wd_batch(seed, ord),
        "gov" => gov_batch(seed, ord),
        _ => gen(seed, 4 + (seed % 9) as u32, 1 + (seed % 25) as u32, 1 + (seed % 3) as u32, ord, seed % 2 == 0).0,
    };
    let mut rng = Rng(seed.wrapping_mul(0x51_7CC1_B727_220A) | 1);
    let size = 1 + rng.below(200) as u32;
    let refs = if mode == "perp" || mode == "gov" { session_refs_v2(&w, size) } else { session_refs(&w, size) };
    // split an event stream into units
    let units = |ev: &[u32]| -> Vec<Vec<u32>> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < ev.len() {
            let x = ev[i];
            let n = if x & mnpilot::EV_APPLIED != 0 { 1 + 6 * (x & 0xFFFF) as usize } else { 1 };
            out.push(ev[i..(i + n).min(ev.len())].to_vec());
            i += n;
        }
        out
    };
    for (k, r) in refs.iter().enumerate() {
        let b = WitBuilder::new(&r.pre);
        let Ok((_, _, o, ev, _)) = operate(&b, &r.seg) else { continue };
        if o.status != 0 || ev == r.ev {
            continue;
        }
        let (us, uref) = (units(&ev), units(&r.ev));
        let j = us.iter().zip(&uref).position(|(a, b)| a != b).unwrap_or(0);
        let base = 4 + 8 * r.seg[1] as usize;
        let ow: [u32; 8] = r.seg[base + 8 * j..base + 8 * j + 8].try_into().unwrap();
        let op = mnpilot::decode_op(&ow);
        // session-side replay up to unit j (dispatch on the full pre-state): the fill of unit j in full
        let n_acc = r.seg[1];
        let accts: Vec<mnpilot::types::AccountId> = (0..n_acc)
            .map(|a| {
                let mut id = [0u8; 32];
                for q in 0..8 {
                    id[q * 4..q * 4 + 4].copy_from_slice(&r.seg[4 + (a * 8) as usize + q].to_le_bytes());
                }
                mnpilot::types::AccountId(id)
            })
            .collect();
        let mut eng = mnpilot::engine::Engine { state: r.pre.clone() };
        let seg = r.seg.clone();
        let mut rd = |i: u32| seg.get(i as usize).copied().unwrap_or(0);
        let mut detail = String::new();
        for i in 0..=j as u32 {
            let mut w8 = [0u32; 8];
            for (q, x) in w8.iter_mut().enumerate() {
                *x = r.seg[base + 8 * i as usize + q];
            }
            let o2 = mnpilot::decode_op(&w8);
            let sq = eng.state.seq;
            let res = mnpilot::dispatch(&mut eng, &o2, &accts, mnpilot::Uid { v2: false, at: (base + 8 * r.seg[2] as usize) as u32 + i * 8 }, sq, &mnpilot::Ext::NONE, &mut rd, false);
            if i == j as u32 {
                detail = match &res {
                    Ok(f) => f.iter().map(|x| format!("taker {:02x?} maker {:02x?} kind {} taker_acct {:02x?} maker_acct {:02x?}", &x.taker_id.0[..6], &x.maker_id.0[..6], x.kind, &x.taker.0[..4], &x.maker.0[..4])).collect::<Vec<_>>().join("; "),
                    Err(e) => format!("err {:?}", e),
                };
            }
            if res.is_ok() {
                eng.state.seq += 1;
            }
            let _ = eng.state.take_dirty();
        }
        return format!("seed {} seg {} unit {}/{}: op {:?}\n  stateless {:?}\n  session   {:?}\n  prev units equal: {}\n  replay fill: {}\n  liq id(0) {:02x?}", seed, k, j, r.seg[2], op, us.get(j), uref.get(j), us[..j] == uref[..j], detail, &mnpilot::types::liq_order_id([0u8; 32]).0[..6]);
    }
    "no differing segment".into()
}

/// slpoc18 (round 18 PoCs / regression, stateless governance):
///  P1 a vote after a balance change weighs the snapshot weight (pexc: entry), not the balance; events + end root = direct
///  P2 finalize of a proposal with exception holders: honest -> status 0 = direct; round 19 (R18-M1 fix): the operator
///     loads no exception holder (the proposal's exception sub-tree goes with its pglob: entry)
///  P3 R18-M1 (fixed in round 19): a proposal with `v` voters finalizes with an O(1) witness for any `v` (round 18:
///     `v` exception records, above SL_MAX_ACCOUNTS (4096) refused -> the proposal could never be finalized)
///  P5 round 19: forged exception lists (entry dropped / weight altered / fake entry) against the sub-trees -> BADWIT
pub fn slpoc18(big: u32) -> String {
    use mnpilot::types::AccountId as A;
    let id = |i: u32| A(acct_id(i).0);
    let mut res: Vec<String> = Vec::new();
    let mut all_ok = true;
    let mk = |n_hold: u32, voters: u32, seq: u64| -> mnpilot::state::ChainState {
        let mut s = mnpilot::state::ChainState::genesis();
        for i in 0..n_hold {
            s.set_perp(id(i), 2_000);
        }
        s.perp_supply = 2_000 * n_hold as u128;
        let snap: std::collections::BTreeMap<A, u128> = (0..n_hold).map(|i| (id(i), 2_000u128)).collect();
        let mut p = mnpilot::state::Proposal {
            creator: id(0),
            market: mnpilot::types::MarketId(1),
            key: mnpilot::types::ParamKey::from_u8(2).unwrap(),
            value: 5,
            created_seq: 0,
            deadline_seq: minuend_types::PROPOSAL_DURATION_SEQS,
            supply_at_create: s.perp_supply,
            yes: 0,
            no: 0,
            voted: Default::default(),
            weight_snapshot: snap,
        };
        for i in 0..voters {
            p.voted.insert(id(i));
            p.yes += 2_000;
        }
        s.proposals.insert(1, p);
        s.next_proposal_id = 2;
        s.seq = seq;
        let _ = s.take_dirty();
        s
    };
    // ---- P1: account 1 withdrew half after the snapshot (exception entry), then votes ----
    {
        let mut s = mk(8, 0, 100);
        s.set_perp(id(1), 500);
        let _ = s.take_dirty();
        let seg = seg_words(&[1], &[crate::gov::GB::w_vote(0, 1, true)]);
        let l = check15("P1 vote after a balance change: snapshot weight 2000 (balance 500)", &s, &seg, &|post, _, _| post.proposals[&1].yes == 2_000);
        all_ok &= l.contains("\"ok\":true");
        res.push(l);
    }
    // ---- P2: finalize with 10 voters (10 exception holders) ----
    {
        let s = mk(20, 10, minuend_types::PROPOSAL_DURATION_SEQS + 5);
        let seg = seg_words(&[0], &[crate::gov::GB::w_fin(0, 1)]);
        let l = check15("P2 finalize, 10 exception holders (passes: taker fee -> 5)", &s, &seg, &|post, _, _| post.proposals.is_empty() && post.markets[&mnpilot::types::MarketId(1)].taker_fee_bps == 5);
        all_ok &= l.contains("\"ok\":true");
        res.push(l);
        let b = WitBuilder::new(&s);
        if let Ok((needs, wit, o, _, _)) = operate(&b, &seg) {
            let ok = o.status == 0 && !needs.iter().any(|n| matches!(n, Need::Pexc(_)));
            all_ok &= ok;
            res.push(format!("{{\"case\":\"P2 finalize reads no exception holder\",\"ok\":{},\"status\":{},\"needs\":\"{:?}\",\"witness_bytes\":{}}}", ok, o.status, needs, wit.len()));
        }
    }
    // ---- P4: R6-H2 (session state_cap_ok) evaluated statelessly: |snapshot| = 1, 65 zero-weight voters recorded ->
    // a fresh zero-weight voter is refused (code 19), the snapshot holder still votes ----
    {
        let mut s = mk(1, 0, 100);
        {
            let p = s.proposals.get_mut(&1).unwrap();
            for i in 0..(1 + mnpilot::MAX_ZERO_VOTERS as u32) {
                p.voted.insert(id(1000 + i));
            }
        }
        let _ = s.take_dirty();
        let seg = seg_words(&[2000, 0], &[crate::gov::GB::w_vote(0, 1, true), crate::gov::GB::w_vote(1, 1, true)]);
        let b = WitBuilder::new(&s);
        let line = match operate(&b, &seg) {
            Ok((_, _, o, ev, _)) => {
                let ok = o.status == 0 && ev.len() == 2 && ev[0] == mnpilot::STATE_CAP_CODE && ev[1] & EV_APPLIED != 0;
                all_ok &= ok;
                format!("{{\"case\":\"P4 R6-H2: fresh zero-weight voter beyond |snapshot| + 64 refused, holder votes\",\"ok\":{},\"status\":{},\"ev\":{:?}}}", ok, o.status, ev)
            }
            Err(e) => {
                all_ok = false;
                format!("{{\"case\":\"P4 R6-H2\",\"ok\":false,\"why\":\"{}\"}}", e)
            }
        };
        res.push(line);
    }
    // ---- P5: forged exception lists (P1 state: account 1 has an entry, account 0 none) ----
    {
        let mut s = mk(8, 3, 100);
        s.set_perp(id(1), 500);
        s.set_perp(id(5), 900);
        let _ = s.take_dirty();
        for (vi, who) in [(1u32, "entry holder"), (6u32, "no entry")] {
            let seg = seg_words(&[vi], &[crate::gov::GB::w_vote(0, 1, true)]);
            let b = WitBuilder::new(&s);
            if let Ok((needs, _, o0, _, _)) = operate(&b, &seg) {
                for (m, f) in [(1u8, "drop / fake entry"), (2u8, "weight + 1 / fake entry"), (3u8, "entry-less + sub-trees without its entries")] {
                    b.t_pxe.set(m);
                    let (o, _) = run_sl(&seg, &b.build(&needs));
                    b.t_pxe.set(0);
                    // mode 3 on an entry-less account is the honest witness
                    let ok = o0.status == 0 && if m == 3 && vi == 6 { o.status == 0 } else { o.status == sl::ST_SL_BADWIT };
                    all_ok &= ok;
                    res.push(format!("{{\"case\":\"P5 vote by {} ({}): forged list {}\",\"ok\":{},\"status\":{}}}", vi, who, f, ok, o.status));
                }
            } else {
                all_ok = false;
            }
        }
    }
    // ---- P3: R18-M1 (fixed: any number of voters) ----
    for v in [big.min(4000), 4097, big.max(4097)] {
        let s = mk(v, v, minuend_types::PROPOSAL_DURATION_SEQS + 5);
        let seg = seg_words(&[0], &[crate::gov::GB::w_fin(0, 1)]);
        let b = WitBuilder::new(&s);
        match operate(&b, &seg) {
            Ok((needs, wit, o, _, _)) => {
                let (post, _) = direct(&s, &seg);
                let ok = o.status == 0 && o.end_root == sl::s_root(&post) && wit.len() < 64 * 1024;
                all_ok &= ok;
                res.push(format!("{{\"case\":\"P3 R18-M1 finalize with {} voters\",\"ok\":{},\"status\":{},\"needs\":{},\"witness_bytes\":{}}}", v, ok, o.status, needs.len(), wit.len()));
            }
            Err(e) => {
                all_ok = false;
                res.push(format!("{{\"case\":\"P3 R18-M1 finalize with {} voters\",\"ok\":false,\"why\":\"{}\"}}", v, e));
            }
        }
    }
    format!("{{\"ok\":{},\"cases\":[{}]}}", all_ok, res.join(",\n"))
}

/// round 18: migration (session export -> stateless::migrate) of gov-workload sessions with live proposals, votes and
/// exception holders: the migrated MNWIT-S root must equal s_root of the session state (pglob: / pexc: / prop: counts
/// derived from the snapshot's proposals); checked at up to 4 segment boundaries per batch
pub fn slmiggov(n: u64, ord: u32) -> String {
    let (mut ok, mut migs, mut with_props, mut with_exc) = (0u64, 0u64, 0u64, 0u64);
    let mut first_bad = String::new();
    for seed in 1..=n {
        let w = gov_batch(seed, ord);
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
        let n_ops = w[2] as usize;
        let size = 1 + (seed as usize * 37) % 120;
        let mut lo = 0usize;
        let mut done = 0;
        let mut bad: Option<String> = None;
        while lo < n_ops {
            let hi = (lo + size).min(n_ops);
            let mut sw = crate::gov::cut_v2(&w, lo, hi);
            sw[3] = 0;
            let (_, st, _) = mnpilot::run_segment(&mut |i| sw.get(i as usize).copied().unwrap_or(0), &mut |_| {}, &mut |_, _, _| {}, mnpilot::WitMode::Incremental, &mut sess);
            if st.status != 0 {
                bad = Some(format!("session status {}", st.status));
                break;
            }
            lo = hi;
            let s = &sess.as_ref().unwrap().eng.state;
            if done < 4 && !s.proposals.is_empty() {
                done += 1;
                let (dg, nw, words) = mnpilot::snapshot::export(sess.as_ref().unwrap(), true);
                let words = words.unwrap();
                let mut inp = vec![sl::SL_MIG_MAGIC];
                inp.extend_from_slice(&words);
                let mo = sl::migrate(&mut |j| inp.get(j as usize).copied().unwrap_or(0), Some(&(dg, nw)), true);
                let s = &sess.as_ref().unwrap().eng.state;
                migs += 1;
                with_props += 1;
                if !sl::pexc_all(s).is_empty() {
                    with_exc += 1;
                }
                if mo.status != 0 || mo.root != sl::s_root(s) {
                    bad = Some(format!("migrate status {} root_ok {}", mo.status, mo.root == sl::s_root(s)));
                    break;
                }
            }
        }
        match bad {
            None => ok += 1,
            Some(b) if first_bad.is_empty() => first_bad = format!("seed {}: {}", seed, b),
            _ => {}
        }
    }
    format!("{{\"batches\":{},\"ok\":{},\"migrations\":{},\"with_live_proposals\":{},\"with_exception_lists\":{},\"first_bad\":\"{}\"}}", n, ok, migs, with_props, with_exc, first_bad)
}


// ------------------------------------------------------------------------------------------------
// round 20: stateless oracle (design §12.1): Stake / Unstake / Report + the eager unbonding expiry (R19-I2)
// ------------------------------------------------------------------------------------------------
fn w_report(a: u32, price: i64, market: u32) -> [u32; 8] {
    [8 | (a << 8), 0, price as u32, (price >> 32) as u32, 0, 0, 0, market]
}
fn w_stake(a: u32) -> [u32; 8] {
    [11 | (a << 8), 0, 0, 0, 0, 0, 0, 0]
}
fn w_unstake(a: u32) -> [u32; 8] {
    [12 | (a << 8), 0, 0, 0, 0, 0, 0, 0]
}
fn w_slash(a: u32, target: u32, market: u32) -> [u32; 8] {
    [13 | (a << 8), target, 0, 0, 0, 0, 0, market]
}
/// the 'orc' workload (MNP2, built on the REAL engine by gov::GB): genesis oracles 1..3 (ORACLES_FLAG), PERP holders
/// 4..9 (PERP_FLAG: two bonds each), markets 1 and 2; reports (mostly at the market's mid so the funding premium is 0,
/// some off-mid -> a funding transfer -> unsupported segment; zero / MARK_CAP / unknown market / unbonded reporter),
/// stakes / unstakes (re-stake after the unbonding expired, unstake twice, unbonded), trading on both markets (fills on
/// oracled markets), deposits, PERP deposits. No withdrawals / commits (their lazy expiry is tested by slmig).
/// the run schedule of an orc batch cut into segments of `size` units: segment k runs at height .0, and an empty run
/// (hook only) follows it at height .1 when Some (round 20: the builder needs the heights for commit TTLs)
pub fn orc_sched(hstep: u64, seed: u64, n_seg: usize) -> Vec<(u64, Option<u64>)> {
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x2020);
    let mut h = 0u64;
    let mut v = Vec::with_capacity(n_seg);
    for _ in 0..n_seg {
        h += 1 + if hstep > 0 { rng.below(hstep) } else { 0 };
        let hk = h;
        let e = if rng.below(10) == 0 {
            h += 1 + if hstep > 0 { rng.below(hstep * 4) } else { 0 };
            Some(h)
        } else {
            None
        };
        v.push((hk, e));
    }
    v
}
/// (no commit-reveal: with bound heights the session prunes expired commits eagerly while the stateless image keeps them
/// lazily (R16-I1), so the session root is not the reference there; revealed oracle ops: slpoc20 P8)
pub fn orc_batch(seed: u64, n_ops: u32, size: u32, sched: &[(u64, Option<u64>)]) -> Vec<u32> {
    let _ = (size, sched);
    use crate::gov::GB;
    let mut rng = Rng(seed.wrapping_mul(0x8CB9_2BA7_2F3D_8DD7) | 1);
    let n_acc = 12 + rng.below(5) as u32;
    let mut g = GB::new(n_acc, mnpilot::ORACLES_FLAG | mnpilot::PERP_FLAG | mnpilot::MARKET2_FLAG);
    let mid = 100_000 * PRICE_SCALE as i64;
    let dollar = PRICE_SCALE as i64;
    for a in 1..n_acc {
        g.op(GB::w_dep(a, 20_000 * USD_SCALE as i64));
    }
    let off = (seed % 3) as i64; // seed 0 mod 3: every report at mid (no funding at all)
    // seed 2 mod 3: reports drift +-2 000 dollars around mid (median moves -> a funding premium -> unsupported segments)
    let drift = [0i64, 1, 100][(seed % 3) as usize] * dollar;
    // round 20 (step 3): a deviant oracle (8 % above mid in market 1, one report per op slot it gets) and slashes of it
    let bad = 1 + (seed % 3) as u32;
    for _ in 0..n_ops {
        let a = 1 + rng.below((n_acc - 1) as u64) as u32;
        let orc = 1 + rng.below(9) as u32;
        match rng.below(100) {
            0..=24 => {
                let m = match rng.below(10) {
                    0..=5 => 1,
                    6..=8 => 2,
                    _ => 99,
                };
                let px = match rng.below(20) {
                    0 => 0,
                    1 => mnpilot::types::MARK_CAP,
                    2..=4 => mid + (rng.below(5) as i64 - 2) * dollar * 500 * off.min(1),
                    _ => mid + drift * (rng.below(41) as i64 - 20) * (rng.below(2) == 0) as i64,
                };
                let who = if rng.below(8) == 0 { a } else { orc };
                g.op(w_report(who, px, m));
            }
            25..=31 => {
                g.op(w_stake(if rng.below(6) == 0 { a } else { orc }));
            }
            32..=37 => {
                g.op(w_unstake(if rng.below(6) == 0 { a } else { orc }));
            }
            38..=74 => {
                let m = 1 + rng.below(2) as u32;
                let px = mid + (rng.below(7) as i64 - 3) * dollar * 50;
                let mk = 1 + rng.below((n_acc - 1) as u64) as u32;
                let w1 = g.w_place(mk, rng.below(2) == 0, false, px, QTY_SCALE / 100, m);
                g.op(w1);
                if rng.below(2) == 0 {
                    let w2 = g.w_place(a, rng.below(2) == 0, rng.below(2) == 0, px, QTY_SCALE / 100, m);
                    g.op(w2);
                }
            }
            75..=79 => {
                g.op(GB::w_gdep(4 + rng.below(6) as u32, 1_000 + rng.below(60_000)));
            }
            80..=86 => {
                g.op(w_report(bad, mid + mid / 12 + (rng.below(3) as i64) * dollar, 1));
            }
            87..=89 => {
                let t = if rng.below(4) == 0 { orc } else { bad };
                g.op(w_slash(a, t, if rng.below(5) == 0 { 2 } else { 1 }));
            }
            _ => {
                g.op(GB::w_dep(a, USD_SCALE as i64 * (1 + rng.below(100) as i64)));
            }
        }
    }
    g.words()
}
/// session reference with the height binding (run number = height): heights advance by 1 + rand(hstep) per segment
pub fn orc_refs(w: &[u32], s: u32, sched: &[(u64, Option<u64>)]) -> Vec<(SegRef, u64)> {
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
    let mut out = Vec::new();
    let n = w[2] as usize;
    let mut lo = 0usize;
    let mut k = 0usize;
    loop {
        let hi = (lo + s as usize).min(n);
        let (h, e) = sched[k];
        k += 1;
        let mut runs = vec![(lo, hi, h)];
        if hi < n {
            if let Some(he) = e {
                runs.push((hi, hi, he));
            }
        }
        for (a, b, hh) in runs {
            let mut sw = crate::gov::cut_v2(w, a, b);
            sw[3] = 0;
            let pre = sess.as_ref().unwrap().eng.state.clone();
            let mut ev = Vec::new();
            let (_, st, _) = mnpilot::run_segment_n(&mut |i| sw.get(i as usize).copied().unwrap_or(0), &mut |x| ev.push(x), &mut |_, _, _| {}, mnpilot::WitMode::Incremental, &mut sess, mnpilot::SegOpt { run_no: Some(hh as u32), bind: true });
            assert_eq!(st.status, 0);
            let s1 = sess.as_ref().unwrap();
            out.push((SegRef { pre, post_root: sl::s_root(&s1.eng.state), post: s1.eng.state.clone(), ev, seg: sw, sess_hashes: 0 }, hh));
        }
        if hi >= n {
            break;
        }
        lo = hi;
    }
    out
}
/// forged oracle records under the honest tree / root (state edits of the pre-state, records spliced): must be refused
fn ora_forges(pre: &mnpilot::state::ChainState, needs: &BTreeSet<Need>) -> Vec<(&'static str, mnpilot::state::ChainState)> {
    use mnpilot::types::MarketId;
    let mut v: Vec<(&'static str, mnpilot::state::ChainState)> = Vec::new();
    for n in needs {
        match *n {
            Need::Ostk(a) => {
                let mut p = pre.clone();
                if p.oracle_bonds.remove(&a).is_none() {
                    p.oracle_bonds.insert(a, mnpilot::types::ORACLE_BOND_PERP);
                }
                v.push(("forge20:ostk-bond", p));
                if pre.oracle_unbonding.contains_key(&a) {
                    let mut p = pre.clone();
                    *p.oracle_unbonding.get_mut(&a).unwrap() += 1;
                    v.push(("forge20:ostk-unlock", p));
                }
            }
            Need::Orep(m) => {
                if let Some((k, _)) = pre.oracle_reports.range((MarketId(m), mnpilot::types::AccountId([0; 32]))..).next().filter(|(k, _)| k.0 .0 == m) {
                    let mut p = pre.clone();
                    *p.oracle_reports.get_mut(k).unwrap() += 1;
                    v.push(("forge20:orep-price", p));
                }
            }
            Need::Ohist(m, a) => {
                if let Some(q) = pre.oracle_report_history.get(&(MarketId(m), a)) {
                    let mut p = pre.clone();
                    let q2 = p.oracle_report_history.get_mut(&(MarketId(m), a)).unwrap();
                    q2.back_mut().unwrap().price += 1;
                    let _ = q;
                    v.push(("forge20:ohist-sample", p));
                }
            }
            Need::Omk(m) => {
                if pre.oracle_twap.get(&MarketId(m)).is_some_and(|q| !q.is_empty()) {
                    let mut p = pre.clone();
                    p.oracle_twap.get_mut(&MarketId(m)).unwrap().pop_front();
                    v.push(("forge20:omk-ring", p));
                }
            }
            Need::Oglob => {
                let mut p = pre.clone();
                p.oracle_slash_nonce += 1;
                v.push(("forge20:oglob-nonce", p));
            }
            _ => {}
        }
    }
    v
}
/// slora <n> <orders> <hstep> [adv]: per seed an 'orc' batch cut into segments of 1..12 units, each run at a bound
/// height (run number) advancing by 1 + rand(hstep); every segment is proven statelessly from the session pre-state
/// (operator fixpoint with the height hook) and must give status 0, the session's events and the MNWIT-S root of the
/// session post-state (or UNSUPPORTED: a funding transfer). `adv`: per segment, omission of each supplied need, extra
/// valid oracle records, forged oracle records under the honest root, dropped list entries (t_odrop), byte flips.
pub fn slora(n: u64, ord: u32, hstep: u64, adv: bool) -> String {
    let mut a = Adv { cases: 0, sound: 0, unsound: Vec::new(), counts: Default::default() };
    let (mut ok, mut segs, mut units, mut bad, mut unsup) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut wbytes, mut maxw, mut iters) = (0u64, 0usize, 0u64);
    // proven with status 0: [report applied, report rejected, stake applied, stake rejected, unstake applied, unstake
    // rejected], segments whose hook released bonds, released oracles, empty-height runs
    let mut kinds = [0u64; 10];
    let (mut hook_segs, mut released, mut empty_runs) = (0u64, 0u64, 0u64);
    let mut first_bad = String::new();
    for seed in 1..=n {
        let mut rng = Rng(seed.wrapping_mul(0x51_7CC1_B727_220A) | 1);
        let size = 1 + rng.below(12) as u32;
        let sched = orc_sched(hstep, seed, (3 * ord as usize + 64) / size as usize + 2);
        let w = orc_batch(seed, ord, size, &sched);
        let refs = orc_refs(&w, size, &sched);
        let mut batch_ok = true;
        for (k, (r, h)) in refs.iter().enumerate() {
            segs += 1;
            units += r.seg[2] as u64;
            let b = WitBuilder::new(&r.pre);
            let res = operate_h(&b, &r.seg, Some(*h));
            if matches!(&res, Ok((_, _, o, _, _)) if o.status == sl::ST_SL_UNSUPPORTED) {
                unsup += 1;
                continue;
            }
            let why = match &res {
                Err(e) => Some(e.clone()),
                Ok((needs, wit, o, ev, it)) => {
                    wbytes += wit.len() as u64;
                    maxw = maxw.max(wit.len());
                    iters += *it as u64;
                    if o.status != 0 {
                        Some(format!("status {} need {:?}", o.status, o.need))
                    } else if o.start_root != b.root {
                        Some("start root".into())
                    } else if o.end_root != r.post_root {
                        Some(format!("end root; {}", diag(r, o)))
                    } else if *ev != r.ev {
                        Some(format!("events differ (len {} vs {})", ev.len(), r.ev.len()))
                    } else {
                        let rel = r.pre.oracle_unbonding.values().filter(|u| **u <= *h).count() as u64;
                        if rel > 0 {
                            hook_segs += 1;
                            released += rel;
                        }
                        if r.seg[2] == 0 {
                            empty_runs += 1;
                        }
                        let base = 4 + 8 * r.seg[1] as usize;
                        let mut i = 0usize;
                        for kk in 0..r.seg[2] as usize {
                            let x = r.ev.get(i).copied().unwrap_or(0);
                            let app = x & mnpilot::EV_APPLIED != 0;
                            i += if app { 1 + 6 * (x & 0xFFFF) as usize } else { 1 };
                            let kd = r.seg[base + 8 * kk] & 0xff;
                            let slot = match kd {
                                8 => Some(0),
                                11 => Some(2),
                                12 => Some(4),
                                13 => Some(6),
                                21 => Some(8),
                                _ => None,
                            };
                            if let Some(sl0) = slot {
                                kinds[sl0 + (!app) as usize] += 1;
                            }
                        }
                        if adv {
                            ora_adv(&mut a, &b, r, *h, needs, wit, &mut rng);
                        }
                        None
                    }
                }
            };
            if let Some(why) = why {
                bad += 1;
                batch_ok = false;
                if first_bad.is_empty() {
                    first_bad = format!("seed {} seg {} (size {}, h {}): {}", seed, k, size, h, why);
                }
                break;
            }
        }
        if batch_ok {
            ok += 1;
        }
    }
    let mut cs: Vec<String> = a.counts.iter().map(|(k, v)| format!("\"{}\":[{},{},{}]", k, v.0, v.1, v.2)).collect();
    cs.sort();
    format!(
        "{{\"mode\":\"orc\",\"batches\":{},\"ok\":{},\"bad_segments\":{},\"unsupported_segments\":{},\"segments\":{},\"units\":{},\"witness_bytes\":{},\"max_witness\":{},\"operator_iterations\":{},\"proven_report_ok_rej_stake_ok_rej_unstake_ok_rej_slash_ok_rej_reveal_ok_rej\":{:?},\"hook_segments\":{},\"released_oracles\":{},\"empty_runs\":{},\"adv_cases\":{},\"adv_unsound\":{},\"adv_counts\":{{{}}},\"first_unsound\":\"{}\",\"first_bad\":\"{}\"}}",
        n, ok, bad, unsup, segs, units, wbytes, maxw, iters, kinds, hook_segs, released, empty_runs, a.cases, a.unsound.len(), cs.join(","), a.unsound.first().cloned().unwrap_or_default(), first_bad
    )
}
fn ora_adv(a: &mut Adv, b: &WitBuilder, r: &SegRef, h: u64, needs: &BTreeSet<Need>, wit: &[u8], rng: &mut Rng) {
    let run = |w: &[u8]| run_sl_xh(&r.seg, w, Some(&b.root), Some(h));
    // omission of each supplied need: status 0 must still be the reference
    for nd in needs.iter() {
        let mut n2 = needs.clone();
        n2.remove(nd);
        let (o2, ev2) = run(&b.build(&n2));
        let kind = match nd {
            Need::Oglob => "omit20:oglob",
            Need::Ostk(_) => "omit20:ostk",
            Need::Orm(_) => "omit20:orm",
            Need::Orep(_) => "omit20:orep",
            Need::Ohist(..) => "omit20:ohist",
            Need::Omk(_) => "omit20:omk",
            Need::Oexp(_) => "omit20:oexp",
            Need::Account(_) => "omit20:account",
            Need::Market(_) => "omit20:market",
            _ => "omit20:other",
        };
        a.rec(kind, r, &o2, &ev2, false);
    }
    // extra valid oracle records: every account's ostk / orm, both markets' orep / omk, every history, every queue
    // group + absent heights around the hook
    let mut n3 = needs.clone();
    let ids: BTreeSet<mnpilot::types::AccountId> = r.pre.accounts.keys().chain(r.pre.oracle_bonds.keys()).copied().collect();
    for id in &ids {
        n3.insert(Need::Ostk(*id));
        n3.insert(Need::Orm(*id));
        n3.insert(Need::Ohist(1, *id));
        n3.insert(Need::Ohist(2, *id));
    }
    for m in [1u32, 2, 99] {
        n3.insert(Need::Orep(m));
        n3.insert(Need::Omk(m));
        n3.insert(Need::Market(m));
    }
    n3.insert(Need::Oglob);
    for u in r.pre.oracle_unbonding.values() {
        n3.insert(Need::Oexp(*u));
    }
    n3.insert(Need::Oexp(h + 256));
    n3.insert(Need::Oexp(h + 1));
    let (o3, ev3) = run(&b.build(&n3));
    a.rec("extra20:valid", r, &o3, &ev3, false);
    if o3.status != 0 {
        a.unsound.push(format!("extra valid oracle records refused: status {} {:?}", o3.status, o3.need));
    }
    // dropped list entries (orep / orm / oexp): the digests bind them -> refused
    for (m, kind) in [(1u8, "forge20:orep-drop"), (2u8, "forge20:orm-drop"), (3u8, "forge20:oexp-drop"), (4u8, "forge20:ohist-samples")] {
        b.t_odrop.set(m);
        let w2 = b.build(needs);
        b.t_odrop.set(0);
        if w2.as_slice() == wit {
            continue;
        }
        let (o2, ev2) = run(&w2);
        a.rec(kind, r, &o2, &ev2, true);
    }
    // forged records under the honest tree / root
    let lay = layout(wit);
    for (kind, p2) in ora_forges(&r.pre, needs) {
        let bf = WitBuilder::new(&p2);
        let forged = bf.build(needs);
        let lay_f = layout(&forged);
        let mut wf = wit[..lay.tree_end].to_vec();
        wf.extend_from_slice(&forged[lay_f.tree_end..]);
        if wf.as_slice() == wit {
            continue;
        }
        let (o2, ev2) = run(&wf);
        a.rec(kind, r, &o2, &ev2, true);
    }
    // byte flips in the record area
    for _ in 0..3 {
        if wit.len() <= lay.tree_end {
            break;
        }
        let mut w2 = wit.to_vec();
        let i = lay.tree_end + rng.below((wit.len() - lay.tree_end) as u64) as usize;
        w2[i] ^= 1 << rng.below(8);
        let (o4, ev4) = run(&w2);
        a.rec("flip20:records", r, &o4, &ev4, false);
    }
}

/// slpoc20 (round 20 PoCs / regression, stateless oracle):
///  P1 R20-M2: 20 bonded oracles unstake at one height: the first SL_MAX_UNSTAKES (16) start unbonding, the rest are
///     refused (code 19, stateless bound); events + end root = direct (the first 16 units)
///  P2 R19-I2 / R20-M1 / R20-M3: at the unlock height the hook releases the 16 oracles, each with entries in 16 DISTINCT
///     markets (256 markets: the R20-M3 worst case = SL_MAX_MARKETS) -> one report-set record per market (round-20 first
///     form: one ohist: record per (market, oracle)); end root = the session hook (prune_oracle_unbonding) on the full
///     state; mkx `oracled` of the 256 markets flips
///  P3 the expiry witness without a released oracle's ostk: / without oglob: / with a group entry dropped / with a report
///     set entry dropped -> refused
///  P4 / P5 SL_MAX_REPORTERS / SL_MAX_ORACLE_MKTS refusals (code 19) = direct; migration bound
pub fn slpoc20() -> String {
    use mnpilot::types::{AccountId as A, MarketId as M};
    let mut res: Vec<String> = Vec::new();
    let mut all_ok = true;
    let id = |i: u32| A(acct_id(i).0);
    let h0: u64 = 1_000;
    let nu = sl::ora::SL_MAX_UNSTAKES as u32;
    let nm = sl::ora::SL_MAX_ORACLE_MKTS as u32;
    let mut s = mnpilot::state::ChainState::genesis();
    for m in 2..=nu * nm {
        s.markets.insert(M(m), s.markets[&M(1)]);
        s.books.insert(M(m), mnpilot::book::OrderBook::new(M(m)));
    }
    for i in 0..nu + 4 {
        s.oracle_bonds.insert(id(100 + i), mnpilot::types::ORACLE_BOND_PERP);
        if i < nu {
            for k in 1..=nm {
                let m = i * nm + k;
                s.oracle_reports.insert((M(m), id(100 + i)), MID + i as i64);
                let mut q = std::collections::VecDeque::new();
                q.push_back(mnpilot::types::ReportSample { height: h0 - 1, price: MID + i as i64, seq: i as u64 });
                s.oracle_report_history.insert((M(m), id(100 + i)), q);
            }
        }
    }
    s.height = h0;
    let _ = s.take_dirty();
    let table: Vec<u32> = (100..100 + nu + 4).collect();
    let ops: Vec<[u32; 8]> = (0..nu + 4).map(w_unstake).collect();
    let seg = seg_words(&table, &ops);
    // ---- P1 ----
    let b = WitBuilder::new(&s);
    let p1 = operate_h(&b, &seg, Some(h0));
    let (post16, ev16) = direct(&s, &seg_words(&table, &ops[..nu as usize]));
    let mut want_ev = ev16.clone();
    want_ev.extend(std::iter::repeat(mnpilot::STATE_CAP_CODE).take(4));
    let (st1, root1, ev1, wb1) = match &p1 {
        Ok((_, wit, o, ev, _)) => (o.status, o.end_root == sl::s_root(&post16), *ev == want_ev, wit.len()),
        Err(_) => (99, false, false, 0),
    };
    let ok1 = st1 == 0 && root1 && ev1 && post16.oracle_unbonding.len() == nu as usize;
    all_ok &= ok1;
    res.push(format!("{{\"case\":\"P1 R20-M2 {} unstakes at one height: {} start unbonding, 4 refused (19)\",\"ok\":{},\"status\":{},\"root_ok\":{},\"ev_ok\":{},\"witness_bytes\":{}}}", nu + 4, nu, ok1, st1, root1, ev1, wb1));
    // ---- P2: the hook at the unlock height (an empty run) ----
    let u = h0 + mnpilot::types::ORACLE_UNBOND_HEIGHTS;
    let pre2 = post16.clone();
    let mut want = pre2.clone();
    want.height = u;
    want.prune_oracle_unbonding(u);
    let _ = want.take_dirty();
    let empty = seg_words(&table, &[]);
    let b2 = WitBuilder::new(&pre2);
    let p2 = operate_h(&b2, &empty, Some(u));
    let orc_flip = (1..=nu * nm).all(|m| sl::oracled(&pre2, M(m)) && !sl::oracled(&want, M(m)));
    let (st2, root2, wb2, nrec, nmk) = match &p2 {
        Ok((needs, wit, o, _, _)) => (o.status, o.end_root == sl::s_root(&want), wit.len(), needs.iter().filter(|n| matches!(n, Need::Orep(_))).count(), needs.iter().filter(|n| matches!(n, Need::Market(_))).count()),
        Err(e) => {
            res.push(format!("{{\"case\":\"P2 operator\",\"error\":\"{}\"}}", e));
            (99, false, 0, 0, 0)
        }
    };
    let ok2 = st2 == 0 && root2 && orc_flip && want.oracle_bonds.len() == 4 && nrec == (nu * nm) as usize;
    all_ok &= ok2;
    res.push(format!("{{\"case\":\"P2 R19-I2 / R20-M1 / R20-M3 hook releases {} oracles x {} distinct markets: one report-set record per market\",\"ok\":{},\"status\":{},\"root_ok\":{},\"oracled_flipped\":{},\"orep_records\":{},\"market_records\":{},\"witness_bytes\":{}}}", nu, nm, ok2, st2, root2, orc_flip, nrec, nmk, wb2));
    // ---- P3: incomplete / forged expiry witnesses ----
    if let Ok((needs, wit, _, _, _)) = &p2 {
        let mut refused = 0;
        let mut runs = 0;
        let mut wrong = 0;
        let mut cases: Vec<BTreeSet<Need>> = Vec::new();
        if let Some(x) = needs.iter().find(|n| matches!(n, Need::Ostk(_))) {
            let mut n2 = needs.clone();
            n2.remove(x);
            cases.push(n2);
        }
        let mut n3 = needs.clone();
        n3.remove(&Need::Oglob);
        cases.push(n3);
        for n2 in &cases {
            runs += 1;
            let (o, _) = run_sl_xh(&empty, &b2.build(n2), Some(&b2.root), Some(u));
            if o.status != 0 {
                refused += 1;
            } else if o.end_root != sl::s_root(&want) {
                wrong += 1;
            }
        }
        for m in [1u8, 3] {
            b2.t_odrop.set(m);
            let w2 = b2.build(needs);
            b2.t_odrop.set(0);
            if w2 == *wit {
                continue;
            }
            runs += 1;
            let (o, _) = run_sl_xh(&empty, &w2, Some(&b2.root), Some(u));
            if o.status != 0 {
                refused += 1;
            } else if o.end_root != sl::s_root(&want) {
                wrong += 1;
            }
        }
        let ok3 = runs == refused && wrong == 0 && runs == 4;
        all_ok &= ok3;
        res.push(format!("{{\"case\":\"P3 expiry witness: ostk / oglob omitted, report-set / group entry dropped\",\"ok\":{},\"runs\":{},\"refused\":{},\"wrong\":{}}}", ok3, runs, refused, wrong));
    }
    // ---- P4: the stateless report bounds (code 19): a 65th reporter in a market, a 17th market for an oracle ----
    {
        let mut s4 = mnpilot::state::ChainState::genesis();
        for m in 2..=nm + 1 {
            s4.markets.insert(M(m), s4.markets[&M(1)]);
            s4.books.insert(M(m), mnpilot::book::OrderBook::new(M(m)));
        }
        for i in 0..65u32 {
            s4.oracle_bonds.insert(id(100 + i), mnpilot::types::ORACLE_BOND_PERP);
        }
        for i in 0..64u32 {
            s4.oracle_reports.insert((M(1), id(100 + i)), MID);
        }
        for m in 2..=nm {
            s4.oracle_reports.insert((M(m), id(100)), MID);
        }
        s4.height = h0;
        let _ = s4.take_dirty();
        let table: Vec<u32> = vec![164, 101, 100];
        // 65th reporter in market 1 (refused), an existing reporter of market 1 (applied), oracle 100 (entries in
        // SL_MAX_ORACLE_MKTS markets) in one of them (applied)
        let ops = vec![w_report(0, MID, 1), w_report(1, MID + 1, 1), w_report(2, MID, 1)];
        let seg4 = seg_words(&table, &ops);
        let b4 = WitBuilder::new(&s4);
        let r4 = operate_h(&b4, &seg4, Some(h0));
        let (post4, ev_d) = direct(&s4, &seg_words(&table, &ops[1..]));
        let mut want = vec![mnpilot::STATE_CAP_CODE];
        want.extend(ev_d);
        let (st, root_ok, ev_ok) = match &r4 {
            Ok((_, _, o, ev, _)) => (o.status, o.end_root == sl::s_root(&post4), *ev == want),
            Err(_) => (99, false, false),
        };
        // an oracle with entries in SL_MAX_ORACLE_MKTS markets reports in one more (refused); another oracle there (applied)
        let s5 = s4.clone();
        let seg5 = seg_words(&[100, 101], &[w_report(0, MID, nm + 1), w_report(1, MID, nm + 1)]);
        let b5 = WitBuilder::new(&s5);
        let r5 = operate_h(&b5, &seg5, Some(h0));
        let (post5, ev5d) = direct(&s5, &seg_words(&[101], &[w_report(0, MID, nm + 1)]));
        let mut want5 = vec![mnpilot::STATE_CAP_CODE];
        want5.extend(ev5d);
        let (st5, root5, ev5ok) = match &r5 {
            Ok((_, _, o, ev, _)) => (o.status, o.end_root == sl::s_root(&post5), *ev == want5),
            Err(_) => (99, false, false),
        };
        let ok4 = st == 0 && root_ok && ev_ok && st5 == 0 && root5 && ev5ok;
        all_ok &= ok4;
        res.push(format!("{{\"case\":\"P4 SL_MAX_REPORTERS / SL_MAX_ORACLE_MKTS: 65th reporter, 17th market refused (19)\",\"ok\":{},\"status\":[{},{}],\"root_ok\":[{},{}],\"ev_ok\":[{},{}]}}", ok4, st, st5, root_ok, root5, ev_ok, ev5ok));
        // migration bound: the same state as a migration input would hold a 65-entry report set
        let mut s6 = s4.clone();
        s6.oracle_reports.insert((M(1), id(164)), MID);
        let ok6 = !sl::ora::mig_ok(&s6) && sl::ora::mig_ok(&s4);
        all_ok &= ok6;
        res.push(format!("{{\"case\":\"P5 migration bound (65 reporters in a market)\",\"ok\":{}}}", ok6));
    }
    // ---- P7 R20-L1: the session image refuses the 17th unstake at one height too (state_cap_ok, code 19) ----
    {
        let mut s7 = s.clone();
        for i in 0..nu {
            s7.oracle_unbonding.insert(id(100 + i), h0 + mnpilot::types::ORACLE_UNBOND_HEIGHTS);
        }
        let op = mnpilot::BatchOp::Unstake { acct: 0 };
        let full = !mnpilot::state_cap_ok(&s7, &op, id(100 + nu), 256);
        s7.oracle_unbonding.remove(&id(100));
        let room = mnpilot::state_cap_ok(&s7, &op, id(100 + nu), 256);
        // an already unbonding / unbonded author is not counted (upstream's Unbonding / NotBonded)
        let other = mnpilot::state_cap_ok(&s7, &op, id(101), 256) && mnpilot::state_cap_ok(&s7, &op, id(999), 256);
        let ok7 = full && room && other;
        all_ok &= ok7;
        res.push(format!("{{\"case\":\"P7 R20-L1 session state_cap_ok: 17th unstake at one height refused, 16th allowed\",\"ok\":{}}}", ok7));
    }
    // ---- P8: revealed oracle ops (non-bound session reference): an inner Report / Stake / Unstake runs with its guards,
    // an inner Slash is unsupported (its target guard runs on the op only) ----
    {
        use crate::gov::GB;
        let mut g = GB::new(12, mnpilot::ORACLES_FLAG | mnpilot::PERP_FLAG);
        let mut st8: Vec<(&str, u32)> = Vec::new();
        let inners: [(&str, [u32; 8]); 4] = [("report", w_report(4, MID, 1)), ("stake", w_stake(4)), ("unstake", w_unstake(4)), ("slash", w_slash(4, 1, 1))];
        // heights 1..=3 (SetHeight fixture, session-only segments): oracles 2, 3 report mid, oracle 1 reports 8 % above:
        // a slashable streak of oracle 1 at height 3; account 4 holds PERP (commit bond)
        for h in 1..=3u64 {
            g.op(GB::w_height(h));
            g.op(w_report(2, MID, 1));
            g.op(w_report(3, MID, 1));
            g.op(w_report(1, MID + MID / 12, 1));
        }
        for (k, (_, inner)) in inners.iter().enumerate() {
            let mut salt = [0u8; 32];
            salt[0] = k as u8 + 1;
            let hash = g.commit_hash_any(inner, &salt);
            let w = g.w_commit(4, &hash, 5);
            g.op(w);
            let cu = *g.uids.last().unwrap();
            let p1 = g.last();
            let w = g.w_reveal(4, &hash, &salt, inner, p1, cu);
            g.op(w);
        }
        let w = g.words();
        let refs = session_refs_v2(&w, 1);
        let mut ok8 = true;
        let mut nrev = 0usize;
        let mut slash_applied = false;
        for r in refs.iter() {
            let kd = r.seg[4 + 8 * r.seg[1] as usize] & 0xff;
            if kd != 20 && kd != 21 {
                continue;
            }
            let b = WitBuilder::new(&r.pre);
            let res = operate(&b, &r.seg);
            let stt = match &res {
                Ok((_, _, o, ev, _)) if o.status == 0 && (o.end_root != r.post_root || *ev != r.ev) => 98,
                Ok((_, _, o, _, _)) => o.status,
                Err(_) => 99,
            };
            if kd == 21 {
                st8.push((inners[nrev].0, stt));
                if nrev == 3 {
                    ok8 &= stt == sl::ST_SL_UNSUPPORTED;
                    slash_applied = r.ev.first().is_some_and(|e| e & EV_APPLIED != 0);
                } else {
                    ok8 &= stt == 0;
                }
                nrev += 1;
            } else {
                ok8 &= stt == 0;
            }
        }
        ok8 &= nrev == 4 && slash_applied;
        all_ok &= ok8;
        res.push(format!("{{\"case\":\"P8 revealed oracle ops: inner report (rejected) / stake / unstake proven = session, inner slash unsupported\",\"ok\":{},\"reveal_status\":{:?},\"session_slash_applied\":{}}}", ok8, st8, slash_applied));
    }
    // ---- P6: Slash (step 3): X deviates 8 % for 3 consecutive heights in market 1 and also reports in market 2 (sole
    // reporter: `oracled` flips), X is unbonding alone in the queue head (the group is unlinked); Y (honest) cannot be
    // slashed; the challenger is a fresh id (its acct: key is created by the reward)
    {
        let mut s6 = mnpilot::state::ChainState::genesis();
        s6.markets.insert(M(2), s6.markets[&M(1)]);
        s6.books.insert(M(2), mnpilot::book::OrderBook::new(M(2)));
        let (x, y) = (id(100), id(101));
        for o in [x, y] {
            s6.oracle_bonds.insert(o, mnpilot::types::ORACLE_BOND_PERP);
        }
        s6.oracle_unbonding.insert(x, h0 + 100);
        s6.oracle_unbonding.insert(y, h0 + 200);
        let dev = MID + MID / 12;
        s6.oracle_reports.insert((M(1), x), dev);
        s6.oracle_reports.insert((M(2), x), MID);
        s6.oracle_reports.insert((M(1), y), MID);
        let mut q = std::collections::VecDeque::new();
        for k in 0..3u64 {
            q.push_back(mnpilot::types::ReportSample { height: h0 - 2 + k, price: dev, seq: k });
        }
        s6.oracle_report_history.insert((M(1), x), q);
        let mut qy = std::collections::VecDeque::new();
        qy.push_back(mnpilot::types::ReportSample { height: h0, price: MID, seq: 9 });
        s6.oracle_report_history.insert((M(1), y), qy);
        let mut tw = std::collections::VecDeque::new();
        for k in 0..5u64 {
            tw.push_back(mnpilot::types::TwapSample { seq: k, height: h0 - 4 + k, median: MID });
        }
        s6.oracle_twap.insert(M(1), tw);
        s6.perp_supply = 10 * mnpilot::types::ORACLE_BOND_PERP;
        s6.height = h0;
        let _ = s6.take_dirty();
        let seg6 = seg_words(&[200, 100, 101], &[w_slash(0, 2, 1), w_slash(0, 1, 1), w_slash(0, 1, 2)]);
        let (post6, ev6d) = direct(&s6, &seg6);
        let b6 = WitBuilder::new(&s6);
        let r6 = operate_h(&b6, &seg6, Some(h0));
        let (st, root_ok, ev_ok, wb) = match &r6 {
            Ok((_, wit, o, ev, _)) => (o.status, o.end_root == sl::s_root(&post6), *ev == ev6d, wit.len()),
            Err(_) => (99, false, false, 0),
        };
        let applied = ev6d.get(1).is_some_and(|e| e & EV_APPLIED != 0) && ev6d[0] & EV_APPLIED == 0;
        let flip = sl::oracled(&s6, M(2)) && !sl::oracled(&post6, M(2)) && !post6.oracle_unbonding.contains_key(&x);
        let ok = st == 0 && root_ok && ev_ok && applied && flip;
        all_ok &= ok;
        res.push(format!("{{\"case\":\"P6 Slash: honest Y refused, deviant X slashed (queue head unlinked, market 2 oracled flips, challenger reward), X again refused\",\"ok\":{},\"status\":{},\"root_ok\":{},\"ev_ok\":{},\"ev\":{:?},\"witness_bytes\":{}}}", ok, st, root_ok, ev_ok, ev6d, wb));
        // ---- P9 (round-20 closing, kills pass-2 survivor pre-slash-omk-off): every single omission from the P6 witness
        // -- the honest operator's guess supplies `omk:` for a Slash, so only a forged witness can leave it out; a
        // Slash of X without its market's TWAP would be refused (SlashNotEligible) with status 0 -> wrong
        if let Ok((needs, _, _, _, _)) = &r6 {
            let (mut runs, mut refused, mut wrong) = (0u32, 0u32, 0u32);
            let mut wrong_kinds: Vec<String> = Vec::new();
            for nd in needs.iter() {
                let mut n2 = needs.clone();
                n2.remove(nd);
                runs += 1;
                let (o, ev) = run_sl_xh(&seg6, &b6.build(&n2), Some(&b6.root), Some(h0));
                if o.status != 0 {
                    refused += 1;
                } else if o.end_root != sl::s_root(&post6) || ev != ev6d {
                    wrong += 1;
                    wrong_kinds.push(format!("{:?}", nd));
                }
            }
            let ok9 = wrong == 0 && runs > 0 && needs.contains(&Need::Omk(1));
            all_ok &= ok9;
            res.push(format!("{{\"case\":\"P9 single omissions from the P6 (Slash) witness: refused or identical\",\"ok\":{},\"runs\":{},\"refused\":{},\"wrong\":{},\"wrong_needs\":{:?}}}", ok9, runs, refused, wrong, wrong_kinds));
        }
    }
    format!("{{\"ok\":{},\"cases\":[{}]}}", all_ok, res.join(",\n"))
}

/// round 22 PoCs. P0 (round-21 close-out, kills mutant end-del-off): a fill that flattens the ONLY long and the ONLY
/// short holder of a market empties both rank sub-trees present at segment start -> both `adlr:` leaves must be
/// deleted (end root = direct, status 0).
pub fn slpoc22_p0() -> String {
    use mnpilot::types::{AccountId as A, MarketId as M, Side};
    let mut s = mnpilot::state::ChainState::genesis();
    let id = |i: u32| A(acct_id(i).0);
    let q = (QTY_SCALE / 10) as i64;
    let px = MID;
    for (i, qty) in [(0u32, q), (1, -q)] {
        let mut a = mnpilot::account::Account::new(id(i));
        a.collateral = 1_000_000_000 * USD_SCALE as i128;
        a.positions.insert(M(1), mnpilot::account::Position { market: M(1), qty, entry_price: MID, isolated: false });
        s.put_account(id(i), a);
    }
    // B (short) rests a bid of q: A's IOC ask fills it -> A flat, B flat
    let oid = mnpilot::types::order_id(id(1), M(1), 1);
    s.book_mut(M(1)).sl_restore(mnpilot::Order {
        id: oid, account: id(1), market: M(1), side: Side::Bid, typ: mnpilot::types::OrderType::Limit,
        tif: mnpilot::types::TimeInForce::Gtc, price: px, qty: q as u64, remaining: q as u64, seq: 0, isolated: false, margin_left: 0,
    });
    s.seen_client_seq.insert(id(1), 1);
    let _ = s.take_dirty();
    let pre_trees = sl::adl::sets(&s).len();
    let op = [2u32, 1 | 4, px as u32, (px >> 32) as u32, q as u32, ((q as u64) >> 32) as u32, 1, 1];
    let w = seg_words(&[0, 1], &[op]);
    check15("P0 both rank sub-trees emptied (adlr: leaves deleted)", &s, &w, &|post: &mnpilot::state::ChainState, o: &sl::SlOut, _| {
        pre_trees == 2 && sl::adl::sets(post).is_empty() && o.dels.len() >= 2
    })
}

/// MNP2 batch (unit ids + extension words) for synthetic segments
fn seg_words2(table: &[u32], ops: &[[u32; 8]], ext: &[u32]) -> Vec<u32> {
    let mut w = vec![mnpilot::MAGIC2, table.len() as u32, ops.len() as u32, 0];
    for t in table {
        let x = acct_id(*t);
        for k in 0..8 {
            w.push(u32::from_le_bytes(x.0[k * 4..k * 4 + 4].try_into().unwrap()));
        }
    }
    for o in ops {
        w.extend_from_slice(o);
    }
    for i in 0..ops.len() {
        let mut u = [0u8; 32];
        u[..8].copy_from_slice(&(0x22C0_DE00_0000u64 + i as u64).to_le_bytes());
        u[31] = 0x22;
        for k in 0..8 {
            w.push(u32::from_le_bytes(u[k * 4..k * 4 + 4].try_into().unwrap()));
        }
    }
    w.push(ext.len() as u32);
    w.extend_from_slice(ext);
    w
}

/// the SESSION image (state_cap_ok with account cap `cap`, MAX_STATE_MARKETS / MAX_STATE_ORACLES) on one segment from
/// an arbitrary pre-state: (post state, events)
pub fn sess_seg(pre: &mnpilot::state::ChainState, w: &[u32], cap: usize) -> (mnpilot::state::ChainState, Vec<u32>) {
    let eng = mnpilot::engine::Engine { state: pre.clone() };
    let wt = mnpilot::wit::Wit::from_state(&eng.state);
    let mut sess = Some(mnpilot::Session { eng, w: Some(wt), mode: mnpilot::WitMode::Incremental, segs: 1, state_cap: cap, bind_height: false });
    let mut ev = Vec::new();
    let (_, st, _) = mnpilot::run_segment(&mut |i| w.get(i as usize).copied().unwrap_or(0), &mut |x| ev.push(x), &mut |_, _, _| {}, mnpilot::WitMode::Incremental, &mut sess);
    assert_eq!(st.status, 0);
    let mut s = sess.unwrap().eng.state;
    let _ = s.take_dirty();
    (s, ev)
}

fn ev_units(ev: &[u32]) -> Vec<String> {
    let mut out = Vec::new();
    let mut k = 0;
    while k < ev.len() {
        let e = ev[k];
        if e & EV_APPLIED != 0 {
            let nf = (e & 0xff) as usize;
            out.push(format!("applied/{}", nf));
            k += 1 + 6 * nf;
        } else {
            out.push(e.to_string());
            k += 1;
        }
    }
    out
}

/// round 22: stateless global caps (R16-I3 / R17-I3, `gcnt:0`).
///  P0 (round-21 close-out) both rank sub-trees emptied -> adlr: leaves deleted (kills end-del-off);
///  P1 at the caps: a pre-state one below each session cap (accounts / PERP ids: `cap`; markets MAX_STATE_MARKETS;
///     oracle bonds MAX_STATE_ORACLES), a segment of first credits / listings / stakes by new and existing ids
///     (Deposit, Liquidate keeper, GovDeposit, GovWithdraw, Slash challenger, CreateMarket, Stake) -> the stateless image
///     with SL_CAPS = the session's caps must equal the SESSION image (root + events, code 19 where it refuses), the
///     same segment one below the caps (cap + 1 room) too;
///  P2 forged `gcnt:0` counts (t_gdrop 1-4) and the omission of the Gcnt need -> refused;
///  P3 the production caps (SL_CAPS_PROD: Account map / PERP ledger uncapped, R22-M1; listings 2^16, bonds 2^12): the
///     first credits agree with a session at a large account cap; the listing / stake the session's constants refuse
///     run in the lineage (lifted caps, design §5).
pub fn slpoc22() -> String {
    use crate::gov::{listing_regular, GB};
    use mnpilot::types::{AccountId as A, MarketId as M};
    let mut res: Vec<String> = vec![slpoc22_p0()];
    let id = |i: u32| A(acct_id(i).0);
    // pre-state
    let mk_pre = |cap: usize| -> mnpilot::state::ChainState {
        let mut s = mnpilot::state::ChainState::genesis();
        let mut a0 = mnpilot::account::Account::new(id(0));
        a0.collateral = 1_000_000 * USD_SCALE as i128;
        a0.positions.insert(M(1), mnpilot::account::Position { market: M(1), qty: (QTY_SCALE / 100) as i64, entry_price: MID, isolated: false });
        s.put_account(id(0), a0);
        let big: u128 = 10_000_000;
        s.perp_balances.insert(id(0), big);
        s.perp_supply += big;
        // fillers up to cap - 1 (the session's one `cap` for the Account map and the PERP ledger)
        let mut i = 0u32;
        while s.accounts.len() < cap - 1 {
            let mut a = mnpilot::account::Account::new(id(50_000 + i));
            a.collateral = USD_SCALE as i128;
            s.put_account(id(50_000 + i), a);
            i += 1;
        }
        let mut i = 0u32;
        while s.perp_balances.len() < cap - 1 {
            s.perp_balances.insert(id(60_000 + i), 1);
            s.perp_supply += 1;
            i += 1;
        }
        let p0 = mnpilot::types::genesis_params();
        let mut m = 1000u32;
        while s.markets.len() < mnpilot::MAX_STATE_MARKETS - 1 {
            s.markets.insert(M(m), p0);
            s.marks.insert(M(m), MID);
            m += 1;
        }
        let mut i = 0u32;
        while s.oracle_bonds.len() < mnpilot::MAX_STATE_ORACLES - 1 {
            s.oracle_bonds.insert(id(70_000 + i), mnpilot::types::ORACLE_BOND_PERP);
            i += 1;
        }
        let _ = s.take_dirty();
        s
    };
    // table: 0 funded existing (creator / staker), 1 2 3 new ids
    let table = [0u32, 1, 2, 3];
    let mut ext: Vec<u32> = Vec::new();
    let l = listing_regular("ZZZ");
    ext.extend_from_slice(&l);
    let l2 = listing_regular("ZZY");
    ext.extend_from_slice(&l2);
    let ops: Vec<[u32; 8]> = vec![
        GB::w_dep(1, 1_000 * USD_SCALE as i64),               // new id: fits (accounts cap - 1 -> cap)
        GB::w_dep(2, 1_000 * USD_SCALE as i64),               // new id at the cap -> 19
        GB::w_dep(0, 1_000 * USD_SCALE as i64),               // member -> applied
        [7 | (3 << 8), 0, 0, 0, 0, 0, 0, 1],                  // Liquidate by a new keeper (R17-I3) at the cap -> 19
        GB::w_gdep(2, 60_000),                                // new PERP id: fits (ledger cap - 1 -> cap)
        GB::w_gdep(3, 60_000),                                // new PERP id at the cap -> 19
        GB::w_gwd(3, 5, 1),                                   // GovWithdraw by a non-member at the cap -> 19
        w_slash(3, 0, 1),                                     // Slash challenger new at the cap -> 19
        [16, 0, 0, 0, 0, 0, 0, 0],                            // CreateMarket (markets cap - 1 -> cap)
        [16, 0, 0, 0, 0, 0, 0, l.len() as u32],               // CreateMarket at the cap -> 19
        w_stake(0),                                           // Stake: bonds cap - 1 -> cap
        w_stake(2),                                           // Stake by a new oracle at the cap -> 19
        GB::w_dep(1, 5 * USD_SCALE as i64),                   // member now -> applied
    ];
    let w = seg_words2(&table, &ops, &ext);
    let set_caps = |c: sl::SlCaps| unsafe { sl::SL_CAPS = c };
    for (name, cap) in [("P1 at the caps", 12usize), ("P1 one below the caps (room + 1)", 13usize)] {
        // the pre-state is one below every cap at cap 12; at cap 13 the Account map / PERP ledger have one more slot
        // (markets / oracle bonds: the session's constants in both)
        let pre = mk_pre(12);
        let (post, ev_s) = sess_seg(&pre, &w, cap);
        let room = cap - 12;
        set_caps(sl::SlCaps { accounts: cap as u64, markets: mnpilot::MAX_STATE_MARKETS as u64, oracles: mnpilot::MAX_STATE_ORACLES as u64, commits: mnpilot::MAX_STATE_COMMITS as u64, commit_group: mnpilot::MAX_STATE_COMMITS as u64 });
        let b = WitBuilder::new(&pre);
        let r = operate(&b, &w);
        set_caps(sl::SL_CAPS_PROD);
        let (line, needs) = match r {
            Ok((needs, wit, o, ev, _)) => {
                let ok = o.status == 0 && o.end_root == sl::s_root(&post) && ev == ev_s;
                let caps19 = ev_units(&ev_s).iter().filter(|x| *x == "19").count();
                (format!("{{\"case\":\"{}\",\"ok\":{},\"status\":{},\"root_ok\":{},\"ev_ok\":{},\"session\":{:?},\"stateless\":{:?},\"session_19\":{},\"gcnt_needed\":{},\"witness_bytes\":{}}}", name, ok && (room > 0 || caps19 == 7), o.status, o.end_root == sl::s_root(&post), ev == ev_s, ev_units(&ev_s), ev_units(&ev), caps19, needs.contains(&Need::Gcnt), wit.len()), Some((needs, pre.clone())))
            }
            Err(e) => (format!("{{\"case\":\"{}\",\"ok\":false,\"why\":\"{}\",\"session\":{:?}}}", name, e, ev_units(&ev_s)), None),
        };
        res.push(line);
        // P2: forged counts / omission (at the caps)
        if let (Some((needs, pre)), 12) = (needs, cap) {
            set_caps(sl::SlCaps { accounts: cap as u64, markets: mnpilot::MAX_STATE_MARKETS as u64, oracles: mnpilot::MAX_STATE_ORACLES as u64, commits: mnpilot::MAX_STATE_COMMITS as u64, commit_group: mnpilot::MAX_STATE_COMMITS as u64 });
            let b = WitBuilder::new(&pre);
            let (mut runs, mut refused, mut wrong) = (0u32, 0u32, 0u32);
            for t in 1u8..=4 {
                b.t_gdrop.set(t);
                let wf = b.build(&needs);
                b.t_gdrop.set(0);
                runs += 1;
                let (o, ev) = run_sl_x(&w, &wf, Some(&b.root));
                if o.status != 0 {
                    refused += 1;
                } else if o.end_root != sl::s_root(&post) || ev != ev_s {
                    wrong += 1;
                }
            }
            let mut n2 = needs.clone();
            n2.remove(&Need::Gcnt);
            runs += 1;
            let (o, ev) = run_sl_x(&w, &b.build(&n2), Some(&b.root));
            if o.status != 0 {
                refused += 1;
            } else if o.end_root != sl::s_root(&post) || ev != ev_s {
                wrong += 1;
            }
            // an adversarial operator that never supplies gcnt:0
            let (o, ev) = operate_deny(&b, &w, &|n: &Need| *n == Need::Gcnt);
            runs += 1;
            if o.status != 0 {
                refused += 1;
            } else if o.end_root != sl::s_root(&post) || ev != ev_s {
                wrong += 1;
            }
            set_caps(sl::SL_CAPS_PROD);
            res.push(format!("{{\"case\":\"P2 forged gcnt / omission\",\"ok\":{},\"runs\":{},\"refused\":{},\"wrong\":{}}}", wrong == 0 && refused == runs, runs, refused, wrong));
        }
    }
    // P4: capped units by non-members that fail anyway below the cap (Liquidate of a healthy target, GovWithdraw beyond
    // the balance) and change no count: only the cap check itself needs gcnt:0 (its omission must not turn the session's
    // 19 into the engine's error code); the pre-state is AT the account cap (11 = cap)
    {
        let pre = mk_pre(12);
        let w4 = seg_words2(&table, &[[7 | (3 << 8), 0, 0, 0, 0, 0, 0, 1], GB::w_gwd(3, 5, 1)], &[]);
        let (post, ev_s) = sess_seg(&pre, &w4, 11);
        set_caps(sl::SlCaps { accounts: 11, markets: mnpilot::MAX_STATE_MARKETS as u64, oracles: mnpilot::MAX_STATE_ORACLES as u64, commits: mnpilot::MAX_STATE_COMMITS as u64, commit_group: mnpilot::MAX_STATE_COMMITS as u64 });
        let b = WitBuilder::new(&pre);
        let r = operate(&b, &w4);
        let (od, evd) = operate_deny(&b, &w4, &|n: &Need| *n == Need::Gcnt);
        set_caps(sl::SL_CAPS_PROD);
        let line = match r {
            Ok((needs, _, o, ev, _)) => {
                let ok = o.status == 0 && o.end_root == sl::s_root(&post) && ev == ev_s && ev_units(&ev_s) == ["19", "19"] && needs.contains(&Need::Gcnt);
                let deny_ok = od.status != 0 || (od.end_root == sl::s_root(&post) && evd == ev_s);
                format!("{{\"case\":\"P4 failing capped units at the cap (no count change)\",\"ok\":{},\"session\":{:?},\"stateless\":{:?},\"deny_gcnt_status\":{}}}", ok && deny_ok, ev_units(&ev_s), ev_units(&ev), od.status)
            }
            Err(e) => format!("{{\"case\":\"P4\",\"ok\":false,\"why\":\"{}\"}}", e),
        };
        res.push(line);
    }
    // P5: a Reveal whose INNER op is a capped unit by the (non-member) author at the cap: the session runs state_cap_ok on
    // the decoded inner op with the author whether or not it would run (here its commit does not even exist) -> 19
    {
        let pre = mk_pre(12);
        let mut ext5: Vec<u32> = Vec::new();
        for x in [[0x5Au8; 32], [0x5Bu8; 32]] {
            for k in 0..8 {
                ext5.push(u32::from_le_bytes(x[k * 4..k * 4 + 4].try_into().unwrap()));
            }
        }
        ext5.extend_from_slice(&GB::w_dep(3, 7 * USD_SCALE as i64));
        ext5.extend_from_slice(&[0u32; 16]);
        let w5 = seg_words2(&table, &[[21 | (3 << 8), 0, 0, 0, 0, 0, 0, 0], [21 | (3 << 8), 0, 0, 0, 0, 0, 0, 0]], &ext5);
        let (post, ev_s) = sess_seg(&pre, &w5, 11);
        set_caps(sl::SlCaps { accounts: 11, markets: mnpilot::MAX_STATE_MARKETS as u64, oracles: mnpilot::MAX_STATE_ORACLES as u64, commits: mnpilot::MAX_STATE_COMMITS as u64, commit_group: mnpilot::MAX_STATE_COMMITS as u64 });
        let b = WitBuilder::new(&pre);
        let r = operate(&b, &w5);
        let (od, evd) = operate_deny(&b, &w5, &|n: &Need| *n == Need::Gcnt);
        set_caps(sl::SL_CAPS_PROD);
        let (post12, ev12) = sess_seg(&pre, &w5, 12);
        let line = match r {
            Ok((needs, _, o, ev, _)) => {
                let ok = o.status == 0 && o.end_root == sl::s_root(&post) && ev == ev_s && ev_units(&ev_s) == ["19", "19"] && needs.contains(&Need::Gcnt) && ev_units(&ev12)[0] != "19";
                let deny_ok = od.status != 0 || (od.end_root == sl::s_root(&post) && evd == ev_s);
                let _ = post12;
                format!("{{\"case\":\"P5 Reveal with a capped inner op (author at the cap)\",\"ok\":{},\"session\":{:?},\"session_below_cap\":{:?},\"stateless\":{:?},\"deny_gcnt_status\":{}}}", ok && deny_ok, ev_units(&ev_s), ev_units(&ev12), ev_units(&ev), od.status)
            }
            Err(e) => format!("{{\"case\":\"P5\",\"ok\":false,\"why\":\"{}\"}}", e),
        };
        res.push(line);
    }
    // P3: production caps: accounts / PERP ids lifted -> no 19 for the first credits (the session at a large cap agrees
    // on those; markets / oracles: the session's constants still refuse, the lineage does not -- by design)
    {
        let pre = mk_pre(12);
        let (post, ev_s) = sess_seg(&pre, &w, 1 << 20);
        let b = WitBuilder::new(&pre);
        match operate(&b, &w) {
            Ok((_, _, o, ev, _)) => {
                let su = ev_units(&ev_s);
                let tu = ev_units(&ev);
                // units 0..8 (accounts / PERP ids) must agree; the listing / stake at the session constants differ
                let same = su[..8] == tu[..8];
                let lifted = tu[9] != "19" && tu[11] != "19" && su[9] == "19" && su[11] == "19";
                let _ = post;
                res.push(format!("{{\"case\":\"P3 production caps (lifted)\",\"ok\":{},\"status\":{},\"session\":{:?},\"stateless\":{:?}}}", o.status == 0 && same && lifted, o.status, su, tu));
            }
            Err(e) => res.push(format!("{{\"case\":\"P3 production caps (lifted)\",\"ok\":false,\"why\":\"{}\"}}", e)),
        }
    }
    let ok = res.iter().all(|l| l.contains("\"ok\":true"));
    format!("{{\"ok\":{},\"cases\":[{}]}}", ok, res.join(","))
}

// ------------------------------------------------------------------------------------------------
// round 23: eager commit expiry (R16-I1 / R22-I2): `cexp:<u>` groups, stale cmt: deletion, MAX_STATE_COMMITS mirrored
// ------------------------------------------------------------------------------------------------
/// the 'cr' workload (MNP2 on the REAL engine, gov::GB, PERP holders 4..9): commit-reveal at BOUND heights -- every
/// segment of `size` units runs at the height of `sched` (orc_sched), so commits are made with TTLs relative to the
/// height they run at (mostly short: they expire within a few heights; some invalid: ttl = height or height + 17),
/// reveals of pending commits (many after their expiry), re-commits of an expired hash by its author or another
/// account, commits by non-holders (bond: code 19), GovDeposits (more bond room), deposits and trades. The generator's
/// real engine follows the heights (prune at every segment start), so reveals are realistic.
pub fn cr_batch(seed: u64, n_ops: u32, size: u32, sched: &[(u64, Option<u64>)]) -> Vec<u32> {
    use crate::gov::GB;
    let mut rng = Rng(seed.wrapping_mul(0xA24B_AED4_963E_E407) | 1);
    let n_acc = 10 + rng.below(6) as u32;
    let mut g = GB::new(n_acc, mnpilot::PERP_FLAG);
    let mid = 100_000 * PRICE_SCALE as i64;
    let dollar = PRICE_SCALE as i64;
    let mut pending: Vec<(u32, [u8; 32], [u8; 32], [u32; 8], [u8; 32])> = Vec::new();
    let mut expired: Vec<(u32, [u8; 32], [u8; 32], [u32; 8])> = Vec::new();
    let height_of = |i: usize| -> u64 {
        let k = (i / size.max(1) as usize).min(sched.len().saturating_sub(1));
        sched[k].0
    };
    let mut cur_h = 0u64;
    let mut gnonce = 1_000u64;
    let mut done = 0u32;
    while done < n_ops {
        let h = height_of(g.ops.len());
        if h > cur_h {
            cur_h = h;
            g.eng.state.height = h;
            g.eng.state.prune_commits(h);
            g.eng.state.prune_withdrawals(h);
            g.eng.state.prune_oracle_unbonding(h);
        }
        done += 1;
        let a = 1 + rng.below((n_acc - 1) as u64) as u32;
        let holder = 4 + rng.below(6) as u32;
        let salt = {
            let mut s = [0u8; 32];
            for k in 0..4 {
                s[8 * k..8 * k + 8].copy_from_slice(&rng.next().to_le_bytes());
            }
            s
        };
        match rng.below(100) {
            0..=39 => {
                let who = if rng.below(8) == 0 { a } else { holder };
                // inner ops the engine runs revealed (Place, GovWithdraw); a Deposit (never an inner kind) now and then
                let inner = match rng.below(10) {
                    0..=6 => {
                        let px = mid + (rng.below(11) as i64 - 5) * dollar * 100;
                        g.w_place(who, rng.below(2) == 0, rng.below(2) == 0, px, QTY_SCALE / 1000, 1)
                    }
                    7 | 8 => {
                        gnonce += 1;
                        GB::w_gwd(who, 1 + rng.below(50), gnonce)
                    }
                    _ => GB::w_dep(who, 5 * USD_SCALE as i64),
                };
                let mut hash = g.commit_hash_any(&inner, &salt);
                if rng.below(15) == 0 {
                    hash[0] ^= 1;
                }
                let ttl = match rng.below(12) {
                    0 => h,
                    1 => h + minuend_types::COMMIT_TTL_HEIGHTS + 1,
                    2 | 3 => h + minuend_types::COMMIT_TTL_HEIGHTS,
                    _ => h + 1 + rng.below(3),
                };
                let w = g.w_commit(who, &hash, ttl);
                g.op(w);
                let uid = *g.uids.last().unwrap();
                pending.push((who, hash, salt, inner, uid));
            }
            40..=69 if !pending.is_empty() => {
                // mostly one of the newest commits (likely still live), sometimes any (likely expired)
                let k = if rng.below(10) < 7 { pending.len() - 1 - rng.below(pending.len().min(3) as u64) as usize } else { rng.below(pending.len() as u64) as usize };
                let (ca, hash, salt, inner, cu) = pending[k];
                let who = if rng.below(10) == 0 { a } else { ca };
                let p1 = g.last();
                let w = g.w_reveal(who, &hash, &salt, &inner, p1, cu);
                g.op(w);
                if rng.below(3) != 0 {
                    let x = pending.swap_remove(k);
                    expired.push((x.0, x.1, x.2, x.3));
                }
            }
            70..=77 if !expired.is_empty() => {
                // re-commit of a used / (maybe) expired hash, by its author or another holder
                let k = rng.below(expired.len() as u64) as usize;
                let (ca, hash, salt, inner) = expired[k];
                let who = if rng.below(3) == 0 { holder } else { ca };
                let w = g.w_commit(who, &hash, h + 1 + rng.below(4));
                g.op(w);
                let uid = *g.uids.last().unwrap();
                pending.push((ca, hash, salt, inner, uid));
            }
            78..=83 => {
                g.op(GB::w_gdep(holder, 1_000 + rng.below(20_000)));
            }
            84..=92 => {
                let px = mid + (rng.below(7) as i64 - 3) * dollar * 50;
                let mk = 1 + rng.below((n_acc - 1) as u64) as u32;
                let w1 = g.w_place(mk, rng.below(2) == 0, false, px, QTY_SCALE / 1000, 1);
                g.op(w1);
            }
            _ => {
                g.op(GB::w_dep(a, USD_SCALE as i64 * (1 + rng.below(100) as i64)));
            }
        }
    }
    g.words()
}

/// slcr <n> <orders> <hstep> [adv]: per seed a 'cr' batch cut into segments of 1..12 units at bound heights advancing
/// by 1 + rand(hstep) (plus hook-only runs, orc_sched); every segment is proven statelessly from the session pre-state
/// with the height hook and must give status 0, the session's events and the MNWIT-S root of the SESSION post-state
/// (round 23: eager commit expiry -- before it, the lazily expired commit leaves made the session root unusable as the
/// reference at bound heights). `adv`: per segment with a hook expiry: omission of each supplied need, a denied
/// Cexp / Cmt / Acmt / Gcnt (adversarial operator), forged groups (t_cdrop 1-3), a forged commit count (t_gdrop 5).
pub fn slcr(n: u64, ord: u32, hstep: u64, adv: bool) -> String {
    let mut a = Adv { cases: 0, sound: 0, unsound: Vec::new(), counts: Default::default() };
    let (mut ok, mut segs, mut units, mut bad, mut unsup) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let (mut wbytes, mut maxw) = (0u64, 0usize);
    // [commit ok, commit rej, reveal ok, reveal rej]
    let mut kinds = [0u64; 4];
    let (mut hook_segs, mut expired_n, mut max_group, mut recommit) = (0u64, 0u64, 0usize, 0u64);
    let mut rej_codes: std::collections::BTreeMap<(u32, u32), u64> = Default::default();
    let mut first_bad = String::new();
    for seed in 1..=n {
        let mut rng = Rng(seed.wrapping_mul(0x3C6E_F372_FE94_F82B) | 1);
        let size = 1 + rng.below(12) as u32;
        let sched = orc_sched(hstep, seed ^ 0x23, (3 * ord as usize + 64) / size as usize + 2);
        let w = cr_batch(seed, ord, size, &sched);
        let refs = orc_refs(&w, size, &sched);
        let mut batch_ok = true;
        for (k, (r, h)) in refs.iter().enumerate() {
            segs += 1;
            units += r.seg[2] as u64;
            let b = WitBuilder::new(&r.pre);
            let res = operate_h(&b, &r.seg, Some(*h));
            if matches!(&res, Ok((_, _, o, _, _)) if o.status == sl::ST_SL_UNSUPPORTED) {
                unsup += 1;
                continue;
            }
            let why = match &res {
                Err(e) => Some(e.clone()),
                Ok((needs, wit, o, ev, _)) => {
                    wbytes += wit.len() as u64;
                    maxw = maxw.max(wit.len());
                    if o.status != 0 {
                        Some(format!("status {} need {:?}", o.status, o.need))
                    } else if o.end_root != r.post_root {
                        Some(format!("end root; {}", diag(r, o)))
                    } else if *ev != r.ev {
                        Some(format!("events differ (len {} vs {})", ev.len(), r.ev.len()))
                    } else {
                        let gone: Vec<_> = r.pre.commits.values().filter(|e| e.ttl_height < *h).collect();
                        if !gone.is_empty() && *h > r.pre.height {
                            hook_segs += 1;
                            expired_n += gone.len() as u64;
                            let mut gs: std::collections::BTreeMap<u64, usize> = Default::default();
                            for e in &gone {
                                *gs.entry(e.ttl_height).or_default() += 1;
                            }
                            max_group = max_group.max(gs.values().copied().max().unwrap_or(0));
                        }
                        let base = 4 + 8 * r.seg[1] as usize;
                        let mut i = 0usize;
                        for kk in 0..r.seg[2] as usize {
                            let x = r.ev.get(i).copied().unwrap_or(0);
                            let app = x & mnpilot::EV_APPLIED != 0;
                            i += if app { 1 + 6 * (x & 0xFFFF) as usize } else { 1 };
                            let kd = r.seg[base + 8 * kk] & 0xff;
                            let slot = match kd {
                                20 => Some(0),
                                21 => Some(2),
                                _ => None,
                            };
                            if let Some(sl0) = slot {
                                kinds[sl0 + (!app) as usize] += 1;
                                if !app {
                                    *rej_codes.entry((kd, x)).or_insert(0u64) += 1;
                                }
                            }
                        }
                        // a commit applied in this segment whose hash was in the pre-state's tree (expiring now)
                        for (hh, e) in &r.post.commits {
                            if !r.pre.commits.contains_key(hh) {
                                continue;
                            }
                            if r.pre.commits[hh] != *e && r.pre.commits[hh].ttl_height < *h {
                                recommit += 1;
                            }
                        }
                        if adv && !gone.is_empty() {
                            cr_adv(&mut a, &b, r, *h, needs, wit, &mut rng);
                        }
                        None
                    }
                }
            };
            if let Some(why) = why {
                bad += 1;
                batch_ok = false;
                if first_bad.is_empty() {
                    first_bad = format!("seed {} seg {} (size {}, h {}): {}", seed, k, size, h, why);
                }
                break;
            }
        }
        if batch_ok {
            ok += 1;
        }
    }
    let mut cs: Vec<String> = a.counts.iter().map(|(k, v)| format!("\"{}\":[{},{},{}]", k, v.0, v.1, v.2)).collect();
    cs.sort();
    format!(
        "{{\"mode\":\"cr\",\"batches\":{},\"ok\":{},\"bad_segments\":{},\"unsupported_segments\":{},\"segments\":{},\"units\":{},\"witness_bytes\":{},\"max_witness\":{},\"proven_commit_ok_rej_reveal_ok_rej\":{:?},\"hook_expiry_segments\":{},\"expired_commits\":{},\"max_expiry_group\":{},\"recommits_of_expiring_hash\":{},\"rejections_kind_code\":\"{:?}\",\"adv_cases\":{},\"adv_unsound\":{},\"adv_counts\":{{{}}},\"first_unsound\":\"{}\",\"first_bad\":\"{}\"}}",
        n, ok, bad, unsup, segs, units, wbytes, maxw, kinds, hook_segs, expired_n, max_group, recommit, rej_codes, a.cases, a.unsound.len(), cs.join(","), a.unsound.first().cloned().unwrap_or_default(), first_bad
    )
}
fn cr_adv(a: &mut Adv, b: &WitBuilder, r: &SegRef, h: u64, needs: &BTreeSet<Need>, wit: &[u8], rng: &mut Rng) {
    let run = |w: &[u8]| run_sl_xh(&r.seg, w, Some(&b.root), Some(h));
    for nd in needs.iter() {
        let kind = match nd {
            Need::Cexp(_) => "omit23:cexp",
            Need::Cmt(_) => "omit23:cmt",
            Need::Acmt(_) => "omit23:acmt",
            Need::Gcnt => "omit23:gcnt",
            _ => {
                if rng.below(4) != 0 {
                    continue;
                }
                "omit23:other"
            }
        };
        let mut n2 = needs.clone();
        n2.remove(nd);
        let (o2, ev2) = run(&b.build(&n2));
        a.rec(kind, r, &o2, &ev2, false);
    }
    // adversarial operators that never supply one need class (the run must not succeed with another result)
    let denies: [(&str, &dyn Fn(&Need) -> bool); 4] = [
        ("deny23:cexp", &|n: &Need| matches!(n, Need::Cexp(_))),
        ("deny23:cmt", &|n: &Need| matches!(n, Need::Cmt(_))),
        ("deny23:acmt", &|n: &Need| matches!(n, Need::Acmt(_))),
        ("deny23:gcnt", &|n: &Need| matches!(n, Need::Gcnt)),
    ];
    for (kind, d) in denies {
        let (o2, ev2) = operate_deny_h(b, &r.seg, d, Some(h));
        a.rec(kind, r, &o2, &ev2, false);
    }
    // forged groups / count under the honest root
    for t in 1u8..=3 {
        b.t_cdrop.set(t);
        let w2 = b.build(needs);
        b.t_cdrop.set(0);
        if w2.as_slice() == wit {
            continue;
        }
        let (o2, ev2) = run(&w2);
        a.rec(["forge23:cexp-drop", "forge23:cexp-absent", "forge23:cexp-fake"][t as usize - 1], r, &o2, &ev2, true);
    }
    if needs.contains(&Need::Gcnt) {
        b.t_gdrop.set(5);
        let w2 = b.build(needs);
        b.t_gdrop.set(0);
        let (o2, ev2) = run(&w2);
        a.rec("forge23:gcnt-commits", r, &o2, &ev2, true);
    }
    // extra valid records: every group of the pre-state + a few absent heights, every commit, every index
    let mut n3 = needs.clone();
    for (u, _) in sl::cexp_groups(&r.pre) {
        n3.insert(Need::Cexp(u));
    }
    n3.insert(Need::Cexp(h + 100));
    n3.insert(Need::Cexp(h + 1));
    for (hh, e) in &r.pre.commits {
        n3.insert(Need::Cmt(*hh));
        n3.insert(Need::Acmt(e.account));
    }
    let (o3, ev3) = run(&b.build(&n3));
    a.rec("extra23:valid", r, &o3, &ev3, false);
    if o3.status != 0 {
        a.unsound.push(format!("extra valid commit records refused: status {} {:?}", o3.status, o3.need));
    }
    let lay = layout(wit);
    for _ in 0..2 {
        if wit.len() <= lay.tree_end {
            break;
        }
        let mut w2 = wit.to_vec();
        let i = lay.tree_end + rng.below((wit.len() - lay.tree_end) as u64) as usize;
        w2[i] ^= 1 << rng.below(8);
        let (o4, ev4) = run(&w2);
        a.rec("flip23:records", r, &o4, &ev4, false);
    }
}

/// the SESSION image on one segment from an arbitrary pre-state at a BOUND height h (commit_height hook first)
pub fn sess_seg_h(pre: &mnpilot::state::ChainState, w: &[u32], cap: usize, h: u64) -> (mnpilot::state::ChainState, Vec<u32>) {
    let eng = mnpilot::engine::Engine { state: pre.clone() };
    let wt = mnpilot::wit::Wit::from_state(&eng.state);
    let mut sess = Some(mnpilot::Session { eng, w: Some(wt), mode: mnpilot::WitMode::Incremental, segs: pre.height as u32, state_cap: cap, bind_height: true });
    let mut ev = Vec::new();
    let (_, st, _) = mnpilot::run_segment_n(&mut |i| w.get(i as usize).copied().unwrap_or(0), &mut |x| ev.push(x), &mut |_, _, _| {}, mnpilot::WitMode::Incremental, &mut sess, mnpilot::SegOpt { run_no: Some(h as u32), bind: true });
    assert_eq!(st.status, 0);
    let mut s = sess.unwrap().eng.state;
    let _ = s.take_dirty();
    (s, ev)
}

/// slpoc23 (round 23: eager commit expiry, MAX_STATE_COMMITS mirrored):
///  P1 the session's commit cap: a pre-state with MAX_STATE_COMMITS - 1 live commits (16 owners, TTLs spread over the
///     17 live heights), Commit by a holder (fits), Commit by another holder (at the cap -> 19), = SESSION image; one
///     below: both applied;
///  P2 hook at the cap: the full commit set, run at height h0 + 1 -> the group of TTL h0 expires (cmt: leaves, group,
///     owners' indexes rewritten), a Commit now fits; root = s_root(session post);
///  P3 a jump of 40 heights: every commit expires (17 groups), worst-case expiry witness at the cap;
///  P4 adversarial on P2 / P3: omitted / denied Cexp, Cmt, Acmt, Gcnt; forged groups (t_cdrop 1-3); forged count
///     (t_gdrop 5) -> refused, never a different result;
///  P5 a re-commit of an expiring hash by another account in the hook's run (session: pruned -> applied): the cmt:
///     leaf is rewritten, not deleted; a Reveal of an expiring commit -> BadCommit = session;
///  P6 migration: the full commit set migrates (root = s_root incl. cexp groups and gcnt:0 commits); a TTL outside
///     [height, height + COMMIT_TTL_HEIGHTS] or a count above SL_CAPS.commits is refused (ST_SL_MIG_BOUNDS).
pub fn slpoc23() -> String {
    use mnpilot::types::{AccountId as A, MarketId as M};
    let mut res: Vec<String> = Vec::new();
    let mut all_ok = true;
    let id = |i: u32| A(acct_id(i).0);
    let h0: u64 = 100;
    let cap = mnpilot::MAX_STATE_COMMITS;
    let ttl_n = minuend_types::COMMIT_TTL_HEIGHTS + 1;
    let hash_of = |i: u32| -> [u8; 32] {
        use sha2::Digest;
        let mut x = sha2::Sha256::new();
        x.update(b"poc23");
        x.update(i.to_le_bytes());
        x.finalize().into()
    };
    // table accounts 0..3 = committers in the segments (acct_id 0..3), owners of the pre-state commits: 1000..1015
    let mk_pre = |n: usize| -> mnpilot::state::ChainState {
        let mut s = mnpilot::state::ChainState::genesis();
        s.height = h0;
        for i in 0..4u32 {
            let mut a = mnpilot::account::Account::new(id(i));
            a.collateral = 1_000_000 * USD_SCALE as i128;
            s.put_account(id(i), a);
            s.perp_balances.insert(id(i), 10_000_000);
            s.perp_supply += 10_000_000;
        }
        for j in 0..16u32 {
            s.perp_balances.insert(id(1000 + j), 10_000_000);
            s.perp_supply += 10_000_000;
        }
        for i in 0..n as u32 {
            let ttl = h0 + (i as u64 % ttl_n);
            let e = mnpilot::state::CommitEntry { account: id(1000 + i / 64), commit_unit: hash_of(1_000_000 + i), commit_height: ttl.saturating_sub(minuend_types::COMMIT_TTL_HEIGHTS).max(1).min(h0), ttl_height: ttl, revealed: i % 5 == 0 };
            s.commits.insert(hash_of(i), e);
        }
        let _ = s.take_dirty();
        s
    };
    let table = [0u32, 1, 2, 3];
    // commit ops: hash words in the ext area
    let hw = |h: &[u8; 32]| -> Vec<u32> { (0..8).map(|k| u32::from_le_bytes(h[4 * k..4 * k + 4].try_into().unwrap())).collect() };
    let commit = |a: u32, off: u32, ttl: u64| -> [u32; 8] { [20 | (a << 8), ttl as u32, (ttl >> 32) as u32, 0, 0, 0, 0, off] };
    let new_h = [hash_of(5_000_000), hash_of(5_000_001), hash_of(5_000_002)];
    let mut ext: Vec<u32> = Vec::new();
    for h in &new_h {
        ext.extend_from_slice(&hw(h));
    }
    // P1-P5 compare with the SESSION image: the session's commit cap (the lineage's own values: P7)
    let sess_caps = sl::SlCaps { commits: cap as u64, commit_group: cap as u64, ..sl::SL_CAPS_PROD };
    unsafe { sl::SL_CAPS = sess_caps };
    // P1 (no hook): at the cap and one below
    let w1 = seg_words2(&table, &[commit(1, 0, h0 + 5), commit(2, 8, h0 + 6), GB_dep(3)], &ext);
    for (name, n, want19) in [("P1 at the commit cap", cap - 1, 1usize), ("P1 one below the commit cap", cap - 2, 0)] {
        let pre = mk_pre(n);
        let (post, ev_s) = sess_seg(&pre, &w1, 256);
        let b = WitBuilder::new(&pre);
        let line = match operate(&b, &w1) {
            Ok((needs, wit, o, ev, _)) => {
                let n19 = ev_units(&ev_s).iter().filter(|x| *x == "19").count();
                let ok = o.status == 0 && o.end_root == sl::s_root(&post) && ev == ev_s && n19 == want19 && needs.contains(&Need::Gcnt);
                all_ok &= ok;
                format!("{{\"case\":\"{}\",\"ok\":{},\"session\":{:?},\"stateless\":{:?},\"witness_bytes\":{}}}", name, ok, ev_units(&ev_s), ev_units(&ev), wit.len())
            }
            Err(e) => {
                all_ok = false;
                format!("{{\"case\":\"{}\",\"ok\":false,\"why\":\"{}\"}}", name, e)
            }
        };
        res.push(line);
    }
    // P1c at the total cap, a Commit the engine would reject anyway (duplicate live hash): the session's cap check runs
    // first (19), so the count is an input even though nothing changes (mutant gcap-commit-gcnt-off)
    {
        let pre = mk_pre(cap);
        let mut ext_c = ext.clone();
        ext_c.extend_from_slice(&hw(&hash_of(0)));
        let w = seg_words2(&table, &[commit(1, 24, h0 + 5)], &ext_c);
        let (post, ev_s) = sess_seg(&pre, &w, 256);
        let b = WitBuilder::new(&pre);
        let (od, evd) = operate_deny(&b, &w, &|n: &Need| *n == Need::Gcnt);
        let line = match operate(&b, &w) {
            Ok((_, _, o, ev, _)) => {
                let deny_ok = od.status != 0 || (od.end_root == sl::s_root(&post) && evd == ev_s);
                let ok = o.status == 0 && o.end_root == sl::s_root(&post) && ev == ev_s && ev_units(&ev_s) == ["19"] && deny_ok;
                all_ok &= ok;
                format!("{{\"case\":\"P1c duplicate hash at the commit cap\",\"ok\":{},\"session\":{:?},\"stateless\":{:?},\"deny_gcnt_status\":{}}}", ok, ev_units(&ev_s), ev_units(&ev), od.status)
            }
            Err(e) => {
                all_ok = false;
                format!("{{\"case\":\"P1c\",\"ok\":false,\"why\":\"{}\"}}", e)
            }
        };
        res.push(line);
    }
    // P2 / P3: hook expiry at the cap (full set), then commits fit again
    let full = mk_pre(cap);
    let w2 = seg_words2(&table, &[commit(1, 0, h0 + 41 + 5), commit(2, 8, h0 + 41 + 6)], &ext);
    for (name, h1) in [("P2 hook at the cap (one group expires)", h0 + 1), ("P3 jump of 40 heights (every group expires)", h0 + 40)] {
        let w = if h1 == h0 + 1 { seg_words2(&table, &[commit(1, 0, h1 + 5), commit(2, 8, h1 + 6)], &ext) } else { w2.clone() };
        let (post, ev_s) = sess_seg_h(&full, &w, 256, h1);
        let gone = full.commits.values().filter(|e| e.ttl_height < h1).count();
        let b = WitBuilder::new(&full);
        let line = match operate_h(&b, &w, Some(h1)) {
            Ok((needs, wit, o, ev, it)) => {
                let ok = o.status == 0 && o.end_root == sl::s_root(&post) && ev == ev_s && ev_units(&ev_s).iter().all(|x| x.starts_with("applied")) && post.commits.len() == cap - gone + 2;
                all_ok &= ok;
                // P4 on this run
                let mut adv = Adv { cases: 0, sound: 0, unsound: Vec::new(), counts: Default::default() };
                let r = SegRef { pre: full.clone(), post_root: sl::s_root(&post), post: post.clone(), ev: ev_s.clone(), seg: w.clone(), sess_hashes: 0 };
                let mut rng = Rng(h1);
                cr_adv(&mut adv, &b, &r, h1, &needs, &wit, &mut rng);
                let adv_ok = adv.unsound.is_empty();
                all_ok &= adv_ok;
                let mut cs: Vec<String> = adv.counts.iter().map(|(k, v)| format!("\"{}\":[{},{},{}]", k, v.0, v.1, v.2)).collect();
                cs.sort();
                format!(
                    "{{\"case\":\"{}\",\"ok\":{},\"expired\":{},\"session\":{:?},\"stateless\":{:?},\"dels\":{},\"witness_bytes\":{},\"operator_iterations\":{},\"P4_adv_ok\":{},\"P4_cases\":{},\"P4_unsound\":{},\"P4_counts\":{{{}}},\"first_unsound\":\"{}\"}}",
                    name, ok, gone, ev_units(&ev_s), ev_units(&ev), o.dels.len(), wit.len(), it, adv_ok, adv.cases, adv.unsound.len(), cs.join(","), adv.unsound.first().cloned().unwrap_or_default()
                )
            }
            Err(e) => {
                all_ok = false;
                format!("{{\"case\":\"{}\",\"ok\":false,\"why\":\"{}\"}}", name, e)
            }
        };
        res.push(line);
    }
    // P5: re-commit of an expiring hash (group h0, owner 1000) by account 1; Reveal of an expiring commit by its owner
    {
        let pre = mk_pre(64);
        let (hx0, e0) = pre.commits.iter().find(|(_, e)| e.ttl_height == h0).map(|(h, e)| (*h, *e)).unwrap();
        let mut ext5 = hw(&hx0);
        // reveal ext: commit_ref, salt, inner op, parents (the commit unit)
        ext5.extend_from_slice(&hw(&hx0));
        ext5.extend_from_slice(&[0u32; 8]);
        ext5.extend_from_slice(&GB_dep(3));
        ext5.extend_from_slice(&hw(&[9u8; 32]));
        ext5.extend_from_slice(&hw(&e0.commit_unit));
        let tbl = [0u32, 1, 2, 1000];
        let w5 = seg_words2(&tbl, &[commit(1, 0, h0 + 3), [21 | (3 << 8), 0, 0, 0, 0, 0, 0, 8]], &ext5);
        let h1 = h0 + 1;
        let (post, ev_s) = sess_seg_h(&pre, &w5, 256, h1);
        let b = WitBuilder::new(&pre);
        let line = match operate_h(&b, &w5, Some(h1)) {
            Ok((_, _, o, ev, _)) => {
                let ok = o.status == 0 && o.end_root == sl::s_root(&post) && ev == ev_s && post.commits.get(&hx0).is_some_and(|e| e.account == id(1)) && ev_units(&ev_s)[0].starts_with("applied") && !ev_units(&ev_s)[1].starts_with("applied");
                all_ok &= ok;
                format!("{{\"case\":\"P5 re-commit of an expiring hash + Reveal of an expiring commit\",\"ok\":{},\"session\":{:?},\"stateless\":{:?}}}", ok, ev_units(&ev_s), ev_units(&ev))
            }
            Err(e) => {
                all_ok = false;
                format!("{{\"case\":\"P5\",\"ok\":false,\"why\":\"{}\"}}", e)
            }
        };
        res.push(line);
    }
    // P6: migration of the full commit set; bounds
    {
        let mig = |st: &mnpilot::state::ChainState| -> (u32, bool) {
            let eng = mnpilot::engine::Engine { state: st.clone() };
            let wt = mnpilot::wit::Wit::from_state(&eng.state);
            let sess = mnpilot::Session { eng, w: Some(wt), mode: mnpilot::WitMode::Incremental, segs: st.height as u32, state_cap: 256, bind_height: true };
            let (dg, nw, words) = mnpilot::snapshot::export(&sess, true);
            let mut inp = vec![sl::SL_MIG_MAGIC];
            inp.extend_from_slice(&words.unwrap());
            let mo = sl::migrate(&mut |j| inp.get(j as usize).copied().unwrap_or(0), Some(&(dg, nw)), true);
            (mo.status, mo.root == sl::s_root(st))
        };
        let (st_full, root_ok) = mig(&full);
        let mut bad_ttl = mk_pre(10);
        bad_ttl.commits.values_mut().next().unwrap().ttl_height = h0 + minuend_types::COMMIT_TTL_HEIGHTS + 1;
        let (st_ttl, _) = mig(&bad_ttl);
        let mut old_ttl = mk_pre(10);
        old_ttl.commits.values_mut().next().unwrap().ttl_height = h0 - 1;
        let (st_old, _) = mig(&old_ttl);
        unsafe { sl::SL_CAPS = sl::SlCaps { commits: cap as u64 - 1, ..sl::SL_CAPS_PROD } };
        let (st_cap, _) = mig(&full);
        unsafe { sl::SL_CAPS = sl::SlCaps { commit_group: 60, ..sl::SL_CAPS_PROD } };
        let (st_grp, _) = mig(&full);
        unsafe { sl::SL_CAPS = sess_caps };
        let ok = st_full == 0 && root_ok && st_ttl == sl::ST_SL_MIG_BOUNDS && st_old == sl::ST_SL_MIG_BOUNDS && st_cap == sl::ST_SL_MIG_BOUNDS && st_grp == sl::ST_SL_MIG_BOUNDS;
        all_ok &= ok;
        res.push(format!("{{\"case\":\"P6 migration (full commit set; TTL / count / group bounds)\",\"ok\":{},\"full\":[{},{}],\"ttl_above\":{},\"ttl_below\":{},\"count_above_cap\":{},\"group_above_bound\":{}}}", ok, st_full, root_ok, st_ttl, st_old, st_cap, st_grp));
    }
    // P7 (R23-M1) the lineage's production values: no global commit cap (a Commit beyond the session's 1024 applies),
    // and the per-TTL group bound (commit_group): a Commit into a full group is refused (19), into the next group it
    // applies; the group is an input of the rule (omitted / denied -> refused). Expected post-state built by hand: the
    // applied commits inserted, seq + 1 per applied unit (a refusal changes nothing)
    {
        let uid = |i: u64| -> [u8; 32] {
            let mut u = [0u8; 32];
            u[..8].copy_from_slice(&(0x22C0_DE00_0000u64 + i).to_le_bytes());
            u[31] = 0x22;
            u
        };
        let expect = |pre: &mnpilot::state::ChainState, applied: &[(usize, u32, u64)]| -> mnpilot::state::ChainState {
            let mut p = pre.clone();
            for (i, a, ttl) in applied {
                p.commits.insert(new_h[*i], mnpilot::state::CommitEntry { account: id(*a), commit_unit: uid(*i as u64), commit_height: p.height, ttl_height: *ttl, revealed: false });
                p.seq += 1;
            }
            p
        };
        let mut lines: Vec<String> = Vec::new();
        let mut ok7 = true;
        // P7a beyond the session's cap: the full set + one more commit (session: 19)
        unsafe { sl::SL_CAPS = sl::SL_CAPS_PROD };
        let w7 = seg_words2(&table, &[commit(1, 0, h0 + 7)], &ext);
        let (_, ev_s) = sess_seg(&full, &w7, 256);
        let b = WitBuilder::new(&full);
        match operate(&b, &w7) {
            Ok((_, _, o, ev, _)) => {
                let want = expect(&full, &[(0, 1, h0 + 7)]);
                let k = o.status == 0 && o.end_root == sl::s_root(&want) && ev_units(&ev) == ["applied/0"] && ev_units(&ev_s) == ["19"];
                ok7 &= k;
                lines.push(format!("\"P7a beyond 1024 (prod)\":[{},{:?},{:?}]", k, ev_units(&ev_s), ev_units(&ev)));
            }
            Err(e) => {
                ok7 = false;
                lines.push(format!("\"P7a\":\"{}\"", e));
            }
        }
        // P7b group bound 8: group h0 + 3 of mk_pre(300) holds 18 commits -> bound 18: the Commit into it is refused, the
        // one into the group h0 + 16 (the next TTL with room) applies
        let pre = mk_pre(300);
        let g3 = pre.commits.values().filter(|e| e.ttl_height == h0 + 3).count() as u64;
        let g16 = pre.commits.values().filter(|e| e.ttl_height == h0 + 16).count() as u64;
        unsafe { sl::SL_CAPS = sl::SlCaps { commit_group: g3, ..sl::SL_CAPS_PROD } };
        let w7b = seg_words2(&table, &[commit(1, 0, h0 + 3), commit(2, 8, h0 + 16)], &ext);
        let b = WitBuilder::new(&pre);
        let r = operate(&b, &w7b);
        let (od, evd) = operate_deny(&b, &w7b, &|n: &Need| matches!(n, Need::Cexp(_)));
        unsafe { sl::SL_CAPS = sess_caps };
        match r {
            Ok((needs, _, o, ev, _)) => {
                let want = expect(&pre, &[(1, 2, h0 + 16)]);
                let deny_ok = od.status != 0 || (od.end_root == sl::s_root(&want) && evd == ev);
                let k = g16 < g3 && o.status == 0 && o.end_root == sl::s_root(&want) && ev_units(&ev) == ["19", "applied/0"] && needs.contains(&Need::Cexp(h0 + 3)) && deny_ok;
                ok7 &= k;
                lines.push(format!("\"P7b group bound {} (group h0+3 full, h0+16 has {})\":[{},{:?},\"deny_cexp_status\",{}]", g3, g16, k, ev_units(&ev), od.status));
            }
            Err(e) => {
                ok7 = false;
                lines.push(format!("\"P7b\":\"{}\"", e));
            }
        }
        // P7c two commits into a group with one slot left (the bound counts the run's own commits); P7d a Commit that the
        // engine would reject anyway (duplicate live hash) into a full group: the group bound refuses it first (19), so
        // the group must be loaded even though no count changes (mutants cexp-now-created-off / gcap-commit-cexp-need-off)
        let pre = mk_pre(300);
        let dup = hash_of(3); // live, TTL h0 + 3
        let mut ext_d = ext.clone();
        ext_d.extend_from_slice(&hw(&dup));
        for (name, bound, ops, want_ev, applied) in [
            ("P7c two commits, one slot left", g16 + 1, vec![commit(1, 0, h0 + 16), commit(2, 8, h0 + 16)], vec!["applied/0", "19"], vec![(0usize, 1u32, h0 + 16)]),
            ("P7d duplicate hash into a full group", g3, vec![commit(1, 24, h0 + 3)], vec!["19"], vec![]),
        ] {
            unsafe { sl::SL_CAPS = sl::SlCaps { commit_group: bound, ..sl::SL_CAPS_PROD } };
            let w = seg_words2(&table, &ops, &ext_d);
            let b = WitBuilder::new(&pre);
            let r = operate(&b, &w);
            let (od, evd) = operate_deny(&b, &w, &|n: &Need| matches!(n, Need::Cexp(_)));
            unsafe { sl::SL_CAPS = sess_caps };
            match r {
                Ok((_, _, o, ev, _)) => {
                    let want = expect(&pre, &applied);
                    let deny_ok = od.status != 0 || (od.end_root == sl::s_root(&want) && evd == ev);
                    let k = o.status == 0 && o.end_root == sl::s_root(&want) && ev_units(&ev) == want_ev && deny_ok;
                    ok7 &= k;
                    lines.push(format!("\"{}\":[{},{:?},\"deny_cexp_status\",{}]", name, k, ev_units(&ev), od.status));
                }
                Err(e) => {
                    ok7 = false;
                    lines.push(format!("\"{}\":\"{}\"", name, e));
                }
            }
        }
        all_ok &= ok7;
        res.push(format!("{{\"case\":\"P7 production values (R23-M1): beyond the session's cap, per-TTL group bound\",\"ok\":{},{}}}", ok7, lines.join(",")));
    }
    // P8 (R23-H1) a jump hook after failed runs drops EVERY live commit: at the production bound (SL_MAX_CMT_LIVE = 4096,
    // 64 owners) the height is provable (= session hook); beyond it (8 200 commits, the uncapped draft f0cb05d) no
    // witness can carry the expiry (record sections bounded by SL_MAX_CMT_RECS): the lineage would halt at that height
    {
        unsafe { sl::SL_CAPS = sl::SL_CAPS_PROD };
        let big = |n: usize| -> mnpilot::state::ChainState {
            let mut s = mk_pre(0);
            for i in 0..n as u32 {
                let ttl = h0 + (i as u64 % ttl_n);
                s.commits.insert(hash_of(i), mnpilot::state::CommitEntry { account: id(1000 + i / 64), commit_unit: hash_of(1_000_000 + i), commit_height: ttl.saturating_sub(minuend_types::COMMIT_TTL_HEIGHTS).max(1).min(h0), ttl_height: ttl, revealed: false });
            }
            s
        };
        let h1 = h0 + 40;
        let w8 = seg_words2(&table, &[commit(1, 0, h1 + 5)], &ext);
        let mut lines: Vec<String> = Vec::new();
        let mut ok8 = true;
        for (n, want_ok) in [(sl::SL_MAX_CMT_LIVE, true), (8_200usize, false)] {
            let pre = big(n);
            let (post, ev_s) = sess_seg_h(&pre, &w8, 256, h1);
            let b = WitBuilder::new(&pre);
            match operate_h(&b, &w8, Some(h1)) {
                Ok((_, wit, o, ev, it)) => {
                    let proven = o.status == 0 && o.end_root == sl::s_root(&post) && ev == ev_s;
                    let k = proven == want_ok && (want_ok || o.status == sl::ST_SL_BADWIT);
                    ok8 &= k;
                    lines.push(format!("\"{} commits\":{{\"ok\":{},\"status\":{},\"proven\":{},\"witness_bytes\":{},\"operator_iterations\":{}}}", n, k, o.status, proven, wit.len(), it));
                }
                Err(e) => {
                    ok8 = false;
                    lines.push(format!("\"{} commits\":\"{}\"", n, e));
                }
            }
        }
        all_ok &= ok8;
        res.push(format!("{{\"case\":\"P8 (R23-H1) jump hook: every live commit expires\",\"ok\":{},{}}}", ok8, lines.join(",")));
    }
    // P9 (R23-H2, review of the round-20 oracle hook): the same jump on the oracle expiry queue -- R20-M3 sized one
    // height's expiry (16 oracles x 16 markets = SL_MAX_MARKETS report sets), but after a failed run the upstream hook
    // releases every due group: two adjacent full groups with disjoint markets (32 oracles, 512 markets) needed 512
    // report-set / market records -> no witness existed at that height (round-22 code: status 12). Fix: the bound hook
    // releases at most MAX_UNSTAKES_PER_HEIGHT due unbondings per run in (unlock, id) order, in BOTH images
    // (commit_height_bound): the jump hook releases the first group, the next run the second; root = SESSION image
    {
        let nu = sl::ora::SL_MAX_UNSTAKES as u32;
        let nm = sl::ora::SL_MAX_ORACLE_MKTS as u32;
        let u = 5_000u64;
        let mut s = mnpilot::state::ChainState::genesis();
        for m in 2..=2 * nu * nm {
            s.markets.insert(M(m), s.markets[&M(1)]);
            s.books.insert(M(m), mnpilot::book::OrderBook::new(M(m)));
        }
        for i in 0..2 * nu {
            s.oracle_bonds.insert(id(100 + i), mnpilot::types::ORACLE_BOND_PERP);
            s.oracle_unbonding.insert(id(100 + i), if i < nu { u } else { u + 1 });
            for k in 1..=nm {
                s.oracle_reports.insert((M(i * nm + k), id(100 + i)), MID);
            }
        }
        s.height = u - 1;
        let _ = s.take_dirty();
        let table: Vec<u32> = vec![100];
        let empty = seg_words(&table, &[]);
        let mut out: Vec<String> = Vec::new();
        let mut ok9 = true;
        // one-step hook (u): 16 released; jump (u + 1, one failed run): 16 released, 16 left due; the next run (u + 2): the rest
        let mut pre = s.clone();
        for (k, h) in [(0, u), (1, u + 1), (2, u + 2)] {
            if k == 2 {
                // continue from the jump's post-state
            } else {
                pre = s.clone();
            }
            let (post, _) = sess_seg_h(&pre, &empty, 256, h);
            let b = WitBuilder::new(&pre);
            let r = operate_h(&b, &empty, Some(h));
            let (st, proven, wb) = match &r {
                Ok((_, wit, o, _, _)) => (o.status, o.status == 0 && o.end_root == sl::s_root(&post), wit.len()),
                Err(_) => (99, false, 0),
            };
            let rel = pre.oracle_unbonding.len() - post.oracle_unbonding.len();
            let want_rel = nu as usize;
            let k_ok = proven && rel == want_rel;
            ok9 &= k_ok;
            out.push(format!("\"run {} at h0+{} ({} due, {} released)\":{{\"ok\":{},\"status\":{},\"witness_bytes\":{}}}", k, h - (u - 1), pre.oracle_unbonding.values().filter(|x| **x <= h).count(), rel, k_ok, st, wb));
            pre = post;
        }
        all_ok &= ok9;
        res.push(format!("{{\"case\":\"P9 (R23-H2) oracle expiry after a jump: at most 16 releases per run\",\"ok\":{},{}}}", ok9, out.join(",")));
    }
    unsafe { sl::SL_CAPS = sl::SL_CAPS_PROD };
    let _ = M(0);
    format!("{{\"slpoc23\":{},\"cases\":[{}]}}", all_ok, res.join(",\n"))
}
#[allow(non_snake_case)]
fn GB_dep(a: u32) -> [u32; 8] {
    crate::gov::GB::w_dep(a, 5 * USD_SCALE as i64)
}
