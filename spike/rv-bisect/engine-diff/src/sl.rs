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

pub fn run_sl(seg: &[u32], wit: &[u8]) -> (sl::SlOut, Vec<u32>) {
    let mut ev = Vec::new();
    let o = sl::run_stateless(&mut |i| seg.get(i as usize).copied().unwrap_or(0), wit, &mut |x| ev.push(x));
    (o, ev)
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
    n.insert(Need::Account(mnpilot::types::INSURANCE_ACCOUNT));
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
                _ => {}
            }
        }
    }
    n
}

/// operator fixpoint: Some((needs, witness, out, ev, iterations)) or None (need loop / not converging)
pub fn operate(b: &WitBuilder, seg: &[u32]) -> Result<(BTreeSet<Need>, Vec<u8>, sl::SlOut, Vec<u32>, u32), String> {
    let mut needs = guess(seg);
    for it in 0..20_000u32 {
        let wit = b.build(&needs);
        let (o, ev) = run_sl(seg, &wit);
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

pub fn slfuzz(n: u64, ord: u32, adv: bool) -> String {
    let (mut ok, mut segs, mut units, mut bad) = (0u64, 0u64, 0u64, 0u64);
    let (mut wbytes, mut verified, mut nodes, mut hashes, mut sess_hashes, mut iters) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut maxw = 0usize;
    let mut first_bad = String::new();
    for s in 1..=n {
        let w = if adv {
            adv::adv_batch(s, ord)
        } else {
            let makers = 4 + (s % 9) as u32;
            let levels = 1 + (s % 25) as u32;
            let per = 1 + (s % 3) as u32;
            gen(s, makers, levels, per, ord, s % 2 == 0).0
        };
        let mut rng = Rng(s.wrapping_mul(0x51_7CC1_B727_220A) | 1);
        let size = 1 + rng.below(200) as u32;
        let refs = session_refs(&w, size);
        let mut batch_ok = true;
        for (k, r) in refs.iter().enumerate() {
            segs += 1;
            units += r.seg[2] as u64;
            let b = WitBuilder::new(&r.pre);
            let res = operate(&b, &r.seg);
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
        "{{\"batches\":{},\"ok\":{},\"bad_segments\":{},\"segments\":{},\"units\":{},\"witness_bytes\":{},\"max_witness\":{},\"leaves_verified\":{},\"tree_nodes\":{},\"sl_hashes\":{},\"session_hashes\":{},\"operator_iterations\":{},\"first_bad\":\"{}\"}}",
        n, ok, bad, segs, units, wbytes, maxw, verified, nodes, hashes, sess_hashes, iters, first_bad
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
            _ => panic!("tag"),
        }
    }
    let mut i = 36;
    skip(wit, &mut i);
    Layout { tree_end: i }
}

pub fn sladv(n: u64, ord: u32) -> String {
    let mut a = Adv { cases: 0, sound: 0, unsound: Vec::new(), counts: Default::default() };
    let mut done_segs = 0u64;
    for s in 1..=n {
        let makers = 4 + (s % 9) as u32;
        let levels = 1 + (s % 25) as u32;
        let per = 1 + (s % 3) as u32;
        let w = gen(s, makers, levels, per, ord, s % 2 == 0).0;
        let mut rng = Rng(s.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1);
        let size = 8 + rng.below(64) as u32;
        let refs = session_refs(&w, size);
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
                };
                a.rec(kind, r, &o2, &ev2, false);
            }
            // A2 extra valid records: every account / market of the pre-state + every level of market 1
            let mut n3 = needs.clone();
            for id in r.pre.accounts.keys().take(40) {
                n3.insert(Need::Account(*id));
                n3.insert(Need::Aord(*id));
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
            if o3.status != 0 {
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
                a.rec(if t % 2 == 0 { "flip:records" } else { "flip:tree" }, r, &o4, &ev4, true);
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
                // forged tree + forged root (self-consistent) -> start_root != chain root
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
            // A10 duplicate record: the same account twice (patch the count) -> BADWIT
            {
                let one: BTreeSet<Need> = [Need::Account(mnpilot::types::INSURANCE_ACCOUNT)].into_iter().collect();
                let wv = b.build(&one);
                let lv = layout(&wv);
                // records: seq 8, height 8, markets u16 (0), accounts u16 (1) + record
                let mut wd = wv.clone();
                let acc_cnt = lv.tree_end + 16 + 2;
                let rec_start = acc_cnt + 2;
                // the account record runs to the aord count (3 trailing u16 zeros after it: aord, bmp, levels, ordx)
                let rec_end = wv.len() - 8;
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
