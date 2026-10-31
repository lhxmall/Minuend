//! Loop round 2 tools (findings/rv-loop-2.md).
//!   frag <out.bin> [per max_units]               allocator fragmentation stress: phases whose live sets sit in
//!                                  different size classes (crowded level / many levels / fills)
//!   grind <seed> <log2_accounts> <target|any> <out.bin>
//!                                  grind an attacker ACCOUNT (key pair; client_seq is forced to
//!                                  last+1) so its first `ord:` key shares a long prefix with a
//!                                  victim's key (target) or any existing key (any); prints the
//!                                  resulting MNWIT1 depths and the key-generation-bound try rate (W2)
//!   depth8 <dir>                   (depth8 build) batches whose checked insertions cross
//!                                  MAX_WIT_DEPTH = 8; verifies the rule against the real engine and
//!                                  an independent depth computation
//!   proofdump <batch.bin>          real-engine final leaves -> proofs (deepest / median member,
//!                                  absent key) as JSON for the Oscript verifier (js/smtverify.js)
//!   depthsel                       explicit boundary checks of Smt::insert_depth / the rule
use super::*;
use adv::batch_words;
use std::cell::RefCell;

fn dep(a: u32, amt: i64) -> [u32; 8] {
    [1 | (a << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, 0, 0]
}
fn place_w(a: u32, bid: bool, price: i64, qty: u64, cs: u64, market: u32) -> [u32; 8] {
    [2 | (a << 8), (!bid) as u32, price as u32, (price >> 32) as u32, qty as u32, (qty >> 32) as u32, cs as u32, market]
}
fn cancel_w(a: u32, cs: u64) -> [u32; 8] {
    [3 | (a << 8), 0, 0, 0, 0, 0, cs as u32, 1]
}
fn new_gen(n_acc: u32) -> (Vec<AccountId>, Gen) {
    let ids_real: Vec<AccountId> = (0..n_acc).map(acct_id).collect();
    let ids: Vec<mnpilot::types::AccountId> = ids_real.iter().map(|a| mnpilot::types::AccountId(a.0)).collect();
    let g = Gen { eng: mnpilot::engine::Engine { state: mnpilot::state::ChainState::genesis() }, ops: Vec::new(), live: Vec::new(), ids };
    (ids_real, g)
}

/// Fragmentation stress (A3): 64 accounts; phase A crowds one bid level (64 x 62 orders), phase B
/// cancels them all, phase C rests 64 x 62 orders on distinct price levels, phase D cancels them,
/// phase E crosses: every account trades (positions -> pos: leaves, account maps grow).
pub fn frag(per: u64, max_units: u32) -> Vec<u32> {
    let n = 64u32;
    let (ids_real, mut g) = new_gen(n);
    let q = QTY_SCALE / 10_000;
    for a in 0..n {
        g.apply(dep(a, 100_000 * USD_SCALE as i64));
    }
    // A: one crowded level
    for c in 1..=per {
        for a in 0..n {
            g.apply(place_w(a, true, MID - 1_000 * DOLLAR, q, c, 1));
        }
    }
    // B: cancel all
    for c in 1..=per {
        for a in 0..n {
            g.apply(cancel_w(a, c));
        }
    }
    // C: distinct levels
    for c in 1..=per {
        for a in 0..n {
            let px = MID - 2_000 * DOLLAR - ((c as i64) * n as i64 + a as i64) * DOLLAR;
            g.apply(place_w(a, true, px, q, per + c, 1));
        }
    }
    // D: cancel all
    for c in 1..=per {
        for a in 0..n {
            g.apply(cancel_w(a, per + c));
        }
    }
    // E: asks from even accounts, crossing bids from odd accounts (one fill each)
    let mut cs = 2 * per;
    while (g.ops.len() as u32) + 2 <= max_units {
        cs += 1;
        for a in (0..n).step_by(2) {
            if (g.ops.len() as u32) + 2 > max_units {
                break;
            }
            g.apply(place_w(a, false, MID + 10 * DOLLAR, q, cs, 1));
            g.apply(place_w(a + 1, true, MID + 10 * DOLLAR, q, cs, 1));
        }
    }
    batch_words(&ids_real, &g.ops, 0)
}

fn cpl(a: &[u8; 32], b: &[u8; 32]) -> usize {
    let mut c = 0;
    for i in 0..32 {
        let x = a[i] ^ b[i];
        if x == 0 {
            c += 8;
        } else {
            return c + x.leading_zeros() as usize;
        }
    }
    256
}
fn ord_key_hex(oid: &[u8; 32]) -> [u8; 32] {
    smt_ref::key(&format!("ord:{}", smt_ref::hex(oid)))
}

/// Best client_seq in [from, from + 2^log2) for account `acct` against `targets` (sorted keys):
/// maximizes the common prefix with the closest target. 4 threads. NOTE: the engine only accepts
/// client_seq == last + 1, so this is NOT a real attacker capability (a gap is rejected
/// DuplicateClientSeq); used by the depth8 test only to make collisions frequent (the rejected
/// units then also exercise "a place the rule rejects does not consume the client_seq").
fn grind_cs(acct: mnpilot::types::AccountId, from: u64, log2: u32, targets: &[[u8; 32]]) -> (u64, usize) {
    let total = 1u64 << log2;
    let nt = 4u64;
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..nt)
            .map(|t| {
                s.spawn(move || {
                    let mut best = (from, 0usize);
                    let mut i = t;
                    while i < total {
                        let cs = from + i;
                        let oid = mnpilot::types::order_id(acct, mnpilot::types::BTC_USD, cs);
                        let c = near_cpl(&ord_key_hex(&oid.0), targets);
                        if c > best.1 { best = (cs, c); }
                        i += nt;
                    }
                    best
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).max_by_key(|b| (b.1, u64::MAX - b.0)).unwrap()
    })
}
fn near_cpl(k: &[u8; 32], targets: &[[u8; 32]]) -> usize {
    let p = targets.partition_point(|x| x < k);
    let mut c = 0;
    if p < targets.len() { c = c.max(cpl(k, &targets[p])); }
    if p > 0 { c = c.max(cpl(k, &targets[p - 1])); }
    c
}

/// Real attacker capability (W2): order ids are order_id(account, market, client_seq) with
/// client_seq forced to last+1, so the grindable input is the ACCOUNT (an ed25519 key pair: the
/// account id is a hash of the public key). Grind account indices [lo, hi) (harness secrets) so the
/// account's first order key (client_seq 1) shares the longest prefix with the target set; returns
/// (index, prefix bits, tries/s incl. key generation).
fn grind_acct(lo: u32, hi: u32, targets: &[[u8; 32]]) -> (u32, usize, f64) {
    let t0 = std::time::Instant::now();
    let nt = 4u32;
    let best = std::thread::scope(|s| {
        let hs: Vec<_> = (0..nt)
            .map(|t| {
                s.spawn(move || {
                    let mut best = (lo, 0usize);
                    let mut i = lo + t;
                    while i < hi {
                        let id = mnpilot::types::AccountId(acct_id(i).0);
                        let oid = mnpilot::types::order_id(id, mnpilot::types::BTC_USD, 1);
                        let c = near_cpl(&ord_key_hex(&oid.0), targets);
                        if c > best.1 { best = (i, c); }
                        i += nt;
                    }
                    best
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).max_by_key(|b| (b.1, u32::MAX - b.0)).unwrap()
    });
    (best.0, best.1, (hi - lo) as f64 / t0.elapsed().as_secs_f64())
}

/// 16 accounts + ~400 resting orders; then the account (index in [16, 2^log2 + 16), at most
/// MAX_ACCOUNTS: the harness signs index i with secret(i)) whose first order key collides best with a
/// victim's `ord:` key (target) or with any existing key (any) deposits and rests that order.
pub fn grind(seed: u64, log2: u32, any: bool) -> (Vec<u32>, String) {
    let n = 16u32;
    let hi = (16 + (1u32 << log2)).min(mnpilot::MAX_ACCOUNTS);
    let all: Vec<AccountId> = (0..hi).map(acct_id).collect();
    let (_, mut g) = new_gen(n);
    g.ids = all.iter().map(|a| mnpilot::types::AccountId(a.0)).collect();
    let mut rng = Rng(seed | 1);
    let q = QTY_SCALE / 1_000;
    for a in 0..n {
        g.apply(dep(a, 1_000_000 * USD_SCALE as i64));
    }
    for i in 0..400u64 {
        let a = 1 + (i % (n as u64 - 1)) as u32;
        let bid = rng.below(2) == 0;
        let off = (1 + rng.below(300)) as i64 * DOLLAR;
        let cs = g.next_cseq(a);
        g.apply(place_w(a, bid, if bid { MID - off } else { MID + off }, q, cs, 1));
    }
    let leaves = mnpilot::wit::all_leaves(&g.eng.state);
    let mut keys: Vec<[u8; 32]> = leaves.iter().map(|l| smt_ref::key(l)).collect();
    keys.sort();
    let victim = leaves.iter().find(|l| l.starts_with("ord:")).unwrap().clone();
    let targets = if any { keys.clone() } else { vec![smt_ref::key(&victim)] };
    let (ai, c, rate) = grind_acct(n, hi, &targets);
    let before = smt_ref::depths(&leaves).into_iter().max().unwrap_or(0);
    g.apply(dep(ai, 1_000_000 * USD_SCALE as i64));
    g.apply(place_w(ai, true, MID - 500 * DOLLAR, q, 1, 1));
    let after_leaves = mnpilot::wit::all_leaves(&g.eng.state);
    let d = smt_ref::depths(&after_leaves);
    let after = d.iter().copied().max().unwrap_or(0);
    let mut sorted = d.clone();
    sorted.sort();
    let info = format!(
        "{{\"mode\":\"{}\",\"accounts_tried\":{},\"tries_per_s\":{:.0},\"attacker_index\":{},\"common_prefix_bits\":{},\"leaves\":{},\"max_depth_before\":{},\"max_depth_after\":{},\"median_depth\":{}}}",
        if any { "any" } else { "target" }, hi - n, rate, ai, c, after_leaves.len(), before, after, sorted[sorted.len() / 2]
    );
    (batch_words(&all[..(ai + 1) as usize], &g.ops, 0), info)
}

/// Port run with the per-unit event slices (for the depth rule checks).
fn port_units(w: &[u32]) -> (Vec<Vec<u32>>, [u8; 32], Vec<Vec<String>>) {
    let evs: RefCell<Vec<u32>> = RefCell::new(Vec::new());
    let mut per: Vec<Vec<u32>> = Vec::new();
    let mut pre: Vec<Vec<String>> = Vec::new();
    let mut last = mnpilot::wit::all_leaves(&port_genesis(w));
    let mut cut = 0usize;
    let (h, _, _) = mnpilot::run_batch_wit(
        &mut |i| w.get(i as usize).copied().unwrap_or(0),
        &mut |x| evs.borrow_mut().push(x),
        &mut |_, st, _| {
            let e = evs.borrow();
            per.push(e[cut..].to_vec());
            cut = e.len();
            pre.push(std::mem::replace(&mut last, mnpilot::wit::all_leaves(st)));
        },
        mnpilot::WitMode::Incremental,
    );
    (per, h, pre)
}
/// Depth a new key would get in the canonical tree over `leaves` (independent of wit.rs):
/// 1 + max common prefix with an existing key, or None if present. (For an empty slot the depth
/// is that prefix + 1 as well: the canonical tree splits exactly at the first differing bit.)
fn ref_insert_depth(leaves: &[String], k: &[u8; 32]) -> Option<usize> {
    let mut best = 0usize;
    for l in leaves {
        let k2 = smt_ref::key(l);
        if &k2 == k {
            return None;
        }
        best = best.max(cpl(&k2, k) + 1);
    }
    // a single-leaf tree: the new key splits it at cpl+1; empty tree: depth 0
    Some(if leaves.is_empty() { 0 } else { best })
}

/// depth8 build: a batch with ground ord / acct / pos keys around MAX_WIT_DEPTH; returns the
/// batch. Checks are in `depth8_check`.
pub fn depth8_batch(seed: u64) -> Vec<u32> {
    let base_n = 12u32;
    // the real-engine harness signs account index i with secret(i): ground accounts are picked
    // among table indices < MAX_ACCOUNTS (their acct:/pos: key collides with an existing key)
    let all: Vec<AccountId> = (0..mnpilot::MAX_ACCOUNTS).map(acct_id).collect();
    let (_, mut g) = new_gen(base_n);
    g.ids = all.iter().map(|a| mnpilot::types::AccountId(a.0)).collect();
    let mut used = base_n;
    let mut rng = Rng(seed | 1);
    let q = QTY_SCALE / 1_000;
    for a in 0..base_n {
        g.apply(dep(a, 1_000_000 * USD_SCALE as i64));
    }
    for i in 0..60u64 {
        let a = (i % base_n as u64) as u32;
        let bid = rng.below(2) == 0;
        let off = (1 + rng.below(50)) as i64 * DOLLAR;
        let cs = g.next_cseq(a);
        g.apply(place_w(a, bid, if bid { MID - off } else { MID + off }, q, cs, 1));
    }
    let keys_now = |g: &Gen| {
        let mut k: Vec<[u8; 32]> = mnpilot::wit::all_leaves(&g.eng.state).iter().map(|l| smt_ref::key(l)).collect();
        k.sort();
        k
    };
    // ord keys: alternate ground (>= 8 shared bits) and plain orders, some crossing (fills)
    for r in 0..40u64 {
        let a = (r % base_n as u64) as u32;
        let from = g.next_cseq(a);
        let cs = if r % 2 == 0 { grind_cs(g.ids[a as usize], from, 12, &keys_now(&g)).0 } else { from };
        let bid = rng.below(2) == 0;
        let off = (rng.below(40) as i64 - 5) * DOLLAR;
        g.apply(place_w(a, bid, if bid { MID - off } else { MID + off }, q, cs, 1));
    }
    // ground accounts: acct key collides (deposit + place rejected) / only pos key collides
    let mut extra = 0u32;
    let mut i = base_n + 1 + (seed as u32 % 64);
    let mut keys = keys_now(&g);
    while extra < 6 && i < mnpilot::MAX_ACCOUNTS {
        let mid = g.ids[i as usize];
        let near = |k: [u8; 32]| {
            let p = keys.partition_point(|x| x < &k);
            let mut c = 0;
            if p < keys.len() { c = c.max(cpl(&k, &keys[p])); }
            if p > 0 { c = c.max(cpl(&k, &keys[p - 1])); }
            c
        };
        let ca = near(mnpilot::wit::acct_key(&mid));
        let cp = near(mnpilot::wit::pos_key(&mid, mnpilot::types::BTC_USD));
        let want_acct = extra % 2 == 0;
        if (want_acct && ca >= 8) || (!want_acct && cp >= 8 && ca < 7) {
            g.apply(dep(i, 1_000_000 * USD_SCALE as i64));
            let cs = g.next_cseq(i);
            g.apply(place_w(i, true, MID - 3 * DOLLAR, q, cs, 1));
            used = used.max(i + 1);
            extra += 1;
            keys = keys_now(&g);
        }
        i += 1;
    }
    // tail: normal flow
    for _ in 0..60u64 {
        let a = rng.below(base_n as u64) as u32;
        let bid = rng.below(2) == 0;
        let off = (rng.below(30) as i64 - 3) * DOLLAR;
        let cs = g.next_cseq(a);
        g.apply(place_w(a, bid, if bid { MID - off } else { MID + off }, q, cs, 1));
    }
    batch_words(&all[..used as usize], &g.ops, 0)
}

/// Checks for one depth-rule batch: (a) port(B) == real engine(B without the units the rule
/// rejected): state hash + events; (b) every unit the rule rejected has a checked key whose
/// independent insertion depth > MAX_WIT_DEPTH, and every applied deposit/place has all checked
/// keys <= MAX_WIT_DEPTH (independent depth over the pre-state leaves).
pub fn depth8_check(w: &[u32]) -> (bool, String) {
    let (per, h, pre) = port_units(w);
    let n_acc = w[1] as usize;
    let base = 4 + 8 * n_acc;
    let ids: Vec<mnpilot::types::AccountId> = (0..n_acc)
        .map(|a| {
            let mut id = [0u8; 32];
            for k in 0..8 {
                id[k * 4..k * 4 + 4].copy_from_slice(&w[4 + 8 * a + k].to_le_bytes());
            }
            mnpilot::types::AccountId(id)
        })
        .collect();
    let dmax = mnpilot::wit::MAX_WIT_DEPTH;
    let (mut rejected, mut bad) = (0u32, Vec::new());
    let mut kept: Vec<[u32; 8]> = Vec::new();
    let mut port_ev: Vec<u32> = Vec::new();
    for (i, e) in per.iter().enumerate() {
        let mut ow = [0u32; 8];
        ow.copy_from_slice(&w[base + 8 * i..base + 8 * i + 8]);
        let leaves = &pre[i];
        let deep = |k: [u8; 32]| ref_insert_depth(leaves, &k).map(|d| d > dmax).unwrap_or(false);
        let has_acct = |id: &mnpilot::types::AccountId| leaves.iter().any(|l| l.starts_with(&format!("acct:{}", smt_ref::hex(&id.0))));
        let would = match mnpilot::decode_op(&ow) {
            mnpilot::BatchOp::Deposit { acct, .. } => {
                let id = ids[acct as usize];
                !has_acct(&id) && deep(mnpilot::wit::acct_key(&id))
            }
            mnpilot::BatchOp::Place { acct, market, client_seq, .. } => {
                let id = ids[acct as usize];
                let m = mnpilot::types::MarketId(market);
                let has_pos = leaves.iter().any(|l| l.starts_with(&format!("pos:{}:{}:", smt_ref::hex(&id.0), market)));
                (!has_acct(&id) && deep(mnpilot::wit::acct_key(&id)))
                    || deep(mnpilot::wit::ord_key(&mnpilot::types::order_id(id, m, client_seq)))
                    || (!has_pos && deep(mnpilot::wit::pos_key(&id, m)))
            }
            _ => false,
        };
        let is18 = e == &vec![mnpilot::WIT_DEPTH_CODE];
        if is18 != would {
            bad.push(i);
        }
        if is18 {
            rejected += 1;
        } else {
            kept.push(ow);
            port_ev.extend_from_slice(e);
        }
    }
    // real engine over the batch without the rejected units
    let mut w2 = w[..base].to_vec();
    w2[2] = kept.len() as u32;
    for o in &kept {
        w2.extend_from_slice(o);
    }
    let r = run_real(&w2);
    let ok = bad.is_empty() && r.hash == h && r.ev == port_ev && rejected > 0;
    (ok, format!("{{\"units\":{},\"depth_rejected\":{},\"rule_mismatch_units\":{:?},\"real_equal\":{},\"ok\":{}}}", per.len(), rejected, bad, r.hash == h && r.ev == port_ev, ok))
}

/// Real-engine final leaf set -> proofs for the Oscript verifier.
pub fn proofdump(w: &[u32]) -> String {
    let (_, e) = run_real_eng(w);
    let leaves = real_pilot_leaves(&e);
    let root = smt_ref::root(&leaves);
    let mut by_depth: Vec<(usize, String)> = leaves
        .iter()
        .map(|l| (smt_ref::prove(&leaves, &smt_ref::key(l)).0.len(), l.clone()))
        .collect();
    by_depth.sort();
    let mem = |l: &str| {
        let (sib, _) = smt_ref::prove(&leaves, &smt_ref::key(l));
        assert!(smt_ref::verify_member(&root, l, &sib));
        let s: Vec<String> = sib.iter().rev().map(|x| format!("\"{}\"", smt_ref::b64(x))).collect();
        format!("{{\"leaf\":\"{}\",\"depth\":{},\"sib\":[{}]}}", l, sib.len(), s.join(","))
    };
    let deepest = &by_depth.last().unwrap().1;
    let median = &by_depth[by_depth.len() / 2].1;
    let shallow = &by_depth[0].1;
    // absent: a fresh ord kid; terminal EMPTY or another leaf
    let akid = "ord:00000000000000000000000000000000000000000000000000000000000000ff";
    let ak = smt_ref::key(akid);
    let (asib, t) = smt_ref::prove(&leaves, &ak);
    assert!(smt_ref::verify_absent(&root, &ak, &t, &asib));
    let term = match &t { smt_ref::Term::Empty => "\"\"".to_string(), smt_ref::Term::Leaf(l) => format!("\"{}\"", l) };
    let s: Vec<String> = asib.iter().rev().map(|x| format!("\"{}\"", smt_ref::b64(x))).collect();
    format!(
        "{{\"root\":\"{}\",\"leaves\":{},\"members\":[{},{},{}],\"absent\":{{\"key\":\"{}\",\"term\":{},\"depth\":{},\"sib\":[{}]}}}}",
        smt_ref::b64(&root), leaves.len(), mem(deepest), mem(median), mem(shallow), smt_ref::hex(&ak), term, asib.len(), s.join(",")
    )
}

/// Explicit boundary checks of insert_depth / MAX_WIT_DEPTH on raw keys (no grinding needed).
pub fn depthsel() -> String {
    let mut fails: Vec<String> = Vec::new();
    let mut chk = |n: &str, c: bool| if !c { fails.push(n.into()) };
    let d = mnpilot::wit::MAX_WIT_DEPTH;
    let mut t = mnpilot::wit::Smt::new();
    let k0 = [0x55u8; 32];
    chk("empty_tree_depth0", t.insert_depth(&k0) == Some(0));
    t.set(k0, [1; 32]);
    chk("present_none", t.insert_depth(&k0).is_none());
    // key differing from k0 first at bit b: shares b bits -> depth b+1
    let flip = |b: usize| { let mut k = k0; k[b / 8] ^= 0x80 >> (b % 8); k };
    chk("depth_at_limit", t.insert_depth(&flip(d - 1)) == Some(d));
    chk("depth_over_limit", t.insert_depth(&flip(d)) == Some(d + 1));
    chk("depth_bit0", t.insert_depth(&flip(0)) == Some(1));
    t.set(flip(d - 1), [2; 32]);
    chk("max_depth_tree", t.max_depth() == d);
    // a third key landing in an empty slot below a node: depth = node depth + 1
    chk("empty_slot", t.insert_depth(&flip(3)) == Some(4));
    chk("deep_split", t.insert_depth(&flip(d + 5)) == Some(d + 6));
    format!("{{\"max_wit_depth\":{},\"depthsel_fail\":{:?}}}", d, fails)
}
