//! Loop round 1 adversarial generators (findings/rv-loop-1.md).
//!   crowd   : n accounts x k bids resting at ONE price (guest heap / journal-clone blowup, G3)
//!   advfuzz : edge-heavy random ops (negative/zero/huge amounts, prices at caps, misaligned ticks,
//!             wrong markets, client_seq gaps, foreign/stale cancels, isolated margins at the
//!             boundaries, market GTC, two markets) -- real engine vs port: hash + events + per-unit
//!             MNWIT1 roots (real state from scratch / port incremental / port from scratch)
//!   robust  : malformed batches (header limits, truncation, out-of-range ids, bad kinds,
//!             insurance-id author) written to a directory for the host-vs-guest check (js/robust.js)
use super::*;

pub fn batch_words(ids_real: &[AccountId], ops: &[[u32; 8]], flags: u32) -> Vec<u32> {
    let mut w = vec![mnpilot::MAGIC, ids_real.len() as u32, ops.len() as u32, flags];
    for id in ids_real {
        for k in 0..8 {
            w.push(u32::from_le_bytes(id.0[k * 4..k * 4 + 4].try_into().unwrap()));
        }
    }
    for o in ops {
        w.extend_from_slice(o);
    }
    w
}
fn new_gen(n_acc: u32, flags: u32) -> (Vec<AccountId>, Gen) {
    let ids_real: Vec<AccountId> = (0..n_acc).map(acct_id).collect();
    let ids: Vec<mnpilot::types::AccountId> = ids_real.iter().map(|a| mnpilot::types::AccountId(a.0)).collect();
    let g = Gen { eng: mnpilot::engine::Engine { state: mnpilot::state::ChainState::genesis_flags(flags) }, ops: Vec::new(), live: Vec::new(), ids };
    (ids_real, g)
}
fn dep(a: u32, amt: i64) -> [u32; 8] {
    [1 | (a << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, 0, 0]
}

/// `n_acc` accounts deposit 1 000 USD, then round-robin each places `per` bids of 0.0001 BTC at
/// 99 000 USD (one price level). Every place touches that level, and the book's undo journal
/// clones the level's whole order-id deque on first touch.
pub fn crowd(n_acc: u32, per: u32) -> Vec<u32> {
    let (ids_real, mut g) = new_gen(n_acc, 0);
    for a in 0..n_acc {
        g.apply(dep(a, 1_000 * USD_SCALE as i64));
    }
    for _ in 0..per {
        for a in 0..n_acc {
            if g.ops.len() as u32 >= mnpilot::MAX_UNITS {
                break;
            }
            g.place(a, true, false, false, MID - 1_000 * DOLLAR, QTY_SCALE / 10_000);
        }
    }
    batch_words(&ids_real, &g.ops, 0)
}

/// One edge-heavy random batch.
pub fn adv_batch(seed: u64, n_ops: u32) -> Vec<u32> {
    let mut rng = Rng(seed.wrapping_mul(0xA24B_AED4_963E_E407) | 1);
    let n_acc = 3 + rng.below(10) as u32;
    let flags = if rng.below(2) == 0 { mnpilot::MARKET2_FLAG } else { 0 };
    let (ids_real, mut g) = new_gen(n_acc, flags);
    let pick = |rng: &mut Rng, v: &[i64]| v[rng.below(v.len() as u64) as usize];
    for a in 0..n_acc {
        let usd = pick(&mut rng, &[1, 2, 5, 30, 200, 2_000, 50_000, 10_000_000]);
        g.apply(dep(a, usd * USD_SCALE as i64));
    }
    for _ in 0..n_ops {
        let a = rng.below(n_acc as u64) as u32;
        let r = rng.below(100);
        let mkt = if rng.below(10) == 0 { pick(&mut rng, &[0, 2, 3, 1]) as u32 } else if flags != 0 && rng.below(3) == 0 { 2 } else { 1 };
        if r < 8 {
            // deposits incl. 0, negative, tiny, huge
            let amt = pick(&mut rng, &[0, -1, -1_000_000, 1, 999_999, 1_000_000, 37 * USD_SCALE as i64, 1_000_000 * USD_SCALE as i64, i64::MAX / 4, i64::MAX, i64::MIN]);
            g.apply(dep(a, amt));
            continue;
        }
        if r < 22 {
            // cancels: own live, stale, random seq, foreign order id, wrong market
            let (ca, cs, cm) = match rng.below(5) {
                0 | 1 if !g.live.is_empty() => {
                    let i = rng.below(g.live.len() as u64) as usize;
                    let (x, y) = if rng.below(4) == 0 { g.live[i] } else { g.live.swap_remove(i) };
                    (x, y, 1)
                }
                2 if !g.live.is_empty() => {
                    let (_, y) = g.live[rng.below(g.live.len() as u64) as usize];
                    (a, y, 1) // someone else's seq under my id (usually NotFound)
                }
                3 => (a, rng.below(40), mkt),
                _ => (a, g.next_cseq(a).saturating_sub(1 + rng.below(3)), pick(&mut rng, &[1, 2, 7]) as u32),
            };
            g.apply([3 | (ca << 8), 0, 0, 0, 0, 0, cs as u32, cm]);
            continue;
        }
        // places
        let bid = rng.below(2) == 0;
        let typ_mkt = rng.below(6) == 0;
        let ioc = rng.below(4) == 0;
        let (bb, ba) = {
            let bk = g.eng.state.books.get(&mnpilot::types::MarketId(1));
            (bk.and_then(|b| b.best_bid().map(|x| x.0)), bk.and_then(|b| b.best_ask().map(|x| x.0)))
        };
        let near = |rng: &mut Rng| {
            let k = rng.below(6) as i64 - 2;
            if bid { ba.unwrap_or(MID) - k * DOLLAR } else { bb.unwrap_or(MID) + k * DOLLAR }
        };
        let price: i64 = if typ_mkt && rng.below(4) != 0 {
            0
        } else {
            match rng.below(14) {
                0 => 0,
                1 => -MID,
                2 => mnpilot::types::MARK_CAP - DOLLAR,
                3 => mnpilot::types::MARK_CAP,
                4 => near(&mut rng) + 1, // misaligned tick (if tick > 1)
                5 => MID + 9_999 * DOLLAR,
                6 => MID - 9_999 * DOLLAR,
                7 => MID * 3,
                8 => DOLLAR,
                _ => near(&mut rng),
            }
        };
        let qty: u64 = match rng.below(14) {
            0 => 0,
            1 => 1,
            2 => 100,
            3 => mnpilot::types::QTY_CAP - 1,
            4 => i64::MAX as u64,
            5 => u64::MAX,
            6 => i64::MAX as u64 + 1,
            7 => 3 * QTY_SCALE,
            _ => (1 + rng.below(300)) * (QTY_SCALE / 1_000),
        };
        let cs = match rng.below(12) {
            0 => 0,
            1 => g.next_cseq(a) + 1,
            2 => g.next_cseq(a).saturating_sub(1),
            _ => g.next_cseq(a),
        };
        let flagsw = (!bid as u32) | ((typ_mkt as u32) << 1) | ((ioc as u32) << 2) | ((rng.below(8) as u32) << 3);
        let (k, w7) = match rng.below(10) {
            0 | 1 => (4, pick(&mut rng, &[0, 1, 2, 10, 100, 1_000, 30_000, 4_000_000_000]) as u32),
            2 => (5, pick(&mut rng, &[0, 1, 9_999, 10_000, 1_000_000, 4_294_967_295]) as u32),
            _ => (2, mkt),
        };
        let w = [k | (a << 8), flagsw, price as u32, (price >> 32) as u32, qty as u32, (qty >> 32) as u32, cs as u32, w7];
        let ok = g.apply(w);
        if ok && !typ_mkt && !ioc && price != 0 {
            g.live.push((a, cs));
        }
    }
    batch_words(&ids_real, &g.ops, flags)
}

/// real vs port (hash + events) and per-unit roots for `n` adversarial batches.
pub fn advfuzz(n: u64, ops: u32) -> String {
    let (mut ok, mut units, mut fills, mut applied) = (0u64, 0u64, 0u64, 0u64);
    let mut codes: std::collections::BTreeMap<u32, u32> = Default::default();
    for s in 1..=n {
        let w = adv_batch(s, ops);
        let mut a = Vec::new();
        let (r, _) = run_real_eng_cb(&w, &mut |e| a.push(smt_ref::root(&real_pilot_leaves(e))));
        let p = run_port(&w);
        let (b, c, wo) = port_roots(&w);
        let same = r.hash == p.hash && r.ev == p.ev && r.applied == p.applied;
        let roots = a == b && b == c && wo.scratch_ok && a.len() == w[2] as usize;
        if same && roots {
            ok += 1;
        } else {
            let first_ev = r.ev.iter().zip(&p.ev).position(|(x, y)| x != y);
            let first_root = a.iter().zip(&b).zip(&c).position(|((x, y), z)| x != y || y != z);
            println!("ADVMISMATCH seed {} engine {} roots {} first_ev {:?} first_root {:?}", s, same, roots, first_ev, first_root);
        }
        units += a.len() as u64;
        fills += r.fills as u64;
        applied += r.applied as u64;
        let mut k = 0;
        while k < r.ev.len() {
            let e = r.ev[k];
            if e & EV_APPLIED != 0 {
                *codes.entry(EV_APPLIED | (e & 0xff)).or_default() += 1;
                k += 1 + 6 * (e & 0xff) as usize;
            } else {
                *codes.entry(e).or_default() += 1;
                k += 1;
            }
        }
    }
    let cs: Vec<String> = codes.iter().map(|(k, v)| format!("\"{:#x}\":{}", k, v)).collect();
    format!("{{\"seeds\":{},\"match\":{},\"units\":{},\"applied\":{},\"fills\":{},\"codes\":{{{}}}}}", n, ok, units, applied, fills, cs.join(","))
}

/// Malformed / limit batches for the host-vs-guest robustness check.
pub fn robust(dir: &str) -> String {
    let base = gen(5, 4, 3, 1, 40, true).0; // valid 4-maker batch
    let n_acc = base[1] as usize;
    let mut cases: Vec<(String, Vec<u32>)> = Vec::new();
    cases.push(("ok_base".into(), base.clone()));
    let mut b = base.clone(); b[0] ^= 1; cases.push(("bad_magic".into(), b));
    let mut b = base.clone(); b[1] = mnpilot::MAX_ACCOUNTS + 1; cases.push(("acc_over_limit".into(), b));
    let mut b = base.clone(); b[1] = u32::MAX; cases.push(("acc_u32max".into(), b));
    let mut b = base.clone(); b[2] = mnpilot::MAX_UNITS + 1; cases.push(("ops_over_limit".into(), b));
    let mut b = base.clone(); b[2] = u32::MAX; cases.push(("ops_u32max".into(), b));
    let mut b = base.clone(); b[2] = 0; cases.push(("ops_zero".into(), b));
    let mut b = base.clone(); b[1] = 0; cases.push(("acc_zero_ops_shift".into(), b)); // ops read from the id table
    // truncated: header claims all ops, words stop halfway (missing words read as 0)
    let mut b = base.clone(); b.truncate(4 + 8 * n_acc + 8 * (base[2] as usize / 2) + 3); cases.push(("truncated".into(), b));
    let mut b = base[..4 + 8 * n_acc].to_vec(); b[2] = mnpilot::MAX_UNITS; cases.push(("truncated_max_units".into(), b));
    // garbage op words: out-of-range account index, unknown kinds, all-ones
    let mut b = base.clone();
    let o = 4 + 8 * n_acc;
    for (i, x) in [0xFFFF_FF02u32, 0x0000_0007, 0xFFFF_FFFF, (n_acc as u32) << 8 | 2, 0x0000_0100].iter().enumerate() {
        b[o + 8 * (10 + i)] = *x;
    }
    for k in 0..8 { b[o + 8 * 20 + k] = 0xFFFF_FFFF; }
    cases.push(("garbage_ops".into(), b));
    // insurance id (all zero) in the account table, authoring a deposit + a place
    let mut b = base.clone();
    for k in 0..8 { b[4 + k] = 0; }
    cases.push(("insurance_author".into(), b));
    // trailing junk after the declared ops (ignored)
    let mut b = base.clone(); b.extend_from_slice(&[7; 64]); cases.push(("trailing_junk".into(), b));
    // limit batch: MAX_ACCOUNTS accounts table, MAX_UNITS ops of mostly-rejected junk
    let mut b = vec![mnpilot::MAGIC, mnpilot::MAX_ACCOUNTS, mnpilot::MAX_UNITS, 0];
    for i in 0..mnpilot::MAX_ACCOUNTS { for k in 0..8 { b.push(i.wrapping_mul(0x9E37_79B9) ^ k + 1); } }
    let mut r = Rng(99);
    for i in 0..mnpilot::MAX_UNITS {
        let a = r.below(mnpilot::MAX_ACCOUNTS as u64) as u32;
        let amt = 10 * USD_SCALE as i64;
        let op = match i % 4 { 0 => dep(a, amt), 1 => [2 | a << 8, 0, (MID - 50 * DOLLAR) as u32, ((MID - 50 * DOLLAR) >> 32) as u32, 100_000, 0, 1, 1], 2 => [3 | a << 8, 0, 0, 0, 0, 0, 1, 1], _ => [r.next() as u32, r.next() as u32, 0, 0, 0, 0, 0, 0] };
        b.extend_from_slice(&op);
    }
    cases.push(("limit_max_accounts_units".into(), b));
    let mut names = Vec::new();
    for (n, w) in &cases {
        write_words(&format!("{}/{}.bin", dir, n), w);
        names.push(format!("\"{}\"", n));
    }
    format!("{{\"cases\":[{}]}}", names.join(","))
}

/// Port output in the guest's result shape (status, hash, events, per-unit roots) for js/robust.js.
pub fn portout(w: &[u32]) -> String {
    let mut ev = Vec::new();
    let mut roots = Vec::new();
    let (h, st, wo) = mnpilot::run_batch_wit(
        &mut |i| w.get(i as usize).copied().unwrap_or(0),
        &mut |x| ev.push(x),
        &mut |_, _, r| roots.push(format!("\"{}\"", smt_ref::hex(r))),
        mnpilot::WitMode::Incremental,
    );
    let e: Vec<String> = ev.iter().map(|x| x.to_string()).collect();
    format!(
        "{{\"status\":{},\"hash\":\"{}\",\"applied\":{},\"rejected\":{},\"fills\":{},\"scratch_ok\":{},\"ev\":[{}],\"roots\":[{}]}}",
        st.status, smt_ref::hex(&h), st.applied, st.rejected, st.fills, wo.scratch_ok as u32, e.join(","), roots.join(",")
    )
}

/// MNWIT1 proof soundness/completeness + forgery attempts over the real engine's per-unit leaf sets
/// of `n` gen/adv batches (every `stride`-th unit).
pub fn proofs(n: u64, stride: usize) -> String {
    use smt_ref::{key, prove, verify_absent, verify_member, Term};
    let (mut mem_ok, mut mem_bad, mut abs_ok, mut abs_bad, mut forged, mut forge_try) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut max_depth = 0usize;
    for s in 1..=n {
        let w = if s % 2 == 0 { adv_batch(s, 200) } else { gen(s, 4 + (s % 9) as u32, 1 + (s % 25) as u32, 1 + (s % 3) as u32, 200, s % 4 == 1).0 };
        let mut sets: Vec<Vec<String>> = Vec::new();
        let mut i = 0usize;
        run_real_eng_cb(&w, &mut |e| { if i % stride == 0 { sets.push(real_pilot_leaves(e)); } i += 1; });
        let mut rng = Rng(s | 1);
        for leaves in &sets {
            let root = smt_ref::root(leaves);
            for l in leaves {
                let (sib, t) = prove(leaves, &key(l));
                max_depth = max_depth.max(sib.len());
                if t == Term::Leaf(l.clone()) && verify_member(&root, l, &sib) { mem_ok += 1 } else { mem_bad += 1 }
                // forgery 1: claim absence of a present key with its own leaf as terminal
                forge_try += 1; if verify_absent(&root, &key(l), &Term::Leaf(l.clone()), &sib) { forged += 1 }
                // forgery 2: tampered leaf text (one more unit of the last field) still "member"
                let mut t2 = l.clone(); t2.push('0');
                forge_try += 1; if verify_member(&root, &t2, &sib) { forged += 1 }
                // forgery 3: stop one level early, presenting the leaf as the subtree there
                if !sib.is_empty() { forge_try += 1; if verify_member(&root, l, &sib[..sib.len() - 1]) { forged += 1 } }
                // forgery 4: absence via EMPTY at the leaf's own position
                forge_try += 1; if verify_absent(&root, &key(l), &Term::Empty, &sib) { forged += 1 }
            }
            // absent keys: random kids of every tag, incl. kids that exist with a changed field
            for j in 0..20 {
                let kid = match j % 4 { 0 => format!("acct:{:064x}", rng.next()), 1 => format!("ord:{:064x}", rng.next()), 2 => format!("pos:{:064x}:{}", rng.next(), j), _ => format!("meta:{}", 3 + j) };
                let k = smt_ref::key(&format!("{}:0", kid));
                if leaves.iter().any(|l| key(l) == k) { continue; }
                let (sib, t) = prove(leaves, &k);
                if verify_absent(&root, &k, &t, &sib) { abs_ok += 1 } else { abs_bad += 1 }
                // forgery 5: membership of a made-up leaf with that absence path
                forge_try += 1; if verify_member(&root, &format!("{}:0", kid), &sib) { forged += 1 }
                // forgery 6: absence proof with the terminal swapped to some other real leaf
                if let Some(o) = leaves.get(rng.below(leaves.len() as u64) as usize) {
                    if Term::Leaf(o.clone()) != t { forge_try += 1; if verify_absent(&root, &k, &Term::Leaf(o.clone()), &sib) { forged += 1 } }
                }
            }
        }
    }
    format!("{{\"batches\":{},\"membership_ok\":{},\"membership_bad\":{},\"absence_ok\":{},\"absence_bad\":{},\"forgery_attempts\":{},\"forged\":{},\"max_depth\":{}}}",
        n, mem_ok, mem_bad, abs_ok, abs_bad, forge_try, forged, max_depth)
}

/// Explicit expectations for the shared host/guest input checks (kills mutants that a host-vs-guest
/// diff cannot see because both run the same mnpilot code).
pub fn selftest(dir: &str) -> String {
    let mut fails: Vec<String> = Vec::new();
    let mut chk = |name: &str, cond: bool| if !cond { fails.push(name.to_string()) };
    let run = |n: &str| -> (u32, Vec<u32>, u32, [u8; 32]) {
        let w = read_words(&format!("{}/{}.bin", dir, n));
        let mut ev = Vec::new();
        let (h, st, _) = mnpilot::run_batch_wit(&mut |i| w.get(i as usize).copied().unwrap_or(0), &mut |x| ev.push(x), &mut |_, _, _| {}, mnpilot::WitMode::Incremental);
        (st.status, ev, st.applied, h)
    };
    let (st, _, _, h) = run("bad_magic"); chk("bad_magic", st == mnpilot::ST_BAD_MAGIC && h == [0; 32]);
    let (st, ev, _, _) = run("acc_over_limit"); chk("acc_over_limit", st == mnpilot::ST_TOO_MANY_ACCOUNTS && ev.is_empty());
    let (st, ev, _, _) = run("acc_u32max"); chk("acc_u32max", st == mnpilot::ST_TOO_MANY_ACCOUNTS && ev.is_empty());
    let (st, ev, _, _) = run("ops_over_limit"); chk("ops_over_limit", st == mnpilot::ST_TOO_MANY_UNITS && ev.is_empty());
    let (st, ev, _, _) = run("ops_u32max"); chk("ops_u32max", st == mnpilot::ST_TOO_MANY_UNITS && ev.is_empty());
    let (st, ev, _, _) = run("ops_zero"); chk("ops_zero", st == 0 && ev.is_empty());
    let (st, ev, ap, _) = run("truncated_max_units"); chk("truncated_max_units", st == 0 && ev.len() == mnpilot::MAX_UNITS as usize && ev.iter().all(|&e| e == 2) && ap == 0);
    let (st, ev, _, _) = run("insurance_author");
    // account 0 of the base batch is a maker whose first op is a deposit: with an all-zero id it must be BadAccount
    let w = read_words(&format!("{}/insurance_author.bin", dir));
    let n_acc = w[1] as usize;
    let first0 = (0..w[2] as usize).position(|i| w[4 + 8 * n_acc + 8 * i] >> 8 == 0).unwrap();
    let mut k = 0; let mut e0 = u32::MAX;
    for i in 0..w[2] as usize {
        if i == first0 { e0 = ev[k]; break; }
        k += if ev[k] & EV_APPLIED != 0 { 1 + 6 * (ev[k] & 0xff) as usize } else { 1 };
    }
    chk("insurance_author", st == 0 && e0 == 2);
    let (_, ev, _, _) = run("garbage_ops"); chk("garbage_ops_nonempty", !ev.is_empty());
    let a = run("ok_base"); let b = run("trailing_junk"); chk("trailing_junk", a.1 == b.1 && a.3 == b.3);
    format!("{{\"selftest_fail\":[{}]}}", fails.iter().map(|f| format!("\"{}\"", f)).collect::<Vec<_>>().join(","))
}
