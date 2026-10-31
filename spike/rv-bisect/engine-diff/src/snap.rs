//! Loop round 4 (R3-H2): session export / import (guest-engine/src/snapshot.rs).
//!   snaptest <n> <ops> : random batches (place/cancel mix and liqfuzz mix) cut into random
//!       segments; at a random boundary k the session is exported, imported into a FRESH session
//!       and the remaining segments run on the import -- every later segment output (status, state
//!       hash, start / end roots, per-unit roots, events) must equal the uninterrupted session's
//!       (which segrun / segfuzz tie to the real engine), the import's root must equal the export's,
//!       and re-exporting the import must give the same digest. Plus malformed imports (truncated,
//!       one word flipped, non-canonical order) must never panic: a flip either fails the decode or
//!       changes the digest; truncation always fails. Export without a session / import over a live
//!       session are refused.
//!   snapdir <batch> <S> <k> <dir> : files for js/snapguest.js (segments, export.bin, snap.bin,
//!       manifest.json with the uninterrupted run's expectations)
use super::*;

fn run_seg(sw: &[u32], sess: &mut Option<mnpilot::Session>) -> (String, [u8; 32]) {
    let mut ev = Vec::new();
    let mut roots: Vec<[u8; 32]> = Vec::new();
    let (h, st, wo) = mnpilot::run_segment(
        &mut |i| sw.get(i as usize).copied().unwrap_or(0),
        &mut |x| ev.push(x),
        &mut |_, s, r| {
            assert!(s.oi_ok(), "index");
            roots.push(*r)
        },
        mnpilot::WitMode::Incremental,
        sess,
    );
    let hx = |b: &[u8; 32]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
    (
        format!(
            "{} {} {} {} {} {} {:?} {:?}",
            st.status,
            hx(&h),
            hx(&wo.start_root),
            hx(&wo.root),
            st.applied,
            sess.as_ref().map(|s| s.segs).unwrap_or(0),
            roots.iter().map(hx).collect::<Vec<_>>(),
            ev
        ),
        wo.root,
    )
}
pub(crate) fn export_words(sess: &mnpilot::Session) -> ([u8; 32], Vec<u32>) {
    let (d, _, k) = mnpilot::snapshot::export(sess, true);
    (d, k.unwrap())
}
const EXPORT_HDR: [u32; 4] = [mnpilot::snapshot::EXPORT_MAGIC, 0, 0, 0];

pub fn snaptest(n: u64, ops: u32) -> String {
    let (mut ok, mut words_max, mut bad_ok, mut flips, mut flip_decoded) = (0u64, 0u32, 0u64, 0u64, 0u64);
    let mut why = String::new();
    for seed in 1..=n {
        let mut rng = Rng(seed.wrapping_mul(0x5851_F42D_4C95_7F2D) | 1);
        let w = if seed % 2 == 0 { liq::liq_batch(seed, ops) } else { gen(seed, 4 + (seed % 9) as u32, 1 + (seed % 25) as u32, 1 + (seed % 3) as u32, ops, seed % 4 == 1).0 };
        let s = 1 + rng.below((w[2] as u64 / 3).max(1)) as u32;
        let segs = seg::split(&w, s);
        let k = rng.below(segs.len() as u64 + 1) as usize; // export after k segments (k = 0: before any)
        // reference: uninterrupted session (it runs the export too: the export is a segment)
        let mut a: Option<mnpilot::Session> = None;
        let mut b: Option<mnpilot::Session> = None;
        let mut good = true;
        let mut note = |c: bool, what: &str| {
            if !c && good {
                good = false;
                if why.is_empty() {
                    why = format!("seed {} k {} S {}: {}", seed, k, s, what);
                }
            }
        };
        for sw in &segs[..k] {
            run_seg(sw, &mut a);
            run_seg(sw, &mut b);
        }
        // export without a session is refused
        if k == 0 {
            let mut none: Option<mnpilot::Session> = None;
            let o = mnpilot::run_export(&mut |i| EXPORT_HDR.get(i as usize).copied().unwrap_or(0), &mut none);
            note(o.status == mnpilot::ST_NO_SESSION && none.is_none(), "export without session");
            run_seg(&segs[0], &mut a);
            run_seg(&segs[0], &mut b);
        }
        let ea = mnpilot::run_export(&mut |i| EXPORT_HDR.get(i as usize).copied().unwrap_or(0), &mut a);
        let eb = mnpilot::run_export(&mut |i| EXPORT_HDR.get(i as usize).copied().unwrap_or(0), &mut b);
        note(ea.status == 0 && eb.status == 0 && ea.digest == eb.digest, "export status / determinism");
        let (d, words) = export_words(b.as_ref().unwrap());
        note(d == eb.digest && words.len() as u32 == eb.words, "export digest == streamed digest");
        words_max = words_max.max(words.len() as u32);
        // import over a live session is refused (and changes nothing)
        let o = mnpilot::run_import(&mut |i| words.get(i as usize).copied().unwrap_or(0), &mut b, Some(&(d, words.len() as u32)));
        note(o.status == mnpilot::ST_SESSION_LIVE, "import over live session");
        // R4-S1: an image without the compiled-in digest refuses every import
        let mut l: Option<mnpilot::Session> = None;
        let lo = mnpilot::run_import(&mut |i| words.get(i as usize).copied().unwrap_or(0), &mut l, None);
        note(lo.status == mnpilot::ST_IMPORT_LOCKED && l.is_none(), "import without expected digest");
        // fresh import
        let mut c: Option<mnpilot::Session> = None;
        let io = mnpilot::run_import(&mut |i| words.get(i as usize).copied().unwrap_or(0), &mut c, Some(&(d, words.len() as u32)));
        note(io.status == 0 && io.digest == eb.digest && io.words == eb.words && io.root == eb.root, "import digest / root");
        // (the import counted itself as a run, segs + 1: re-export with the exported count)
        c.as_mut().unwrap().segs -= 1;
        let (d2, words2) = export_words(c.as_ref().unwrap());
        c.as_mut().unwrap().segs += 1;
        note(d2 == d && words2 == words, "re-export of the import");
        note(c.as_ref().unwrap().eng.state.oi_ok(), "derived indexes after import");
        note(c.as_ref().unwrap().eng.state.books.values().all(|bk| bk.index_ok() && bk.level_ok()), "book indexes after import");
        // loop round 5 (R4-M4): the import run is a rollup height of its own (segs + 1); the
        // uninterrupted session spends that height too
        note(c.as_ref().unwrap().segs == a.as_ref().unwrap().segs + 1, "import counts as a run");
        a.as_mut().unwrap().segs += 1;
        // loop round 5 (mutation follow-up, round-4 survivor 17): an image built for the digest of
        // the snapshot + one trailing word refuses it (decode must consume exactly `words`)
        {
            let mut v = words.clone();
            v.push(rng.below(1 << 32) as u32);
            let dv: [u8; 32] = {
                let mut h = Sha256::new();
                for x in &v {
                    h.update(x.to_le_bytes());
                }
                h.finalize().into()
            };
            let mut z: Option<mnpilot::Session> = None;
            let o = mnpilot::run_import(&mut |i| v.get(i as usize).copied().unwrap_or(0), &mut z, Some(&(dv, v.len() as u32)));
            note(o.status == mnpilot::ST_BAD_SNAP && z.is_none(), "snapshot + trailing word accepted");
        }
        // continue: every later segment identical
        let start = if k == 0 { 1 } else { k };
        for (j, sw) in segs.iter().enumerate().skip(start) {
            let (ra, _) = run_seg(sw, &mut a);
            let (rc, _) = run_seg(sw, &mut c);
            note(ra == rc, &format!("segment {} after import differs", j));
        }
        let (fa, wa) = export_words(a.as_ref().unwrap());
        let (fc, _) = export_words(c.as_ref().unwrap());
        note(fa == fc, "final export differs");
        // R4-S1: a different well-formed snapshot (the final state) against the expected digest
        let mut y: Option<mnpilot::Session> = None;
        let yo = mnpilot::run_import(&mut |i| wa.get(i as usize).copied().unwrap_or(0), &mut y, Some(&(d, words.len() as u32)));
        note(fa == d || (yo.status == mnpilot::ST_BAD_SNAP && y.is_none()), "another valid snapshot accepted");
        // malformed imports: truncation always fails; a flip fails or changes the digest
        let cut = rng.below(words.len() as u64) as usize;
        let mut z: Option<mnpilot::Session> = None;
        let t = mnpilot::run_import(&mut |i| if (i as usize) < cut { words[i as usize] } else { 0 }, &mut z, Some(&(d, words.len() as u32)));
        let trunc_ok = t.status == mnpilot::ST_BAD_SNAP && z.is_none();
        let mut flip_ok = true;
        for _ in 0..8 {
            let mut v = words.clone();
            let i = rng.below(v.len() as u64) as usize;
            v[i] ^= 1 << rng.below(32);
            let mut z: Option<mnpilot::Session> = None;
            let f = mnpilot::run_import(&mut |i| v.get(i as usize).copied().unwrap_or(0), &mut z, Some(&(d, words.len() as u32)));
            flips += 1;
            // decodes as a well-formed snapshot (another state) vs not: both must be refused
            let mut rdv = |i: u32| v.get(i as usize).copied().unwrap_or(0);
            let mut rr = mnpilot::snapshot::SnapR::new(&mut rdv, mnpilot::SNAP_LIMIT);
            if mnpilot::snapshot::decode(&mut rr).is_ok() {
                flip_decoded += 1;
            }
            flip_ok &= f.status == mnpilot::ST_BAD_SNAP && z.is_none();
        }
        if trunc_ok && flip_ok {
            bad_ok += 1;
        }
        note(trunc_ok, "truncated import accepted");
        note(flip_ok, "flipped import accepted with the same digest");
        if good {
            ok += 1;
        }
    }
    format!(
        "{{\"batches\":{},\"ok\":{},\"malformed_ok\":{},\"flips\":{},\"flips_decoded_new_digest\":{},\"max_snapshot_words\":{},\"why\":\"{}\"}}",
        n, ok, bad_ok, flips, flip_decoded, words_max, why
    )
}

/// Files for js/snapguest.js: seg000..seg{k-1}.bin, export.bin, snap.bin, seg{k}.. and
/// manifest.json = per-file expectations of the UNINTERRUPTED session (host).
pub fn snapdir(w: &[u32], s: u32, k: usize, dir: &str, bind: bool) -> String {
    fs::create_dir_all(dir).unwrap();
    let segs = seg::split(w, s);
    let k = k.clamp(1, segs.len());
    let mut a: Option<mnpilot::Session> = None;
    let hx = |b: &[u8; 32]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
    let mut man = Vec::new();
    let seg_entry = |name: String, sw: &[u32], a: &mut Option<mnpilot::Session>| {
        let mut ev = Vec::new();
        let mut roots: Vec<[u8; 32]> = Vec::new();
        let (h, st, wo) = mnpilot::run_segment_n(
            &mut |i| sw.get(i as usize).copied().unwrap_or(0),
            &mut |x| ev.push(x),
            &mut |_, _, r| roots.push(*r),
            mnpilot::WitMode::Incremental,
            a,
            mnpilot::SegOpt { run_no: None, bind },
        );
        write_words(&format!("{}/{}", dir, name), sw);
        format!(
            "{{\"file\":\"{}\",\"kind\":\"seg\",\"status\":{},\"hash\":\"{}\",\"start_root\":\"{}\",\"end_root\":\"{}\",\"applied\":{},\"rejected\":{},\"fills\":{},\"segs\":{},\"roots\":[{}],\"ev\":[{}]}}",
            name, st.status, hx(&h), hx(&wo.start_root), hx(&wo.root), st.applied, st.rejected, st.fills,
            a.as_ref().map(|s| s.segs).unwrap_or(0),
            roots.iter().map(|r| format!("\"{}\"", hx(r))).collect::<Vec<_>>().join(","),
            ev.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")
        )
    };
    for (j, sw) in segs[..k].iter().enumerate() {
        man.push(seg_entry(format!("seg{:03}.bin", j), sw, &mut a));
    }
    let eo = mnpilot::run_export(&mut |i| EXPORT_HDR.get(i as usize).copied().unwrap_or(0), &mut a);
    write_words(&format!("{}/export.bin", dir), &EXPORT_HDR);
    let (_, words) = export_words(a.as_ref().unwrap());
    write_words(&format!("{}/snap.bin", dir), &words);
    man.push(format!(
        "{{\"file\":\"export.bin\",\"kind\":\"export\",\"status\":{},\"digest\":\"{}\",\"words\":{},\"root\":\"{}\",\"segs\":{}}}",
        eo.status, hx(&eo.digest), eo.words, hx(&eo.root), a.as_ref().unwrap().segs
    ));
    // loop round 5 (R4-M4): the expectations after the export are those of the UPGRADE path (the
    // import is a run = a rollup height); an image that runs on without importing is one behind
    a.as_mut().unwrap().segs += 1;
    for (j, sw) in segs.iter().enumerate().skip(k) {
        man.push(seg_entry(format!("seg{:03}.bin", j), sw, &mut a));
    }
    fs::write(format!("{}/manifest.json", dir), format!("[{}]", man.join(",\n"))).unwrap();
    format!("{{\"segments\":{},\"export_after\":{},\"snapshot_words\":{},\"digest\":\"{}\"}}", segs.len(), k, words.len(), hx(&eo.digest))
}

/// Loop round 4 (long-run heap bound): the worst per-account session footprint. Builds a session
/// with `n` accounts, each with a deposit, positions in BTC_USD and market 2, `orders` resting
/// orders (<= MAX_LIVE_ORDERS_PER_ACCOUNT, spread over both books, distinct prices) and `wd`
/// withdrawals (<= MAX_PENDING_WITHDRAWALS_PER_ACCOUNT), MNWIT1 tree committed after every op;
/// reports the host heap simulation (64-bit sizes = upper bound of rv32) per account and the
/// snapshot size.
pub fn statecap(n: u32, orders: u32, wd: u32) -> String {
    use mnpilot::types::{MarketId as M, OrderType, Side as S, TimeInForce as T, AccountId as A};
    heapsim::reset();
    heapsim::ON.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut sess = mnpilot::Session::genesis(mnpilot::MARKET2_FLAG, mnpilot::WitMode::Incremental);
    let id = |i: u32| A(Sha256::digest(format!("statecap-{}", i).as_bytes()).into());
    let mut fails = 0u32;
    for i in 0..n {
        let a = id(i);
        let e = &mut sess.eng;
        let mut ok = |r: Result<Vec<mnpilot::Fill>, mnpilot::engine::RejectReason>, e: &mut mnpilot::engine::Engine| {
            if r.is_ok() { e.state.seq += 1 } else { fails += 1 }
        };
        let r = e.deposit(a, 10_000_000 * USD_SCALE as i128);
        ok(r, e);
        // positions: cross a counterparty's resting order (counterparty = previous account)
        if i > 0 {
            for m in [1u32, 2] {
                let b = id(i - 1);
                let seq = e.state.seq;
                let cs = e.state.seen_client_seq.get(&b).copied().unwrap_or(0) + 1;
                let r = e.place(b, M(m), S::Ask, OrderType::Limit, T::Gtc, MID + 7 * DOLLAR, QTY_SCALE / 100, cs, [0; 32], seq, false, 0);
                ok(r, e);
                let seq = e.state.seq;
                let cs = e.state.seen_client_seq.get(&a).copied().unwrap_or(0) + 1;
                let r = e.place(a, M(m), S::Bid, OrderType::Limit, T::Gtc, MID + 7 * DOLLAR, QTY_SCALE / 100, cs, [0; 32], seq, false, 0);
                ok(r, e);
            }
        }
        for j in 0..orders {
            let seq = e.state.seq;
            let cs = e.state.seen_client_seq.get(&a).copied().unwrap_or(0) + 1;
            let m = 1 + (j % 2);
            let px = MID - (1000 + (i as i64 * 64 + j as i64) % 5000) * DOLLAR;
            let r = e.place(a, M(m), S::Bid, OrderType::Limit, T::Gtc, px, QTY_SCALE / 1000, cs, [0; 32], seq, j % 3 == 0, if j % 3 == 0 { 50 * USD_SCALE } else { 0 });
            ok(r, e);
        }
        for k in 0..wd {
            let r = e.withdraw(a, USD_SCALE as i128, k as u64 + 1);
            ok(r, e);
        }
        if let Some(w) = sess.w.as_mut() {
            w.commit(&mut sess.eng.state);
        }
    }
    heapsim::ON.store(false, std::sync::atomic::Ordering::Relaxed);
    let (top, peak, _) = heapsim::read();
    let (_, words, _) = mnpilot::snapshot::export(&sess, false);
    let live: usize = sess.eng.state.books.values().map(|b| b.live_orders().count()).sum();
    format!(
        "{{\"accounts\":{},\"orders_per_account\":{},\"withdrawals_per_account\":{},\"rejected_ops\":{},\"live_orders\":{},\"leaves\":{},\"sizeclass_highwater\":{},\"peak_live\":{},\"sum_class_peaks\":{},\"bytes_per_account_highwater\":{},\"snapshot_words\":{},\"guest_heap_limit\":{}}}",
        sess.eng.state.accounts.len(), orders, wd, fails, live, sess.w.as_ref().map(|w| w.smt.count).unwrap_or(0), top, peak,
        heapsim::sum_class_peaks(), top / n.max(1) as usize, words, 0x0300_0000u32 - 0x0002_0000
    )
}

/// Loop round 4: the session account cap (STATE_CAP_CODE). Runs liqfuzz-style batches with
/// many depositing accounts through a session whose cap is lowered to `cap`, and checks after
/// every unit: accounts <= cap; every code-19 unit is a deposit / liquidate whose author had no
/// account while the session was at the cap; no other unit is ever code 19; and the run equals
/// the uncapped run up to the first code-19 unit (the rule never fires early).
pub fn capcheck(n: u64, ops: u32, cap: usize) -> String {
    let (mut ok, mut fired) = (0u64, 0u64);
    let mut why = String::new();
    for seed in 1..=n {
        let mut w = liq::liq_batch(seed, ops);
        // extra depositors: new accounts in the table, depositing late
        let n_acc = w[1] as usize;
        let extra = cap as u32 + 8;
        let base = 4 + n_acc * 8;
        let mut ids: Vec<u32> = w[4..base].to_vec();
        for i in 0..extra {
            let id = acct_id(n_acc as u32 + i);
            for k in 0..8 {
                ids.push(u32::from_le_bytes(id.0[k * 4..k * 4 + 4].try_into().unwrap()));
            }
        }
        let mut opsv: Vec<u32> = w[base..].to_vec();
        for i in 0..extra {
            let a = n_acc as u32 + i;
            let amt = 1_000 * USD_SCALE as i64;
            opsv.extend_from_slice(&[1 | (a << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, 0, 0]);
            // a keeper-style liquidate by a brand-new account
            opsv.extend_from_slice(&[7 | ((n_acc as u32 + extra - 1 - i) << 8), 10, 0, 0, 0, 0, 0, 1]);
        }
        let n_ops = opsv.len() / 8;
        w = [vec![w[0], (n_acc as u32 + extra), n_ops as u32, w[3]], ids, opsv].concat();
        let run = |cap: usize| {
            let mut evs: Vec<Vec<u32>> = Vec::new();
            let mut lens: Vec<usize> = Vec::new();
            let mut cur: Vec<u32> = Vec::new();
            let ids_p: Vec<mnpilot::types::AccountId> = (0..w[1] as usize)
                .map(|a| {
                    let mut id = [0u8; 32];
                    for k in 0..8 {
                        id[k * 4..k * 4 + 4].copy_from_slice(&w[4 + a * 8 + k].to_le_bytes());
                    }
                    mnpilot::types::AccountId(id)
                })
                .collect();
            let mut g = mnpilot::Session::genesis_with(w[3], mnpilot::WitMode::Incremental, &ids_p);
            g.segs = 1;
            g.state_cap = cap;
            let mut s = Some(g);
            let mut hdr = w.clone();
            hdr[3] = 0; // resumed session: flags must be 0 (fixtures already applied above)
            let evc = std::cell::RefCell::new(&mut cur);
            let _ = mnpilot::run_segment(
                &mut |i| hdr.get(i as usize).copied().unwrap_or(0),
                &mut |x| evc.borrow_mut().push(x),
                &mut |_, st, _| {
                    let mut c = evc.borrow_mut();
                    evs.push(std::mem::take(&mut **c));
                    lens.push(st.accounts.len());
                },
                mnpilot::WitMode::Incremental,
                &mut s,
            );
            (evs, lens)
        };
        let (ec, lc) = run(cap);
        let (eu, _) = run(usize::MAX);
        let base = 4 + w[1] as usize * 8;
        let mut good = lc.iter().all(|&l| l <= cap);
        let first19 = ec.iter().position(|e| e == &vec![mnpilot::STATE_CAP_CODE]);
        if let Some(f) = first19 {
            fired += 1;
            good &= ec[..f] == eu[..f];
            for (i, e) in ec.iter().enumerate() {
                if e == &vec![mnpilot::STATE_CAP_CODE] {
                    let kind = w[base + 8 * i] & 0xff;
                    let pre = if i == 0 { 0 } else { lc[i - 1] };
                    good &= (kind == 1 || kind == 7) && pre >= cap;
                }
            }
        }
        // loop round 5 (round-4 survivor 15): the rule must FIRE for every deposit / liquidate by a
        // brand-new author at the cap (18 = depth rule may come first)
        {
            let mut created = std::collections::BTreeSet::new();
            for (i, e) in ec.iter().enumerate() {
                let op0 = w[base + 8 * i];
                let (kind, au) = (op0 & 0xff, op0 >> 8);
                let pre = if i == 0 { 0 } else { lc[i - 1] };
                if au as usize >= n_acc && (kind == 1 || kind == 7) && pre >= cap && !created.contains(&au) {
                    good &= e == &vec![mnpilot::STATE_CAP_CODE] || e == &vec![mnpilot::WIT_DEPTH_CODE];
                }
                if e.first().is_some_and(|x| x & EV_APPLIED != 0) {
                    created.insert(au);
                }
            }
        }
        if first19.is_none() {
            good &= ec == eu;
        }
        if good {
            ok += 1;
        } else if why.is_empty() {
            why = format!("seed {}", seed);
        }
    }
    format!("{{\"batches\":{},\"ok\":{},\"cap\":{},\"cap_fired_batches\":{},\"why\":\"{}\"}}", n, ok, cap, fired, why)
}

/// Loop round 5 (mutation follow-up, round-4 survivor 18): a snapshot of a session holding more
/// than MAX_STATE_ACCOUNTS accounts (a host session with a raised cap) is refused by the decoder
/// even with a matching digest; one at exactly the cap is accepted.
pub fn snapcap() -> String {
    let mk = |n: usize| {
        let mut s = mnpilot::Session::genesis(0, mnpilot::WitMode::Incremental);
        s.state_cap = n + 10;
        let mut i = 0u32;
        while s.eng.state.accounts.len() < n {
            let a = mnpilot::types::AccountId(Sha256::digest(format!("snapcap-{}", i).as_bytes()).into());
            s.eng.deposit(a, 1_000 * USD_SCALE as i128).unwrap();
            i += 1;
        }
        let _ = s.eng.state.take_dirty();
        s.w = Some(mnpilot::wit::Wit::from_state(&s.eng.state));
        let (d, words) = export_words(&s);
        let mut z: Option<mnpilot::Session> = None;
        let o = mnpilot::run_import(&mut |i| words.get(i as usize).copied().unwrap_or(0), &mut z, Some(&(d, words.len() as u32)));
        o.status
    };
    let at = mk(mnpilot::MAX_STATE_ACCOUNTS);
    let over = mk(mnpilot::MAX_STATE_ACCOUNTS + 1);
    format!("{{\"ok\":{},\"at_cap_status\":{},\"over_cap_status\":{}}}", at == 0 && over == mnpilot::ST_BAD_SNAP, at, over)
}
