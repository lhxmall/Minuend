//! Loop round 3: segmentation of an upstream batch into <= MAX_UNITS-unit guest runs (one rollup
//! height each) with the engine state carried between runs (`mnpilot::Session`).
//!   segrun  <batch> <S> [outdir] : split into segments of S units, run the REAL engine over the
//!            whole batch and the port segment by segment on one session; compare every per-unit
//!            MNWIT1 root, every event, the state hash at every segment end, and the segment
//!            boundary commitment (start root of k == end root of k-1, start of 0 == genesis root).
//!            outdir: seg000.bin.. + manifest.json (expected per-segment outputs, for js/segguest.js);
//!            optional 5th arg k: inject a flags=1 copy of segment k before it (must be refused, status 4)
//!   segfuzz <n> <orders>        : n random batches, random S (1..400), a rejected-header segment
//!            (flags != 0 on a resumed session -> status 4, no op, session unchanged) injected
//!            in every 3rd batch.
use super::*;

pub fn split(w: &[u32], s: u32) -> Vec<Vec<u32>> {
    let (n_acc, n_ops) = (w[1], w[2]);
    let base = (4 + n_acc * 8) as usize;
    let mut out = Vec::new();
    let mut k = 0u32;
    loop {
        let lo = k * s;
        let hi = (lo + s).min(n_ops);
        let mut v = vec![mnpilot::MAGIC, n_acc, hi - lo, if k == 0 { w[3] } else { 0 }];
        v.extend_from_slice(&w[4..base]);
        v.extend_from_slice(&w[base + 8 * lo as usize..base + 8 * hi as usize]);
        out.push(v);
        k += 1;
        if hi >= n_ops {
            break;
        }
    }
    out
}

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub struct SegCheck {
    pub ok: bool,
    pub segs: usize,
    pub units: usize,
    pub manifest: String,
    pub why: String,
}

/// `bad_at`: inject a copy of segment k with flags = 1 before segment k (k >= 1): must be refused
/// with ST_BAD_FLAGS and change nothing.
pub fn check(w: &[u32], s: u32, bad_at: Option<usize>) -> (SegCheck, Vec<Vec<u32>>) {
    let n_ops = w[2] as usize;
    let mut segs = split(w, s);
    if let Some(k) = bad_at {
        if k >= 1 && k < segs.len() {
            let mut b = segs[k].clone();
            b[3] = 1;
            segs.insert(k, b);
        }
    }
    // real engine over the whole batch
    let mut rroots: Vec<[u8; 32]> = Vec::new();
    let mut rhash: Vec<[u8; 32]> = Vec::new();
    let (rout, _) = run_real_eng_cb(w, &mut |e| {
        rroots.push(smt_ref::root(&real_pilot_leaves(e)));
        rhash.push(real_hash(&e.state));
    });
    let genesis_root = mnpilot::wit::Wit::from_state(&mnpilot::state::ChainState::genesis_flags(w[3])).root();
    let mut sess: Option<mnpilot::Session> = None;
    let mut done = 0usize; // units consumed
    let mut prev_end = genesis_root;
    let mut ev_all: Vec<u32> = Vec::new();
    let mut why = String::new();
    let mut man = Vec::new();
    for (k, sw) in segs.iter().enumerate() {
        let mut ev = Vec::new();
        let mut roots: Vec<[u8; 32]> = Vec::new();
        let (h, st, wo) = mnpilot::run_segment(
            &mut |i| sw.get(i as usize).copied().unwrap_or(0),
            &mut |x| ev.push(x),
            &mut |i, s, r| {
                assert!(s.books.values().all(|b| b.index_ok() && b.level_ok()) && s.oi_ok(), "index broken at seg unit {}", i);
                roots.push(*r);
            },
            mnpilot::WitMode::Incremental,
            &mut sess,
        );
        let injected = bad_at == Some(k) && sw[3] != 0;
        let seg_ok;
        if injected {
            seg_ok = st.status == mnpilot::ST_BAD_FLAGS && roots.is_empty() && ev.is_empty() && h == [0; 32];
        } else {
            let n = sw[2] as usize;
            let want = &rroots[done..done + n];
            let end_real = if done + n == 0 { genesis_root } else { rroots[done + n - 1] };
            let hash_real = if n == 0 { None } else { Some(rhash[done + n - 1]) };
            seg_ok = st.status == mnpilot::ST_OK
                && roots.as_slice() == want
                && wo.start_root == prev_end
                && wo.root == end_real
                && hash_real.map(|x| x == h).unwrap_or(true)
                && wo.scratch_ok;
            ev_all.extend_from_slice(&ev);
            prev_end = wo.root;
            done += n;
        }
        if !seg_ok && why.is_empty() {
            why = format!("segment {} (status {}, injected {})", k, st.status, injected);
        }
        man.push(format!(
            "{{\"file\":\"seg{:03}.bin\",\"status\":{},\"hash\":\"{}\",\"start_root\":\"{}\",\"end_root\":\"{}\",\"applied\":{},\"rejected\":{},\"fills\":{},\"segs\":{},\"roots\":[{}],\"ev\":[{}]}}",
            k, st.status, hx(&h), hx(&wo.start_root), hx(&wo.root), st.applied, st.rejected, st.fills,
            sess.as_ref().map(|s| s.segs).unwrap_or(0),
            roots.iter().map(|r| format!("\"{}\"", hx(r))).collect::<Vec<_>>().join(","),
            ev.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(",")
        ));
    }
    let ok = why.is_empty() && done == n_ops && ev_all == rout.ev;
    if why.is_empty() && !ok {
        why = format!("totals: done {} of {}, events equal {}", done, n_ops, ev_all == rout.ev);
    }
    (SegCheck { ok, segs: segs.len(), units: n_ops, manifest: format!("[{}]", man.join(",\n")), why }, segs)
}

pub fn segrun(w: &[u32], s: u32, outdir: Option<&str>, bad: Option<usize>) -> String {
    let (c, segs) = check(w, s, bad);
    if let Some(d) = outdir {
        fs::create_dir_all(d).unwrap();
        for (k, sw) in segs.iter().enumerate() {
            write_words(&format!("{}/seg{:03}.bin", d, k), sw);
        }
        fs::write(format!("{}/manifest.json", d), &c.manifest).unwrap();
    }
    format!("{{\"ok\":{},\"segments\":{},\"units\":{},\"why\":\"{}\"}}", c.ok, c.segs, c.units, c.why)
}

pub fn segfuzz(n: u64, ord: u32) -> String {
    let (mut ok, mut segs, mut units) = (0u64, 0usize, 0usize);
    for seed in 1..=n {
        let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let (w, _, _) = gen(seed, 4 + (seed % 9) as u32, 1 + (seed % 25) as u32, 1 + (seed % 3) as u32, ord, seed % 2 == 0);
        let s = match r.below(4) { 0 => 1 + r.below(8) as u32, 1 => 1 + r.below(64) as u32, _ => 1 + r.below(400) as u32 };
        let nseg = (w[2] as u64).div_ceil(s as u64).max(1);
        let bad = if seed % 3 == 0 && nseg > 1 { Some(1 + r.below(nseg - 1) as usize) } else { None };
        let (c, _) = check(&w, s, bad);
        if c.ok {
            ok += 1;
        } else {
            println!("SEG MISMATCH seed {} S {} bad {:?}: {}", seed, s, bad, c.why);
        }
        segs += c.segs;
        units += c.units;
    }
    format!("{{\"batches\":{},\"ok\":{},\"segments\":{},\"units\":{}}}", n, ok, segs, units)
}
