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
fn export_words(sess: &mnpilot::Session) -> ([u8; 32], Vec<u32>) {
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
        let o = mnpilot::run_import(&mut |i| words.get(i as usize).copied().unwrap_or(0), &mut b);
        note(o.status == mnpilot::ST_SESSION_LIVE, "import over live session");
        // fresh import
        let mut c: Option<mnpilot::Session> = None;
        let io = mnpilot::run_import(&mut |i| words.get(i as usize).copied().unwrap_or(0), &mut c);
        note(io.status == 0 && io.digest == eb.digest && io.words == eb.words && io.root == eb.root, "import digest / root");
        let (d2, words2) = export_words(c.as_ref().unwrap());
        note(d2 == d && words2 == words, "re-export of the import");
        note(c.as_ref().unwrap().eng.state.oi_ok(), "derived indexes after import");
        note(c.as_ref().unwrap().eng.state.books.values().all(|bk| bk.index_ok() && bk.level_ok()), "book indexes after import");
        // continue: every later segment identical
        let start = if k == 0 { 1 } else { k };
        for (j, sw) in segs.iter().enumerate().skip(start) {
            let (ra, _) = run_seg(sw, &mut a);
            let (rc, _) = run_seg(sw, &mut c);
            note(ra == rc, &format!("segment {} after import differs", j));
        }
        let (fa, _) = export_words(a.as_ref().unwrap());
        let (fc, _) = export_words(c.as_ref().unwrap());
        note(fa == fc, "final export differs");
        // malformed imports: truncation always fails; a flip fails or changes the digest
        let cut = rng.below(words.len() as u64) as usize;
        let mut z: Option<mnpilot::Session> = None;
        let t = mnpilot::run_import(&mut |i| if (i as usize) < cut { words[i as usize] } else { 0 }, &mut z);
        let trunc_ok = t.status == mnpilot::ST_BAD_SNAP && z.is_none();
        let mut flip_ok = true;
        for _ in 0..8 {
            let mut v = words.clone();
            let i = rng.below(v.len() as u64) as usize;
            v[i] ^= 1 << rng.below(32);
            let mut z: Option<mnpilot::Session> = None;
            let f = mnpilot::run_import(&mut |i| v.get(i as usize).copied().unwrap_or(0), &mut z);
            flips += 1;
            if f.status == 0 {
                flip_decoded += 1;
                flip_ok &= f.digest != d;
            } else {
                flip_ok &= f.status == mnpilot::ST_BAD_SNAP && z.is_none();
            }
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
pub fn snapdir(w: &[u32], s: u32, k: usize, dir: &str) -> String {
    fs::create_dir_all(dir).unwrap();
    let segs = seg::split(w, s);
    let k = k.clamp(1, segs.len());
    let mut a: Option<mnpilot::Session> = None;
    let hx = |b: &[u8; 32]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
    let mut man = Vec::new();
    let mut seg_entry = |name: String, sw: &[u32], a: &mut Option<mnpilot::Session>| {
        let mut ev = Vec::new();
        let mut roots: Vec<[u8; 32]> = Vec::new();
        let (h, st, wo) = mnpilot::run_segment(
            &mut |i| sw.get(i as usize).copied().unwrap_or(0),
            &mut |x| ev.push(x),
            &mut |_, _, r| roots.push(*r),
            mnpilot::WitMode::Incremental,
            a,
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
    for (j, sw) in segs.iter().enumerate().skip(k) {
        man.push(seg_entry(format!("seg{:03}.bin", j), sw, &mut a));
    }
    fs::write(format!("{}/manifest.json", dir), format!("[{}]", man.join(",\n"))).unwrap();
    format!("{{\"segments\":{},\"export_after\":{},\"snapshot_words\":{},\"digest\":\"{}\"}}", segs.len(), k, words.len(), hx(&eo.digest))
}
