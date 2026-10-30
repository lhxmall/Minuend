//! Snapshot persistence for `ChainState` (gap 11 v1, Choice A-lite).
//!
//! Snapshots are content-addressed by height only: `chainstate.<height>.snap`
//! (bincode). They are a crash-recovery accelerator, NOT consensus state —
//! `state_root` is always recomputed by replay, and the operator replays
//! finalized `temp_data` batches on top of the latest snapshot whose height
//! is still valid. Only finalized heights are immutable, so operators must
//! snapshot at (or before) their last finalized batch.
//!
//! R2-R-10 (round 2 of #47): `Batch::from_applied` currently flushes on its
//! cadence when the batch is CUT, i.e. before it is submitted or finalized.
//! A producer that crashes between that flush and a successful submit
//! restarts one height ahead of the chain with the batch's unit bodies gone
//! (the DAG is not persisted), and re-sent copies of those units are refused
//! as duplicates. Until the producer flushes only at observed finalization,
//! recover such a node by deleting snapshots above the last finalized height
//! (the previous snapshot is kept, see `KEEP_SNAPSHOTS`). The watcher
//! (`minuend-watch --state-dir`) only snapshots heights it has replayed.
//!
//! On restart: [`load_latest`] returns the newest snapshot; the caller then
//! replays `gov_nonces.journal` over it (see [`crate::journal`]) and any
//! batches newer than the snapshot via `Batch::validate_against`.

use crate::ChainState;
use bincode::Options;
use minuend_types::{Height, BATCH_MAX_UNITS};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const SNAPSHOT_PREFIX: &str = "chainstate.";
pub const SNAPSHOT_EXT: &str = "snap";
/// Default flush cadence (`Engine::maybe_flush_snapshot`).
pub const SNAPSHOT_EVERY: Height = 64;
/// Old snapshots kept beyond the newest (crash during rename safety).
const KEEP_SNAPSHOTS: usize = 2;
/// Version header prefixing every snapshot body. Old formats are not
/// migrated (mainnet is not live); [`load_latest`] skips unknown versions
/// and falls back to genesis rather than failing startup (#11).
///
/// Bump this whenever the bincode layout of anything inside `ChainState`
/// changes (bincode is not self-describing, so `#[serde(default)]` does not
/// help). History: v4 = `(ChainState, anchors)` tuple (#45); v5 =
/// `MarketParams` gained `min_price`/`max_price` (#46, M3 in #47); v6 =
/// `ChainState.aa_address_owners` (#47 A2, added after the v5 bump without
/// one — R2-R-14); v7 = `ChainState.deposit_backing` (R3-E-1); v8 = its value became
/// `DepositBacking { amount, payer, account }` (R3-A-5: the payer-designated
/// account is persisted instead of a transient `serde(skip)` map).
/// `layout_fingerprint_is_pinned_to_format_version` pins
/// the layout so the next change cannot land without a bump.
pub const SNAPSHOT_FORMAT_VERSION: u32 = 8;
/// #37-14: bounded pre-snapshot DAG anchors persisted with the state. A
/// restored engine cannot rebuild the DAG, so these ids are treated as
/// already-executed ancestors when replaying post-snapshot batches.
///
/// M2 (#47): the previous 4096 cap was far below `BATCH_MAX_UNITS`
/// (200 000): one busy batch pushed most of its own units out of the ring,
/// and any post-snapshot unit whose parent fell outside it stayed orphaned
/// forever after restart. The ring now holds two full batches' worth of
/// executed unit ids (the batch the snapshot closes plus the one before it),
/// so every parent a client could reference from the last two batches is
/// still linkable. Worst case is 400 000 x 32 B = 12.8 MB per snapshot,
/// and only when the chain is actually that busy (the ring holds executed
/// units, not a fixed allocation).
///
/// R2-R-6/7: this is also the consensus parent window
/// (`minuend_dag::PARENT_WINDOW`, same formula; asserted equal in the
/// watcher's tests): a parent older than the last `DAG_ANCHOR_LIMIT`
/// executed units is refused by every node, so a restored node's anchor
/// set is exactly the set of parents any node may still accept.
pub const DAG_ANCHOR_LIMIT: usize = 2 * BATCH_MAX_UNITS as usize;

/// Exact decoder for snapshot bodies: same wire format as
/// `bincode::serialize` (fixed-width ints, little endian) but trailing bytes
/// are an error, so a body written with a different layout is far more
/// likely to be rejected than silently mis-decoded (M3, #47).
fn snapshot_decoder() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}

/// Durability of directory entries (rename) needs a directory fsync on unix;
/// Windows has no equivalent API, so this is a no-op there.
#[cfg(unix)]
fn fsync_dir(dir: &Path) {
    let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
}
#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) {}

fn snapshot_name(height: Height) -> String {
    format!("{SNAPSHOT_PREFIX}{height}.{SNAPSHOT_EXT}")
}

/// Persist `state` atomically (tmp file + rename), then prune old snapshots.
/// Returns the snapshot path.
pub fn save_snapshot(dir: &Path, state: &ChainState) -> io::Result<PathBuf> {
    save_snapshot_with_anchors(dir, state, &[])
}

/// #37-14: persist the state together with the bounded list of unit ids that
/// were executed before this snapshot (DAG anchors for restart recovery).
/// Anchors are pure recovery metadata: they are not committed in state_root
/// and never influence consensus.
pub fn save_snapshot_with_anchors(
    dir: &Path,
    state: &ChainState,
    anchors: &[[u8; 32]],
) -> io::Result<PathBuf> {
    save_snapshot_retaining(dir, state, anchors, Height::MAX)
}

/// R3-R-2: like [`save_snapshot_with_anchors`], but every snapshot at or
/// above `retain_from` is kept as well (on top of the newest
/// `KEEP_SNAPSHOTS`). The watcher passes its `last_finalized` height so it
/// can rewind to any not-yet-final height that is later judged fraudulent
/// and re-submitted.
pub fn save_snapshot_retaining(
    dir: &Path,
    state: &ChainState,
    anchors: &[[u8; 32]],
    retain_from: Height,
) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let keep = anchors.len().min(DAG_ANCHOR_LIMIT);
    let body = (state, anchors[anchors.len() - keep..].to_vec());
    let bytes =
        bincode::serialize(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let path = dir.join(snapshot_name(state.height));
    let tmp = dir.join(format!("{}.tmp", snapshot_name(state.height)));
    {
        use std::io::Write;
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&SNAPSHOT_FORMAT_VERSION.to_le_bytes())?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    fsync_dir(dir);
    prune_snapshots_from(dir, KEEP_SNAPSHOTS, retain_from)?;
    Ok(path)
}

/// Load the newest readable snapshot in `dir`. Candidates are tried from
/// newest height down: an unreadable newest file falls back to the previous
/// height instead of failing startup (M2); a version mismatch or decode
/// failure skips the candidate; when NO candidate decodes the caller gets
/// `Ok(None)` and recovers from genesis (#11) — real io errors surface only
/// from listing the directory itself. Returns Ok(None) on a fresh dir.
pub fn load_latest(dir: &Path) -> io::Result<Option<(Height, ChainState)>> {
    Ok(load_latest_with_anchors(dir)?.map(|(h, s, _)| (h, s)))
}

/// #37-14: a loaded snapshot plus its DAG anchors (empty for older/absent
/// data). The anchors are execution-log metadata, not consensus state.
pub type LoadedSnapshot = (Height, ChainState, Vec<[u8; 32]>);

/// #37-14: newest snapshot plus its DAG anchors (empty for older/absent data).
pub fn load_latest_with_anchors(dir: &Path) -> io::Result<Option<LoadedSnapshot>> {
    for (_, path) in snapshot_candidates(dir)? {
        if let Ok((state, anchors)) = read_snapshot(&path) {
            return Ok(Some((state.height, state, anchors)));
        }
    }
    Ok(None)
}

fn read_snapshot(path: &Path) -> io::Result<(ChainState, Vec<[u8; 32]>)> {
    let bytes = fs::read(path)?;
    if bytes.len() < 4
        || u32::from_le_bytes(bytes[..4].try_into().unwrap()) != SNAPSHOT_FORMAT_VERSION
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown snapshot format version",
        ));
    }
    snapshot_decoder()
        .deserialize(&bytes[4..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// R3-R-2/R3-R-7: heights of every `chainstate.<h>.snap` file in `dir`
/// (readable or not), newest first. Empty for a missing directory.
pub fn snapshot_heights(dir: &Path) -> io::Result<Vec<Height>> {
    Ok(snapshot_candidates(dir)?
        .into_iter()
        .map(|(h, _)| h)
        .collect())
}

/// R3-R-2: load the snapshot of exactly `height`. `Ok(None)` when there is
/// no such file; a file that does not decode (other format version,
/// corruption, or a body whose height disagrees with its name) is an error.
pub fn load_snapshot_at(dir: &Path, height: Height) -> io::Result<Option<LoadedSnapshot>> {
    let path = dir.join(snapshot_name(height));
    if !path.is_file() {
        return Ok(None);
    }
    let (state, anchors) = read_snapshot(&path)?;
    if state.height != height {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot height does not match its file name",
        ));
    }
    Ok(Some((height, state, anchors)))
}

/// R3-R-2: delete every snapshot above `height` (a dead branch after a
/// fraud verdict / re-submission), so a restart can never resume from it.
pub fn remove_snapshots_above(dir: &Path, height: Height) -> io::Result<()> {
    for (h, path) in snapshot_candidates(dir)? {
        if h > height {
            fs::remove_file(path)?;
        }
    }
    fsync_dir(dir);
    Ok(())
}

/// R4-R-4 / I-4: sub-directory dead-branch checkpoints are moved to.
pub const DEAD_SNAPSHOT_DIR: &str = "dead";

/// R4-R-4 / I-4: move every snapshot above `height` into
/// `dir/`[`DEAD_SNAPSHOT_DIR`] instead of deleting it. They are no longer
/// candidates for [`snapshot_heights`] / resume (only top-level files are),
/// but stay on disk for forensics, and a rewind decided on a bad hub read
/// destroys nothing. A same-named file already in `dead/` is replaced.
/// Returns the heights moved.
pub fn retire_snapshots_above(dir: &Path, height: Height) -> io::Result<Vec<Height>> {
    let mut moved = Vec::new();
    let dead = dir.join(DEAD_SNAPSHOT_DIR);
    for (h, path) in snapshot_candidates(dir)? {
        if h > height {
            fs::create_dir_all(&dead)?;
            let to = dead.join(snapshot_name(h));
            fs::rename(&path, &to)?;
            // R5-R-6: stamp the retirement time, so `cap_dead_snapshots`
            // keeps the most recently retired files (rename keeps mtime).
            if let Ok(f) = fs::OpenOptions::new().write(true).open(&to) {
                let _ = f.set_modified(std::time::SystemTime::now());
            }
            moved.push(h);
        }
    }
    if !moved.is_empty() {
        fsync_dir(&dead);
        fsync_dir(dir);
    }
    Ok(moved)
}

/// R4-R-7: keep at most `max_count` snapshots and at most `max_bytes` of
/// them in `dir` (top level only), deleting the OLDEST first; the newest
/// snapshot is always kept. For throw-away (temp-dir) checkpoint stores.
/// Returns the heights deleted.
pub fn cap_snapshots(dir: &Path, max_count: usize, max_bytes: u64) -> io::Result<Vec<Height>> {
    let mut removed = Vec::new();
    let mut total: u64 = 0;
    for (i, (h, path)) in snapshot_candidates(dir)?.into_iter().enumerate() {
        let len = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        total = total.saturating_add(len);
        if i > 0 && (i >= max_count || total > max_bytes) {
            fs::remove_file(&path)?;
            removed.push(h);
        }
    }
    if !removed.is_empty() {
        fsync_dir(dir);
    }
    Ok(removed)
}

/// R5-R-3: byte-budgeted cap for a throw-away (temp-dir) store that still
/// keeps the rewind floor. Kept unconditionally: the newest snapshot and
/// the FLOOR — the newest snapshot at or below `floor` (the chain's
/// `last_finalized`; no rewind ever goes below it). Everything below the
/// floor snapshot is deleted (never needed). The snapshots between the
/// floor and the newest are kept while the total stays within
/// `max_bytes`; over budget the oldest of them go first. A rewind to any
/// not-yet-final height therefore lands at or above the floor instead of
/// at genesis (the old fixed count of 8 deleted the floor first). Returns
/// the heights deleted.
pub fn cap_snapshots_keep_floor(
    dir: &Path,
    floor: Height,
    max_bytes: u64,
) -> io::Result<Vec<Height>> {
    let all = snapshot_candidates(dir)?; // newest first
    let mut removed = Vec::new();
    if all.is_empty() {
        return Ok(removed);
    }
    let floor_idx = all.iter().position(|(h, _)| *h <= floor);
    let size = |p: &PathBuf| fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    // Below the floor snapshot: delete.
    let keep_end = floor_idx.map(|i| i + 1).unwrap_or(all.len());
    for (h, path) in &all[keep_end..] {
        fs::remove_file(path)?;
        removed.push(*h);
    }
    let kept = &all[..keep_end];
    let mut total: u64 = kept.iter().map(|(_, p)| size(p)).sum();
    // Middle (strictly between newest and floor), oldest first.
    let last = kept.len().saturating_sub(1);
    let middle_hi = if floor_idx.is_some() { last } else { kept.len() };
    for i in (1..middle_hi).rev() {
        if total <= max_bytes {
            break;
        }
        let (h, path) = &kept[i];
        total = total.saturating_sub(size(path));
        fs::remove_file(path)?;
        removed.push(*h);
    }
    if !removed.is_empty() {
        fsync_dir(dir);
    }
    Ok(removed)
}

/// R5-R-6: cap `dir/`[`DEAD_SNAPSHOT_DIR`]: keep at most `max_count`
/// files and `max_bytes` of them, the most recently retired first (by
/// mtime, which [`retire_snapshots_above`] stamps; ties by height). Returns
/// how many files were deleted.
pub fn cap_dead_snapshots(dir: &Path, max_count: usize, max_bytes: u64) -> io::Result<usize> {
    let dead = dir.join(DEAD_SNAPSHOT_DIR);
    let mut files: Vec<(std::time::SystemTime, Height, PathBuf, u64)> = snapshot_candidates(&dead)?
        .into_iter()
        .map(|(h, p)| {
            let m = fs::metadata(&p).ok();
            let t = m
                .as_ref()
                .and_then(|m| m.modified().ok())
                .unwrap_or(std::time::UNIX_EPOCH);
            (t, h, p, m.map(|m| m.len()).unwrap_or(0))
        })
        .collect();
    files.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
    let mut total: u64 = 0;
    let mut n = 0;
    for (i, (_, _, path, len)) in files.iter().enumerate() {
        total = total.saturating_add(*len);
        if i >= max_count || total > max_bytes {
            fs::remove_file(path)?;
            n += 1;
        }
    }
    if n > 0 {
        fsync_dir(&dead);
    }
    Ok(n)
}

/// R5-R-6: total bytes of the top-level snapshots and `dead/` of `dir`.
pub fn snapshot_store_bytes(dir: &Path) -> io::Result<u64> {
    let mut t = 0u64;
    for d in [dir.to_path_buf(), dir.join(DEAD_SNAPSHOT_DIR)] {
        for (_, p) in snapshot_candidates(&d)? {
            t = t.saturating_add(fs::metadata(&p).map(|m| m.len()).unwrap_or(0));
        }
    }
    Ok(t)
}

/// All snapshots in `dir` as (height, path), descending by height.
fn snapshot_candidates(dir: &Path) -> io::Result<Vec<(Height, PathBuf)>> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        // Fresh store dir: genesis recovery, not an error.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out: Vec<(Height, PathBuf)> = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.metadata()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(rest) = name.strip_prefix(SNAPSHOT_PREFIX) else {
            continue;
        };
        let Some(h) = rest.strip_suffix(&format!(".{SNAPSHOT_EXT}")) else {
            continue;
        };
        if let Ok(h) = h.parse::<Height>() {
            out.push((h, dir.join(snapshot_name(h))));
        }
    }
    out.sort_unstable_by_key(|&(h, _)| std::cmp::Reverse(h));
    Ok(out)
}

pub fn latest_snapshot(dir: &Path) -> io::Result<Option<PathBuf>> {
    Ok(snapshot_candidates(dir)?.into_iter().next().map(|(_, p)| p))
}

/// Prune to the newest `keep` snapshots, never deleting one whose height is
/// `>= retain_from` (R3-R-2).
fn prune_snapshots_from(dir: &Path, keep: usize, retain_from: Height) -> io::Result<()> {
    // Orphan tmp files from a crash mid-save are never valid snapshots.
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with(SNAPSHOT_PREFIX)
                && name
                    .to_string_lossy()
                    .ends_with(&format!(".{SNAPSHOT_EXT}.tmp"))
            {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    let candidates = snapshot_candidates(dir)?;
    for (h, _) in candidates.iter().skip(keep) {
        if *h >= retain_from {
            continue;
        }
        let _ = fs::remove_file(dir.join(snapshot_name(*h)));
    }
    fsync_dir(dir);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R4-R-4 / I-4: retiring moves dead-branch snapshots to `dead/`
    /// (no longer resume candidates) without deleting anything.
    #[test]
    fn retire_moves_snapshots_above_into_dead_dir() {
        let dir = std::env::temp_dir().join(format!("minuend-retire-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut st = ChainState::default();
        for h in 1..=5 {
            st.height = h;
            save_snapshot_retaining(&dir, &st, &[], 0).unwrap();
        }
        assert_eq!(snapshot_heights(&dir).unwrap(), vec![5, 4, 3, 2, 1]);
        let moved = retire_snapshots_above(&dir, 2).unwrap();
        assert_eq!(moved.len(), 3);
        assert_eq!(snapshot_heights(&dir).unwrap(), vec![2, 1]);
        let dead = dir.join(DEAD_SNAPSHOT_DIR);
        assert_eq!(snapshot_heights(&dead).unwrap(), vec![5, 4, 3]);
        // Retiring again (same heights re-saved on the new branch) replaces.
        st.height = 3;
        save_snapshot_retaining(&dir, &st, &[], 0).unwrap();
        retire_snapshots_above(&dir, 2).unwrap();
        assert_eq!(snapshot_heights(&dead).unwrap(), vec![5, 4, 3]);
        assert!(retire_snapshots_above(&dir, 2).unwrap().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    /// R4-R-7: the temp-dir store is capped by count and bytes, oldest
    /// first, never dropping the newest snapshot.
    #[test]
    fn cap_snapshots_drops_oldest_and_keeps_newest() {
        let dir = std::env::temp_dir().join(format!("minuend-cap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut st = ChainState::default();
        for h in 1..=6 {
            st.height = h;
            save_snapshot_retaining(&dir, &st, &[], 0).unwrap();
        }
        let removed = cap_snapshots(&dir, 4, u64::MAX).unwrap();
        assert_eq!(removed, vec![2, 1]);
        assert_eq!(snapshot_heights(&dir).unwrap(), vec![6, 5, 4, 3]);
        // A byte budget smaller than one file still keeps the newest.
        cap_snapshots(&dir, 100, 1).unwrap();
        assert_eq!(snapshot_heights(&dir).unwrap(), vec![6]);
        let _ = fs::remove_dir_all(&dir);
    }

    /// R5-R-3: the temp-dir cap keeps the rewind floor (newest snapshot
    /// <= last_finalized) and the newest one whatever the budget; more than
    /// 8 unfinalized heights are all kept while they fit the byte budget.
    #[test]
    fn r5r3_cap_keeps_floor_and_newest_within_budget() {
        let dir = std::env::temp_dir().join(format!("minuend-capfloor-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut st = ChainState::default();
        for h in 1..=20 {
            st.height = h;
            save_snapshot_retaining(&dir, &st, &[], 0).unwrap();
        }
        let one = fs::metadata(dir.join(snapshot_name(1))).unwrap().len();
        // lf = 5: 1..=4 go (below the floor), 5..=20 (16 > 8) all fit.
        let removed = cap_snapshots_keep_floor(&dir, 5, u64::MAX).unwrap();
        assert_eq!(removed, vec![4, 3, 2, 1]);
        assert_eq!(snapshot_heights(&dir).unwrap(), (5..=20).rev().collect::<Vec<_>>());
        // Budget of 4 files: newest (20) + floor (5) + the 2 newest middles.
        cap_snapshots_keep_floor(&dir, 5, 4 * one).unwrap();
        assert_eq!(snapshot_heights(&dir).unwrap(), vec![20, 19, 18, 5]);
        // A budget below one file still keeps newest AND floor.
        cap_snapshots_keep_floor(&dir, 5, 1).unwrap();
        assert_eq!(snapshot_heights(&dir).unwrap(), vec![20, 5]);
        // Floor between snapshots: the newest at or below it is the floor.
        cap_snapshots_keep_floor(&dir, 7, 1).unwrap();
        assert_eq!(snapshot_heights(&dir).unwrap(), vec![20, 5]);
        let _ = fs::remove_dir_all(&dir);
    }

    /// R5-R-6: `dead/` is capped by count and bytes, most recently retired
    /// first; the store size helper counts both.
    #[test]
    fn r5r6_dead_dir_is_capped() {
        let dir = std::env::temp_dir().join(format!("minuend-capdead-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut st = ChainState::default();
        for round in 0..3u64 {
            for h in 1..=4 {
                st.height = h + round * 10;
                save_snapshot_retaining(&dir, &st, &[], 0).unwrap();
            }
            retire_snapshots_above(&dir, 0).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let dead = dir.join(DEAD_SNAPSHOT_DIR);
        assert_eq!(snapshot_heights(&dead).unwrap().len(), 12);
        let one = fs::metadata(dead.join(snapshot_name(1))).unwrap().len();
        assert_eq!(snapshot_store_bytes(&dir).unwrap(), 12 * one);
        assert_eq!(cap_dead_snapshots(&dir, 4, u64::MAX).unwrap(), 8);
        // The last retirement (heights 21..=24) survives.
        assert_eq!(snapshot_heights(&dead).unwrap(), vec![24, 23, 22, 21]);
        assert_eq!(cap_dead_snapshots(&dir, 100, 2 * one).unwrap(), 2);
        assert_eq!(snapshot_heights(&dead).unwrap().len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn snapshot_roundtrip_keeps_newest() {
        let dir = std::env::temp_dir().join(format!("minuend-snap-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let s1 = ChainState::new();
        save_snapshot(&dir, &s1).unwrap();
        let mut s2 = ChainState::new();
        s2.height = 42;
        s2.perp_supply = 777;
        save_snapshot(&dir, &s2).unwrap();
        let (h, st) = load_latest(&dir).unwrap().unwrap();
        assert_eq!(h, 42);
        assert_eq!(st.perp_supply, 777);
        // Pruning caps retained snapshots at KEEP_SNAPSHOTS.
        let mut n = 0;
        for e in fs::read_dir(&dir).unwrap() {
            if e.unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(SNAPSHOT_EXT)
            {
                n += 1;
            }
        }
        assert_eq!(n, KEEP_SNAPSHOTS);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_newest_falls_back_to_previous_and_unknown_version_skipped() {
        let dir = std::env::temp_dir().join(format!("minuend-snap-fb-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let s0 = ChainState::new();
        save_snapshot(&dir, &s0).unwrap();
        let mut s1 = ChainState::new();
        s1.height = 42;
        s1.perp_supply = 777;
        save_snapshot(&dir, &s1).unwrap();
        // Corrupt the newest (height 42) body.
        {
            use std::io::{Seek, Write};
            let mut f = fs::OpenOptions::new()
                .write(true)
                .open(dir.join(snapshot_name(42)))
                .unwrap();
            f.seek(io::SeekFrom::End(-3)).unwrap();
            f.write_all(&[0xDE, 0xAD, 0xBE]).unwrap();
        }
        // M2 regression: startup falls back to the previous snapshot instead
        // of failing outright.
        let (h, st) = load_latest(&dir).unwrap().unwrap();
        assert_eq!(h, 0);
        assert_eq!(st.perp_supply, 0);

        // A file with an unknown version header is skipped, not fatal.
        std::fs::write(dir.join(snapshot_name(99)), [9, 9, 9, 9, 1, 2, 3]).unwrap();
        let (h, _st) = load_latest(&dir).unwrap().unwrap();
        assert_eq!(h, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn version_2_garbage_falls_back_to_genesis() {
        // #11: a v2-header file (the old layout) must not decode as live
        // state; with only such a file the caller gets Ok(None) and starts
        // from genesis instead of an Err that blocks startup.
        let dir = std::env::temp_dir().join(format!("minuend-snap-v2-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut body = 2u32.to_le_bytes().to_vec();
        body.extend_from_slice(&[0xFF; 64]);
        fs::write(dir.join(snapshot_name(7)), &body).unwrap();
        assert!(load_latest(&dir).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    /// M3 (#47): a snapshot written by a build whose `MarketParams` layout
    /// differs (header v4) must never be decoded as live state, even if its
    /// bytes happen to parse. Loading skips it and falls back to the newest
    /// current-version snapshot, or to genesis (`None`) when there is none.
    #[test]
    fn previous_format_version_is_skipped_not_misdecoded() {
        let dir = std::env::temp_dir().join(format!("minuend-snap-v4-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // A v4-headed file whose body is otherwise a perfectly decodable
        // current-layout body: only the version header tells them apart.
        let mut st = ChainState::new();
        st.height = 128;
        st.perp_supply = 999;
        let body = bincode::serialize(&(&st, Vec::<[u8; 32]>::new())).unwrap();
        let mut v4 = 4u32.to_le_bytes().to_vec();
        v4.extend_from_slice(&body);
        fs::write(dir.join(snapshot_name(128)), &v4).unwrap();
        assert!(
            load_latest(&dir).unwrap().is_none(),
            "v4 snapshot must fall back to genesis, not decode"
        );
        // With an older current-version snapshot present, that one is used.
        let mut older = ChainState::new();
        older.height = 64;
        older.perp_supply = 5;
        save_snapshot(&dir, &older).unwrap();
        // save_snapshot prunes to KEEP_SNAPSHOTS=2, so the v4 file survives.
        assert!(dir.join(snapshot_name(128)).exists());
        let (h, got) = load_latest(&dir).unwrap().unwrap();
        assert_eq!(h, 64);
        assert_eq!(got.perp_supply, 5);
        let _ = fs::remove_dir_all(&dir);
    }

    /// M3 (#47): trailing bytes after a valid body (a sign of a layout
    /// mismatch) are rejected instead of being ignored.
    #[test]
    fn trailing_bytes_are_rejected() {
        let dir =
            std::env::temp_dir().join(format!("minuend-snap-trail-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let st = ChainState::new();
        let body = bincode::serialize(&(&st, Vec::<[u8; 32]>::new())).unwrap();
        let mut f = SNAPSHOT_FORMAT_VERSION.to_le_bytes().to_vec();
        f.extend_from_slice(&body);
        f.extend_from_slice(&[0u8; 8]);
        fs::write(dir.join(snapshot_name(3)), &f).unwrap();
        assert!(load_latest(&dir).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    /// M2 (#47): far more than the old 4096 anchors survive a round trip.
    #[test]
    fn anchors_cover_more_than_old_4096_cap() {
        const { assert!(DAG_ANCHOR_LIMIT >= BATCH_MAX_UNITS as usize) };
        let dir =
            std::env::temp_dir().join(format!("minuend-snap-anch-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let anchors: Vec<[u8; 32]> = (0u32..10_000)
            .map(|i| {
                let mut a = [0u8; 32];
                a[..4].copy_from_slice(&i.to_le_bytes());
                a
            })
            .collect();
        save_snapshot_with_anchors(&dir, &ChainState::new(), &anchors).unwrap();
        let (_, _, got) = load_latest_with_anchors(&dir).unwrap().unwrap();
        assert_eq!(got.len(), 10_000);
        assert_eq!(got[0], anchors[0]);
        let _ = fs::remove_dir_all(&dir);
    }

    /// R3 integration: the deposit backing (amount, payer, designated
    /// account) of an admitted but not yet consumed anchor survives a
    /// snapshot round trip, so a restored node rejects a front-running
    /// deposit exactly like a node that never restarted.
    #[test]
    fn deposit_backing_survives_snapshot() {
        let dir =
            std::env::temp_dir().join(format!("minuend-snap-dep-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut st = ChainState::new();
        let victim = minuend_types::AccountId([7u8; 32]);
        let thief = minuend_types::AccountId([8u8; 32]);
        st.allow_deposit([9u8; 32], false, 123, "PAYER", victim);
        save_snapshot_with_anchors(&dir, &st, &[]).unwrap();
        let (_, got, _) = load_latest_with_anchors(&dir).unwrap().unwrap();
        assert_eq!(got.deposit_backing, st.deposit_backing);
        assert!(got.deposits_allowed.contains(&([9u8; 32], false)));
        assert!(got.deposit_account_matches([9u8; 32], false, victim));
        assert!(!got.deposit_account_matches([9u8; 32], false, thief));
        assert!(got.deposit_backing_matches([9u8; 32], false, Some(123), "PAYER"));
        assert!(!got.deposit_backing_matches([9u8; 32], false, Some(124), "PAYER"));
        let _ = fs::remove_dir_all(&dir);
    }

    /// R2-R-14: bincode is not self-describing, so a layout change that
    /// forgets to bump `SNAPSHOT_FORMAT_VERSION` silently invalidates (or,
    /// worse, mis-decodes) old snapshots. The digest below covers the
    /// top-level `ChainState` fields plus one market and one account; when
    /// it changes, bump `SNAPSHOT_FORMAT_VERSION`, extend the history note
    /// and re-pin BOTH constants together.
    #[test]
    fn layout_fingerprint_is_pinned_to_format_version() {
        let mut st = ChainState::new();
        st.markets
            .insert(minuend_types::BTC_USD, minuend_types::genesis_params());
        let id = minuend_types::AccountId([3u8; 32]);
        st.accounts.insert(id, crate::Account::new(id));
        // R3: one deposit backing so a change of its value type is caught
        // too (an empty map encodes the same whatever its value type).
        st.allow_deposit([4u8; 32], false, 5, "ADDR", id);
        let body = bincode::serialize(&(&st, vec![[1u8; 32]])).unwrap();
        let fp = hex::encode(minuend_types::sha256(&body));
        const PINNED: (u32, &str) = (
            8,
            "ea0934c60774c7747d3f0b4325d6bfc20ecf85f18eef9e37f517226215499407",
        );
        assert_eq!(
            (SNAPSHOT_FORMAT_VERSION, fp.as_str()),
            PINNED,
            "snapshot layout changed: bump SNAPSHOT_FORMAT_VERSION and re-pin"
        );
    }

    #[test]
    fn prune_removes_orphan_tmp_files() {
        let dir =
            std::env::temp_dir().join(format!("minuend-snap-tmp-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let orphan = dir.join(format!("{SNAPSHOT_PREFIX}7.{SNAPSHOT_EXT}.tmp"));
        std::fs::write(&orphan, b"junk").unwrap();
        save_snapshot(&dir, &ChainState::new()).unwrap();
        assert!(!orphan.exists(), "crash-orphan .snap.tmp must be pruned");
        let _ = fs::remove_dir_all(&dir);
    }

    /// R3-R-2: snapshots at or above `retain_from` survive pruning, exact-
    /// height loads work, and a dead branch above a height can be removed.
    #[test]
    fn retaining_save_keeps_unfinalized_heights_and_rewinds() {
        let dir = std::env::temp_dir().join(format!("minuend-snap-retain-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        for h in 1..=8u64 {
            let mut s = ChainState::new();
            s.height = h;
            s.perp_supply = h as u128 * 10;
            save_snapshot_retaining(&dir, &s, &[[h as u8; 32]], 3).unwrap();
        }
        assert_eq!(snapshot_heights(&dir).unwrap(), vec![8, 7, 6, 5, 4, 3]);
        let (h, st, anchors) = load_snapshot_at(&dir, 5).unwrap().unwrap();
        assert_eq!((h, st.perp_supply), (5, 50));
        assert_eq!(anchors, vec![[5u8; 32]]);
        assert!(load_snapshot_at(&dir, 2).unwrap().is_none());
        // A corrupt file at an exact height is an error, not "absent".
        fs::write(dir.join(snapshot_name(4)), b"garbage").unwrap();
        assert!(load_snapshot_at(&dir, 4).is_err());
        remove_snapshots_above(&dir, 5).unwrap();
        assert_eq!(snapshot_heights(&dir).unwrap(), vec![5, 4, 3]);
        assert_eq!(load_latest(&dir).unwrap().unwrap().0, 5);
        // The plain save keeps the old behaviour (newest KEEP_SNAPSHOTS).
        let mut s = ChainState::new();
        s.height = 6;
        save_snapshot_with_anchors(&dir, &s, &[]).unwrap();
        assert_eq!(snapshot_heights(&dir).unwrap().len(), KEEP_SNAPSHOTS);
        let _ = fs::remove_dir_all(&dir);
    }
}
