//! Host std reference for the MNWIT1 witness commitment, written independently of
//! guest-engine/src/wit.rs: it rebuilds the root FROM SCRATCH out of plain leaf strings
//! (as a verifier / dispute AA would see them), deriving each key from the leaf text itself.
//! Spec: docs/rv-dispute-design.md §7.3.
use sha2::{Digest, Sha256};

pub type H = [u8; 32];

pub fn b64(b: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    s
}
pub fn unb64(s: &str) -> Vec<u8> {
    const T: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let v: Vec<u32> = s.bytes().filter(|&c| c != b'=').map(|c| T.find(c as char).unwrap() as u32).collect();
    for c in v.chunks(4) {
        let n = c.iter().enumerate().fold(0u32, |a, (i, x)| a | x << (18 - 6 * i));
        for k in 0..c.len() - 1 {
            out.push((n >> (16 - 8 * k)) as u8);
        }
    }
    out
}
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn sha(parts: &[&[u8]]) -> H {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Leaf tags the pilot models (upstream also has adr/adrx/dep/obond and the `~:end` sentinel).
pub fn pilot_leaf(l: &str) -> bool {
    matches!(l.split(':').next(), Some("acct" | "pos" | "ord" | "band" | "meta"))
}

/// Identity prefix of a leaf: `pos:` keeps 3 fields (account, market), every other tag 2.
pub fn kid(leaf: &str) -> &str {
    let fields = if leaf.starts_with("pos:") { 3 } else { 2 };
    let mut seen = 0;
    for (i, c) in leaf.char_indices() {
        if c == ':' {
            seen += 1;
            if seen == fields {
                return &leaf[..i];
            }
        }
    }
    leaf
}
pub fn key(leaf: &str) -> H {
    sha(&[b"~K1:", kid(leaf).as_bytes()])
}
pub fn leaf_hash(leaf: &str) -> H {
    sha(&[b"~L1:", hex(&key(leaf)).as_bytes(), b":", leaf.as_bytes()])
}
pub fn node(l: &H, r: &H) -> H {
    sha(&[b"~N1:", b64(l).as_bytes(), b64(r).as_bytes()])
}
fn bit(k: &H, d: usize) -> bool {
    k[d / 8] & (0x80 >> (d % 8)) != 0
}
fn sub(v: &[(H, H)], d: usize) -> H {
    match v.len() {
        0 => [0u8; 32],
        1 => v[0].1,
        _ => {
            let s = v.partition_point(|(k, _)| !bit(k, d));
            node(&sub(&v[..s], d + 1), &sub(&v[s..], d + 1))
        }
    }
}
/// Root over a set of leaf strings (order irrelevant). Panics on a duplicate key.
pub fn root(leaves: &[String]) -> H {
    let mut v: Vec<(H, H)> = leaves.iter().map(|l| (key(l), leaf_hash(l))).collect();
    v.sort();
    for w in v.windows(2) {
        assert!(w[0].0 != w[1].0, "duplicate witness key");
    }
    sub(&v, 0)
}
/// Root over raw (key, leaf hash) pairs (for the pure tree property test).
pub fn root_kv(kv: &[(H, H)]) -> H {
    let mut v = kv.to_vec();
    v.sort();
    sub(&v, 0)
}
/// Depth (number of siblings) of every leaf's proof path, for stats.
pub fn depths(leaves: &[String]) -> Vec<usize> {
    fn go(v: &[H], d: usize, out: &mut Vec<usize>) {
        match v.len() {
            0 => {}
            1 => out.push(d),
            _ => {
                let s = v.partition_point(|k| !bit(k, d));
                go(&v[..s], d + 1, out);
                go(&v[s..], d + 1, out);
            }
        }
    }
    let mut v: Vec<H> = leaves.iter().map(|l| key(l)).collect();
    v.sort();
    let mut out = Vec::new();
    go(&v, 0, &mut out);
    out
}

// ---------------------------------------------------------------- proofs (loop round 1, W1)
// Reference prover + the verifier rules of docs/rv-dispute-design.md §7.3.3 (as an AA would run
// them), used by `engine-diff proofs` to check soundness/completeness and forgery resistance.

/// Proof terminal: the subtree found at depth `siblings.len()` on the key's path.
#[derive(Clone, Debug, PartialEq)]
pub enum Term {
    Empty,
    /// a leaf string (its key and leaf hash are recomputed by the verifier)
    Leaf(String),
}
/// Max proof depth a verifier accepts: the MNWIT1 depth rule (loop round 2, W2; design §7.5)
/// guarantees every leaf a checked insertion creates sits at depth <= 64, and the AA verifier
/// unrolls exactly that many levels. (Round 1 had 256 = key length.)
#[cfg(not(feature = "depth8"))]
pub const MAX_DEPTH: usize = 64;
#[cfg(feature = "depth8")]
pub const MAX_DEPTH: usize = 8;

/// Path of `k` in the canonical tree over `leaves`: siblings from the ROOT down
/// (s_0 = sibling at depth 0) and the terminal.
pub fn prove(leaves: &[String], k: &H) -> (Vec<H>, Term) {
    let mut v: Vec<(H, H, String)> = leaves.iter().map(|l| (key(l), leaf_hash(l), l.clone())).collect();
    v.sort();
    let mut lo = 0;
    let mut hi = v.len();
    let mut sib = Vec::new();
    let mut d = 0;
    loop {
        match hi - lo {
            0 => return (sib, Term::Empty),
            1 => return (sib, Term::Leaf(v[lo].2.clone())),
            _ => {
                let s = lo + v[lo..hi].partition_point(|(kk, _, _)| !bit(kk, d));
                let kv: Vec<(H, H)> = v.iter().map(|x| (x.0, x.1)).collect();
                if bit(k, d) {
                    sib.push(sub(&kv[lo..s], d + 1));
                    lo = s;
                } else {
                    sib.push(sub(&kv[s..hi], d + 1));
                    hi = s;
                }
                d += 1;
            }
        }
    }
}
/// Fold a terminal hash up the path of `k` (siblings root-first).
fn fold(k: &H, mut h: H, sib: &[H]) -> H {
    for (d, s) in sib.iter().enumerate().rev() {
        h = if bit(k, d) { node(s, &h) } else { node(&h, s) };
    }
    h
}
/// Membership: the key is DERIVED from the leaf text (never taken from the prover).
pub fn verify_member(root: &H, leaf: &str, sib: &[H]) -> bool {
    sib.len() <= MAX_DEPTH && fold(&key(leaf), leaf_hash(leaf), sib) == *root
}
/// Non-membership of key `k`: the terminal is EMPTY, or a leaf whose (derived) key differs from
/// `k` but shares its first `sib.len()` bits.
pub fn verify_absent(root: &H, k: &H, term: &Term, sib: &[H]) -> bool {
    if sib.len() > MAX_DEPTH {
        return false;
    }
    let h = match term {
        Term::Empty => [0u8; 32],
        Term::Leaf(l) => {
            let k2 = key(l);
            if k2 == *k || (0..sib.len()).any(|d| bit(&k2, d) != bit(k, d)) {
                return false;
            }
            leaf_hash(l)
        }
    };
    fold(k, h, sib) == *root
}
