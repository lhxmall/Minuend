//! Differential harness for the Minuend engine pilot port.
//!
//!   engine-diff gen <seed> <makers> <levels> <per_level> <n_orders> <out.bin>
//!       writes out.bin (setup + n_orders flow ops) and out.setup.bin (setup only)
//!   engine-diff real <batch.bin>   run through the REAL engine (signed units -> Engine::ingest)
//!   engine-diff port <batch.bin>   run through the mnpilot port natively
//!   engine-diff fuzz <n_seeds> <n_orders>   gen + real + port for many seeds, compare
//!
//!   engine-diff wroots <batch.bin> [legacy <skip>]   per-unit witness roots of the REAL engine's
//!       state: MNWIT1 rebuilt from scratch by smt_ref (default) or the legacy Obyte-merkle root
//!       (upstream obyte_merkle::root over the pilot's leaf tags + `~:end`) for units >= skip
//!   engine-diff portroots <batch.bin>   per-unit MNWIT1 roots of the port (incremental, native)
//!   engine-diff witfuzz <n_seeds> <n_orders> [smt_rounds]   property + diff test of MNWIT1
//!
//! real/port print one JSON line: {"hash":..,"applied":..,"rejected":..,"fills":..,"ev":[..]}
use minuend_dag::{genesis_id, sign_unit, unit_id, Op};
use minuend_exec::{Engine, ExecEvent, RejectReason};
use minuend_state::ChainState;
use minuend_types::{
    account_id_from_pubkey, order_id, AccountId, MarketId, OrderType, Side, TimeInForce, BTC_USD,
    PRICE_SCALE, QTY_SCALE, USD_SCALE,
};
use sha2::{Digest, Sha256};
use std::fs;
mod smt_ref;

const EV_APPLIED: u32 = mnpilot::EV_APPLIED;

fn secret(i: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"mnpilot-acct-");
    h.update(i.to_le_bytes());
    h.finalize().into()
}
fn acct_id(i: u32) -> AccountId {
    let pk = ed25519_dalek::SigningKey::from_bytes(&secret(i)).verifying_key().to_bytes();
    account_id_from_pubkey(&pk)
}
/// 32-char [A-Z2-7] address unique per account index.
fn addr(i: u32) -> String {
    const B32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut s = vec![b'A'; 32];
    let mut x = i as u64 + 1;
    let mut k = 31;
    while x > 0 {
        s[k] = B32[(x % 32) as usize];
        x /= 32;
        k -= 1;
    }
    String::from_utf8(s).unwrap()
}

fn read_words(path: &str) -> Vec<u32> {
    let b = fs::read(path).expect("read batch");
    b.chunks(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect()
}
fn write_words(path: &str, w: &[u32]) {
    let mut b = Vec::with_capacity(w.len() * 4);
    for x in w {
        b.extend_from_slice(&x.to_le_bytes());
    }
    fs::write(path, b).expect("write batch");
}

// ---------------------------------------------------------------- real engine
fn real_reason(r: &RejectReason) -> u32 {
    use minuend_book::BookError as B;
    match r {
        RejectReason::BadSig => 1,
        RejectReason::BadAccount => 2,
        RejectReason::DuplicateClientSeq => 3,
        RejectReason::DuplicateDeposit => 4,
        RejectReason::UnbackedDeposit => 5,
        RejectReason::DuplicateNonce => 6,
        RejectReason::Risk => 7,
        RejectReason::Book(e) => {
            0x100
                + match e {
                    B::NotFound => 1,
                    B::ZeroQty => 2,
                    B::ZeroPrice => 3,
                    B::DuplicateOrder => 4,
                    B::WrongMarket => 5,
                    B::SelfTrade => 6,
                    B::MultiFill => 7,
                }
        }
        RejectReason::Insufficient => 9,
        RejectReason::NotFound => 10,
        RejectReason::NotLiquidatable => 11,
        RejectReason::NoProposal => 12,
        RejectReason::NotBonded => 13,
        RejectReason::AlreadyBonded => 14,
        RejectReason::Unbonding => 15,
        RejectReason::SlashNotEligible => 16,
        RejectReason::BadCommit => 17,
    }
}

/// Same bytes as mnpilot::state_hash, computed from the REAL ChainState.
fn real_hash(s: &ChainState) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"MNPILOT1");
    h.update(s.seq.to_le_bytes());
    h.update((s.accounts.len() as u32).to_le_bytes());
    for a in s.accounts.values() {
        let perp = s.perp_balances.get(&a.id).copied().unwrap_or(0);
        let wd = s.withdrawn_total.get(&a.id).copied().unwrap_or(0);
        h.update(minuend_state::account_leaf(a, perp, wd));
    }
    h.update((s.books.len() as u32).to_le_bytes());
    for (m, b) in &s.books {
        h.update(m.0.to_le_bytes());
        h.update(minuend_types::sha256(&b.commitment_bytes()));
    }
    h.update((s.marks.len() as u32).to_le_bytes());
    for (m, p) in &s.marks {
        h.update(m.0.to_le_bytes());
        h.update(p.to_le_bytes());
    }
    let mut seen: Vec<_> = s.seen_client_seq.iter().collect();
    seen.sort();
    h.update((seen.len() as u32).to_le_bytes());
    for (a, c) in seen {
        h.update(a.0);
        h.update(c.to_le_bytes());
    }
    h.finalize().into()
}

struct Out {
    hash: [u8; 32],
    applied: u32,
    rejected: u32,
    fills: u32,
    ev: Vec<u32>,
}
impl Out {
    fn json(&self) -> String {
        let hx: String = self.hash.iter().map(|b| format!("{:02x}", b)).collect();
        let ev: Vec<String> = self.ev.iter().map(|x| x.to_string()).collect();
        format!(
            "{{\"hash\":\"{}\",\"applied\":{},\"rejected\":{},\"fills\":{},\"ev\":[{}]}}",
            hx, self.applied, self.rejected, self.fills, ev.join(",")
        )
    }
}

fn run_real(w: &[u32]) -> Out {
    run_real_eng(w).0
}

fn run_real_eng(w: &[u32]) -> (Out, Engine) {
    run_real_eng_cb(w, &mut |_| {})
}

/// `per_unit(&engine)` runs after every ingested unit (one apply_one each in a linear chain).
fn run_real_eng_cb(w: &[u32], per_unit: &mut dyn FnMut(&Engine)) -> (Out, Engine) {
    assert_eq!(w[0], mnpilot::MAGIC);
    let n_acc = w[1];
    let n_ops = w[2];
    let ids: Vec<AccountId> = (0..n_acc)
        .map(|a| {
            let mut id = [0u8; 32];
            for k in 0..8 {
                id[k * 4..k * 4 + 4].copy_from_slice(&w[(4 + a * 8) as usize + k].to_le_bytes());
            }
            AccountId(id)
        })
        .collect();
    for (i, id) in ids.iter().enumerate() {
        assert_eq!(*id, acct_id(i as u32), "batch account ids must come from the harness key derivation");
    }
    let base = (4 + n_acc * 8) as usize;
    let mut eng = Engine::new();
    // tests' allow_all: genesis BTC_USD params (ChainState::new already seeds them).
    eng.state.markets.insert(BTC_USD, minuend_types::genesis_params());
    let mut parent = genesis_id();
    let mut out = Out { hash: [0; 32], applied: 0, rejected: 0, fills: 0, ev: Vec::new() };
    for i in 0..n_ops as usize {
        let mut ow = [0u32; 8];
        ow.copy_from_slice(&w[base + i * 8..base + i * 8 + 8]);
        let (ai, op) = match mnpilot::decode_op(&ow) {
            mnpilot::BatchOp::Deposit { acct, amount } => {
                let mut aa = [0u8; 32];
                aa.copy_from_slice(&Sha256::digest(format!("aa-{}", i).as_bytes()));
                eng.state.deposits_allowed.insert((aa, false));
                (acct, Op::Deposit { account: ids[acct as usize], addr: addr(acct), amount: amount as i128, aa_unit: aa })
            }
            mnpilot::BatchOp::Place { acct, side, typ, tif, isolated, price, qty, client_seq, market, margin } => {
                let cv = |s: mnpilot::types::Side| if s == mnpilot::types::Side::Bid { Side::Bid } else { Side::Ask };
                let ct = |t: mnpilot::types::OrderType| if t == mnpilot::types::OrderType::Limit { OrderType::Limit } else { OrderType::Market };
                let cf = |t: mnpilot::types::TimeInForce| if t == mnpilot::types::TimeInForce::Gtc { TimeInForce::Gtc } else { TimeInForce::Ioc };
                (
                    acct,
                    Op::Place {
                        account: ids[acct as usize],
                        market: MarketId(market),
                        side: cv(side),
                        typ: ct(typ),
                        tif: cf(tif),
                        price,
                        qty,
                        client_seq,
                        isolated,
                        margin,
                    },
                )
            }
            mnpilot::BatchOp::Cancel { acct, client_seq, market } => {
                let a = ids[acct as usize];
                (acct, Op::Cancel { account: a, order_id: order_id(a, MarketId(market), client_seq) })
            }
            mnpilot::BatchOp::Bad => panic!("bad op {}", i),
        };
        let u = sign_unit(vec![parent], op, &secret(ai));
        let id = unit_id(&u);
        let evs = eng.ingest(u).expect("ingest");
        assert_eq!(evs.len(), 1, "linear chain: one event per unit");
        match &evs[0] {
            ExecEvent::Applied { fills, .. } => {
                out.applied += 1;
                out.fills += fills.len() as u32;
                out.ev.push(EV_APPLIED | fills.len() as u32);
                for f in fills {
                    out.ev.push(u32::from_le_bytes(f.maker_id.0[..4].try_into().unwrap()));
                    out.ev.push(u32::from_le_bytes(f.taker_id.0[..4].try_into().unwrap()));
                    out.ev.push(f.price as u32);
                    out.ev.push((f.price >> 32) as u32);
                    out.ev.push(f.qty as u32);
                    out.ev.push((f.qty >> 32) as u32);
                }
            }
            ExecEvent::Rejected { reason, .. } => {
                out.rejected += 1;
                out.ev.push(real_reason(reason));
            }
        }
        parent = id;
        per_unit(&eng);
    }
    out.hash = real_hash(&eng.state);
    (out, eng)
}

/// Size of the per-unit witness tree upstream `apply_one` rebuilds after EVERY unit
/// (`wit_root` = obyte_merkle::root(wit_leaves(state))), at the batch's final state:
/// leaves, bytes and sha256 compression blocks (leaf: ceil((len+9)/64); node: 88-char
/// base64 pair = 2 blocks).
fn witstat(w: &[u32]) -> String {
    let (_, eng) = run_real_eng(w);
    let leaves = minuend_state::wit_leaves(&eng.state);
    let bytes: usize = leaves.iter().map(|l| l.len()).sum();
    let leaf_blocks: usize = leaves.iter().map(|l| (l.len() + 9).div_ceil(64)).sum();
    let (mut n, mut nodes) = (leaves.len(), 0usize);
    while n > 1 {
        n = n.div_ceil(2);
        nodes += n;
    }
    let live: usize = eng.state.books.values().map(|b| b.live_orders().count()).sum();
    format!(
        "{{\"leaves\":{},\"bytes\":{},\"leaf_blocks\":{},\"nodes\":{},\"blocks\":{},\"accounts\":{},\"live_orders\":{}}}",
        leaves.len(), bytes, leaf_blocks, nodes, leaf_blocks + 2 * nodes, eng.state.accounts.len(), live
    )
}

fn run_port(w: &[u32]) -> Out {
    let mut ev = Vec::new();
    let (hash, st) = mnpilot::run_batch(&mut |i| w.get(i as usize).copied().unwrap_or(0), &mut |x| ev.push(x));
    Out { hash, applied: st.applied, rejected: st.rejected, fills: st.fills, ev }
}

// ---------------------------------------------------------------- generator
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

struct Gen {
    eng: mnpilot::engine::Engine,
    ops: Vec<[u32; 8]>,
    live: Vec<(u32, u64)>, // (acct, client_seq) of orders that rested
    ids: Vec<mnpilot::types::AccountId>,
}
const DOLLAR: i64 = PRICE_SCALE as i64;
const MID: i64 = 100_000 * DOLLAR;

impl Gen {
    fn apply(&mut self, w: [u32; 8]) -> bool {
        // Keep the generator's own port engine in step (used only to pick valid client_seq,
        // crossing sizes and cancel targets; the diff compares real vs port independently).
        use mnpilot::types::{order_id as oid, MarketId as M};
        let seq = self.eng.state.seq;
        let r = match mnpilot::decode_op(&w) {
            mnpilot::BatchOp::Deposit { acct, amount } => self.eng.deposit(self.ids[acct as usize], amount as i128),
            mnpilot::BatchOp::Place { acct, side, typ, tif, isolated, price, qty, client_seq, market, margin } => {
                self.eng.place(self.ids[acct as usize], M(market), side, typ, tif, price, qty, client_seq, [0; 32], seq, isolated, margin)
            }
            mnpilot::BatchOp::Cancel { acct, client_seq, market } => {
                let a = self.ids[acct as usize];
                self.eng.cancel(a, oid(a, M(market), client_seq))
            }
            mnpilot::BatchOp::Bad => unreachable!(),
        };
        self.ops.push(w);
        if r.is_ok() {
            self.eng.state.seq += 1;
        }
        r.is_ok()
    }
    fn next_cseq(&self, a: u32) -> u64 {
        self.eng.state.seen_client_seq.get(&self.ids[a as usize]).copied().unwrap_or(0) + 1
    }
    fn book(&self) -> &mnpilot::book::OrderBook {
        &self.eng.state.books[&mnpilot::types::BTC_USD]
    }
    fn is_live(&self, a: u32, c: u64) -> bool {
        let id = mnpilot::types::order_id(self.ids[a as usize], mnpilot::types::BTC_USD, c);
        self.book().get(id).map(|o| o.remaining > 0).unwrap_or(false)
    }
    fn live_count(&self, a: u32) -> usize {
        let id = self.ids[a as usize];
        self.book().live_orders().filter(|o| o.account == id).count()
    }
    fn place(&mut self, a: u32, bid: bool, typ_mkt: bool, ioc: bool, price: i64, qty: u64) {
        self.place_m(a, bid, typ_mkt, ioc, price, qty, None)
    }
    /// `iso = Some(margin_usd)` places an isolated order (kind 4).
    #[allow(clippy::too_many_arguments)]
    fn place_m(&mut self, a: u32, bid: bool, typ_mkt: bool, ioc: bool, price: i64, qty: u64, iso: Option<u32>) {
        let c = self.next_cseq(a);
        let flags = (!bid as u32) | ((typ_mkt as u32) << 1) | ((ioc as u32) << 2);
        let (k, w7) = match iso { Some(m) => (4, m), None => (2, 1) };
        let w = [k | (a << 8), flags, price as u32, (price >> 32) as u32, qty as u32, (qty >> 32) as u32, c as u32, w7];
        if self.apply(w) && !typ_mkt && !ioc && self.is_live(a, c) {
            self.live.push((a, c));
        }
    }
}

/// `stress`: half the traders are thin (2k-20k USD), 15% of trader orders are isolated
/// (1k-20k USD margin) and the live-order cap (64) is sometimes exceeded -- exercises the
/// IM / reduce-only / escrow / claw / cap paths that the default (well-funded) mix never hits.
fn gen(seed: u64, makers: u32, levels: u32, per_level: u32, n_orders: u32, stress: bool) -> (Vec<u32>, Vec<u32>, u32) {
    let traders = 16u32;
    let n_acc = makers + traders;
    let ids_real: Vec<AccountId> = (0..n_acc).map(acct_id).collect();
    let ids: Vec<mnpilot::types::AccountId> = ids_real.iter().map(|a| mnpilot::types::AccountId(a.0)).collect();
    let mut g = Gen { eng: mnpilot::engine::Engine { state: mnpilot::state::ChainState::genesis() }, ops: Vec::new(), live: Vec::new(), ids };
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let qty_rand = |rng: &mut Rng| (1 + rng.below(200)) * (QTY_SCALE / 100); // 0.01 .. 2 BTC
    // setup: deposits + resting depth (`levels` per side, `per_level` orders each)
    for a in 0..n_acc {
        let thin = stress && a >= makers && (a - makers) % 2 == 1;
        let usd = if thin { 2_000 + rng.below(18_000) as i64 } else { 10_000_000 };
        let amt = usd * USD_SCALE as i64;
        g.apply([1 | (a << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, 0, 0]);
    }
    let mut m = 0u32;
    for l in 0..levels as i64 {
        for _ in 0..per_level {
            for bid in [true, false] {
                let px = if bid { MID - (l + 1) * DOLLAR } else { MID + (l + 1) * DOLLAR };
                let q = qty_rand(&mut rng);
                g.place(m % makers, bid, false, false, px, q);
                m += 1;
            }
        }
    }
    let n_setup = g.ops.len() as u32;
    let setup_ops = g.ops.clone();
    // flow
    for _ in 0..n_orders {
        let r = rng.below(100);
        let a = rng.below(n_acc as u64) as u32;
        // stress: one trader (index `makers`) spams a third of the passive orders, so the
        // 64 live-order cap is reached and exceeded (Risk rejections at the cap).
        let a = if stress && (12..55).contains(&r) && rng.below(3) == 0 { makers } else { a };
        let bid = rng.below(2) == 0;
        let (bb, ba) = (g.book().best_bid().map(|x| x.0), g.book().best_ask().map(|x| x.0));
        let passive_px = |rng: &mut Rng| {
            let k = 1 + rng.below(levels.max(1) as u64) as i64;
            if bid { ba.unwrap_or(MID) - k * DOLLAR } else { bb.unwrap_or(MID) + k * DOLLAR }
        };
        let iso = if stress && a >= makers && rng.below(100) < 15 { Some(1_000 + rng.below(19_000) as u32) } else { None };
        let cap_hit = if stress { g.live_count(a) >= 64 && rng.below(3) != 0 } else { g.live_count(a) >= 60 };
        if r < 12 || cap_hit {
            // cancel one of a's (or anyone's) live orders
            let mine: Vec<usize> = (0..g.live.len()).filter(|&i| g.live[i].0 == a).collect();
            let pick = if !mine.is_empty() { Some(mine[rng.below(mine.len() as u64) as usize]) } else if !g.live.is_empty() { Some(rng.below(g.live.len() as u64) as usize) } else { None };
            if let Some(i) = pick {
                let (ca, cs) = g.live.swap_remove(i);
                // stale (already filled) targets are kept: the engine rejects them (NotFound) as it would in production
                g.apply([3 | (ca << 8), 0, 0, 0, 0, 0, cs as u32, 1]);
                continue;
            }
        }
        if r < 55 {
            let px = passive_px(&mut rng);
            let q = qty_rand(&mut rng);
            g.place_m(a, bid, false, false, px, q, iso);
        } else if r < 75 {
            // aggressive limit sized to the first maker: exactly one fill
            let taker = mnpilot::types::AccountId(ids_real[a as usize].0);
            let side = if bid { mnpilot::types::Side::Bid } else { mnpilot::types::Side::Ask };
            match (g.book().first_maker_qty(side, taker), if bid { ba } else { bb }) {
                (Some(mq), Some(px)) => {
                    let q = 1 + rng.below(mq);
                    g.place_m(a, bid, false, false, px, q.min(mq), iso);
                }
                _ => {
                    let px = passive_px(&mut rng);
                    g.place(a, bid, false, false, px, qty_rand(&mut rng));
                }
            }
        } else if r < 90 {
            // market IOC (takes the first maker only)
            g.place_m(a, bid, true, true, 0, qty_rand(&mut rng), iso);
        } else {
            // oversized crossing GTC (usually refused whole: MultiFill) or IOC limit through the book
            let px = if bid { ba.unwrap_or(MID) + 3 * DOLLAR } else { bb.unwrap_or(MID) - 3 * DOLLAR };
            let ioc = rng.below(2) == 0;
            g.place(a, bid, false, ioc, px, 5 * QTY_SCALE);
        }
    }
    let mk = |ops: &[[u32; 8]]| {
        let mut w = vec![mnpilot::MAGIC, n_acc, ops.len() as u32, 0];
        for id in &ids_real {
            for k in 0..8 {
                w.push(u32::from_le_bytes(id.0[k * 4..k * 4 + 4].try_into().unwrap()));
            }
        }
        for o in ops {
            w.extend_from_slice(o);
        }
        w
    };
    (mk(&g.ops), mk(&setup_ops), n_setup)
}

/// Pilot-modelled leaves of the REAL engine state (upstream wit_leaves, filtered by tag).
fn real_pilot_leaves(e: &Engine) -> Vec<String> {
    minuend_state::wit_leaves(&e.state).into_iter().filter(|l| smt_ref::pilot_leaf(l)).collect()
}
fn legacy_real_root(e: &Engine) -> [u8; 32] {
    let mut l = real_pilot_leaves(e);
    l.push(minuend_state::WIT_MAX_SENTINEL.to_string());
    l.sort();
    smt_ref::unb64(&minuend_state::obyte_merkle::root(&l)).try_into().unwrap()
}
fn wroots(w: &[u32], legacy: Option<u32>) -> String {
    let mut roots: Vec<String> = Vec::new();
    let mut i = 0u32;
    let (_, eng) = run_real_eng_cb(w, &mut |e| {
        let r = match legacy {
            None => smt_ref::root(&real_pilot_leaves(e)),
            Some(skip) => if i >= skip { legacy_real_root(e) } else { [0u8; 32] },
        };
        roots.push(format!("\"{}\"", smt_ref::hex(&r)));
        i += 1;
    });
    let leaves = real_pilot_leaves(&eng);
    let d = smt_ref::depths(&leaves);
    let live: usize = eng.state.books.values().map(|b| b.live_orders().count()).sum();
    format!(
        "{{\"leaves\":{},\"live_orders\":{},\"depth_max\":{},\"depth_avg\":{:.2},\"roots\":[{}]}}",
        leaves.len(), live, d.iter().max().unwrap_or(&0), d.iter().sum::<usize>() as f64 / d.len().max(1) as f64, roots.join(",")
    )
}
fn port_roots(w: &[u32]) -> (Vec<[u8; 32]>, Vec<[u8; 32]>, mnpilot::WitOut) {
    let (mut inc, mut scratch) = (Vec::new(), Vec::new());
    let (_, _, wo) = mnpilot::run_batch_wit(
        &mut |i| w.get(i as usize).copied().unwrap_or(0),
        &mut |_| {},
        &mut |_, st, r| {
            inc.push(*r);
            scratch.push(smt_ref::root(&mnpilot::wit::all_leaves(st)));
        },
        mnpilot::WitMode::Incremental,
    );
    (inc, scratch, wo)
}
/// Pure tree property test: random set/remove sequences on the incremental Smt vs a
/// from-scratch root over a model map, after EVERY op; keys drawn from clustered prefixes so
/// splits/collapses happen deep in the tree (up to depth ~250).
fn smt_fuzz(rounds: u64) -> (u64, u64, u64) {
    use std::collections::BTreeMap;
    let (mut ok, mut ops, mut bad) = (0u64, 0u64, 0u64);
    for r in 1..=rounds {
        let mut rng = Rng(r.wrapping_mul(0xD1B5_4A32_D192_ED03) | 1);
        let mut t = mnpilot::wit::Smt::new();
        let mut m: BTreeMap<[u8; 32], [u8; 32]> = BTreeMap::new();
        let mut good = true;
        let n = 20 + rng.below(200);
        for _ in 0..n {
            let mut k = [0u8; 32];
            match rng.below(3) {
                0 => k.iter_mut().for_each(|b| *b = rng.next() as u8),                // random
                1 => { k = [0x5a; 32]; k[31] = rng.below(8) as u8; }                    // share 253 bits
                _ => { k[0] = rng.below(4) as u8; k[1] = rng.below(4) as u8; k[2] = rng.next() as u8; } // clustered
            }
            if rng.below(3) == 0 && !m.is_empty() {
                let pick = *m.keys().nth(rng.below(m.len() as u64) as usize).unwrap();
                let k2 = if rng.below(4) == 0 { k } else { pick };
                t.remove(&k2);
                m.remove(&k2);
            } else {
                let mut v = [0u8; 32];
                v.iter_mut().for_each(|b| *b = rng.next() as u8);
                t.set(k, v);
                m.insert(k, v);
            }
            ops += 1;
            let kv: Vec<_> = m.iter().map(|(a, b)| (*a, *b)).collect();
            if t.root() != smt_ref::root_kv(&kv) || t.count as usize != m.len() {
                good = false;
            }
        }
        if good { ok += 1 } else { bad += 1 }
    }
    (ok, bad, ops)
}
fn witfuzz(n: u64, ord: u32, smt_rounds: u64) -> String {
    let (mut ok, mut units, mut max_leaves, mut hist_ok) = (0u64, 0u64, 0u32, 0u64);
    for s in 1..=n {
        let makers = 4 + (s % 9) as u32;
        let levels = 1 + (s % 25) as u32;
        let per = 1 + (s % 3) as u32;
        let stress = s % 2 == 0;
        let (w, _, _) = gen(s, makers, levels, per, ord, stress);
        let mut a = Vec::new();
        run_real_eng_cb(&w, &mut |e| a.push(smt_ref::root(&real_pilot_leaves(e))));
        let (b, c, wo) = port_roots(&w);
        // history independence: same final leaf set, shuffled, with churn of extra keys
        let mut leaves: Vec<String> = Vec::new();
        let last = w[2].saturating_sub(1);
        let _ = mnpilot::run_batch_wit(&mut |i| w.get(i as usize).copied().unwrap_or(0), &mut |_| {}, &mut |i, st, _| {
            if i == last { leaves = mnpilot::wit::all_leaves(st); }
        }, mnpilot::WitMode::Off);
        let mut rng = Rng(s | 1);
        let mut order: Vec<usize> = (0..leaves.len()).collect();
        for i in (1..order.len()).rev() { order.swap(i, rng.below(i as u64 + 1) as usize); }
        let mut t = mnpilot::wit::Smt::new();
        for (j, &i) in order.iter().enumerate() {
            let l = &leaves[i];
            t.set(smt_ref::key(l), smt_ref::leaf_hash(l));
            if j % 3 == 0 {
                let junk = smt_ref::key(&format!("ord:junk{}", j));
                t.set(junk, [1u8; 32]);
                if rng.below(2) == 0 { t.root(); }
                t.remove(&junk);
            }
        }
        if Some(&t.root()) == b.last() { hist_ok += 1; }
        units += a.len() as u64;
        max_leaves = max_leaves.max(wo.leaves);
        if a == b && b == c && wo.scratch_ok && a.len() == w[2] as usize {
            ok += 1;
        } else {
            let first = a.iter().zip(&b).zip(&c).position(|((x, y), z)| x != y || y != z);
            println!("WITMISMATCH seed {} first unit {:?} scratch_ok {} lens {} {} {}", s, first, wo.scratch_ok, a.len(), b.len(), c.len());
        }
    }
    let (sok, sbad, sops) = smt_fuzz(smt_rounds);
    format!(
        "{{\"seeds\":{},\"match\":{},\"units_compared\":{},\"history_independent\":{},\"max_leaves\":{},\"smt_rounds_ok\":{},\"smt_rounds_bad\":{},\"smt_ops\":{}}}",
        n, ok, units, hist_ok, max_leaves, sok, sbad, sops
    )
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(|s| s.as_str()) {
        Some("gen") => {
            let p = |i: usize| a[i].parse::<u64>().unwrap();
            let stress = a.get(8).map(|x| x == "stress").unwrap_or(false);
            let (full, setup, n_setup) = gen(p(2), p(3) as u32, p(4) as u32, p(5) as u32, p(6) as u32, stress);
            let out = &a[7];
            write_words(out, &full);
            write_words(&out.replace(".bin", ".setup.bin"), &setup);
            println!("{{\"ops\":{},\"setup_ops\":{},\"words\":{}}}", full[2], n_setup, full.len());
        }
        Some("real") => println!("{}", run_real(&read_words(&a[2])).json()),
        Some("witstat") => println!("{}", witstat(&read_words(&a[2]))),
        Some("port") => println!("{}", run_port(&read_words(&a[2])).json()),
        Some("wroots") => {
            let legacy = if a.get(3).map(|x| x == "legacy").unwrap_or(false) { Some(a[4].parse().unwrap()) } else { None };
            println!("{}", wroots(&read_words(&a[2]), legacy))
        }
        Some("portroots") => {
            let (inc, scr, wo) = port_roots(&read_words(&a[2]));
            let r: Vec<String> = inc.iter().map(|x| format!("\"{}\"", smt_ref::hex(x))).collect();
            println!("{{\"scratch_equal\":{},\"scratch_ok\":{},\"leaves\":{},\"leaf_updates\":{},\"node_hashes\":{},\"roots\":[{}]}}",
                inc == scr, wo.scratch_ok, wo.leaves, wo.leaf_updates, wo.node_hashes, r.join(","));
        }
        Some("witfuzz") => {
            let p = |i: usize, d: u64| a.get(i).map(|x| x.parse().unwrap()).unwrap_or(d);
            println!("{}", witfuzz(p(2, 300), p(3, 300) as u32, p(4, 300)));
        }
        Some("fuzz") => {
            let n: u64 = a[2].parse().unwrap();
            let ord: u32 = a[3].parse().unwrap();
            let (mut ok, mut evs, mut fills, mut rej) = (0, 0usize, 0u32, 0u32);
            let mut codes: std::collections::BTreeMap<u32, u32> = Default::default();
            for s in 1..=n {
                let makers = 4 + (s % 9) as u32;
                let levels = 1 + (s % 25) as u32;
                let per = 1 + (s % 3) as u32;
                let stress = s % 2 == 0;
                let (w, _, _) = gen(s, makers, levels, per, ord, stress);
                let r = run_real(&w);
                let p = run_port(&w);
                if r.hash == p.hash && r.ev == p.ev && r.applied == p.applied {
                    ok += 1;
                } else {
                    let first = r.ev.iter().zip(&p.ev).position(|(x, y)| x != y);
                    println!("MISMATCH seed {} makers {} levels {} per {}: first ev diff at {:?}", s, makers, levels, per, first);
                }
                let mut k = 0;
                while k < r.ev.len() {
                    let e = r.ev[k];
                    if e & EV_APPLIED != 0 { *codes.entry(EV_APPLIED | (e & 0xff)).or_default() += 1; k += 1 + 6 * (e & 0xff) as usize; } else { *codes.entry(e).or_default() += 1; k += 1; }
                }
                evs += r.ev.len();
                fills += r.fills;
                rej += r.rejected;
            }
            let cs: Vec<String> = codes.iter().map(|(k, v)| format!("\"{:#x}\":{}", k, v)).collect();
            println!("{{\"seeds\":{},\"match\":{},\"ev_words\":{},\"fills\":{},\"rejected\":{},\"codes\":{{{}}}}}", n, ok, evs, fills, rej, cs.join(","));
        }
        _ => eprintln!("usage: see header"),
    }
}
