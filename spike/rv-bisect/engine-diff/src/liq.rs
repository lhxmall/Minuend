//! Loop round 4: differential batches for the newly ported engine paths -- `Withdraw`,
//! `Liquidate` (book IOC path, ADL remainder, funding-rate off-book close + haircut, keeper
//! reward), `ReportPrice` (median, ±10 % cap, index band, TWAP, peer-to-peer funding),
//! `UpdateExternalPrice` + the funding-rate peg (`settle_funding_peg`), the funding-rate
//! open-interest cap (`funding_open_interest`, the round-3 surviving mutant) and the
//! `SetHeight` fixture (peg interval / feed staleness).
//!
//!   liqgen  <seed> <n_ops> <out.bin>   one batch
//!   liqfuzz <n> <n_ops>                real vs port: hash + events + per-unit MNWIT1 roots
//!                                      (real from scratch / port incremental / port scratch)
//!
//! Accounts: 0 = external feed of the funding-rate market 3 (fixture), 1..=3 bonded oracles
//! (fixture), 4..=5 keepers, 6..=9 makers, 10.. traders (thin ones run near 10x).
use super::*;

const ORACLES: [u32; 3] = [1, 2, 3];
const KEEPERS: [u32; 2] = [4, 5];
const MAKERS: std::ops::Range<u32> = 6..10;

fn w8(k: u32, a: u32, w1: u32, p: i64, w4: u32, w5: u32, w6: u32, w7: u32) -> [u32; 8] {
    [k | (a << 8), w1, p as u32, (p >> 32) as u32, w4, w5, w6, w7]
}

pub fn liq_batch(seed: u64, n_ops: u32) -> Vec<u32> {
    let mut rng = Rng(seed.wrapping_mul(0xA24B_AED4_963E_E407) | 1);
    let traders = 8 + rng.below(12) as u32;
    let n_acc = 10 + traders;
    let flags = mnpilot::FUNDING_MKT_FLAG | mnpilot::ORACLES_FLAG | if seed % 3 == 0 { mnpilot::MARKET2_FLAG } else { 0 };
    let (ids_real, mut g) = adv::new_gen(n_acc, flags);
    let fm = mnpilot::FUNDING_MKT.0;
    let m2 = seed % 3 == 0;
    let qs = QTY_SCALE;
    // setup: deposits (thin traders), first oracle prints, external feed, maker depth
    for a in 0..n_acc {
        let usd: i64 = if a >= 10 && (a % 3 == 1) { 1_500 + rng.below(8_000) as i64 } else if a >= 10 { 20_000 + rng.below(200_000) as i64 } else { 5_000_000 };
        let amt = usd * USD_SCALE as i64;
        g.apply([1 | (a << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, 0, 0]);
    }
    let mut mark = MID;
    // reports only in some seeds before trading: seeds without them exercise the fill-driven mark
    if rng.below(3) != 0 {
        for o in ORACLES {
            g.apply(w8(8, o, 0, mark, 0, 0, 0, 1));
        }
    }
    let mut rate: i64 = 50 + rng.below(400) as i64; // funding-rate market works in bps
    g.apply(w8(9, 0, 0, mnpilot::types::encode_funding_price(rate), 0, 0, 0, fm));
    let mut height = 0u64;
    let trend_up = rng.below(2) == 0;
    let place = |g: &mut Gen, a: u32, bid: bool, mkt: bool, ioc: bool, price: i64, qty: u64, market: u32| {
        let c = g.next_cseq(a);
        let fl = (!bid as u32) | ((mkt as u32) << 1) | ((ioc as u32) << 2);
        g.apply([2 | (a << 8), fl, price as u32, (price >> 32) as u32, qty as u32, (qty >> 32) as u32, c as u32, market]);
    };
    let depth = |g: &mut Gen, rng: &mut Rng, mark: i64, rate: i64, m2: bool| {
        for mk in MAKERS {
            for l in 1..=3i64 {
                let off = l * mark / 400;
                place(g, mk, true, false, false, mark - off, (1 + rng.below(30)) * qs / 10, 1);
                place(g, mk, false, false, false, mark + off, (1 + rng.below(30)) * qs / 10, 1);
                if m2 && l == 1 {
                    place(g, mk, rng.below(2) == 0, false, false, mark + (rng.below(5) as i64 - 2) * mark / 300, (1 + rng.below(10)) * qs / 10, 2);
                }
            }
            let r = mnpilot::types::encode_funding_price(rate + (rng.below(5) as i64 - 2));
            place(g, mk, rng.below(2) == 0, false, false, r, (1 + rng.below(40)) * qs, fm);
        }
    };
    depth(&mut g, &mut rng, mark, rate, m2);
    for _ in 0..n_ops {
        let r = rng.below(100);
        let t = 10 + rng.below(traders as u64) as u32;
        let bid = rng.below(2) == 0;
        match r {
            // leveraged market orders (take the first maker) on BTC / market 2
            0..=17 => {
                // thin traders: size the order to ~5-9x leverage on their collateral
                let col = g.eng.state.accounts.get(&g.ids[t as usize]).map(|x| x.collateral).unwrap_or(0).max(0) as u128;
                let lev = 5 + rng.below(5) as u128;
                let q_lev = (col * lev * QTY_SCALE as u128 * DOLLAR as u128 / (USD_SCALE as u128 * mark.max(1) as u128)) as u64;
                let q = if t % 3 == 1 && rng.below(3) != 0 { q_lev.max(qs / 1000) } else { (1 + rng.below(60)) * qs / 100 };
                place(&mut g, t, bid, true, true, 0, q, if m2 && rng.below(4) == 0 { 2 } else { 1 });
            }
            // funding-rate market: trade at rates near the current one (sometimes big qty: OI cap)
            18..=29 => {
                let big = rng.below(6) == 0;
                // thin traders: ~70-95 % of collateral as IM (100x market: IM = 100 USD per unit)
                let col = g.eng.state.accounts.get(&g.ids[t as usize]).map(|x| x.collateral).unwrap_or(0).max(0) as u64;
                let q_thin = (col / USD_SCALE * (70 + rng.below(26)) / 100 / 100).max(1) * qs;
                let q = if big { (100 + rng.below(900)) * qs } else if t % 3 == 1 { q_thin } else { (1 + rng.below(30)) * qs };
                // the traded rate walks (fills are the mark source of this market, <= 10 % per fill)
                if rng.below(3) == 0 {
                    let up = if rng.below(10) < 7 { trend_up } else { !trend_up };
                    rate += if up { (rate.abs() / 12).max(1) } else { -(rate.abs() / 12).max(1) };
                }
                let px = mnpilot::types::encode_funding_price(rate + rng.below(3) as i64 - 1);
                if rng.below(2) == 0 {
                    // a maker rests at the new rate first, so the taker can cross it
                    let mk = MAKERS.start + rng.below(4) as u32;
                    place(&mut g, mk, !bid, false, false, px, q, fm);
                }
                let ioc = rng.below(2) == 0;
                place(&mut g, t, bid, false, ioc, px, q, fm);
            }
            // oracle report: drift, sometimes a jump (capped at 10 % by apply_report)
            30..=41 => {
                let step = if rng.below(5) == 0 { mark / 8 } else { mark / 50 };
                mark = if rng.below(2) == 0 { mark - step } else { mark + step };
                mark = mark.max(10_000 * DOLLAR);
                let o = ORACLES[rng.below(3) as usize];
                let mkt = match rng.below(10) { 0 if m2 => 2, 1 => fm, _ => 1 };
                let px = if mkt == fm { mnpilot::types::encode_funding_price(rate + rng.below(40) as i64 - 20) } else { mark + rng.below(200) as i64 * DOLLAR };
                if mkt != fm && rng.below(3) == 0 {
                    // joint move: every oracle reports the same 6-9 % step (moves the median)
                    let step = mark * (6 + rng.below(4) as i64) / 100;
                    let up = if rng.below(10) < 7 { trend_up } else { !trend_up };
                    mark = if up { mark + step } else { mark - step };
                    for o in ORACLES {
                        g.apply(w8(8, o, 0, mark, 0, 0, 0, mkt));
                    }
                } else {
                    // an unbonded reporter now and then
                    let o = if rng.below(15) == 0 { t } else { o };
                    g.apply(w8(8, o, 0, px, 0, 0, 0, mkt));
                }
            }
            // liquidation attempts: holders of the market first, anyone sometimes
            42..=60 => {
                let mkt = match rng.below(6) { 0 | 1 => fm, 2 if m2 => 2, _ => 1 };
                let holders: Vec<u32> = (0..n_acc).filter(|&a| g.eng.state.accounts.get(&g.ids[a as usize]).is_some_and(|x| x.positions.contains_key(&mnpilot::types::MarketId(mkt)))).collect();
                // a "smart" keeper half of the time: the holder closest to its maintenance margin
                let st = &g.eng.state;
                let worst = holders.iter().copied().max_by_key(|&h| {
                    let a = &st.accounts[&g.ids[h as usize]];
                    let sn = a.snapshot(&st.marks, &st.markets);
                    (sn.mm.max(0) * 1_000_000 / sn.equity.max(1), h)
                });
                let target = if let (Some(wt), true) = (worst, rng.below(2) == 0) { wt } else if !holders.is_empty() && rng.below(5) != 0 { holders[rng.below(holders.len() as u64) as usize] } else if rng.below(20) == 0 { mnpilot::LIQ_TARGET_INSURANCE } else { rng.below(n_acc as u64) as u32 };
                let k = if rng.below(10) == 0 && target < n_acc { target } else { KEEPERS[rng.below(2) as usize] };
                if mkt != fm && rng.below(3) == 0 {
                    // dust at the top of the book: the liquidation skips it and goes to ADL (R7-H1 rule)
                    let mk = MAKERS.start + rng.below(4) as u32;
                    place(&mut g, mk, true, false, false, mark - mark / 1000, qs / 10_000, mkt);
                    place(&mut g, mk, false, false, false, mark + mark / 1000, qs / 10_000, mkt);
                }
                if std::env::var("LIQDBG").is_ok() && target != mnpilot::LIQ_TARGET_INSURANCE {
                    let st = &g.eng.state;
                    if let Some(a) = st.accounts.get(&g.ids[target as usize]) {
                        let sn = a.snapshot(&st.marks, &st.markets);
                        eprintln!("liq t{} m{} col {} pos {:?} eq {} mm {} liq {} mark {:?}", target, mkt, a.collateral / 1_000_000, a.positions.get(&mnpilot::types::MarketId(mkt)).map(|p| p.qty), sn.equity / 1_000_000, sn.mm / 1_000_000, sn.liquidatable, st.marks.get(&mnpilot::types::MarketId(mkt)));
                    }
                }
                g.apply(w8(7, k, target, 0, 0, 0, 0, mkt));
            }
            // withdrawals: valid, too large, dust, duplicate nonce, unknown-ish account
            61..=69 => {
                let a = if rng.below(4) == 0 { rng.below(n_acc as u64) as u32 } else { t };
                let col = g.eng.state.accounts.get(&g.ids[a as usize]).map(|x| x.collateral).unwrap_or(0) as i64;
                let amt = match rng.below(6) {
                    0 => col,
                    1 => col + 1,
                    2 => (USD_SCALE / 2) as i64,
                    3 => -(rng.below(1000) as i64),
                    _ => col / (2 + rng.below(6) as i64),
                };
                let nonce = if rng.below(6) == 0 { 1 } else { 1 + rng.below(1 << 20) };
                g.apply(w8(6, a, amt as u32, 0, 0, 0, nonce as u32, (nonce >> 32) as u32).map_w1w2(amt));
            }
            // external feed of the funding-rate market (sometimes by a non-source, sometimes broken)
            70..=75 => {
                rate += rng.below(41) as i64 - 20;
                let src = if rng.below(8) == 0 { t } else { 0 };
                let px = match rng.below(12) { 0 => mnpilot::types::encode_funding_price(20_000), 1 => 0, _ => mnpilot::types::encode_funding_price(rate) };
                let mkt = if rng.below(10) == 0 { 1 } else { fm };
                g.apply(w8(9, src, 0, px, 0, 0, rng.below(4) as u32, mkt));
            }
            // heights: +1 (same window), +33 (feed goes stale), +14 400 (peg interval)
            76..=79 => {
                height += match rng.below(4) { 0 => 1, 1 => 33, 2 => mnpilot::types::FUNDING_PEG_INTERVAL_HEIGHTS, _ => 0 };
                let h = if rng.below(15) == 0 { height.saturating_sub(5) } else { height };
                g.apply([10, h as u32, (h >> 32) as u32, 0, 0, 0, 0, 0]);
            }
            // refill the book / deposits / cancels
            80..=87 => depth(&mut g, &mut rng, mark, rate, m2),
            88..=92 => {
                let amt = (500 + rng.below(20_000) as i64) * USD_SCALE as i64;
                g.apply([1 | (t << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, 0, 0]);
            }
            _ => {
                if let Some(i) = (!g.live.is_empty()).then(|| rng.below(g.live.len() as u64) as usize) {
                    let (ca, cs) = g.live.swap_remove(i);
                    g.apply([3 | (ca << 8), 0, 0, 0, 0, 0, cs as u32, 1]);
                } else {
                    let q = (1 + rng.below(40)) * qs / 100;
                    place(&mut g, t, bid, false, false, mark + if bid { -DOLLAR } else { DOLLAR } * (1 + rng.below(50) as i64), q, 1);
                }
            }
        }
    }
    adv::batch_words(&ids_real, &g.ops, flags)
}

trait W12 {
    fn map_w1w2(self, amt: i64) -> Self;
}
impl W12 for [u32; 8] {
    fn map_w1w2(mut self, amt: i64) -> Self {
        self[1] = amt as u32;
        self[2] = (amt >> 32) as u32;
        self
    }
}

/// Per-kind outcome counters from the port's event log (op kind -> applied / rejected).
fn coverage(w: &[u32], ev: &[u32], cov: &mut std::collections::BTreeMap<String, u64>) {
    let base = (4 + w[1] * 8) as usize;
    let mut k = 0usize;
    for i in 0..w[2] as usize {
        let kind = w[base + 8 * i] & 0xff;
        let e = ev[k];
        let mk = w[base + 8 * i + 7];
        let name = match kind {
            1 => "deposit".to_string(),
            2 | 4 | 5 => format!("place{}", if kind == 2 { mk } else { 1 }),
            3 => "cancel".to_string(),
            6 => "withdraw".to_string(),
            7 => format!("liquidate{}", mk),
            8 => "report".to_string(),
            9 => "extprice".to_string(),
            10 => "height".to_string(),
            _ => "bad".to_string(),
        };
        let tag = if e == mnpilot::EV_HEIGHT { "set".to_string() } else if e & EV_APPLIED != 0 { format!("ok{}", e & 0xff) } else { format!("{:#x}", e) };
        *cov.entry(format!("{}:{}", name, tag)).or_default() += 1;
        if e & EV_APPLIED != 0 && e != mnpilot::EV_HEIGHT {
            let n = (e & 0xff) as usize;
            if kind == 7 && n > 0 {
                // kind of the liquidation fill: ADL (maker id 0) vs book
                let adl = ev[k + 1] == 0;
                *cov.entry(format!("liquidate:{}", if adl { "adl" } else { "book" })).or_default() += 1;
            }
            k += 1 + 6 * n;
        } else {
            k += 1;
        }
    }
}

pub fn liqfuzz(n: u64, ops: u32) -> String {
    let (mut ok, mut units) = (0u64, 0u64);
    let mut cov: std::collections::BTreeMap<String, u64> = Default::default();
    let mut paid = 0u64;
    let mut liq_fills = 0u64;
    for s in 1..=n {
        let w = liq_batch(s, ops);
        let mut a = Vec::new();
        let (r, eng) = run_real_eng_cb(&w, &mut |e| a.push(smt_ref::root(&real_pilot_leaves(e))));
        let p = run_port(&w);
        let (b, c, wo) = port_roots(&w);
        let same = r.hash == p.hash && r.ev == p.ev && r.applied == p.applied;
        let roots = a == b && b == c && wo.scratch_ok && a.len() == w[2] as usize;
        // loop round 5 (R4-M2): the same batch as MNP2 (real unit ids as input): unmasked
        // liquidation taker ids must match too, and state / roots stay equal
        let w2 = to_v2(&w);
        let r2 = run_real(&w2);
        let p2 = run_port(&w2);
        let (b2, _, _) = port_roots(&w2);
        let v2 = r2.hash == p2.hash && r2.ev == p2.ev && r2.hash == r.hash && b2 == b;
        liq_fills += r.ev.iter().filter(|x| **x == mnpilot::LIQ_TAKER_EV).count() as u64;
        if !v2 {
            println!("LIQMISMATCH v2 seed {} first_ev {:?}", s, r2.ev.iter().zip(&p2.ev).position(|(x, y)| x != y));
        }
        if same && roots && v2 {
            ok += 1;
        } else {
            let first_ev = r.ev.iter().zip(&p.ev).position(|(x, y)| x != y);
            let first_root = a.iter().zip(&b).zip(&c).position(|((x, y), z)| x != y || y != z);
            println!("LIQMISMATCH seed {} engine {} roots {} first_ev {:?} first_root {:?}", s, same, roots, first_ev, first_root);
        }
        units += a.len() as u64;
        coverage(&w, &p.ev, &mut cov);
        if !eng.state.last_funding_height.is_empty() {
            paid += 1;
        }
    }
    let cs: Vec<String> = cov.iter().map(|(k, v)| format!("\"{}\":{}", k, v)).collect();
    format!("{{\"seeds\":{},\"match\":{},\"units\":{},\"liq_fills_unmasked_v2\":{},\"funding_clock_armed_batches\":{},\"coverage\":{{{}}}}}", n, ok, units, liq_fills, paid, cs.join(","))
}

/// Per-op first event word (EV_APPLIED|fills, a reject code, or EV_HEIGHT).
fn outcomes(w: &[u32], ev: &[u32]) -> Vec<u32> {
    let mut o = Vec::new();
    let mut k = 0usize;
    for _ in 0..w[2] as usize {
        let e = ev[k];
        o.push(e);
        k += if e & EV_APPLIED != 0 && e != mnpilot::EV_HEIGHT { 1 + 6 * (e & 0xff) as usize } else { 1 };
    }
    o
}

/// Loop round 4 (mutation follow-up): deterministic boundary batches for the ported paths that
/// random liqfuzz batches rarely hit exactly. Each case is checked real vs port (hash, events,
/// per-unit roots) AND for intent (the real engine's outcome at the boundary op is the expected
/// one, so the case really sits on the boundary):
///   wd_limit   64 pending withdrawals accepted, the 65th refused (Risk)
///   wd_min     exactly MIN_WITHDRAW_AMOUNT accepted, one micro-USD less refused
///   wd_prune   a nonce stays used at height h0 + REPLAY_WINDOW - 1, is reusable at h0 + REPLAY_WINDOW
///   stale_peg  external print at P + 14400 - 32 is stale for the peg at P + 14400 (no payment);
///              print one height later is fresh (payment) -- both must match the real engine
///   band10     an oracle median exactly 10 % above the mark moves the mark (dev == old / 10)
pub fn liqedge() -> String {
    use mnpilot::types::encode_funding_price as efp;
    let fm = mnpilot::FUNDING_MKT.0;
    let flags = mnpilot::FUNDING_MKT_FLAG | mnpilot::ORACLES_FLAG;
    let mut res = Vec::new();
    let mut all = true;
    let mut case = |name: &str, build: &dyn Fn(&mut Gen) -> Vec<(usize, u32)>| {
        let (ids_real, mut g) = adv::new_gen(12, flags);
        for a in 0..12u32 {
            let amt = 5_000_000 * USD_SCALE as i64;
            g.apply([1 | (a << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, 0, 0]);
        }
        let want = build(&mut g);
        let w = adv::batch_words(&ids_real, &g.ops, flags);
        let mut a = Vec::new();
        let (r, _) = run_real_eng_cb(&w, &mut |e| a.push(smt_ref::root(&real_pilot_leaves(e))));
        let p = run_port(&w);
        let (b, c, wo) = port_roots(&w);
        let same = r.hash == p.hash && r.ev == p.ev && r.applied == p.applied && a == b && b == c && wo.scratch_ok;
        let out = outcomes(&w, &r.ev);
        let intent = want.iter().all(|&(i, e)| if e == EV_APPLIED { out[i] & EV_APPLIED != 0 && out[i] != mnpilot::EV_HEIGHT } else { out[i] == e });
        all &= same && intent;
        res.push(format!("\"{}\":{{\"match\":{},\"intent\":{}}}", name, same, intent));
    };
    let wd = |a: u32, amt: i64, nonce: u64| -> [u32; 8] { [6 | (a << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, nonce as u32, (nonce >> 32) as u32] };
    let hgt = |h: u64| -> [u32; 8] { [10, h as u32, (h >> 32) as u32, 0, 0, 0, 0, 0] };
    let risk = reason_code_of(mnpilot::engine::RejectReason::Risk);
    let dup = reason_code_of(mnpilot::engine::RejectReason::DuplicateNonce);
    case("wd_limit", &|g| {
        let mut want = Vec::new();
        for n in 1..=64u64 {
            g.apply(wd(10, 2 * USD_SCALE as i64, n));
            want.push((g.ops.len() - 1, EV_APPLIED));
        }
        g.apply(wd(10, 2 * USD_SCALE as i64, 65));
        want.push((g.ops.len() - 1, risk));
        want
    });
    case("wd_min", &|g| {
        g.apply(wd(10, USD_SCALE as i64, 1));
        let i = g.ops.len() - 1;
        g.apply(wd(11, USD_SCALE as i64 - 1, 1));
        vec![(i, EV_APPLIED), (i + 1, risk)]
    });
    case("wd_prune", &|g| {
        let w0 = mnpilot::types::REPLAY_WINDOW;
        g.apply(hgt(5));
        g.apply(wd(10, 3 * USD_SCALE as i64, 7));
        let i0 = g.ops.len() - 1;
        g.apply(hgt(5 + w0 - 1));
        g.apply(wd(10, 3 * USD_SCALE as i64, 7));
        let i1 = g.ops.len() - 1;
        g.apply(hgt(5 + w0));
        g.apply(wd(10, 3 * USD_SCALE as i64, 7));
        let i2 = g.ops.len() - 1;
        vec![(i0, EV_APPLIED), (i1, dup), (i2, EV_APPLIED)]
    });
    for (name, late) in [("stale_peg", 0u64), ("fresh_peg", 1u64)] {
        case(name, &|g| {
            let qs = QTY_SCALE;
            let p0 = 10u64;
            g.apply(hgt(p0));
            // index 100 bps; a print at 105 bps sets the mark (bootstrap within the 10 bps cap) and arms the peg clock
            g.apply([9, 0, efp(100) as u32, (efp(100) >> 32) as u32, 0, 0, 0, fm]);
            let c6 = g.next_cseq(6);
            g.apply([2 | (6 << 8), 1, efp(105) as u32, (efp(105) >> 32) as u32, qs as u32, (qs >> 32) as u32, c6 as u32, fm]);
            let c10 = g.next_cseq(10);
            g.apply([2 | (10 << 8), 0, efp(105) as u32, (efp(105) >> 32) as u32, qs as u32, (qs >> 32) as u32, c10 as u32, fm]);
            let fill = g.ops.len() - 1;
            let pk = p0 + mnpilot::types::FUNDING_PEG_INTERVAL_HEIGHTS;
            let hp = pk - mnpilot::types::FUNDING_EXTERNAL_MAX_STALENESS + late;
            g.apply(hgt(hp));
            g.apply([9, 0, efp(40) as u32, (efp(40) >> 32) as u32, 0, 0, 1, fm]);
            g.apply(hgt(pk));
            // a bonded oracle report on the funding market settles the peg at pk
            g.apply([8 | (1 << 8), 0, efp(105) as u32, (efp(105) >> 32) as u32, 0, 0, 0, fm]);
            vec![(fill, EV_APPLIED | 1), (g.ops.len() - 1, EV_APPLIED)]
        });
    }
    case("band10", &|g| {
        let m = 100_000 * DOLLAR;
        g.apply([8 | (1 << 8), 0, (m + m / 10) as u32, ((m + m / 10) >> 32) as u32, 0, 0, 0, 1]);
        let i = g.ops.len() - 1;
        g.apply([8 | (2 << 8), 0, (m + m / 10 + m / 50) as u32, ((m + m / 10 + m / 50) >> 32) as u32, 0, 0, 0, 1]);
        vec![(i, EV_APPLIED)]
    });
    // adl_hole: a 10x long (0.3 + 0.7 BTC from two makers) loses 27.1 % through three exact 10 % oracle
    // steps; the keeper's liquidation finds no bid, closes by ADL against the two shorts, and the hole
    // left on the target is haircut pro-rata from them (the last one takes the remainder)
    case("adl_hole", &|g| {
        let qs = QTY_SCALE;
        let m = 100_000 * DOLLAR;
        let keep = 15_000 * USD_SCALE as i64;
        g.apply(wd(11, 5_000_000 * USD_SCALE as i64 - keep, 1));
        for (mk, q) in [(6u32, 3 * qs / 10), (7u32, 7 * qs / 10)] {
            let c = g.next_cseq(mk);
            g.apply([2 | (mk << 8), 1, m as u32, (m >> 32) as u32, q as u32, (q >> 32) as u32, c as u32, 1]);
        }
        for q in [3 * qs / 10, 7 * qs / 10] {
            let c = g.next_cseq(11);
            g.apply([2 | (11 << 8), 0, m as u32, (m >> 32) as u32, q as u32, (q >> 32) as u32, c as u32, 1]);
        }
        let mut p = m;
        for h in 1..=3u64 {
            p -= p / 10;
            g.apply(hgt(h));
            for o in ORACLES {
                g.apply([8 | (o << 8), 0, p as u32, (p >> 32) as u32, 0, 0, 0, 1]);
            }
        }
        g.apply([7 | (4 << 8), 11, 0, 0, 0, 0, 0, 1]);
        vec![(g.ops.len() - 1, EV_APPLIED | 1)]
    });
    format!("{{\"ok\":{},\"cases\":{{{}}}}}", all, res.join(","))
}
fn reason_code_of(r: mnpilot::engine::RejectReason) -> u32 {
    mnpilot::reason_code(&r)
}

/// Loop round 5 (R4-M4): height binding. A liqfuzz batch without its SetHeight fixtures is cut
/// into random segments, each run with a run number (= rollup height) that advances by 1 or
/// jumps (heights the session did not run a batch in: exports, imports, or simply long gaps;
/// up to 20 000 to cross REPLAY_WINDOW and the feed staleness) on a height-binding session; the
/// real engine runs the whole batch with the batch-commit hook (height = run number, prune)
/// before each segment's first unit. Per-unit roots, events, segment-end state hashes (which
/// include the height and the withdrawal ledger) must be equal, and the session's segs / height
/// must equal the run number. Also: SetHeight in a binding session is refused (event 2).
pub fn hbind(n: u64, ops: u32) -> String {
    let (mut ok, mut segs_total, mut jumps, mut empties) = (0u64, 0u64, 0u64, 0u64);
    let mut why = String::new();
    for seed in 1..=n {
        // odd seeds: oracle batches (unstake + height jumps -> the hook releases bonds into PERP = acct: leaves)
        let w0 = if seed % 2 == 0 { liq_batch(seed, ops) } else { oracle_batch(seed, ops) };
        let (n_acc, n0) = (w0[1] as usize, w0[2] as usize);
        let base = 4 + 8 * n_acc;
        let mut w: Vec<u32> = w0[..base].to_vec();
        let mut kept = 0u32;
        for i in 0..n0 {
            let o = &w0[base + 8 * i..base + 8 * i + 8];
            if o[0] & 0xff != 10 {
                w.extend_from_slice(o);
                kept += 1;
            }
        }
        w[2] = kept;
        let mut rng = Rng(seed.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1);
        let mut cuts: Vec<(usize, usize, u32)> = Vec::new();
        let (mut lo, mut rn) = (0usize, 0u32);
        while lo < kept as usize || cuts.is_empty() {
            // now and then an empty segment (a height whose batch carries no unit: the hook alone)
            let hi = if rng.below(8) == 0 && !cuts.is_empty() { lo } else { (lo + 1 + rng.below(80) as usize).min(kept as usize) };
            let gap = match rng.below(6) { 0 => rng.below(3000) as u32, 1 if rng.below(3) == 0 => 10_000 + rng.below(10_000) as u32, _ => 0 };
            if gap > 0 {
                jumps += 1;
            }
            rn += 1 + gap;
            cuts.push((lo, hi, rn));
            lo = hi;
        }
        let mut rroots = Vec::new();
        let mut rhash = Vec::new();
        let pre = |i: usize| cuts.iter().find(|c| c.0 == i && c.1 > c.0).map(|c| c.2 as u64);
        let (rout, _) = run_real_eng_h(&w, &pre, &mut |e| {
            rroots.push(smt_ref::root(&real_pilot_leaves(e)));
            rhash.push(real_hash(&e.state));
        });
        let mut sess: Option<mnpilot::Session> = None;
        let mut ev_all = Vec::new();
        let mut good = true;
        let mut fail = |c: bool, what: String, good: &mut bool| {
            if !c && *good {
                *good = false;
                if why.is_empty() {
                    why = format!("seed {}: {}", seed, what);
                }
            }
        };
        for (k, &(lo, hi, rn)) in cuts.iter().enumerate() {
            let mut sw = vec![mnpilot::MAGIC, n_acc as u32, (hi - lo) as u32, if k == 0 { w[3] } else { 0 }];
            sw.extend_from_slice(&w[4..base]);
            sw.extend_from_slice(&w[base + 8 * lo..base + 8 * hi]);
            let mut roots = Vec::new();
            let (h, st, wo) = mnpilot::run_segment_n(
                &mut |i| sw.get(i as usize).copied().unwrap_or(0),
                &mut |x| ev_all.push(x),
                &mut |_, s, r| {
                    assert!(s.oi_ok());
                    roots.push(*r)
                },
                mnpilot::WitMode::Incremental,
                &mut sess,
                mnpilot::SegOpt { run_no: Some(rn), bind: true },
            );
            let s = sess.as_ref().unwrap();
            fail(st.status == 0 && roots.as_slice() == &rroots[lo..hi], format!("segment {} roots / status {}", k, st.status), &mut good);
            if hi > lo {
                fail(h == rhash[hi - 1], format!("segment {} state hash", k), &mut good);
                fail(s.eng.state.height == rn as u64, format!("segment {} height {} != run {}", k, s.eng.state.height, rn), &mut good);
            }
            fail(s.segs == rn, format!("segment {} segs", k), &mut good);
            // R5-L4: the segment end root commits the whole state incl. the hook's effects (empty segments too)
            fail(wo.root == smt_ref::root(&mnpilot::wit::all_leaves(&s.eng.state)), format!("segment {} end root != scratch root (empty {})", k, hi == lo), &mut good);
            empties += (hi == lo) as u64;
        }
        fail(ev_all == rout.ev, "events".into(), &mut good);
        // SetHeight under binding: refused, nothing changes
        let h0 = sess.as_ref().unwrap().eng.state.height;
        let sh = [mnpilot::MAGIC, n_acc as u32, 1, 0];
        let mut sw = sh.to_vec();
        sw.extend_from_slice(&w[4..base]);
        sw.extend_from_slice(&[10, (h0 + 5) as u32, ((h0 + 5) >> 32) as u32, 0, 0, 0, 0, 0]);
        let mut ev = Vec::new();
        let _ = mnpilot::run_segment_n(&mut |i| sw.get(i as usize).copied().unwrap_or(0), &mut |x| ev.push(x), &mut |_, _, _| {}, mnpilot::WitMode::Incremental, &mut sess, mnpilot::SegOpt { run_no: Some(rn + 1), bind: true });
        let s = sess.as_ref().unwrap();
        fail(ev == [2] && s.eng.state.height == rn as u64 + 1, format!("SetHeight under binding: ev {:?} height {}", ev, s.eng.state.height), &mut good);
        segs_total += cuts.len() as u64;
        if good {
            ok += 1;
        }
    }
    format!("{{\"seeds\":{},\"ok\":{},\"segments\":{},\"empty_segments\":{},\"height_jumps\":{},\"why\":\"{}\"}}", n, ok, segs_total, empties, jumps, why)
}

/// Loop round 5 (R4-M3): oracle stake / unstake / slash batches. Accounts 1..=3 bonded (fixture),
/// 4..=9 hold 2 x ORACLE_BOND_PERP PERP (fixture bit 27), 10.. traders / challengers. One of 4..=9
/// is the "deviant": once staked it reports 6-20 % off the honest price at consecutive heights, so
/// slash streaks form; heights advance by SetHeight (+1, sometimes +300 to finish unbondings).
pub fn oracle_batch(seed: u64, n_ops: u32) -> Vec<u32> {
    let mut rng = Rng(seed.wrapping_mul(0x9FB2_1C65_1E98_DF25) | 1);
    let n_acc = 14 + rng.below(6) as u32;
    let flags = mnpilot::ORACLES_FLAG | mnpilot::PERP_FLAG | mnpilot::FUNDING_MKT_FLAG;
    let (ids_real, mut g) = adv::new_gen(n_acc, flags);
    for a in 0..n_acc {
        let amt = 50_000 * USD_SCALE as i64;
        g.apply([1 | (a << 8), amt as u32, (amt >> 32) as u32, 0, 0, 0, 0, 0]);
    }
    let deviant = 4 + rng.below(6) as u32;
    let mut mark = MID;
    let mut height = 0u64;
    for o in ORACLES {
        g.apply(w8(8, o, 0, mark, 0, 0, 0, 1));
    }
    for _ in 0..n_ops {
        let r = rng.below(100);
        let any = rng.below(n_acc as u64) as u32;
        let staker = 4 + rng.below(6) as u32;
        match r {
            0..=9 => {
                g.apply([11 | ((if rng.below(5) == 0 { any } else { staker }) << 8), 0, 0, 0, 0, 0, 0, 0]);
            }
            10..=13 => {
                let a = if rng.below(3) == 0 { any } else if rng.below(2) == 0 { staker } else { ORACLES[rng.below(3) as usize] };
                g.apply([12 | (a << 8), 0, 0, 0, 0, 0, 0, 0]);
            }
            14..=55 => {
                // a round of reports at this height: honest oracles + bonded stakers, the deviant off
                mark += (rng.below(41) as i64 - 20) * mark / 2000;
                mark = mark.max(10_000 * DOLLAR);
                let mut who: Vec<u32> = ORACLES.to_vec();
                who.extend((4..10).filter(|a| rng.below(2) == 0 || *a == deviant));
                for o in who {
                    let px = if o == deviant {
                        let d = mark * (6 + rng.below(15) as i64) / 100;
                        if rng.below(2) == 0 { mark + d } else { mark - d }
                    } else {
                        mark + (rng.below(21) as i64 - 10) * mark / 10_000
                    };
                    let mkt = if rng.below(12) == 0 { mnpilot::FUNDING_MKT.0 } else { 1 };
                    let px = if mkt == 1 { px } else { mnpilot::types::encode_funding_price(100 + rng.below(40) as i64) };
                    g.apply(w8(8, o, 0, px, 0, 0, 0, mkt));
                }
                height += 1;
                g.apply([10, height as u32, (height >> 32) as u32, 0, 0, 0, 0, 0]);
            }
            56..=63 => {
                height += if rng.below(4) == 0 { 300 } else { 1 + rng.below(3) };
                g.apply([10, height as u32, (height >> 32) as u32, 0, 0, 0, 0, 0]);
            }
            64..=89 => {
                // slash: mostly the deviant, sometimes an honest oracle / a non-bonded id; any challenger
                // (incl. a fresh id: the reward creates its PERP-only acct: leaf)
                let target = match rng.below(6) { 0 => ORACLES[rng.below(3) as usize], 1 => any, _ => deviant };
                let ch = if rng.below(4) == 0 { n_acc - 1 - rng.below(3) as u32 } else { any };
                let mkt = if rng.below(10) == 0 { 2 } else { 1 };
                g.apply([13 | (ch << 8), target, 0, 0, 0, 0, 0, mkt]);
            }
            _ => {
                // a trade now and then (positions keep the acct leaves busy)
                let t = 10 + rng.below((n_acc - 10) as u64) as u32;
                let c = g.next_cseq(t);
                let bid = rng.below(2) == 0;
                let px = if bid { mark + mark / 100 } else { mark - mark / 100 };
                let mk = 4 + rng.below(6) as u32;
                let cm = g.next_cseq(mk);
                g.apply([2 | (mk << 8), bid as u32, px as u32, (px >> 32) as u32, (QTY_SCALE / 100) as u32, 0, cm as u32, 1]);
                g.apply([2 | (t << 8), !bid as u32, px as u32, (px >> 32) as u32, (QTY_SCALE / 100) as u32, 0, c as u32, 1]);
            }
        }
    }
    adv::batch_words(&ids_real, &g.ops, flags)
}

/// real vs port on oracle_batch: hash, events, per-unit MNWIT1 roots (real scratch / port
/// incremental / port scratch); plus a snapshot round trip of the final session (new v2 fields)
pub fn orafuzz(n: u64, ops: u32) -> String {
    let (mut ok, mut units) = (0u64, 0u64);
    let mut cov: std::collections::BTreeMap<String, u64> = Default::default();
    for s in 1..=n {
        let w = oracle_batch(s, ops);
        let mut a = Vec::new();
        let (r, _) = run_real_eng_cb(&w, &mut |e| a.push(smt_ref::root(&real_pilot_leaves(e))));
        let p = run_port(&w);
        let (b, c, wo) = port_roots(&w);
        let same = r.hash == p.hash && r.ev == p.ev && r.applied == p.applied;
        let roots = a == b && b == c && wo.scratch_ok && a.len() == w[2] as usize;
        // snapshot round trip
        let mut sess: Option<mnpilot::Session> = None;
        let _ = mnpilot::run_segment(&mut |i| w.get(i as usize).copied().unwrap_or(0), &mut |_| {}, &mut |_, _, _| {}, mnpilot::WitMode::Incremental, &mut sess);
        let (d, words) = snap::export_words(sess.as_ref().unwrap());
        let mut imp: Option<mnpilot::Session> = None;
        let io = mnpilot::run_import(&mut |i| words.get(i as usize).copied().unwrap_or(0), &mut imp, Some(&(d, words.len() as u32)));
        let er = sess.as_mut().unwrap().w.as_mut().map(|t| t.root());
        let snap_ok = io.status == 0 && er == Some(io.root) && imp.as_ref().map(|x| mnpilot::state_hash(&x.eng.state) == p.hash).unwrap_or(false);
        if same && roots && snap_ok {
            ok += 1;
        } else {
            let first_ev = r.ev.iter().zip(&p.ev).position(|(x, y)| x != y);
            let first_root = a.iter().zip(&b).zip(&c).position(|((x, y), z)| x != y || y != z);
            println!("ORAMISMATCH seed {} engine {} roots {} snap {} first_ev {:?} first_root {:?}", s, same, roots, snap_ok, first_ev, first_root);
        }
        units += a.len() as u64;
        let o = outcomes(&w, &p.ev);
        let base = 4 + 8 * w[1] as usize;
        for (i, e) in o.iter().enumerate() {
            let k = w[base + 8 * i] & 0xff;
            let name = match k { 11 => "stake", 12 => "unstake", 13 => "slash", 8 => "report", 10 => "height", _ => continue };
            let res = if *e == mnpilot::EV_HEIGHT { "set".to_string() } else if e & EV_APPLIED != 0 { "ok".to_string() } else { format!("{:#x}", e) };
            *cov.entry(format!("{}:{}", name, res)).or_default() += 1;
        }
    }
    let cs: Vec<String> = cov.iter().map(|(k, v)| format!("\"{}\":{}", k, v)).collect();
    format!("{{\"seeds\":{},\"match\":{},\"units\":{},\"coverage\":{{{}}}}}", n, ok, units, cs.join(","))
}
