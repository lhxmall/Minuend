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
    for s in 1..=n {
        let w = liq_batch(s, ops);
        let mut a = Vec::new();
        let (r, eng) = run_real_eng_cb(&w, &mut |e| a.push(smt_ref::root(&real_pilot_leaves(e))));
        let p = run_port(&w);
        let (b, c, wo) = port_roots(&w);
        let same = r.hash == p.hash && r.ev == p.ev && r.applied == p.applied;
        let roots = a == b && b == c && wo.scratch_ok && a.len() == w[2] as usize;
        if same && roots {
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
    format!("{{\"seeds\":{},\"match\":{},\"units\":{},\"funding_clock_armed_batches\":{},\"coverage\":{{{}}}}}", n, ok, units, paid, cs.join(","))
}
