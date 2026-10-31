//! Minuend engine pilot port (no_std + alloc) for the riscv32im dispute guest.
//!
//! Faithful subset of fix/47-all @ 20326c0: minuend-book (OrderBook, verbatim except
//! HashMap->BTreeMap), minuend-account (verbatim), minuend-state (ChainState subset,
//! `apply_fill_pair[_journaled]`, journal/rollback verbatim) and minuend-exec
//! (`Engine::place`, `cancel` verbatim; `deposit` simplified). See ../README.md.
//!
//! Batch format (u32 words, read through `rd(i)`, i.e. ecall a7=63 in the guest):
//!   [0] MAGIC  [1] n_accounts  [2] n_ops  [3] flags
//!   n_accounts x 8 words: 32-byte AccountId (little-endian words)
//!   n_ops x 8 words:
//!     w0 = kind | acct_idx << 8          kind 1 Deposit, 2 Place, 3 Cancel, 4/5 isolated Place
//!     Deposit: w1,w2 = amount (i64 lo,hi, USD_SCALE units)
//!     Place:   w1 = side | typ<<1 | tif<<2 (other bits ignored; isolated = kind 4/5);
//!              w2,w3 = price i64; w4,w5 = qty u64;
//!              w6 = client_seq; w7 = market id
//!     Place4:  as Place but isolated, market = BTC_USD (1), w7 = margin in whole USD
//!     Place5:  as Place4 but w7 = margin in USD_SCALE units (<= 4294.967295 USD)
//!   header [3]: bits 0..23 = legacywit skip (units before it get no legacy root), bit 24 = also list
//!     market 2 (genesis params, mark 100 000 USD; upstream test fixtures insert markets the same way)
//!     Cancel:  w6 = client_seq of the account's own order to cancel; w7 = market id
//!              (order id = order_id(account, market, client_seq), computed in the guest)
//!   loop round 4 (upstream ops ported with their engine paths):
//!     6 Withdraw:      w1,w2 = amount (i64); w6,w7 = nonce (u64 lo,hi)
//!     7 Liquidate:     author = keeper (caller); w1 = target account index (LIQ_TARGET_INSURANCE =
//!                      the insurance account); w7 = market. The liquidation order id
//!                      `liq_order_id(unit id)` needs the unit's hash, which the pilot batch does not
//!                      carry: the port uses unit id 0 and the event log writes LIQ_TAKER_EV for the
//!                      taker id of kind-2/3 fills on both sides (production: the unit id is part of
//!                      the unit input)
//!     8 ReportPrice:   author = oracle; w2,w3 = price; w7 = market
//!     9 ExternalPrice: author = source; w2,w3 = price; w6 = source_id (low byte); w7 = market
//!    10 SetHeight:     the batch-commit hook (minuend-settle: height = prev + 1, prune_withdrawals):
//!                      w1,w2 = new batch height; test builds without height binding: any height >=
//!                      current (fixtures); refused (event 2) with binding, i.e. always in `prod`
//!                      (round 5, R4-M4: the hook runs at segment start with the rollup height).
//!                      Emits EV_HEIGHT, is neither applied nor rejected (no seq), but is a unit for
//!                      the per-unit roots
//!   loop round 5 (R4-M3 port): 11 StakeOracle (author), 12 UnstakeOracle (author), 13 SlashOracle
//!                      (author = challenger; w1 = target account index; w7 = market). Header bit 27
//!                      (fixture, non-prod): accounts 4..=9 of the table hold 2 x ORACLE_BOND_PERP PERP
//!                      (upstream: a GovDeposit; not ported) and perp_supply counts it.
//!   header [3] loop round 4 fixtures: bit 25 = list market 3 as a funding-rate market (the 100x
//!     listing of upstream's funding tests; account 0 of the table is its external feed), bit 26 =
//!     accounts 1..=3 of the table are bonded oracles (oracle_bonds = ORACLE_BOND_PERP)
//!   loop round 6 (R4-M3 rest): 14 GovDeposit (w1,w2 = amount u64), 15 GovWithdraw (w1,w2 = amount u64; w6,w7 =
//!                      nonce), 16 CreateMarket (w7 = extension offset: 23 words = symbol 4, tick i64, im, mm, fee,
//!                      keeper u64, flags (bit0 spot_only, bit1 funding_rate), usd_per_unit u64, funding_cap u64,
//!                      min_price i64, max_price i64), 17 CreateProposal (w1 = market, w2 = key u8, w3,w4 = value),
//!                      18 Vote (w1,w2 = proposal id, w3 bit0 = approve), 19 FinalizeProposal (w1,w2 = id),
//!                      20 Commit (w1,w2 = ttl height; w7 = extension offset: 8 words commit hash), 21 Reveal (w7 =
//!                      extension offset: 40 words = commit_ref 8, salt 8, inner op 8 (pilot op words; an inner
//!                      CreateMarket names its own offset), parent P1 8, parent P2 8), 22 SetSeq (test fixture:
//!                      w1,w2 = new seq >= current; refused in prod; event EV_SEQ).
//!   MNP2 extension area (round 6): after the unit-id table, word n_ext (<= MAX_EXT) then n_ext words. MNP1 has none
//!   (ops needing it are refused BadAccount). An offset whose payload is not inside the area -> BadAccount.
//! Each op is one unit: seq advances only when it applies (upstream `apply_one`).
//!
//! Loop round 5 (R4-M2): batch format v2, MAGIC2 "MNP2": identical to MNP1, followed by a unit-id
//!   table of n_ops x 8 words (the 32-byte upstream unit id of op i, little-endian words, at
//!   4 + 8*n_accounts + 8*n_ops + 8*i). The unit id is a unit INPUT (like the op words): it feeds
//!   `liq_order_id(unit id)`, so a liquidation fill's taker id is the real one and the event log
//!   is no longer masked. MNP1 keeps unit id 0 + LIQ_TAKER_EV (test fixtures); in `prod` an MNP1
//!   Liquidate is refused (BadAccount): a production liquidation always names its unit.
//! Loop round 5 (R4-M4): engine height = rollup height. The guest counts its runs in memory (main.rs
//!   RUNS: the rollup carries the final memory of h-1 into s0 of h, so the n-th run of an image
//!   lineage IS rollup height n; an upgrade image takes the count from the imported snapshot's
//!   `segs`, which the export at h-1 wrote) and keeps `Session::segs` equal to it. With
//!   `Session::bind_height` (always in `prod`) every batch run first runs the batch-commit hook
//!   with height = segs (> previous height: export / import heights are skipped), so units of
//!   rollup height h see engine height h, and SetHeight (kind 10) is refused (event 2): the operator
//!   no longer decides the engine clock. OUT[0x1FFE6] = engine height (low word); rv_witbind binds
//!   OUT[0x1FFE7] (segs) == h with the segment end root.
//!
//! Segments (loop round 3): an upstream batch (<= 200 000 units) is cut into guest runs of
//! <= MAX_UNITS units. One guest run = one segment = one rollup height. The guest keeps its
//! engine state in memory between runs (`Session`, see main.rs: the rollup carries the final
//! memory of height h-1 into s0 of height h), so segment k starts exactly where k-1 ended. A run
//! starts from genesis only when no session exists yet (first height). Segment boundary
//! commitment: the MNWIT1 root BEFORE the segment's first unit (`WitOut::start_root`, guest
//! OUT[0x1FFF0..8]) and AFTER its last unit (`WitOut::root`, guest OUT[0x1FFE8..8]); segment
//! k's start root == segment k-1's end root (the rollup chains them, design §7.6).
//! Header flags (word 3): test fixtures only (bit 24 market 2 at genesis, bits 0-23 legacywit
//! skip). Feature `prod` (the rollup's committed image) requires flags == 0, else status
//! ST_BAD_FLAGS; a resumed session always requires flags == 0 (genesis flags cannot apply).
//!
//! Input validation (loop round 1, findings/rv-loop-1.md G1/G2): the header is checked BEFORE any
//! op runs; a batch with a bad magic, `n_accounts > MAX_ACCOUNTS` or `n_ops > MAX_UNITS` runs no op
//! and returns status != 0 with a zero state hash (host and guest share this code, so both agree).
//! Within the limits every input index is < 4 + 8*(MAX_ACCOUNTS + MAX_UNITS) < 2^24, so no read can
//! wrap or reach the input ecall's trap range; words past the end of a truncated batch read as 0
//! (input-tree semantics), which decodes as kind 0 = BadAccount. An op whose account index is out of
//! range, or whose account id is the INSURANCE_ACCOUNT (all-zero id; no ed25519 key hashes to it,
//! so the real engine can never see such an author), is rejected BadAccount.
#![no_std]
extern crate alloc;

pub mod account;
pub mod book;
pub mod book_types;
pub mod engine;
pub mod snapshot;
pub mod state;
pub mod types;
pub mod wit;

pub use book_types::*;

use alloc::vec::Vec;
use engine::{Engine, RejectReason};
use sha2::Digest;
use types::*;

pub const MAGIC: u32 = 0x4D4E_5031; // "MNP1"
/// loop round 5 (R4-M2): MNP1 + a per-op unit-id table after the ops
pub const MAGIC2: u32 = 0x4D4E_5032; // "MNP2"

/// Event code per op (shared numbering with the host harness).
pub fn reason_code(r: &RejectReason) -> u32 {
    match r {
        RejectReason::BadSig => 1,
        RejectReason::BadAccount => 2,
        RejectReason::DuplicateClientSeq => 3,
        RejectReason::DuplicateDeposit => 4,
        RejectReason::UnbackedDeposit => 5,
        RejectReason::DuplicateNonce => 6,
        RejectReason::Risk => 7,
        RejectReason::Book(e) => 0x100 + book_code(e),
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
pub fn book_code(e: &BookError) -> u32 {
    match e {
        BookError::NotFound => 1,
        BookError::ZeroQty => 2,
        BookError::ZeroPrice => 3,
        BookError::DuplicateOrder => 4,
        BookError::WrongMarket => 5,
        BookError::SelfTrade => 6,
        BookError::MultiFill => 7,
    }
}
pub const EV_APPLIED: u32 = 0x8000_0000;
pub const MARKET2_FLAG: u32 = 1 << 24;
/// loop round 4 fixtures (header word 3, non-prod): funding-rate market 3 / bonded oracles
pub const FUNDING_MKT_FLAG: u32 = 1 << 25;
pub const ORACLES_FLAG: u32 = 1 << 26;
/// loop round 5 fixture: accounts 4..=9 hold PERP (stake / slash tests)
pub const PERP_FLAG: u32 = 1 << 27;
pub const PERP_FIXTURE: u128 = 2 * ORACLE_BOND_PERP;
pub const FUNDING_MKT: MarketId = MarketId(3);
/// Liquidate op: target index meaning the insurance account
pub const LIQ_TARGET_INSURANCE: u32 = 0xFF_FFFF;
/// event word standing in for the taker id of a liquidation fill (kind 2 / 3)
pub const LIQ_TAKER_EV: u32 = 0x4C49_5121;
/// event of a SetHeight fixture op
pub const EV_HEIGHT: u32 = 0x4000_0000;
/// event of a SetSeq fixture op (loop round 6)
pub const EV_SEQ: u32 = 0x4000_0001;

/// Max units (ops) per guest batch: the per-unit root region OUT+0x20000.. (8 words per unit)
/// ends exactly at the top of the 2^24-word RAM (0x0400_0000), and the event log
/// (<= 7 words per unit: a unit carries at most one fill) fits below the counters at OUT+0x1FFF0.
pub const MAX_UNITS: u32 = 16_384;
/// Max entries of the batch's account table.
pub const MAX_ACCOUNTS: u32 = 4_096;
/// Event-log word capacity in the guest's OUT area (words 13 .. 0x1FFE0; 0x1FFE0.. holds the
/// segment words and counters, loop round 3).
pub const EV_CAP: u32 = 0x1FFD6 - 13;
/// Batch status (OUT[0x1FFF9] in the guest; `Stats::status` on the host).
pub const ST_OK: u32 = 0;
pub const ST_BAD_MAGIC: u32 = 1;
pub const ST_TOO_MANY_ACCOUNTS: u32 = 2;
pub const ST_TOO_MANY_UNITS: u32 = 3;
/// header word 3 != 0 where it must be 0 (feature `prod`, or any resumed session)
pub const ST_BAD_FLAGS: u32 = 4;
/// a previous run of this session aborted (panic / out of memory): its state may be torn
/// mid-unit, so every later run refuses to execute (guest only; main.rs)
pub const ST_DEAD: u32 = 5;
/// loop round 4 (snapshot.rs): EXPORT run without a session
pub const ST_NO_SESSION: u32 = 6;
/// IMPORT input malformed / non-canonical (no session is created; a dead image stays dead)
pub const ST_BAD_SNAP: u32 = 7;
/// IMPORT refused: the image already holds a live session (only a fresh or dead image imports)
pub const ST_SESSION_LIVE: u32 = 8;
/// EXPORT header words 1..3 must be 0
pub const ST_BAD_EXPORT: u32 = 9;
/// IMPORT refused: the image has no compiled-in expected digest (an ordinary image, e.g. the
/// genesis image). Loop round 4 review R4-S1.
pub const ST_IMPORT_LOCKED: u32 = 10;
/// batch refused: an upgrade image (one with an expected import digest) must import before it
/// runs units -- else its first batch would start a fresh genesis session (R4-S2)
pub const ST_NEED_IMPORT: u32 = 11;
/// input words an import may read (the input tree's index range below the ecall trap range)
pub const SNAP_LIMIT: u32 = (1 << 24) - 1;

/// Event code of a unit rejected by the session account cap (loop round 4, `state_cap_ok`).
pub const STATE_CAP_CODE: u32 = 19;
/// Loop round 4 (long-run heap bound): the session lives in guest memory across heights and
/// accounts are never deleted, so the heap needs a consensus bound on the state. Everything else
/// is bounded per account (<= MAX_LIVE_ORDERS_PER_ACCOUNT live orders, <= 64 withdrawals, one
/// position per market, one seen client_seq) or globally constant (markets, bonded oracles,
/// rings), so capping the number of accounts bounds the heap. Measured (engine-diff statecap,
/// 64-bit host sizes = upper bound of rv32): <= 1.3 KB per bare account, ~170 B per withdrawal,
/// ~1 KB per live order incl. book indexes and MNWIT1 nodes -> <= ~80 KB per fully loaded account;
/// MAX_STATE_ACCOUNTS fully loaded <= 20.5 MB, x1.3 fragmentation (round 2 A3) + 4.4 MB per-run
/// transient (limit batch) = 31.1 MB < the 50.2 MB heap (statecap 384 x 64 x 64 measured 23.1 MB
/// with 42 live orders per account). The cap is a STOPGAP that makes OOM
/// impossible; production needs a stateless guest (state as witness input) or a larger RAM, see
/// findings/rv-loop-4.md R4-H1.
pub const MAX_STATE_ACCOUNTS: usize = 256;
/// Loop round 6 review (governance + commit-reveal heap bounds, pilot consensus rules like the
/// account cap; STATE_CAP_CODE): live commits (R6-H1), zero-weight voters per proposal beyond its
/// weight snapshot (R6-H2), listed markets (R6-M1). The PERP ledger shares the account cap (R6-H3).
pub const MAX_STATE_COMMITS: usize = 1024;
pub const MAX_ZERO_VOTERS: usize = 64;
pub const MAX_STATE_MARKETS: usize = 256;
/// Units that can create an account for their author (deposit; liquidate: the keeper reward
/// credits the caller) are rejected (STATE_CAP_CODE) when the author is new and the session
/// already holds `cap` accounts (the insurance account included).
pub fn state_cap_ok(s: &state::ChainState, op: &BatchOp, author: AccountId, cap: usize) -> bool {
    // loop round 8 (R7-M2): the commit bond (see commit_bond_ok)
    if !commit_bond_ok(op, || s.perp_balances.get(&author).copied().unwrap_or(0), || s.commits.values().filter(|e| e.account == author).count()) {
        return false;
    }
    match op {
        BatchOp::Deposit { .. } | BatchOp::Liquidate { .. } => s.accounts.contains_key(&author) || s.accounts.len() < cap,
        // loop round 6 review R6-H3 (R5-L3 with GovDeposit ported): every unit that can add an id to
        // the PERP ledger (an acct: leaf without an accounts entry) -- a gov deposit, a gov withdraw
        // (amount 0 succeeds for ANY id and inserts a zero balance), a slash (the reward credits the
        // challenger) -- is refused for a new id once the ledger holds `cap` ids
        // loop round 7 review R7-M1: a GovWithdraw of 0 by an id WITHOUT a ledger entry succeeds upstream (it only
        // inserts a zero balance + a nonce watermark), so below the cap it filled the shared ledger for free: 256 such
        // units and every later GovDeposit / Slash by a new id was refused (code 19) -- new stakers locked out of
        // governance, new challengers unable to slash. It is now refused (code 19) at any ledger size; it has no
        // effect upstream besides the bloat (R6-L3). A GovWithdraw of 0 by an existing id is unchanged.
        BatchOp::GovWithdraw { amount: 0, .. } if !s.perp_balances.contains_key(&author) => false,
        BatchOp::GovDeposit { .. } | BatchOp::GovWithdraw { .. } | BatchOp::Slash { .. } => {
            s.perp_balances.contains_key(&author) || s.perp_balances.len() < cap
        }
        // R6-H1: commits are kept until their TTL passes (revealed ones too) and any id may commit
        // -> a global cap (also bounds upstream's O(commits) pending scan per Commit)
        BatchOp::Commit { .. } => s.commits.len() < MAX_STATE_COMMITS,
        // R6-H2: a voter outside the creation-time weight snapshot votes with weight 0 but is
        // recorded in `voted` (any fresh id) -> at most MAX_ZERO_VOTERS such voters per proposal
        // beyond the snapshot size; a snapshot voter (and a repeat voter, refused by the engine) passes
        BatchOp::Vote { id, .. } => match s.proposals.get(id) {
            Some(p) => p.weight_snapshot.contains_key(&author) || p.voted.contains(&author) || p.voted.len() < p.weight_snapshot.len() + MAX_ZERO_VOTERS,
            None => true,
        },
        // R6-M1: listings are bounded only by the burned fee upstream
        BatchOp::CreateMarket { .. } => s.markets.len() < MAX_STATE_MARKETS,
        _ => true,
    }
}

/// Loop round 8 review R7-M2 (PILOT consensus rule, refusal code STATE_CAP_CODE like the caps; NOT upstream
/// semantics -- upstream @ 20326c0 has no commit deposit): every live commit (revealed or not, until it is pruned at
/// its TTL) reserves COMMIT_BOND_PERP of its author's PERP balance. A Commit needs
/// `balance >= (live + 1) * COMMIT_BOND_PERP`; a unit that debits its author's PERP (GovWithdraw amount, CreateMarket
/// fee, oracle Stake bond) is refused when the debit is covered by the balance but would leave less than
/// `live * COMMIT_BOND_PERP` (a debit larger than the balance keeps upstream's Insufficient). Nothing is moved: the
/// reservation is a predicate over (balance, live commits), so state, snapshot and MNWIT1 are unchanged and the bond
/// is "refunded" when the commit is pruned. Filling MAX_STATE_COMMITS now ties up
/// MAX_STATE_COMMITS * COMMIT_BOND_PERP PERP for up to COMMIT_TTL_HEIGHTS heights instead of costing only unit fees
/// (fresh ids no longer help: an id needs a PERP ledger entry, itself under the shared account cap).
/// Applies to a Reveal's inner op too (state_cap_ok runs on it). `balance` / `live` (the author's PERP balance and
/// live commits) are evaluated only for the four affected kinds: `live` is an O(commits) <= MAX_STATE_COMMITS scan,
/// the same bound as upstream's per-Commit pending scan.
pub const COMMIT_BOND_PERP: u128 = 1_000;
pub fn commit_bond_ok(op: &BatchOp, balance: impl FnOnce() -> u128, live: impl FnOnce() -> usize) -> bool {
    let debit = match *op {
        BatchOp::Commit { .. } => None,
        BatchOp::GovWithdraw { amount, .. } => Some(amount as u128),
        BatchOp::CreateMarket { .. } => Some(types::CREATE_MARKET_FEE_PERP),
        BatchOp::Stake { .. } => Some(types::ORACLE_BOND_PERP),
        _ => return true,
    };
    let (balance, reserved) = (balance(), live() as u128 * COMMIT_BOND_PERP);
    match debit {
        None => balance >= reserved + COMMIT_BOND_PERP,
        Some(d) => reserved == 0 || d > balance || balance - d >= reserved,
    }
}

/// Event code of a unit rejected by the MNWIT1 depth rule (wit::MAX_WIT_DEPTH, loop round 2 W2);
/// outside the engine's RejectReason codes (1..17, 0x100+).
pub const WIT_DEPTH_CODE: u32 = 18;

/// MNWIT1 depth rule (W2): every key this op could newly create *for its own author* -- the
/// author's `acct:` key if the account does not exist yet (deposit / place), the order's `ord:` key
/// and the author's `pos:` key in the order's market if it has no position there (place) -- must
/// land at depth <= MAX_WIT_DEPTH. Checked against the tree BEFORE the op runs, independent of
/// whether the order then rests or fills (a deterministic, cheap pre-check; no rollback needed).
/// Side-effect insertions (the maker's first `pos:` at a fill) are not checked: making one deep
/// needs a targeted 2^MAX_WIT_DEPTH prefix grind, see wit::MAX_WIT_DEPTH.
pub fn wit_depth_ok(w: &wit::Wit, s: &state::ChainState, op: &BatchOp, author: AccountId) -> bool {
    let ok = |k: &wit::H| w.smt.insert_depth(k).map(|d| d <= wit::MAX_WIT_DEPTH).unwrap_or(true);
    let new_acct = !s.accounts.contains_key(&author);
    match *op {
        BatchOp::Deposit { .. } => !new_acct || ok(&wit::acct_key(&author)),
        // loop round 4: a keeper reward credits the caller (`account_mut(caller)`): its acct: key
        // can be created by the unit -> checked like a deposit's
        BatchOp::Liquidate { .. } => !new_acct || ok(&wit::acct_key(&author)),
        // loop round 5: a slash reward credits the challenger's PERP -> its acct: key may be created
        BatchOp::Slash { .. } => !new_acct || s.perp_balances.contains_key(&author) || s.withdrawn_total.contains_key(&author) || ok(&wit::acct_key(&author)),
        // loop round 6: a gov deposit may create the author's acct: key; a listing creates band: + meta:
        BatchOp::GovDeposit { .. } => !new_acct || s.perp_balances.contains_key(&author) || s.withdrawn_total.contains_key(&author) || ok(&wit::acct_key(&author)),
        BatchOp::CreateMarket { .. } => wit::market_keys(MarketId(s.next_market_id)).iter().all(|k| ok(k)),
        BatchOp::Place { market, client_seq, .. } => {
            let m = MarketId(market);
            let has_pos = s.accounts.get(&author).map(|a| a.positions.contains_key(&m)).unwrap_or(false);
            (!new_acct || ok(&wit::acct_key(&author)))
                && ok(&wit::ord_key(&order_id(author, m, client_seq)))
                && (has_pos || ok(&wit::pos_key(&author, m)))
        }
        _ => true,
    }
}
const _: () = assert!(13 + 7 * MAX_UNITS <= 0x1FFD6);
const _: () = assert!(0x03F0_0000 / 4 + 0x20000 + 8 * MAX_UNITS <= 1 << 24);
const _: () = assert!(4 + 8 * (MAX_ACCOUNTS + MAX_UNITS) < 1 << 24);
// MNP2: the unit-id table after the ops stays below the input ecall's trap range too
const _: () = assert!(4 + 8 * (MAX_ACCOUNTS + 2 * MAX_UNITS) < 1 << 24);

/// Header check shared by host and guest. `resumed` = a session already exists (not genesis).
pub fn check_header_seg(rd: &mut dyn FnMut(u32) -> u32, resumed: bool) -> u32 {
    if rd(0) != MAGIC && rd(0) != MAGIC2 {
        ST_BAD_MAGIC
    } else if rd(1) > MAX_ACCOUNTS {
        ST_TOO_MANY_ACCOUNTS
    } else if rd(2) > MAX_UNITS {
        ST_TOO_MANY_UNITS
    } else if rd(3) != 0 && (resumed || cfg!(feature = "prod")) {
        ST_BAD_FLAGS
    } else {
        ST_OK
    }
}
pub fn check_header(rd: &mut dyn FnMut(u32) -> u32) -> u32 {
    check_header_seg(rd, false)
}

impl state::ChainState {
    /// Mirrors the parts of upstream `ChainState::new()` the pilot keeps, plus the
    /// test-fixture `allow_all` market seed (BTC_USD genesis params).
    /// genesis plus market 2 when `flags` bit 24 is set (batch header word 3)
    pub fn genesis_flags(flags: u32) -> Self {
        Self::genesis_fixture(flags, &[])
    }
    /// loop round 4: + the funding-rate market / oracle fixtures (bits 25 / 26), which name
    /// accounts of the batch's table
    pub fn genesis_fixture(flags: u32, accts: &[AccountId]) -> Self {
        let mut s = Self::genesis();
        if flags & MARKET2_FLAG != 0 {
            s.markets.insert(MarketId(2), genesis_params());
            s.marks.insert(MarketId(2), 100_000 * PRICE_SCALE as i64);
        }
        if flags & FUNDING_MKT_FLAG != 0 {
            s.markets.insert(FUNDING_MKT, funding_fixture_params());
            if let Some(a) = accts.first() {
                s.external_sources.insert(*a);
            }
        }
        if flags & ORACLES_FLAG != 0 {
            for a in accts.iter().skip(1).take(3) {
                s.oracle_bonds.insert(*a, ORACLE_BOND_PERP);
            }
        }
        if flags & PERP_FLAG != 0 {
            for a in accts.iter().skip(4).take(6) {
                if *a != INSURANCE_ACCOUNT {
                    s.set_perp(*a, PERP_FIXTURE);
                    s.perp_supply += PERP_FIXTURE;
                }
            }
        }
        s
    }
    pub fn genesis() -> Self {
        let mut s = Self::default();
        s.books.insert(BTC_USD, book::OrderBook::new(BTC_USD));
        s.marks.insert(BTC_USD, 100_000 * PRICE_SCALE as i64);
        let mut insurance = account::Account::new(INSURANCE_ACCOUNT);
        insurance.collateral = 10_000 * USD_SCALE as Usd; // INSURANCE_SEED
        s.put_account(INSURANCE_ACCOUNT, insurance);
        s.markets.insert(BTC_USD, genesis_params());
        // loop round 6: upstream ChainState::new cursors
        s.next_market_id = 2;
        s.next_proposal_id = 1;
        s
    }
}

/// Params of the funding-rate fixture market (upstream test `funding_rate_lists_at_100x`:
/// tick 1, im 100, mm 50, fee 5, keeper 10, funding_rate, usd_per_unit 10 000, cap 10 bps).
pub fn funding_fixture_params() -> MarketParams {
    let mut symbol = [0u8; 16];
    symbol[..6].copy_from_slice(b"HUNDRD");
    MarketParams {
        symbol,
        tick_size: 1,
        im_bps: 100,
        mm_bps: 50,
        taker_fee_bps: 5,
        keeper_reward_bps: 10,
        delisted: false,
        spot_only: false,
        funding_rate: true,
        usd_per_unit: 10_000,
        funding_cap_bps: 10,
        min_price: 0,
        max_price: 0,
    }
}

/// Copied from minuend-state/src/lib.rs `account_leaf` (perp / withdrawn passed in).
pub fn account_leaf(acct: &account::Account, perp: u128, withdrawn: i128) -> [u8; 32] {
    let mut b = Vec::new();
    b.extend_from_slice(b"acct");
    b.extend_from_slice(&acct.id.0);
    b.extend_from_slice(&acct.collateral.to_le_bytes());
    b.extend_from_slice(&acct.realized_pnl.to_le_bytes());
    b.extend_from_slice(&(acct.positions.len() as u32).to_le_bytes());
    for (m, p) in &acct.positions {
        b.extend_from_slice(&m.0.to_le_bytes());
        b.extend_from_slice(&p.qty.to_le_bytes());
        b.extend_from_slice(&p.entry_price.to_le_bytes());
    }
    b.extend_from_slice(&(acct.isolated_margin.len() as u32).to_le_bytes());
    for (m, margin) in &acct.isolated_margin {
        b.extend_from_slice(&m.0.to_le_bytes());
        b.extend_from_slice(&margin.to_le_bytes());
    }
    b.extend_from_slice(&perp.to_le_bytes());
    b.extend_from_slice(&withdrawn.to_le_bytes());
    sha256(&b)
}

/// Pilot state hash (the host harness computes the same bytes from the real ChainState):
/// sha256("MNPILOT1" || seq le8 || n_acc le4 || account_leaf(a,0,0)* || n_books le4 ||
///        (market le4 || sha256(book.commitment_bytes()))* || n_marks le4 ||
///        (market le4 || mark le8)* || n_seen le4 || (account 32 || client_seq le8)*)
pub fn state_hash(s: &state::ChainState) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    h.update(b"MNPILOT1");
    h.update(s.seq.to_le_bytes());
    h.update((s.accounts.len() as u32).to_le_bytes());
    for a in s.accounts.values() {
        h.update(account_leaf(a, s.perp_balances.get(&a.id).copied().unwrap_or(0), s.withdrawn_total.get(&a.id).copied().unwrap_or(0)));
    }
    h.update((s.books.len() as u32).to_le_bytes());
    for (m, b) in &s.books {
        h.update(m.0.to_le_bytes());
        h.update(sha256(&b.commitment_bytes()));
    }
    h.update((s.marks.len() as u32).to_le_bytes());
    for (m, p) in &s.marks {
        h.update(m.0.to_le_bytes());
        h.update(p.to_le_bytes());
    }
    h.update((s.seen_client_seq.len() as u32).to_le_bytes());
    for (a, c) in &s.seen_client_seq {
        h.update(a.0);
        h.update(c.to_le_bytes());
    }
    // loop round 4: oracle / funding / withdrawal state (the host computes the same bytes from
    // the real ChainState, engine-diff `real_hash`)
    h.update(b"MNPILOT2");
    h.update(s.height.to_le_bytes());
    h.update((s.withdrawals.len() as u32).to_le_bytes());
    for ((a, n), w) in &s.withdrawals {
        h.update(a.0);
        h.update(n.to_le_bytes());
        h.update(w.amount.to_le_bytes());
        h.update([w.pending as u8]);
        h.update(w.height.to_le_bytes());
    }
    h.update((s.oracle_reports.len() as u32).to_le_bytes());
    for ((m, a), p) in &s.oracle_reports {
        h.update(m.0.to_le_bytes());
        h.update(a.0);
        h.update(p.to_le_bytes());
    }
    for map in [&s.last_index, &s.funding_index_twap] {
        h.update((map.len() as u32).to_le_bytes());
        for (m, p) in map {
            h.update(m.0.to_le_bytes());
            h.update(p.to_le_bytes());
        }
    }
    h.update((s.last_funding_height.len() as u32).to_le_bytes());
    for (m, x) in &s.last_funding_height {
        h.update(m.0.to_le_bytes());
        h.update(x.to_le_bytes());
    }
    for map in [&s.oracle_twap, &s.funding_twap] {
        h.update((map.len() as u32).to_le_bytes());
        for (m, q) in map {
            h.update(m.0.to_le_bytes());
            h.update((q.len() as u32).to_le_bytes());
            for t in q {
                h.update(t.seq.to_le_bytes());
                h.update(t.height.to_le_bytes());
                h.update(t.median.to_le_bytes());
            }
        }
    }
    h.update((s.oracle_report_history.len() as u32).to_le_bytes());
    for ((m, a), q) in &s.oracle_report_history {
        h.update(m.0.to_le_bytes());
        h.update(a.0);
        h.update((q.len() as u32).to_le_bytes());
        for t in q {
            h.update(t.height.to_le_bytes());
            h.update(t.price.to_le_bytes());
            h.update(t.seq.to_le_bytes());
        }
    }
    // loop round 5 (R4-M3): PERP ledger + oracle bonds / unbonding / slash state (engine-diff real_hash: same bytes)
    h.update(b"MNPILOT3");
    h.update((s.perp_balances.len() as u32).to_le_bytes());
    for (a, v) in &s.perp_balances {
        h.update(a.0);
        h.update(v.to_le_bytes());
    }
    h.update(s.perp_supply.to_le_bytes());
    h.update(s.perp_burned.to_le_bytes());
    h.update(s.oracle_slash_nonce.to_le_bytes());
    h.update((s.oracle_bonds.len() as u32).to_le_bytes());
    for (a, v) in &s.oracle_bonds {
        h.update(a.0);
        h.update(v.to_le_bytes());
    }
    h.update((s.oracle_unbonding.len() as u32).to_le_bytes());
    for (a, v) in &s.oracle_unbonding {
        h.update(a.0);
        h.update(v.to_le_bytes());
    }
    h.update((s.external_price_ring.len() as u32).to_le_bytes());
    for (m, q) in &s.external_price_ring {
        h.update(m.0.to_le_bytes());
        h.update((q.len() as u32).to_le_bytes());
        for t in q {
            h.update(t.seq.to_le_bytes());
            h.update(t.height.to_le_bytes());
            h.update(t.price.to_le_bytes());
            h.update([t.source_id]);
        }
    }
    // loop round 6 (R4-M3 rest): markets, listing / governance / commit-reveal state (engine-diff
    // real_hash: same bytes)
    h.update(b"MNPILOT4");
    h.update((s.markets.len() as u32).to_le_bytes());
    for (m, p) in &s.markets {
        h.update(m.0.to_le_bytes());
        h.update(p.symbol);
        h.update(p.tick_size.to_le_bytes());
        for x in [p.im_bps, p.mm_bps, p.taker_fee_bps, p.keeper_reward_bps, p.usd_per_unit, p.funding_cap_bps] {
            h.update(x.to_le_bytes());
        }
        h.update([p.delisted as u8, p.spot_only as u8, p.funding_rate as u8]);
        h.update(p.min_price.to_le_bytes());
        h.update(p.max_price.to_le_bytes());
    }
    h.update(s.next_market_id.to_le_bytes());
    h.update((s.external_sources.len() as u32).to_le_bytes());
    for a in &s.external_sources {
        h.update(a.0);
    }
    h.update(s.next_proposal_id.to_le_bytes());
    h.update((s.proposals.len() as u32).to_le_bytes());
    for (id, p) in &s.proposals {
        h.update(id.to_le_bytes());
        h.update(p.creator.0);
        h.update(p.market.0.to_le_bytes());
        h.update([p.key.as_u8()]);
        h.update(p.value.to_le_bytes());
        h.update(p.created_seq.to_le_bytes());
        h.update(p.deadline_seq.to_le_bytes());
        h.update(p.supply_at_create.to_le_bytes());
        h.update(p.yes.to_le_bytes());
        h.update(p.no.to_le_bytes());
        h.update((p.voted.len() as u32).to_le_bytes());
        for a in &p.voted {
            h.update(a.0);
        }
        h.update((p.weight_snapshot.len() as u32).to_le_bytes());
        for (a, w) in &p.weight_snapshot {
            h.update(a.0);
            h.update(w.to_le_bytes());
        }
    }
    h.update((s.seen_gov_nonces.len() as u32).to_le_bytes());
    for (a, n) in &s.seen_gov_nonces {
        h.update(a.0);
        h.update(n.to_le_bytes());
    }
    h.update((s.commits.len() as u32).to_le_bytes());
    for (c, e) in &s.commits {
        h.update(c);
        h.update(e.account.0);
        h.update(e.commit_unit);
        h.update(e.commit_height.to_le_bytes());
        h.update(e.ttl_height.to_le_bytes());
        h.update([e.revealed as u8]);
    }
    h.finalize().into()
}

pub struct Stats {
    /// ST_* (0 = header accepted and every op ran)
    pub status: u32,
    pub applied: u32,
    pub rejected: u32,
    pub fills: u32,
}

/// Decoded op (host tools share this decoder with the guest).
#[derive(Clone, Copy, Debug)]
pub enum BatchOp {
    Deposit { acct: u32, amount: i64 },
    Place { acct: u32, side: Side, typ: OrderType, tif: TimeInForce, isolated: bool, price: i64, qty: u64, client_seq: u64, market: u32, margin: u64 },
    Cancel { acct: u32, client_seq: u64, market: u32 },
    Withdraw { acct: u32, amount: i64, nonce: u64 },
    Liquidate { acct: u32, target: u32, market: u32 },
    Report { acct: u32, price: i64, market: u32 },
    ExtPrice { acct: u32, price: i64, source_id: u8, market: u32 },
    SetHeight { height: u64 },
    Stake { acct: u32 },
    Unstake { acct: u32 },
    Slash { acct: u32, target: u32, market: u32 },
    /// loop round 6 (R4-M3 rest)
    GovDeposit { acct: u32, amount: u64 },
    GovWithdraw { acct: u32, amount: u64, nonce: u64 },
    CreateMarket { acct: u32, ext: u32 },
    CreateProposal { acct: u32, market: u32, key: u8, value: u64 },
    Vote { acct: u32, id: u64, approve: bool },
    Finalize { acct: u32, id: u64 },
    Commit { acct: u32, ttl: u64, ext: u32 },
    Reveal { acct: u32, ext: u32 },
    SetSeq { seq: u64 },
    Bad,
}
impl BatchOp {
    /// the op's signing account index (upstream `op_signer`); None for fixtures / Bad
    pub fn signer(&self) -> Option<u32> {
        match *self {
            BatchOp::Deposit { acct, .. }
            | BatchOp::Place { acct, .. }
            | BatchOp::Cancel { acct, .. }
            | BatchOp::Withdraw { acct, .. }
            | BatchOp::Liquidate { acct, .. }
            | BatchOp::Report { acct, .. }
            | BatchOp::ExtPrice { acct, .. }
            | BatchOp::Stake { acct }
            | BatchOp::Unstake { acct }
            | BatchOp::Slash { acct, .. }
            | BatchOp::GovDeposit { acct, .. }
            | BatchOp::GovWithdraw { acct, .. }
            | BatchOp::CreateMarket { acct, .. }
            | BatchOp::CreateProposal { acct, .. }
            | BatchOp::Vote { acct, .. }
            | BatchOp::Finalize { acct, .. }
            | BatchOp::Commit { acct, .. }
            | BatchOp::Reveal { acct, .. } => Some(acct),
            BatchOp::SetHeight { .. } | BatchOp::SetSeq { .. } | BatchOp::Bad => None,
        }
    }
}

/// loop round 6: MNP2 extension area (after the unit-id table: word n_ext, then n_ext words).
/// Ops whose payload does not fit 8 words (CreateMarket, Commit, Reveal) name an offset into it.
#[derive(Clone, Copy, Debug)]
pub struct Ext {
    pub base: u32,
    pub n: u32,
}
pub const MAX_EXT: u32 = 64 * MAX_UNITS;
pub const EXT_MARKET_LEN: u32 = 23;
pub const EXT_COMMIT_LEN: u32 = 8;
pub const EXT_REVEAL_LEN: u32 = 40;
const _: () = assert!(4 + 8 * (MAX_ACCOUNTS + 2 * MAX_UNITS) + 1 + MAX_EXT < 1 << 24);
impl Ext {
    pub const NONE: Ext = Ext { base: 0, n: 0 };
    /// words [off, off+len) of the area, None when outside it (or no area: MNP1)
    pub fn read(&self, rd: &mut dyn FnMut(u32) -> u32, off: u32, len: u32) -> Option<Vec<u32>> {
        if self.n > MAX_EXT || off.checked_add(len)? > self.n {
            return None;
        }
        Some((0..len).map(|k| rd(self.base + 1 + off + k)).collect())
    }
}
fn lo64(a: u32, b: u32) -> u64 {
    (a as u64) | ((b as u64) << 32)
}
fn id32(w: &[u32]) -> [u8; 32] {
    let mut id = [0u8; 32];
    for k in 0..8 {
        id[k * 4..k * 4 + 4].copy_from_slice(&w[k].to_le_bytes());
    }
    id
}
/// CreateMarket listing from its 23 ext words (see the format at the top)
pub fn listing_of(e: &[u32]) -> types::MarketParams {
    let mut symbol = [0u8; 16];
    for k in 0..4 {
        symbol[k * 4..k * 4 + 4].copy_from_slice(&e[k].to_le_bytes());
    }
    types::MarketParams {
        symbol,
        tick_size: lo64(e[4], e[5]) as i64,
        im_bps: lo64(e[6], e[7]),
        mm_bps: lo64(e[8], e[9]),
        taker_fee_bps: lo64(e[10], e[11]),
        keeper_reward_bps: lo64(e[12], e[13]),
        delisted: false,
        spot_only: e[14] & 1 != 0,
        funding_rate: e[14] & 2 != 0,
        usd_per_unit: lo64(e[15], e[16]),
        funding_cap_bps: lo64(e[17], e[18]),
        min_price: lo64(e[19], e[20]) as i64,
        max_price: lo64(e[21], e[22]) as i64,
    }
}
pub fn decode_op(w: &[u32; 8]) -> BatchOp {
    let acct = w[0] >> 8;
    let lo64 = |a: u32, b: u32| (a as u64) | ((b as u64) << 32);
    match w[0] & 0xff {
        1 => BatchOp::Deposit { acct, amount: lo64(w[1], w[2]) as i64 },
        k @ (2 | 4 | 5) => BatchOp::Place {
            acct,
            side: if w[1] & 1 == 0 { Side::Bid } else { Side::Ask },
            typ: if w[1] & 2 == 0 { OrderType::Limit } else { OrderType::Market },
            tif: if w[1] & 4 == 0 { TimeInForce::Gtc } else { TimeInForce::Ioc },
            isolated: k >= 4,
            price: lo64(w[2], w[3]) as i64,
            qty: lo64(w[4], w[5]),
            client_seq: w[6] as u64,
            market: if k >= 4 { 1 } else { w[7] },
            margin: match k { 4 => w[7] as u64 * USD_SCALE, 5 => w[7] as u64, _ => 0 },
        },
        3 => BatchOp::Cancel { acct, client_seq: w[6] as u64, market: w[7] },
        6 => BatchOp::Withdraw { acct, amount: lo64(w[1], w[2]) as i64, nonce: lo64(w[6], w[7]) },
        7 => BatchOp::Liquidate { acct, target: w[1], market: w[7] },
        8 => BatchOp::Report { acct, price: lo64(w[2], w[3]) as i64, market: w[7] },
        9 => BatchOp::ExtPrice { acct, price: lo64(w[2], w[3]) as i64, source_id: w[6] as u8, market: w[7] },
        10 => BatchOp::SetHeight { height: lo64(w[1], w[2]) },
        11 => BatchOp::Stake { acct },
        12 => BatchOp::Unstake { acct },
        13 => BatchOp::Slash { acct, target: w[1], market: w[7] },
        14 => BatchOp::GovDeposit { acct, amount: lo64(w[1], w[2]) },
        15 => BatchOp::GovWithdraw { acct, amount: lo64(w[1], w[2]), nonce: lo64(w[6], w[7]) },
        16 => BatchOp::CreateMarket { acct, ext: w[7] },
        17 => BatchOp::CreateProposal { acct, market: w[1], key: w[2] as u8, value: lo64(w[3], w[4]) },
        18 => BatchOp::Vote { acct, id: lo64(w[1], w[2]), approve: w[3] & 1 != 0 },
        19 => BatchOp::Finalize { acct, id: lo64(w[1], w[2]) },
        20 => BatchOp::Commit { acct, ttl: lo64(w[1], w[2]), ext: w[7] },
        21 => BatchOp::Reveal { acct, ext: w[7] },
        22 => BatchOp::SetSeq { seq: lo64(w[1], w[2]) },
        _ => BatchOp::Bad,
    }
}

/// Where op i's unit id sits (MNP2 table); MNP1: unit id 0.
#[derive(Clone, Copy, Debug)]
pub struct Uid {
    pub v2: bool,
    pub at: u32,
}
impl Uid {
    pub fn read(&self, rd: &mut dyn FnMut(u32) -> u32) -> [u8; 32] {
        let mut uid = [0u8; 32];
        if self.v2 {
            for k in 0..8 {
                uid[k * 4..k * 4 + 4].copy_from_slice(&rd(self.at + k as u32).to_le_bytes());
            }
        }
        uid
    }
}

/// Upstream `minuend_dag::encode_op` (the commit-reveal preimage) of a pilot op whose signer is
/// `accts[op.signer()]` (loop round 6). None for ops the pilot cannot name upstream (fixtures,
/// Bad, an account index or extension outside the batch, kinds a Reveal may not carry anyway).
pub fn encode_op(op: &BatchOp, accts: &[AccountId], ext: &Ext, rd: &mut dyn FnMut(u32) -> u32) -> Option<Vec<u8>> {
    let id = |a: u32| accts.get(a as usize).copied();
    let mut b = Vec::new();
    match *op {
        BatchOp::Place { acct, side, typ, tif, isolated, price, qty, client_seq, market, margin } => {
            b.push(1);
            b.extend_from_slice(&id(acct)?.0);
            b.extend_from_slice(&market.to_le_bytes());
            b.push(side.as_u8());
            b.push(typ.as_u8());
            b.push(tif.as_u8());
            b.extend_from_slice(&price.to_le_bytes());
            b.extend_from_slice(&qty.to_le_bytes());
            b.extend_from_slice(&client_seq.to_le_bytes());
            b.push(isolated as u8);
            b.extend_from_slice(&margin.to_le_bytes());
        }
        BatchOp::Cancel { acct, client_seq, market } => {
            let a = id(acct)?;
            b.push(2);
            b.extend_from_slice(&a.0);
            b.extend_from_slice(&order_id(a, MarketId(market), client_seq).0);
        }
        BatchOp::Withdraw { acct, amount, nonce } => {
            b.push(4);
            b.extend_from_slice(&id(acct)?.0);
            b.extend_from_slice(&(amount as Usd).to_le_bytes());
            b.extend_from_slice(&nonce.to_le_bytes());
        }
        BatchOp::Report { acct, price, market } => {
            b.push(6);
            b.extend_from_slice(&id(acct)?.0);
            b.extend_from_slice(&market.to_le_bytes());
            b.extend_from_slice(&price.to_le_bytes());
        }
        BatchOp::GovWithdraw { acct, amount, nonce } => {
            b.push(9);
            b.extend_from_slice(&id(acct)?.0);
            b.extend_from_slice(&(amount as u128).to_le_bytes());
            b.extend_from_slice(&nonce.to_le_bytes());
        }
        BatchOp::CreateMarket { acct, ext: off } => {
            let l = listing_of(&ext.read(rd, off, EXT_MARKET_LEN)?);
            b.push(10);
            b.extend_from_slice(&id(acct)?.0);
            b.extend_from_slice(&l.symbol);
            b.extend_from_slice(&l.tick_size.to_le_bytes());
            b.extend_from_slice(&l.im_bps.to_le_bytes());
            b.extend_from_slice(&l.mm_bps.to_le_bytes());
            b.extend_from_slice(&l.taker_fee_bps.to_le_bytes());
            b.extend_from_slice(&l.keeper_reward_bps.to_le_bytes());
            b.push(l.spot_only as u8);
            b.push(l.funding_rate as u8);
            b.extend_from_slice(&l.usd_per_unit.to_le_bytes());
            b.extend_from_slice(&l.funding_cap_bps.to_le_bytes());
            b.extend_from_slice(&l.min_price.to_le_bytes());
            b.extend_from_slice(&l.max_price.to_le_bytes());
        }
        BatchOp::CreateProposal { acct, market, key, value } => {
            b.push(11);
            b.extend_from_slice(&id(acct)?.0);
            b.extend_from_slice(&market.to_le_bytes());
            b.push(key);
            b.extend_from_slice(&value.to_le_bytes());
        }
        BatchOp::Vote { acct, id: pid, approve } => {
            b.push(12);
            b.extend_from_slice(&id(acct)?.0);
            b.extend_from_slice(&pid.to_le_bytes());
            b.push(approve as u8);
        }
        BatchOp::Finalize { acct, id: pid } => {
            b.push(13);
            b.extend_from_slice(&id(acct)?.0);
            b.extend_from_slice(&pid.to_le_bytes());
        }
        BatchOp::Liquidate { acct, target, market } => {
            let t = if target == LIQ_TARGET_INSURANCE { INSURANCE_ACCOUNT } else { id(target)? };
            b.push(7);
            b.extend_from_slice(&id(acct)?.0);
            b.extend_from_slice(&t.0);
            b.extend_from_slice(&market.to_le_bytes());
        }
        BatchOp::Stake { acct } => {
            b.push(14);
            b.extend_from_slice(&id(acct)?.0);
        }
        BatchOp::Unstake { acct } => {
            b.push(15);
            b.extend_from_slice(&id(acct)?.0);
        }
        BatchOp::Slash { acct, target, market } => {
            b.push(16);
            b.extend_from_slice(&id(acct)?.0);
            b.extend_from_slice(&id(target)?.0);
            b.extend_from_slice(&market.to_le_bytes());
        }
        BatchOp::ExtPrice { acct, price, source_id, market } => {
            b.push(UPDATE_EXTERNAL_PRICE_TAG);
            b.extend_from_slice(&id(acct)?.0);
            b.extend_from_slice(&market.to_le_bytes());
            b.extend_from_slice(&price.to_le_bytes());
            b.push(source_id);
        }
        // a Reveal may not carry these (upstream `reveal_inner_kind_ok`; ingest refuses the unit)
        BatchOp::Deposit { .. } | BatchOp::GovDeposit { .. } | BatchOp::Commit { .. } | BatchOp::Reveal { .. } => return None,
        BatchOp::SetHeight { .. } | BatchOp::SetSeq { .. } | BatchOp::Bad => return None,
    }
    Some(b)
}

/// One unit's engine dispatch (upstream `dispatch`), for every op but the fixtures. `nested` = the
/// inner op of a Reveal (loop round 6; upstream runs it through the same `dispatch` with the
/// Reveal's unit id and seq).
#[allow(clippy::too_many_arguments)]
pub fn dispatch(
    eng: &mut Engine,
    op: &BatchOp,
    accts: &[AccountId],
    uid: Uid,
    seq: Seq,
    ext: &Ext,
    rd: &mut dyn FnMut(u32) -> u32,
    nested: bool,
) -> Result<Vec<Fill>, RejectReason> {
    let acct_of = |a: u32| accts.get(a as usize).copied().filter(|id| *id != INSURANCE_ACCOUNT);
    let need = |a: u32| acct_of(a).ok_or(RejectReason::BadAccount);
    match *op {
        BatchOp::Deposit { acct, amount } => eng.deposit(need(acct)?, amount as Usd),
        BatchOp::Place { acct, side, typ, tif, isolated, price, qty, client_seq, market, margin } => {
            eng.place(need(acct)?, MarketId(market), side, typ, tif, price, qty, client_seq, [0u8; 32], seq, isolated, margin)
        }
        BatchOp::Cancel { acct, client_seq, market } => {
            let a = need(acct)?;
            eng.cancel(a, order_id(a, MarketId(market), client_seq))
        }
        BatchOp::Withdraw { acct, amount, nonce } => eng.withdraw(need(acct)?, amount as Usd, nonce),
        BatchOp::Liquidate { acct, target, market } => {
            let t = if target == LIQ_TARGET_INSURANCE { Some(INSURANCE_ACCOUNT) } else { accts.get(target as usize).copied() };
            match (acct_of(acct), t) {
                // R4-M2: the unit id from the MNP2 table (MNP1: 0, refused in prod)
                (Some(_), Some(_)) if !uid.v2 && cfg!(feature = "prod") => Err(RejectReason::BadAccount),
                (Some(a), Some(t)) => eng.liquidate(uid.read(rd), seq, a, t, MarketId(market)),
                _ => Err(RejectReason::BadAccount),
            }
        }
        BatchOp::Report { acct, price, market } => eng.report_price(need(acct)?, MarketId(market), price),
        BatchOp::ExtPrice { acct, price, source_id, market } => eng.update_external_price(need(acct)?, MarketId(market), price, source_id, seq),
        BatchOp::Stake { acct } => eng.stake_oracle(need(acct)?),
        BatchOp::Unstake { acct } => eng.unstake_oracle(need(acct)?),
        BatchOp::Slash { acct, target, market } => match (acct_of(acct), accts.get(target as usize).copied()) {
            (Some(a), Some(t)) => eng.slash_oracle(a, t, MarketId(market)),
            _ => Err(RejectReason::BadAccount),
        },
        // ---- loop round 6 (R4-M3 rest) ----
        BatchOp::GovDeposit { acct, amount } => eng.gov_deposit(need(acct)?, amount as u128),
        BatchOp::GovWithdraw { acct, amount, nonce } => eng.gov_withdraw(need(acct)?, amount as u128, nonce),
        BatchOp::CreateMarket { acct, ext: off } => {
            let a = need(acct)?;
            let e = ext.read(rd, off, EXT_MARKET_LEN).ok_or(RejectReason::BadAccount)?;
            eng.create_market(a, &listing_of(&e))
        }
        BatchOp::CreateProposal { acct, market, key, value } => eng.create_proposal(need(acct)?, MarketId(market), key, value, seq),
        BatchOp::Vote { acct, id, approve } => eng.vote(need(acct)?, id, approve, seq),
        BatchOp::Finalize { acct, id } => eng.finalize_proposal(need(acct)?, id, seq),
        BatchOp::Commit { acct, ttl, ext: off } => {
            let a = need(acct)?;
            let e = ext.read(rd, off, EXT_COMMIT_LEN).ok_or(RejectReason::BadAccount)?;
            // the commit unit's id: MNP2 table (MNP1 has no extension area, so never here)
            eng.commit_op(uid.read(rd), a, id32(&e), ttl)
        }
        BatchOp::Reveal { acct, ext: off } => {
            let a = need(acct)?;
            if nested {
                return Err(RejectReason::BadAccount);
            }
            let e = ext.read(rd, off, EXT_REVEAL_LEN).ok_or(RejectReason::BadAccount)?;
            let commit_ref = id32(&e[0..8]);
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&id32(&e[8..16]));
            let mut iw = [0u32; 8];
            iw.copy_from_slice(&e[16..24]);
            let inner = decode_op(&iw);
            let parents: Vec<[u8; 32]> = [id32(&e[24..32]), id32(&e[32..40])].into_iter().filter(|p| *p != [0u8; 32]).collect();
            // upstream reveal_inner_ok: kind allowed and op_signer(inner) == the Reveal's account
            let signer_ok = inner.signer().and_then(acct_of) == Some(a);
            let enc = if signer_ok { encode_op(&inner, accts, ext, rd) } else { None };
            let hash = match &enc {
                Some(bytes) => {
                    let mut h = sha2::Sha256::new();
                    h.update(bytes);
                    h.update(salt);
                    h.finalize().into()
                }
                None => [0u8; 32],
            };
            eng.reveal_begin(a, commit_ref, enc.is_some(), hash, &parents)?;
            let out = dispatch(eng, &inner, accts, uid, seq, ext, rd, true);
            if out.is_err() {
                eng.reveal_undo(commit_ref);
            }
            out
        }
        BatchOp::SetHeight { .. } | BatchOp::SetSeq { .. } | BatchOp::Bad => Err(RejectReason::BadAccount),
    }
}

/// Per-unit witness mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitMode {
    /// no per-unit commitment (the 2d01fe8 pilot)
    Off,
    /// MNWIT1 incremental sparse Merkle root after every unit (proposal)
    Incremental,
    /// legacy fix/47-all style full rebuild (sort + Obyte merkle) after every unit with index >= skip
    Legacy { skip: u32 },
}

pub struct WitOut {
    /// final incremental root (Incremental) or last legacy root; = segment end root
    pub root: [u8; 32],
    /// MNWIT1 root before the first unit of this run (segment start root; Incremental only)
    pub start_root: [u8; 32],
    /// Incremental: final root == root of a tree rebuilt from scratch over the final state
    pub scratch_ok: bool,
    pub leaves: u32,
    pub leaf_updates: u64,
    pub node_hashes: u64,
}

/// Engine state carried from one segment (guest run) to the next.
pub struct Session {
    pub eng: Engine,
    pub w: Option<wit::Wit>,
    pub mode: WitMode,
    /// segments run so far (incl. ones whose header was rejected)
    pub segs: u32,
    /// account cap (MAX_STATE_ACCOUNTS; host tests may lower it; not part of the snapshot)
    pub state_cap: usize,
    /// loop round 5 (R4-M4): every batch run first sets the engine height to `segs` (the rollup
    /// height) via the batch-commit hook, and SetHeight ops are refused. Always on in `prod`
    /// (genesis and import); host tests opt in (`SegOpt::bind`). Not part of the snapshot.
    pub bind_height: bool,
}
/// Options of a segment run (loop round 5).
#[derive(Clone, Copy, Debug, Default)]
pub struct SegOpt {
    /// the run's number in the image lineage (guest: main.rs RUNS = the rollup height); None =
    /// count on (`segs` + 1, genesis 1)
    pub run_no: Option<u32>,
    /// a genesis session created by this run binds its height (`Session::bind_height`)
    pub bind: bool,
}
impl Session {
    pub fn genesis(flags: u32, mode: WitMode) -> Self {
        Self::genesis_with(flags, mode, &[])
    }
    pub fn genesis_with(flags: u32, mode: WitMode, accts: &[AccountId]) -> Self {
        let mut eng = Engine { state: state::ChainState::genesis_fixture(flags, accts) };
        let w = if mode == WitMode::Incremental { Some(wit::Wit::from_state(&eng.state)) } else { None };
        let _ = eng.state.take_dirty();
        Session { eng, w, mode, segs: 0, state_cap: MAX_STATE_ACCOUNTS, bind_height: cfg!(feature = "prod") }
    }
}

/// Run one batch (no witness), as in 2d01fe8.
pub fn run_batch(rd: &mut dyn FnMut(u32) -> u32, ev: &mut dyn FnMut(u32)) -> ([u8; 32], Stats) {
    let (h, st, _) = run_batch_wit(rd, ev, &mut |_, _, _| {}, WitMode::Off);
    (h, st)
}

/// Run one batch. `rd(i)` returns input word i; `ev(word)` receives the event log
/// (per op: EV_APPLIED|n_fills followed by 6 words per fill [maker_id w0, taker_id w0,
/// price lo, price hi, qty lo, qty hi], or a reject code); `unit(i, state, root)` is called
/// after every unit (applied or rejected, as upstream `apply_one` pushes one wit root per unit)
/// with the unit's witness root (zero when mode = Off, or Legacy before `skip`).
pub fn run_batch_wit(
    rd: &mut dyn FnMut(u32) -> u32,
    ev: &mut dyn FnMut(u32),
    unit: &mut dyn FnMut(u32, &state::ChainState, &[u8; 32]),
    mode: WitMode,
) -> ([u8; 32], Stats, WitOut) {
    let mut sess = None;
    run_segment(rd, ev, unit, mode, &mut sess)
}

/// Run one segment on `sess` (None = no session yet: start from genesis with the header's flags,
/// and leave the new session in `sess`). A rejected header runs no op and leaves `sess` as it was
/// (hash zero). The returned hash is the state hash after the segment.
pub fn run_segment(
    rd: &mut dyn FnMut(u32) -> u32,
    ev: &mut dyn FnMut(u32),
    unit: &mut dyn FnMut(u32, &state::ChainState, &[u8; 32]),
    mode: WitMode,
    sess: &mut Option<Session>,
) -> ([u8; 32], Stats, WitOut) {
    run_segment_n(rd, ev, unit, mode, sess, SegOpt::default())
}

/// The batch-commit hook (minuend-settle: new height, then `prune_withdrawals(height)`; the other
/// prunes touch unmodelled state).
pub fn commit_height(s: &mut state::ChainState, height: Height) {
    s.height = height;
    s.withdrawals.retain(|_, w| w.height + REPLAY_WINDOW > height);
    // loop round 5 (R4-M3): upstream's hook also releases finished oracle unbondings
    s.prune_oracle_unbonding(height);
    // loop round 6: and drops expired commits
    s.prune_commits(height);
}

/// `run_segment` with options (loop round 5: run number = rollup height, height binding).
pub fn run_segment_n(
    rd: &mut dyn FnMut(u32) -> u32,
    ev: &mut dyn FnMut(u32),
    unit: &mut dyn FnMut(u32, &state::ChainState, &[u8; 32]),
    mode: WitMode,
    sess: &mut Option<Session>,
    opt: SegOpt,
) -> ([u8; 32], Stats, WitOut) {
    let mut st = Stats { status: ST_OK, applied: 0, rejected: 0, fills: 0 };
    let mut wo = WitOut { root: [0; 32], start_root: [0; 32], scratch_ok: false, leaves: 0, leaf_updates: 0, node_hashes: 0 };
    if let Some(s) = sess.as_mut() {
        s.segs = opt.run_no.unwrap_or(s.segs + 1);
    }
    st.status = check_header_seg(rd, sess.is_some());
    if st.status != ST_OK {
        return ([0u8; 32], st, wo);
    }
    let n_acc = rd(1);
    let n_ops = rd(2);
    let mut accts: Vec<AccountId> = Vec::with_capacity(n_acc as usize);
    for a in 0..n_acc {
        let mut id = [0u8; 32];
        for k in 0..8 {
            id[k * 4..k * 4 + 4].copy_from_slice(&rd(4 + a * 8 + k as u32).to_le_bytes());
        }
        accts.push(AccountId(id));
    }
    let base = 4 + n_acc * 8;
    // R4-M2: MNP2 carries the unit ids after the ops
    let v2 = rd(0) == MAGIC2;
    let uid_base = base + 8 * n_ops;
    // loop round 6: MNP2 extension area
    let ext = if v2 { Ext { base: uid_base + 8 * n_ops, n: rd(uid_base + 8 * n_ops) } } else { Ext::NONE };
    if sess.is_none() {
        let mut s = Session::genesis_with(rd(3), mode, &accts);
        s.segs = opt.run_no.unwrap_or(1);
        s.bind_height |= opt.bind;
        *sess = Some(s);
    }
    let Session { eng, w, state_cap, segs, bind_height, .. } = sess.as_mut().unwrap();
    let state_cap = *state_cap;
    let bind_height = *bind_height;
    // segment start root = the previous segment's end root (the tree as committed so far)
    if let Some(w) = w.as_mut() {
        wo.root = w.root();
        wo.start_root = wo.root;
    }
    // R4-M4: the batch-commit hook at the rollup height, before any unit (units of height h see
    // engine height h). Since round 5 (R4-M3 port) the hook can change committed leaves: a finished
    // unbonding returns its bond to the reporter's PERP (acct: leaf). Review R5-L4: the witness is
    // committed right after the hook, so the hook's effects are in the end root even of a segment
    // without units (before: they first appeared in the next unit's root, and W<h> of an empty
    // height showed the pre-release balance); with units the first unit's root contains them anyway.
    if bind_height && (*segs as Height) > eng.state.height {
        commit_height(&mut eng.state, *segs as Height);
        if let Some(w) = w.as_mut() {
            wo.root = w.commit(&mut eng.state);
        }
    }
    for i in 0..n_ops {
        let mut ow = [0u32; 8];
        for (k, x) in ow.iter_mut().enumerate() {
            *x = rd(base + i * 8 + k as u32);
        }
        let seq = eng.state.seq;
        // INSURANCE_ACCOUNT can never author a signed unit upstream (ids are pubkey hashes).
        let acct_of = |a: u32| accts.get(a as usize).copied().filter(|id| *id != INSURANCE_ACCOUNT);
        let op = decode_op(&ow);
        let author = op.signer().and_then(acct_of);
        // loop round 6: a Reveal's inner op (its keys / account creation count for the rules below)
        let inner = match op {
            BatchOp::Reveal { ext: off, .. } => ext.read(rd, off, EXT_REVEAL_LEN).map(|e| {
                let mut iw = [0u32; 8];
                iw.copy_from_slice(&e[16..24]);
                decode_op(&iw)
            }),
            _ => None,
        };
        // W2 depth rule (only where the tree exists: Incremental mode; Off/Legacy are bench builds)
        let too_deep = match (w.as_ref(), author) {
            (Some(w), Some(a)) => !wit_depth_ok(w, &eng.state, &op, a) || inner.is_some_and(|x| !wit_depth_ok(w, &eng.state, &x, a)),
            _ => false,
        };
        // loop round 4 (long-run heap bound): session account cap
        let capped = !too_deep
            && author.is_some_and(|a| !state_cap_ok(&eng.state, &op, a, state_cap) || inner.is_some_and(|x| !state_cap_ok(&eng.state, &x, a, state_cap)));
        let rule = if too_deep { WIT_DEPTH_CODE } else { STATE_CAP_CODE };
        let mut height_op = false;
        let res = if too_deep || capped { Err(None) } else { match op {
            BatchOp::SetHeight { height } => {
                // test fixture (peg interval / feed staleness / unbonding): jumps allowed in test
                // builds without height binding (round 4 R4-H2 rule superseded by R4-M4)
                // loop round 5 (R4-M4): with height binding (always in prod) the height is the
                // rollup height, set by the hook at segment start -> SetHeight is always refused
                let ok_h = !bind_height && !cfg!(feature = "prod") && height >= eng.state.height;
                if ok_h {
                    commit_height(&mut eng.state, height);
                    height_op = true;
                    Ok(Vec::new())
                } else {
                    Err(RejectReason::BadAccount)
                }
            }
            BatchOp::SetSeq { seq: x } => {
                // loop round 6 test fixture: jump the global seq (proposal deadlines are 20 000
                // applied units away); never in prod
                if !cfg!(feature = "prod") && x >= eng.state.seq {
                    eng.state.seq = x;
                    height_op = true;
                    Ok(Vec::new())
                } else {
                    Err(RejectReason::BadAccount)
                }
            }
            _ => dispatch(eng, &op, &accts, Uid { v2, at: uid_base + i * 8 }, seq, &ext, rd, false),
        }.map_err(Some) };
        match res {
            Ok(_) if height_op => ev(if matches!(op, BatchOp::SetSeq { .. }) { EV_SEQ } else { EV_HEIGHT }),
            Ok(fills) => {
                eng.state.seq += 1;
                st.applied += 1;
                st.fills += fills.len() as u32;
                ev(EV_APPLIED | fills.len() as u32);
                for f in &fills {
                    ev(u32::from_le_bytes([f.maker_id.0[0], f.maker_id.0[1], f.maker_id.0[2], f.maker_id.0[3]]));
                    ev(if (f.kind == 2 || f.kind == 3) && !v2 {
                        LIQ_TAKER_EV
                    } else {
                        u32::from_le_bytes([f.taker_id.0[0], f.taker_id.0[1], f.taker_id.0[2], f.taker_id.0[3]])
                    });
                    ev(f.price as u32);
                    ev((f.price >> 32) as u32);
                    ev(f.qty as u32);
                    ev((f.qty >> 32) as u32);
                }
            }
            Err(r) => {
                st.rejected += 1;
                ev(r.as_ref().map(reason_code).unwrap_or(rule));
            }
        }
        let root = match mode {
            WitMode::Off => {
                let _ = eng.state.take_dirty();
                [0u8; 32]
            }
            WitMode::Incremental => w.as_mut().unwrap().commit(&mut eng.state),
            WitMode::Legacy { skip } => {
                let _ = eng.state.take_dirty();
                if i >= skip { wit::legacy_root(&eng.state) } else { [0u8; 32] }
            }
        };
        if mode != WitMode::Off {
            wo.root = root;
        }
        unit(i, &eng.state, &root);
    }
    if let Some(w) = w.as_mut() {
        // from-scratch rebuild; also a duplicate-kid check (W3): every leaf put from scratch must
        // land on its own key (count == puts), else two live leaves share a kid.
        // Loop round 4 (item c): O(state) per segment -> test builds only. The `prod` image skips
        // it (scratch_ok stays false = "not checked") and returns a zero state hash: neither is
        // read by the rollup (rv_witbind binds the segment end root, the dispute game the
        // machine roots), and both grow with the whole session state, not with the segment.
        if !cfg!(feature = "prod") {
            let mut sw = wit::Wit::from_state(&eng.state);
            wo.scratch_ok = sw.smt.count as u64 == sw.leaf_updates && sw.root() == wo.root;
        }
        wo.leaves = w.smt.count;
        wo.leaf_updates = w.leaf_updates;
        wo.node_hashes = w.smt.node_hashes;
    }
    let h = if cfg!(feature = "prod") { [0u8; 32] } else { state_hash(&eng.state) };
    (h, st, wo)
}

/// Result of an EXPORT / IMPORT run (loop round 4, snapshot.rs).
pub struct SnapOut {
    pub status: u32,
    /// sha256 over the snapshot words (export: produced; import: consumed)
    pub digest: [u8; 32],
    pub words: u32,
    /// MNWIT1 root of the session (export: current; import: rebuilt) -- both segment roots
    pub root: [u8; 32],
}

/// EXPORT run: stream the live session's canonical snapshot through sha256. Counts as a segment
/// (`segs` += 1 before encoding, so the snapshot carries it); changes nothing else.
pub fn run_export(rd: &mut dyn FnMut(u32) -> u32, sess: &mut Option<Session>) -> SnapOut {
    let mut o = SnapOut { status: ST_OK, digest: [0; 32], words: 0, root: [0; 32] };
    if rd(0) != snapshot::EXPORT_MAGIC {
        o.status = ST_BAD_MAGIC;
        return o;
    }
    if rd(1) != 0 || rd(2) != 0 || rd(3) != 0 {
        o.status = ST_BAD_EXPORT;
        return o;
    }
    let Some(s) = sess.as_mut() else {
        o.status = ST_NO_SESSION;
        return o;
    };
    s.segs += 1;
    let (d, n, _) = snapshot::export(s, false);
    o.digest = d;
    o.words = n;
    if let Some(w) = s.w.as_mut() {
        o.root = w.root();
    }
    o
}

/// IMPORT run: only without a live session, only on an image that carries the expected export
/// (`expect` = digest + word count, compiled into the upgrade image, so the governance-chosen GENMEM
/// commits it). The first `words` input words are hashed BEFORE anything is decoded (R4-L: a bogus
/// snapshot cannot make the decoder allocate first); then they are decoded. On success `sess`
/// holds the decoded session (the import itself does not count as a segment: the imported
/// session IS the exported one). Loop round 4 review R4-S1: without `expect`, any image without a
/// session -- the genesis image at height 1 -- accepted ANY well-formed snapshot (arbitrary state).
pub fn run_import(rd: &mut dyn FnMut(u32) -> u32, sess: &mut Option<Session>, expect: Option<&([u8; 32], u32)>) -> SnapOut {
    let mut o = SnapOut { status: ST_OK, digest: [0; 32], words: 0, root: [0; 32] };
    if sess.is_some() {
        o.status = ST_SESSION_LIVE;
        return o;
    }
    let Some((digest, words)) = expect else {
        o.status = ST_IMPORT_LOCKED;
        return o;
    };
    if *words > SNAP_LIMIT {
        o.status = ST_BAD_SNAP;
        return o;
    }
    let mut h = sha2::Sha256::new();
    for i in 0..*words {
        h.update(rd(i).to_le_bytes());
    }
    let d: [u8; 32] = h.finalize().into();
    if d != *digest {
        o.status = ST_BAD_SNAP;
        return o;
    }
    let mut r = snapshot::SnapR::new(rd, *words);
    match snapshot::decode(&mut r) {
        // the digest matched, so a decode failure / short read means the image was built for a
        // malformed export: refused all the same
        Ok(mut s) if r.i == *words => {
            // loop round 5 (R4-M4): the import run is a rollup height of its own (h = export + 1)
            s.segs += 1;
            s.bind_height = cfg!(feature = "prod");
            o.words = *words;
            o.digest = d;
            if let Some(w) = s.w.as_mut() {
                o.root = w.root();
            }
            *sess = Some(s);
        }
        _ => o.status = ST_BAD_SNAP,
    }
    o
}
/// "<64 lowercase hex>:<decimal words>" -> (digest, words) (the upgrade image's compiled-in
/// MNPILOT_IMPORT_DIGEST)
pub fn parse_expect(h: &str) -> Option<([u8; 32], u32)> {
    let (hx, n) = h.split_once(':')?;
    let b = hx.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let v = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut o = [0u8; 32];
    for i in 0..32 {
        o[i] = (v(b[2 * i])? << 4) | v(b[2 * i + 1])?;
    }
    Some((o, n.parse().ok()?))
}
