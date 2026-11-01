use ed25519_dalek::{Signature, VerifyingKey};
use minuend_types::{
    account_id_from_pubkey, sha256, AccountId, Bps, Height, MarketId, OrderId, OrderType, Price,
    Qty, Side, TimeInForce, UnitId, Usd, COMMIT_TAG, MAX_PARENTS, REVEAL_TAG,
    UPDATE_EXTERNAL_PRICE_TAG,
};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    Place {
        account: AccountId,
        market: MarketId,
        side: Side,
        typ: OrderType,
        tif: TimeInForce,
        price: Price,
        qty: Qty,
        client_seq: u64,
        /// Per-order margin mode: `true` = isolated (losses stop at `margin`),
        /// `false` = cross (today's pooled behavior). Old JSON parses as `false`.
        #[serde(default)]
        isolated: bool,
        /// Escrowed margin for an isolated order, in `USD_SCALE` units.
        /// Old JSON parses as `0`.
        #[serde(default)]
        margin: u64,
    },
    Cancel {
        account: AccountId,
        order_id: OrderId,
    },
    Deposit {
        account: AccountId,
        /// Obyte withdrawal address bound to this deposit (leaf-key domain).
        addr: String,
        amount: Usd,
        aa_unit: [u8; 32],
    },
    Withdraw {
        account: AccountId,
        amount: Usd,
        nonce: u64,
    },
    /// Bonded-oracle price report: writes/updates the reporter's latest quote
    /// for `market`; the effective mark is the median across reporters.
    ReportPrice {
        oracle: AccountId,
        market: MarketId,
        price: Price,
    },
    /// Deposit of the PERP governance asset, mirrored from the vault AA.
    /// `aa_unit` is the AA unit that paid the asset; replay-protected.
    GovDeposit {
        account: AccountId,
        /// Obyte withdrawal address bound to this deposit (leaf-key domain).
        addr: String,
        amount: u128,
        aa_unit: [u8; 32],
    },
    /// Merkle-proof withdrawal of PERP via the vault AA.
    GovWithdraw {
        account: AccountId,
        amount: u128,
        nonce: u64,
    },
    /// Permissionless market creation. Burns `CREATE_MARKET_FEE_PERP` from
    /// the creator's PERP balance and registers per-market risk parameters.
    CreateMarket {
        creator: AccountId,
        symbol: [u8; 16],
        tick_size: Price,
        im_bps: Bps,
        mm_bps: Bps,
        taker_fee_bps: Bps,
        keeper_reward_bps: Bps,
        /// Meme/contract-only market: rejects all price reports, never funds.
        /// Fixed at creation. Old JSON without this field parses as `false`.
        #[serde(default)]
        spot_only: bool,
        /// Funding-rate market: book price is an encoded external funding
        /// rate; reports write the index only, fills write the mark.
        /// Fixed at creation. Old JSON without this field parses as `false`.
        #[serde(default)]
        funding_rate: bool,
        /// Dollars per 1.0 qty for funding-rate money math; 0 unless
        /// `funding_rate`. Fixed at creation.
        #[serde(default)]
        usd_per_unit: u64,
        /// Per-window peg cap bps for this funding-rate market; 0 unless
        /// `funding_rate`. Fixed at creation.
        #[serde(default)]
        funding_cap_bps: u64,
        /// Tradeable price floor for this market (signed price grid); 0 =
        /// unbounded below. For a `spot_only` market — no oracle, so the mark
        /// freezes — a listing price range bounds a long's worst-case loss
        /// (which can exceed the notional when prices may go negative) to
        /// `qty × (max_price − min_price)`. Fixed at creation; old JSON
        /// parses as 0.
        #[serde(default)]
        min_price: Price,
        /// Tradeable price ceiling for this market (signed price grid); 0 =
        /// unbounded above. Fixed at creation; old JSON parses as 0.
        #[serde(default)]
        max_price: Price,
    },
    /// On-chain parameter proposal for `market`; `key` is a `ParamKey` u8.
    CreateProposal {
        creator: AccountId,
        market: MarketId,
        key: u8,
        value: u64,
    },
    /// Vote on an open proposal; weight = voter's PERP balance at execution.
    Vote {
        voter: AccountId,
        proposal_id: u64,
        approve: bool,
    },
    /// Finalize a proposal once past its deadline; anyone may call.
    FinalizeProposal { caller: AccountId, proposal_id: u64 },
    /// Keeper-initiated liquidation. `caller` is the keeper requesting it and
    /// receives the keeper reward; signature must belong to `caller`.
    Liquidate {
        caller: AccountId,
        target: AccountId,
        market: MarketId,
    },
    /// Stake PERP bond to become a price reporter.
    StakeOracle { account: AccountId },
    /// Begin unbonding of a reporter; unlocks after 256 heights.
    UnstakeOracle { account: AccountId },
    /// Slash a reporter whose reports deviate >500bps from TWAP for 3 consecutive heights.
    SlashOracle {
        challenger: AccountId,
        target: AccountId,
        market: MarketId,
    },
    /// v2 commit-reveal (doc 03 §2.3): registers `sha256(op_bytes(inner) ||
    /// salt)` until `ttl_height`. Carries no content MEV; ordered salted.
    Commit {
        account: AccountId,
        commit: [u8; 32],
        ttl_height: Height,
    },
    /// v2 commit-reveal reveal half: proves the preimage of a prior Commit
    /// and executes the inner operation. Must parent its Commit unit.
    Reveal {
        account: AccountId,
        commit_ref: [u8; 32],
        op: Box<Op>,
        salt: [u8; 32],
    },
    /// External price tick posted by an allowlisted keeper (doc 06 §2.6).
    /// Gated on `funding_source == AggregatedExternal`; rejected otherwise.
    UpdateExternalPrice {
        source: AccountId,
        market: MarketId,
        price: Price,
        source_id: u8,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unit {
    pub parents: Vec<UnitId>,
    pub op: Op,
    pub pubkey: [u8; 32],
    pub sig: [u8; 64],
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum DagError {
    #[error("missing parent")]
    MissingParent,
    #[error("too many parents")]
    TooManyParents,
    #[error("unsorted or duplicate parents")]
    BadParents,
    #[error("duplicate unit")]
    Duplicate,
    #[error("empty parents")]
    EmptyParents,
    #[error("deposit address too long")]
    AddrTooLong,
    #[error("orphan retry payload mismatch")]
    RetryMismatch,
    /// R2-R-6/7: a parent is outside the consensus parent window
    /// ([`PARENT_WINDOW`]); the unit can never execute.
    #[error("parent outside the parent window")]
    StaleParent,
}

/// Hard cap on the Obyte withdrawal address bound by Deposit/GovDeposit ops.
/// Enforced before signature checks so even the orphan-buffer path rejects
/// oversized payloads.
pub const MAX_ADDR_LEN: usize = 128;

pub fn genesis_id() -> UnitId {
    UnitId(sha256(b"minuend-mvp-1-genesis"))
}

pub fn canonical_bytes(unit: &Unit) -> Vec<u8> {
    let mut b = Vec::new();
    // v2 commit-reveal / external-price ops hash under the ODX2 domain so
    // their unit ids can never collide with a legacy ODX1 id (doc 03 §2.3.2).
    b.extend_from_slice(match &unit.op {
        Op::Commit { .. } | Op::Reveal { .. } | Op::UpdateExternalPrice { .. } => &b"ODX2"[..],
        _ => &b"ODX1"[..],
    });
    b.push(unit.parents.len() as u8);
    for p in &unit.parents {
        b.extend_from_slice(&p.0);
    }
    encode_op(&mut b, &unit.op);
    b.extend_from_slice(&unit.pubkey);
    b
}

/// Op payload encoding shared by `canonical_bytes` and the commit-reveal
/// hash: tag byte followed by the op's fields in fixed wire order.
fn encode_op(b: &mut Vec<u8>, op: &Op) {
    match op {
        Op::Place {
            account,
            market,
            side,
            typ,
            tif,
            price,
            qty,
            client_seq,
            isolated,
            margin,
        } => {
            b.push(1);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(&market.0.to_le_bytes());
            b.push(side.as_u8());
            b.push(typ.as_u8());
            b.push(tif.as_u8());
            b.extend_from_slice(&price.to_le_bytes());
            b.extend_from_slice(&qty.to_le_bytes());
            b.extend_from_slice(&client_seq.to_le_bytes());
            b.push(*isolated as u8);
            b.extend_from_slice(&margin.to_le_bytes());
        }
        Op::Cancel { account, order_id } => {
            b.push(2);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(&order_id.0);
        }
        Op::Deposit {
            account,
            addr,
            amount,
            aa_unit,
        } => {
            b.push(3);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(&amount.to_le_bytes());
            b.extend_from_slice(aa_unit);
            b.extend_from_slice(&(addr.len() as u32).to_le_bytes());
            b.extend_from_slice(addr.as_bytes());
        }
        Op::Withdraw {
            account,
            amount,
            nonce,
        } => {
            b.push(4);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(&amount.to_le_bytes());
            b.extend_from_slice(&nonce.to_le_bytes());
        }
        Op::ReportPrice {
            oracle,
            market,
            price,
        } => {
            b.push(6);
            b.extend_from_slice(&oracle.0);
            b.extend_from_slice(&market.0.to_le_bytes());
            b.extend_from_slice(&price.to_le_bytes());
        }
        Op::GovDeposit {
            account,
            addr,
            amount,
            aa_unit,
        } => {
            b.push(8);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(&amount.to_le_bytes());
            b.extend_from_slice(aa_unit);
            b.extend_from_slice(&(addr.len() as u32).to_le_bytes());
            b.extend_from_slice(addr.as_bytes());
        }
        Op::GovWithdraw {
            account,
            amount,
            nonce,
        } => {
            b.push(9);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(&amount.to_le_bytes());
            b.extend_from_slice(&nonce.to_le_bytes());
        }
        Op::CreateMarket {
            creator,
            symbol,
            tick_size,
            im_bps,
            mm_bps,
            taker_fee_bps,
            keeper_reward_bps,
            spot_only,
            funding_rate,
            usd_per_unit,
            funding_cap_bps,
            min_price,
            max_price,
        } => {
            b.push(10);
            b.extend_from_slice(&creator.0);
            b.extend_from_slice(symbol);
            b.extend_from_slice(&tick_size.to_le_bytes());
            b.extend_from_slice(&im_bps.to_le_bytes());
            b.extend_from_slice(&mm_bps.to_le_bytes());
            b.extend_from_slice(&taker_fee_bps.to_le_bytes());
            b.extend_from_slice(&keeper_reward_bps.to_le_bytes());
            b.push(*spot_only as u8);
            b.push(*funding_rate as u8);
            b.extend_from_slice(&usd_per_unit.to_le_bytes());
            b.extend_from_slice(&funding_cap_bps.to_le_bytes());
            b.extend_from_slice(&min_price.to_le_bytes());
            b.extend_from_slice(&max_price.to_le_bytes());
        }
        Op::CreateProposal {
            creator,
            market,
            key,
            value,
        } => {
            b.push(11);
            b.extend_from_slice(&creator.0);
            b.extend_from_slice(&market.0.to_le_bytes());
            b.push(*key);
            b.extend_from_slice(&value.to_le_bytes());
        }
        Op::Vote {
            voter,
            proposal_id,
            approve,
        } => {
            b.push(12);
            b.extend_from_slice(&voter.0);
            b.extend_from_slice(&proposal_id.to_le_bytes());
            b.push(u8::from(*approve));
        }
        Op::FinalizeProposal {
            caller,
            proposal_id,
        } => {
            b.push(13);
            b.extend_from_slice(&caller.0);
            b.extend_from_slice(&proposal_id.to_le_bytes());
        }
        Op::Liquidate {
            caller,
            target,
            market,
        } => {
            b.push(7);
            b.extend_from_slice(&caller.0);
            b.extend_from_slice(&target.0);
            b.extend_from_slice(&market.0.to_le_bytes());
        }
        Op::StakeOracle { account } => {
            b.push(14);
            b.extend_from_slice(&account.0);
        }
        Op::UnstakeOracle { account } => {
            b.push(15);
            b.extend_from_slice(&account.0);
        }
        Op::SlashOracle {
            challenger,
            target,
            market,
        } => {
            b.push(16);
            b.extend_from_slice(&challenger.0);
            b.extend_from_slice(&target.0);
            b.extend_from_slice(&market.0.to_le_bytes());
        }
        Op::UpdateExternalPrice {
            source,
            market,
            price,
            source_id,
        } => {
            b.push(UPDATE_EXTERNAL_PRICE_TAG);
            b.extend_from_slice(&source.0);
            b.extend_from_slice(&market.0.to_le_bytes());
            b.extend_from_slice(&price.to_le_bytes());
            b.push(*source_id);
        }
        Op::Commit {
            account,
            commit,
            ttl_height,
        } => {
            b.push(COMMIT_TAG);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(commit);
            b.extend_from_slice(&ttl_height.to_le_bytes());
        }
        Op::Reveal {
            account,
            commit_ref,
            op,
            salt,
        } => {
            b.push(REVEAL_TAG);
            b.extend_from_slice(&account.0);
            b.extend_from_slice(commit_ref);
            // Inner payload in the same tagged wire order, so the commit
            // hash (encode_op(inner) || salt) is derivable from bytes alone.
            encode_op(b, op);
            b.extend_from_slice(salt);
        }
    }
}

/// Commit-reveal binding (doc 03 §2.3.1): sha256(op_bytes(inner) || salt).
pub fn reveal_commit_hash(inner: &Op, salt: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::new();
    encode_op(&mut buf, inner);
    buf.extend_from_slice(salt);
    sha256(&buf)
}

/// Round 7 (PR #51 未修复项 10): the op-descriptor string committed as a
/// unit's `ops_root` leaf (`minuend_settle::ops_element`), or `None` for ops
/// that commit the opaque `x:{unit}`. It is part of the unit id preimage
/// ([`unit_text`]), so it is fixed by the signed unit.
pub fn op_descriptor(op: &Op) -> Option<String> {
    use Op::*;
    match op {
        // #47 A2: deposits commit the Obyte address they bind (first
        // deposit) or must match (later deposits), so the forest dispute AA
        // can check that a new `adr:{addr}:{acct}` witness leaf appears only
        // under a deposit op of that account WITH that address.
        // R2-A-3: a collateral deposit also commits its vault anchor (the
        // Obyte unit hash, standard base64 — the vault AA's `dep_<unit>`
        // key), so P-deposit can require the credit to be backed by a
        // payment the vault actually recorded.
        Deposit {
            account,
            addr,
            amount,
            aa_unit,
        } => {
            use base64::Engine as _;
            Some(format!(
                "d:{}:{}:{}:{}",
                hex::encode(account.0),
                amount,
                addr,
                base64::engine::general_purpose::STANDARD.encode(aa_unit)
            ))
        }
        // R3-A-7: a PERP deposit commits its vault anchor too (the vault's
        // `depp_<unit>` key), so P-deposit can require its backing.
        GovDeposit {
            account,
            addr,
            amount,
            aa_unit,
        } => {
            use base64::Engine as _;
            Some(format!(
                "D:{}:{}:{}:{}",
                hex::encode(account.0),
                amount,
                addr,
                base64::engine::general_purpose::STANDARD.encode(aa_unit)
            ))
        }
        Withdraw {
            account,
            amount,
            nonce,
        } => Some(format!("w:{}:{}:{}", hex::encode(account.0), amount, nonce)),
        GovWithdraw {
            account,
            amount,
            nonce,
        } => Some(format!("W:{}:{}:{}", hex::encode(account.0), amount, nonce)),
        // #47 A3: `typ` (0 Limit / 1 Market) is committed so the fill
        // dispute AA can tell whether an unfilled remainder rests in the
        // book (Limit + Gtc) or is refunded in-unit — the escrow identity
        // derives the taker's resting margin from the op instead of
        // trusting an operator-chosen order id.
        Place {
            account,
            market,
            side,
            typ,
            price,
            qty,
            isolated,
            margin,
            tif,
            ..
        } => Some(format!(
            "p:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            hex::encode(account.0),
            market.0,
            side.as_u8(),
            price,
            qty,
            if *isolated { 1 } else { 0 },
            margin,
            tif.as_u8(),
            typ.as_u8()
        )),
        Cancel { account, order_id } => Some(format!(
            "c:{}:{}",
            hex::encode(account.0),
            hex::encode(order_id.0)
        )),
        Liquidate {
            caller,
            target,
            market,
        } => Some(format!(
            "L:{}:{}:{}",
            hex::encode(caller.0),
            hex::encode(target.0),
            market.0
        )),
        // R2-E-2: a Reveal executes its inner op (or nothing, when
        // rejected), so for the ops whose witness columns the dispute AAs
        // pin (collateral, PERP, W, adr:) the committed descriptor is the
        // INNER op's — otherwise an honest Reveal{Withdraw} raises W under
        // an `x:` tag and P-wpin verdicts it. Other inner ops keep `x:`
        // (no predicate judges them through a Reveal). R3-E-1: a Reveal can
        // no longer carry Deposit/GovDeposit (refused at ingest and in
        // `reveal_op`), so only the withdrawal kinds are forwarded.
        // Round 6 (PR #51 未修复项 30): a revealed Place / Liquidate runs
        // through the same `dispatch` as a direct one, so its fills are
        // judged against the INNER `p:` / `L:` descriptor (fill_math's
        // escrow identity, P-claw's two-leg claw and keeper) instead of an
        // opaque `x:` that hid the margin, tif and keeper.
        // Round 7b (R7-C3, ASSERTION_VERSION 5): a revealed Cancel commits
        // its inner `c:` too — every `x:` unit is now framed by P-xframe
        // (no `x:` op writes an order or collateral), and a Cancel removes
        // an order and refunds its escrow (judged by P-escrow / P-frame).
        Reveal { op: inner, .. }
            if matches!(
                inner.as_ref(),
                Withdraw { .. }
                    | GovWithdraw { .. }
                    | Place { .. }
                    | Liquidate { .. }
                    | Cancel { .. }
            ) =>
        {
            op_descriptor(inner)
        }
        _ => None,
    }
}

/// Round 7: domain prefix of the text a unit id hashes.
pub const UNIT_TEXT_DOMAIN: &str = "mnu3";

/// Round 7: `"mnu3|" + hex(canonical_bytes) + "|"` — the part of
/// [`unit_text`] before the descriptor. Hex has no `|`, so this prefix is
/// exactly the text up to its second `|` (P-opbind checks that shape).
pub fn unit_text_prefix(unit: &Unit) -> String {
    format!("{UNIT_TEXT_DOMAIN}|{}|", hex::encode(canonical_bytes(unit)))
}

/// Round 7 (PR #51 未修复项 10): the UTF-8 text whose sha256 is the unit
/// id: [`unit_text_prefix`] followed by the committed ops descriptor
/// ([`op_descriptor`], or `x` for ops without one). The canonical bytes
/// keep the id injective over the whole unit (parents, op, pubkey); the
/// descriptor tail is what an Oscript AA can read without decoding
/// binary: given this text it recomputes the id with `sha256(text, 'hex')`,
/// matches it to the `units_root` leaf, and compares the tail with the
/// `ops_root` leaf at the same index.
pub fn unit_text(unit: &Unit) -> String {
    let d = op_descriptor(&unit.op).unwrap_or_else(|| "x".to_string());
    format!("{}{d}", unit_text_prefix(unit))
}

/// Unit id (round 7, ASSERTION_VERSION 4): `sha256(unit_text(unit))`. The
/// signature covers this id, so it binds the ops descriptor too.
pub fn unit_id(unit: &Unit) -> UnitId {
    UnitId(sha256(unit_text(unit).as_bytes()))
}

/// Verify a unit's ed25519 signature against an ALREADY-COMPUTED unit id, so
/// Also checks the op's signing-account field (account/caller/oracle/creator/
/// voter) matches the signing key.
pub fn verify_sig_by_id(unit: &Unit, id: &UnitId) -> bool {
    let vk = match VerifyingKey::from_bytes(&unit.pubkey) {
        Ok(v) => v,
        Err(_) => return false,
    };
    // verify_strict rejects non-canonical s / small-order components
    // (signature malleability), satisfying strict r/s group-order checks.
    let sig = Signature::from_bytes(&unit.sig);
    vk.verify_strict(&id.0, &sig).is_ok() && account_matches(unit)
}

/// Bounded pubkey -> VerifyingKey cache. Validator traffic is heavily skewed
/// toward a small operator set, so Edwards-point decompression (the setup
/// cost of every ed25519 verification) amortizes to ~zero in steady state.
/// Clears wholesale past [`SigVerifier::CAP`] to keep memory bounded without
#[derive(Clone, Default, Debug)]
pub struct SigVerifier {
    cache: HashMap<[u8; 32], Option<VerifyingKey>>,
}

impl SigVerifier {
    pub const CAP: usize = 4096;

    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Same contract as [`verify_sig_by_id`] with decompression cached.
    pub fn verify_by_id(&mut self, unit: &Unit, id: &UnitId) -> bool {
        let vk = match self.cache.get(&unit.pubkey) {
            Some(cached) => *cached,
            None => {
                let parsed = VerifyingKey::from_bytes(&unit.pubkey).ok();
                if self.cache.len() >= Self::CAP {
                    self.cache.clear();
                }
                self.cache.insert(unit.pubkey, parsed);
                parsed
            }
        };
        let Some(vk) = vk else { return false };
        let sig = Signature::from_bytes(&unit.sig);
        vk.verify_strict(&id.0, &sig).is_ok() && account_matches(unit)
    }
}

fn account_matches(unit: &Unit) -> bool {
    let expected = account_id_from_pubkey(&unit.pubkey);
    if op_signer(&unit.op) != expected {
        return false;
    }
    // R2-E-1: a Reveal executes its inner op, so the inner op's own signing
    // field (account/caller/voter/creator/…) must name the SAME account as
    // the outer Reveal — i.e. the signer. Otherwise anyone could commit and
    // reveal a Place/Withdraw/Vote "as" another account. Commit/Reveal may
    // not nest inside a Reveal.
    match &unit.op {
        Op::Reveal { op, .. } => reveal_inner_ok(&unit.op, op),
        _ => true,
    }
}

/// R2-E-1: whether `inner` may be executed by the Reveal `outer`: it must
/// not itself be a Commit/Reveal, and its signing account must equal the
/// outer Reveal's account. Shared by ingest (`account_matches`) and the
/// executor (`reveal_op`) so both enforce the exact same rule.
pub fn reveal_inner_ok(outer: &Op, inner: &Op) -> bool {
    reveal_inner_kind_ok(inner) && op_signer(inner) == op_signer(outer)
}

/// Op kinds a Reveal may NOT carry. Commit/Reveal may not nest (R2-E-1).
/// R3-E-1: Deposit/GovDeposit may only ever be top-level ops — their
/// on-chain payment evidence is verified (and their anchor admitted) only
/// for top-level deposit ops, so a revealed deposit could otherwise spend a
/// real anchor with an arbitrary amount. Deposits are triggered by a public
/// on-chain payment anyway, so commit-reveal buys them nothing.
pub fn reveal_inner_kind_ok(inner: &Op) -> bool {
    !matches!(
        inner,
        Op::Commit { .. } | Op::Reveal { .. } | Op::Deposit { .. } | Op::GovDeposit { .. }
    )
}

/// The account whose key must sign `op` (the per-variant signing field).
pub fn op_signer(op: &Op) -> AccountId {
    match op {
        Op::Place { account, .. }
        | Op::Cancel { account, .. }
        | Op::Deposit { account, .. }
        | Op::Withdraw { account, .. }
        | Op::GovDeposit { account, .. }
        | Op::GovWithdraw { account, .. } => *account,
        Op::StakeOracle { account } | Op::UnstakeOracle { account } => *account,
        Op::SlashOracle { challenger, .. } => *challenger,
        Op::Commit { account, .. } | Op::Reveal { account, .. } => *account,
        Op::UpdateExternalPrice { source, .. } => *source,
        Op::Liquidate { caller, .. } | Op::FinalizeProposal { caller, .. } => *caller,
        Op::ReportPrice { oracle, .. } => *oracle,
        Op::CreateMarket { creator, .. } => *creator,
        Op::CreateProposal { creator, .. } => *creator,
        Op::Vote { voter, .. } => *voter,
    }
}

pub fn sign_unit(parents: Vec<UnitId>, op: Op, secret: &[u8; 32]) -> Unit {
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::from_bytes(secret);
    let pubkey = sk.verifying_key().to_bytes();
    let mut unit = Unit {
        parents,
        op,
        pubkey,
        sig: [0u8; 64],
    };
    let id = unit_id(&unit);
    unit.sig = sk.sign(&id.0).to_bytes();
    unit
}

/// R2-R-6 / R2-R-7 (round 2 of #47): consensus parent-age window.
///
/// A unit may only be executed when every one of its parents is among the
/// last `PARENT_WINDOW` executed units (genesis counts as the virtual unit
/// executed just before the first one, so it stops being a valid parent once
/// `PARENT_WINDOW` units have executed). The window is exactly the DAG
/// anchor ring a snapshot persists (`minuend_state::persist::DAG_ANCHOR_LIMIT`
/// is the same number), so a node restored from a snapshot and a node that
/// has run since genesis judge every unit identically:
///
/// * a unit referencing an ancient parent (M2 residue) is refused by every
///   node, instead of being executed by a long-running producer and then
///   breaking every snapshot-restored replayer with `MissingParent`;
/// * an old signed unit re-sent after its execution has slipped out of the
///   window (H4 residue, including `parents == [genesis]`) cannot run a
///   second time: all its parents are older than itself, hence stale.
///
/// The check is evaluated at execution position (see
/// [`Dag::ready_linearized`]), which is identical on the producer and on
/// every replayer, and additionally as an early reject at insertion when a
/// parent is already stale (a stale parent never becomes fresh again).
pub const PARENT_WINDOW: usize = 2 * minuend_types::BATCH_MAX_UNITS as usize;

#[derive(Clone, Debug)]
pub struct Dag {
    units: HashMap<UnitId, Unit>,
    children: HashMap<UnitId, Vec<UnitId>>,
    executed: HashSet<UnitId>,
    /// non-executed units; keeps ready_linearized O(pending) not O(all units)
    pending: HashSet<UnitId>,
    /// units whose parents are not (yet) known; evicted by smallest salted
    /// key past capacity (see `insert_verified`)
    pending_orphans: HashMap<UnitId, Unit>,
    /// R2-R-13: `pending_orphans` ordered by salted eviction key, so an
    /// eviction is O(log n) instead of hashing the whole buffer twice per
    /// comparison. Rebuilt whenever the salt rotates.
    orphan_order: BTreeSet<([u8; 32], UnitId)>,
    /// reverse index over `pending_orphans`: missing parent -> buffered
    /// children waiting on it; lets a newly known parent link only the
    /// orphans it actually unblocks instead of scanning the whole buffer
    waiting: HashMap<UnitId, Vec<UnitId>>,
    /// Salt for orphan eviction only (execution order is plain lexicographic,
    /// see `ready_linearized`): genesis id until the first AA finalization,
    /// then derived from the finalized state root.
    eviction_salt: [u8; 32],
    /// #37-14: ids known to have been executed BEFORE a restored snapshot.
    /// Their full units are gone (the snapshot carries state, not the DAG),
    /// but children must still link and become ready rather than being
    /// buffered as orphans forever. `ready_linearized` already ignores
    /// parents outside `pending`, so an ancestor id is exactly "executed".
    ancestors: HashSet<UnitId>,
    /// R2-R-6/7: the last `parent_window` executed ids, oldest first, with
    /// their execution sequence numbers (`window_seq`). Ids leaving the
    /// window are pruned from every other map (R2-R-5: the DAG no longer
    /// grows with the whole history).
    window: VecDeque<UnitId>,
    window_seq: HashMap<UnitId, u64>,
    /// Number of units executed (or seeded as ancestors) so far; the next
    /// executed unit gets this sequence number.
    next_seq: u64,
    parent_window: usize,
    /// R3-R-5: bodies of executed units that left the parent window before
    /// they were exported in a batch. They are no longer DAG members (not
    /// valid parents, not served by `get`), but `Batch::from_applied` still
    /// needs them; released by [`Dag::release_batched`]. Bounded by the
    /// producer's unbatched backlog.
    retained: HashMap<UnitId, Unit>,
    /// R3-R-5: in-window units already exported in a batch: their bodies are
    /// dropped (not retained) when they leave the window. Bounded by the
    /// window.
    batched: HashSet<UnitId>,
    /// R3-R-5: whether out-of-window unbatched bodies are retained (default
    /// true). A node that never exports or validates batches (a pure relay)
    /// should turn it off to keep the R2-R-5 memory bound.
    retain_unbatched: bool,
    /// Set by `ready_linearized` when it had to hold back a pending unit
    /// with a stale parent; the next mutable call purges such units.
    stale_pending: Cell<bool>,
}

/// Max buffered orphan units. Beyond this the orphan with the smallest
/// salted key is dropped.
const ORPHAN_CAP: usize = 4096;

impl Default for Dag {
    fn default() -> Self {
        Self::new()
    }
}

impl Dag {
    pub fn new() -> Self {
        Self::with_parent_window(PARENT_WINDOW)
    }

    /// A DAG with a non-default parent window. Consensus code always uses
    /// [`Dag::new`] ([`PARENT_WINDOW`]); smaller windows exist so tests can
    /// exercise window expiry without executing 400 000 units.
    pub fn with_parent_window(parent_window: usize) -> Self {
        let mut executed = HashSet::new();
        executed.insert(genesis_id());
        Self {
            units: HashMap::new(),
            children: HashMap::new(),
            waiting: HashMap::new(),
            executed,
            pending: HashSet::new(),
            pending_orphans: HashMap::new(),
            orphan_order: BTreeSet::new(),
            eviction_salt: genesis_id().0,
            ancestors: HashSet::new(),
            window: VecDeque::new(),
            window_seq: HashMap::new(),
            next_seq: 0,
            parent_window: parent_window.max(1),
            retained: HashMap::new(),
            batched: HashSet::new(),
            retain_unbatched: true,
            stale_pending: Cell::new(false),
        }
    }

    /// Rotate the orphan-eviction salt (Step9): the finalization observer
    /// calls this with each newly AA-finalized state root.
    pub fn set_eviction_salt(&mut self, salt: [u8; 32]) {
        self.eviction_salt = salt;
        let ids: Vec<UnitId> = self.pending_orphans.keys().copied().collect();
        self.orphan_order = ids
            .into_iter()
            .map(|id| (self.eviction_key(id), id))
            .collect();
    }

    pub fn eviction_salt(&self) -> [u8; 32] {
        self.eviction_salt
    }

    /// Salted eviction key: sha256(salt || unit_id).
    pub fn eviction_key(&self, id: UnitId) -> [u8; 32] {
        let mut b = Vec::with_capacity(64);
        b.extend_from_slice(&self.eviction_salt);
        b.extend_from_slice(&id.0);
        sha256(&b)
    }

    fn orphan_put(&mut self, id: UnitId, unit: Unit) {
        self.orphan_order.insert((self.eviction_key(id), id));
        self.pending_orphans.insert(id, unit);
    }

    fn orphan_take(&mut self, id: UnitId) -> Option<Unit> {
        let u = self.pending_orphans.remove(&id)?;
        self.orphan_order.remove(&(self.eviction_key(id), id));
        Some(u)
    }

    /// Number of buffered orphans (test/diagnostic aid).
    pub fn orphan_count(&self) -> usize {
        self.pending_orphans.len()
    }

    /// Insert a unit, hashing it to compute its id.
    pub fn insert(&mut self, unit: Unit) -> Result<UnitId, DagError> {
        let id = unit_id(&unit);
        self.insert_verified(unit, id)
    }

    /// Is `p` a valid parent for the unit executed at sequence `s`?
    /// `virtual_seq` carries sequence numbers assigned earlier in the same
    /// `ready_linearized` pass (units not executed yet).
    fn parent_fresh_at(
        &self,
        p: UnitId,
        s: u64,
        virtual_seq: Option<&HashMap<UnitId, u64>>,
    ) -> bool {
        let w = self.parent_window as u64;
        if p == genesis_id() {
            // Genesis = virtual seq -1: fresh while s - (-1) <= w.
            return s < w;
        }
        let seq = self
            .window_seq
            .get(&p)
            .copied()
            .or_else(|| virtual_seq.and_then(|m| m.get(&p).copied()));
        match seq {
            Some(q) => q + w >= s,
            None => false,
        }
    }

    /// R2-R-6/7 early reject: a known parent that is already outside the
    /// window can never become fresh again, so the unit can never execute.
    fn has_stale_known_parent(&self, unit: &Unit) -> bool {
        unit.parents.iter().any(|p| {
            if *p == genesis_id() {
                return self.next_seq >= self.parent_window as u64;
            }
            if self.pending.contains(p) {
                return false; // not executed yet: judged at execution
            }
            if self.window_seq.contains_key(p) {
                return !self.parent_fresh_at(*p, self.next_seq, None);
            }
            // Executed but no longer in the window (or an ancestor that was
            // trimmed): stale. Unknown ids are handled by the orphan path.
            self.executed.contains(p) || self.ancestors.contains(p)
        })
    }

    /// Same as [`Dag::insert`] but the caller supplies the unit id, so an
    /// ingest path that already hashed the unit (signature check) never
    /// computes it twice. Unknown parents no longer drop the unit: on first
    /// sight it is buffered as an orphan and `Err(MissingParent)` returned; a
    /// retry of the same canonical unit while still orphaned returns its id
    /// without error — a retry with DIFFERENT canonical bytes under an equal
    /// id is rejected with [`DagError::RetryMismatch`]. Buffered orphans are
    /// linked automatically once their parents arrive (see `mark_executed`),
    /// so out-of-order delivery recovers. A unit with a parent outside the
    /// consensus parent window ([`PARENT_WINDOW`]) is refused with
    /// [`DagError::StaleParent`].
    ///
    /// Note: arrival-order buffering itself remains replica-dependent (which
    /// units sit in the buffer depends on delivery order). Eviction drops the
    /// orphan with the smallest salted key sha256(salt||unit_id), where the
    /// salt rotates with AA finalizations (`Engine::note_finalized`). Because
    /// replicas can observe finalizations at slightly different times, two
    /// replicas MAY evict different orphans before they converge; the DA
    /// layer's temp_data full replay is the self-healing backstop that
    /// restores a common unit set after convergence.
    pub fn insert_verified(&mut self, unit: Unit, id: UnitId) -> Result<UnitId, DagError> {
        if self.stale_pending.get() {
            self.purge_stale_pending();
        }
        if unit.parents.is_empty() {
            return Err(DagError::EmptyParents);
        }
        if unit.parents.len() > MAX_PARENTS {
            return Err(DagError::TooManyParents);
        }
        // Address-length gate BEFORE signature verification / buffering: a
        // Deposit/GovDeposit with an oversized withdrawal addr must be
        // rejected on every path, including the orphan buffer.
        match &unit.op {
            Op::Deposit { addr, .. } | Op::GovDeposit { addr, .. } if addr.len() > MAX_ADDR_LEN => {
                return Err(DagError::AddrTooLong);
            }
            _ => {}
        }
        let mut sorted = unit.parents.clone();
        sorted.sort();
        sorted.dedup();
        if sorted != unit.parents {
            return Err(DagError::BadParents);
        }
        // H4 (#47): a pre-snapshot ancestor id was already executed before
        // the restart. Treating it only as "known" (a linkable parent) let a
        // re-sent copy of that old unit be linked and executed a second
        // time; it must be refused exactly like a unit already in the DAG.
        if self.units.contains_key(&id) || self.ancestors.contains(&id) {
            return Err(DagError::Duplicate);
        }
        // R2-R-6/7: a parent already outside the window (incl. genesis once
        // the window is full) can never be valid again.
        if self.has_stale_known_parent(&unit) {
            return Err(DagError::StaleParent);
        }
        let missing: Vec<UnitId> = unit
            .parents
            .iter()
            .copied()
            .filter(|p| !self.known(*p))
            .collect();
        if !missing.is_empty() {
            // Already buffered? Accept the retry only if it is byte-for-byte
            // the same unit: id equality alone is caller-supplied, and a
            // second copy with different canonical bytes must not silently
            // pass (the buffer keeps the first copy while the caller would
            // believe its variant was accepted).
            if self.pending_orphans.contains_key(&id) {
                if unit_id(&unit) != id
                    || canonical_bytes(&unit) != canonical_bytes(&self.pending_orphans[&id])
                {
                    return Err(DagError::RetryMismatch);
                }
                return Ok(id);
            }
            if self.pending_orphans.len() >= ORPHAN_CAP {
                // Salted eviction (Step9): drop the orphan with the smallest
                // key sha256(salt||id). R2-R-13: taken from the ordered
                // index (O(log n)) instead of re-hashing the whole buffer.
                if let Some(&(_, k)) = self.orphan_order.iter().next() {
                    if let Some(evicted) = self.orphan_take(k) {
                        // Drop the evicted orphan's reverse-index entries.
                        for p in &evicted.parents {
                            if let Some(v) = self.waiting.get_mut(p) {
                                v.retain(|c| *c != k);
                                if v.is_empty() {
                                    self.waiting.remove(p);
                                }
                            }
                        }
                    }
                }
            }
            // Register the orphan under each of its missing parents so the
            // parent's arrival can find it without a full-buffer scan.
            for p in &missing {
                self.waiting.entry(*p).or_default().push(id);
            }
            self.orphan_put(id, unit);
            return Err(DagError::MissingParent);
        }
        self.link(id, unit);
        Ok(id)
    }

    /// Attach a validated unit to the DAG structures.
    fn link(&mut self, id: UnitId, unit: Unit) {
        for p in &unit.parents {
            self.children.entry(*p).or_default().push(id);
        }
        self.units.insert(id, unit);
        self.pending.insert(id);
    }

    fn known(&self, id: UnitId) -> bool {
        id == genesis_id() || self.units.contains_key(&id) || self.ancestors.contains(&id)
    }

    /// Record `id` as the newest executed unit in the parent window and
    /// prune whatever falls out of it.
    fn push_window(&mut self, id: UnitId) {
        if self.window_seq.contains_key(&id) {
            return;
        }
        self.window.push_back(id);
        self.window_seq.insert(id, self.next_seq);
        self.next_seq += 1;
        while self.window.len() > self.parent_window {
            let Some(old) = self.window.pop_front() else {
                break;
            };
            self.window_seq.remove(&old);
            // R2-R-5: bounded DAG. A unit outside the window can never be a
            // valid parent again, so its body, child list and executed mark
            // are dropped. A re-send of it then finds only stale or unknown
            // parents and can never execute again.
            // R3-R-5: a body not yet exported in a batch is moved aside
            // (not DAG-visible any more), never lost.
            let body = self.units.remove(&old);
            if !self.batched.remove(&old) && self.retain_unbatched {
                if let Some(body) = body {
                    self.retained.insert(old, body);
                }
            }
            self.children.remove(&old);
            self.executed.remove(&old);
            self.ancestors.remove(&old);
        }
    }

    /// #37-14: seed an id that was executed before the restored snapshot.
    /// Idempotent; never overrides a full unit if one is already present.
    /// Anchors must be seeded oldest first (snapshot order): they also seed
    /// the parent window (R2-R-6/7).
    pub fn mark_ancestor_known(&mut self, id: UnitId) {
        if !self.units.contains_key(&id) && !self.window_seq.contains_key(&id) {
            self.ancestors.insert(id);
            self.push_window(id);
        }
    }

    /// Number of seeded pre-snapshot ancestors (test/diagnostic aid).
    pub fn ancestor_count(&self) -> usize {
        self.ancestors.len()
    }

    /// Number of units held with a full body (test/diagnostic aid).
    pub fn unit_count(&self) -> usize {
        self.units.len()
    }

    /// Executed units counted by the parent window (relative after a
    /// snapshot restore; diagnostic aid).
    pub fn executed_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn mark_executed(&mut self, id: UnitId) {
        self.executed.insert(id);
        self.pending.remove(&id);
        self.push_window(id);
        // Newly known parent: link the buffered orphans indexed as waiting on
        // it. Linking an orphan makes it a known parent too, so keep walking
        // until fixpoint (orphans may chain).
        let mut frontier = match self.waiting.remove(&id) {
            Some(w) => w,
            None => return,
        };
        while let Some(oid) = frontier.pop() {
            let unit = match self.orphan_take(oid) {
                Some(u) => u,
                None => continue,
            };
            if !unit.parents.iter().all(|p| self.known(*p)) {
                // Still missing another parent: leave it buffered; its
                // remaining waiting-index entries stay intact.
                self.orphan_put(oid, unit);
                continue;
            }
            // Drop this orphan's stale entries under its other parents.
            for p in &unit.parents {
                if *p == id {
                    continue;
                }
                if let Some(v) = self.waiting.get_mut(p) {
                    v.retain(|c| *c != oid);
                    if v.is_empty() {
                        self.waiting.remove(p);
                    }
                }
            }
            self.link(oid, unit);
            if let Some(waiters) = self.waiting.remove(&oid) {
                frontier.extend(waiters);
            }
        }
    }

    /// Drop pending units that `ready_linearized` held back because a parent
    /// left the window, together with their pending descendants (they can
    /// never become executable).
    fn purge_stale_pending(&mut self) {
        self.stale_pending.set(false);
        let mut doomed: Vec<UnitId> = self
            .pending
            .iter()
            .copied()
            .filter(|id| {
                self.units[id].parents.iter().any(|p| {
                    !self.pending.contains(p) && !self.parent_fresh_at(*p, self.next_seq, None)
                })
            })
            .collect();
        while let Some(id) = doomed.pop() {
            if !self.pending.remove(&id) {
                continue;
            }
            self.units.remove(&id);
            if let Some(cs) = self.children.remove(&id) {
                doomed.extend(cs.into_iter().filter(|c| self.pending.contains(c)));
            }
        }
    }

    pub fn get(&self, id: UnitId) -> Option<&Unit> {
        self.units.get(&id)
    }

    /// R3-R-5: body of an executed unit for batch export: a DAG member, or
    /// one that left the parent window before it was exported.
    pub fn batch_body(&self, id: UnitId) -> Option<&Unit> {
        self.units.get(&id).or_else(|| self.retained.get(&id))
    }

    /// R3-R-5: `ids` were cut into a batch (the producer calls this from
    /// `Batch::from_applied`, i.e. at batch cut, before export / posting;
    /// a validator after a successful validation). Retained bodies among
    /// them are dropped now; in-window ones are dropped (not retained) when
    /// they leave the window. I-2: a body released here cannot be served
    /// again for a re-export; keep the batch itself if that may be needed.
    pub fn release_batched(&mut self, ids: &[UnitId]) {
        for id in ids {
            if self.retained.remove(id).is_none() && self.window_seq.contains_key(id) {
                self.batched.insert(*id);
            }
        }
    }

    /// R3-R-5: turn body retention for unbatched units on/off (see
    /// `retain_unbatched`). Turning it off drops what is retained.
    pub fn set_retain_unbatched(&mut self, on: bool) {
        self.retain_unbatched = on;
        if !on {
            self.retained.clear();
        }
    }

    /// R3-R-5: number of out-of-window bodies kept for batch export.
    pub fn retained_count(&self) -> usize {
        self.retained.len()
    }

    /// Read-only P2P-layer support (docs/mainnet/04 §2.4.3): a WantUnits
    /// peer serves missing units from BOTH linked units (`Dag::get`) and
    /// buffered orphans. Pure peek — no mutation, no consensus-path effect.
    pub fn get_orphan(&self, id: UnitId) -> Option<&Unit> {
        self.pending_orphans.get(&id)
    }

    /// Read-only visibility check for the P2P layer (docs/mainnet/04 §2.4.2):
    /// lets an off-engine observer compute which parents of an orphan are
    /// still unknown so it can emit `WantUnits`. Same predicate as the
    /// internal ingest-time missing-parent computation.
    pub fn is_known(&self, id: UnitId) -> bool {
        self.known(id)
    }

    pub fn is_executed(&self, id: UnitId) -> bool {
        // H4 (#47): pre-snapshot ancestors were executed before the restart.
        self.executed.contains(&id) || self.ancestors.contains(&id)
    }

    /// Deterministic execution order over all known-but-unexecuted units:
    /// Kahn's topological sort with plain lexicographic UnitId tie-break.
    /// The eviction salt is deliberately NOT consulted here (user-approved
    /// desalting): the salt rotates per finalized root, so salting the
    /// ready-set order made replicas that lag finalization disagree; salt
    /// remains in force for orphan eviction only. Salted execution order is
    /// deferred until finalize-batch determinization lands (README
    /// Limitations). Units whose parents are still buffered orphans stay
    /// excluded until `mark_executed` links them.
    ///
    /// R2-R-6/7: the caller executes the returned ids in order, so the i-th
    /// id runs at sequence `next_seq + i`. A unit whose parent is outside
    /// the parent window at that position is left out (with its
    /// descendants) — every node computes the same verdict at the same
    /// position, whether it runs from genesis or from a snapshot.
    pub fn ready_linearized(&self) -> Vec<UnitId> {
        // Indegree counts only parents inside the pending set; executed
        // parents (and genesis) impose no ordering constraint.
        let mut indeg: HashMap<UnitId, usize> = self
            .pending
            .iter()
            .map(|&id| {
                (
                    id,
                    self.units[&id]
                        .parents
                        .iter()
                        .filter(|p| self.pending.contains(p))
                        .count(),
                )
            })
            .collect();
        let mut ready: Vec<UnitId> = indeg
            .iter()
            .filter(|(_, &d)| d == 0)
            .map(|(&id, _)| id)
            .collect();
        ready.sort_unstable();
        let mut out = Vec::with_capacity(self.pending.len());
        let mut virtual_seq: HashMap<UnitId, u64> = HashMap::new();
        while let Some(id) = ready.first().copied() {
            ready.remove(0);
            let s = self.next_seq + out.len() as u64;
            if !self.units[&id]
                .parents
                .iter()
                .all(|p| self.parent_fresh_at(*p, s, Some(&virtual_seq)))
            {
                // Held back for good; its children never reach indegree 0.
                self.stale_pending.set(true);
                continue;
            }
            virtual_seq.insert(id, s);
            out.push(id);
            for c in self.children.get(&id).into_iter().flatten() {
                if let Some(d) = indeg.get_mut(c) {
                    *d -= 1;
                    if *d == 0 {
                        let pos = ready.binary_search(c).unwrap_or_else(|p| p);
                        ready.insert(pos, *c);
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minuend_types::USD_SCALE;

    /// 32-char uppercase [A-Z0-9] Obyte-style test address, varied by `n`.
    fn test_addr(n: u8) -> String {
        let mut bytes = vec![b'A'; 32];
        bytes[0] = b'A' + (n % 26);
        String::from_utf8(bytes).unwrap()
    }

    fn sk(n: u8) -> [u8; 32] {
        [n; 32]
    }

    /// Round 7 (PR #51 未修复项 10): the unit id is sha256 of a UTF-8 text
    /// that ends with the committed ops descriptor; the prefix before it
    /// has exactly two `|` (P-opbind's split rule), even when the
    /// descriptor itself contains `|`.
    #[test]
    fn r7_unit_text_binds_the_ops_descriptor() {
        use sha2::Digest as _;
        let d = deposit(vec![genesis_id()], &sk(1), 3);
        let text = unit_text(&d);
        let pre = unit_text_prefix(&d);
        assert!(text.starts_with(&pre) && pre.starts_with("mnu3|") && pre.ends_with('|'));
        assert_eq!(pre.matches('|').count(), 2);
        let desc = op_descriptor(&d.op).unwrap();
        assert!(desc.starts_with("d:"));
        assert_eq!(&text[pre.len()..], desc);
        let h: [u8; 32] = sha2::Sha256::digest(text.as_bytes()).into();
        assert_eq!(unit_id(&d), UnitId(h));
        // An ops-leaf-relevant change (the deposit amount) changes the id.
        let mut d2 = d.clone();
        if let Op::Deposit { amount, .. } = &mut d2.op {
            *amount += 1;
        }
        assert_ne!(unit_id(&d2), unit_id(&d));
        // A deposit address with '|' (refused at execution, still a unit):
        // the prefix still splits at its own second '|'.
        let mut odd = d.clone();
        if let Op::Deposit { addr, .. } = &mut odd.op {
            *addr = "A|B|C".into();
        }
        let pre = unit_text_prefix(&odd);
        assert_eq!(pre.matches('|').count(), 2);
        assert!(unit_text(&odd).ends_with(&op_descriptor(&odd.op).unwrap()));
        // Ops without a descriptor end in `x`.
        let r = sign_unit(
            vec![genesis_id()],
            Op::StakeOracle {
                account: account_id_from_pubkey(
                    &ed25519_dalek::SigningKey::from_bytes(&sk(2))
                        .verifying_key()
                        .to_bytes(),
                ),
            },
            &sk(2),
        );
        assert!(op_descriptor(&r.op).is_none());
        assert!(unit_text(&r).ends_with("|x"));
        assert!(verify_sig_by_id(&r, &unit_id(&r)));
    }

    fn deposit(parents: Vec<UnitId>, secret: &[u8; 32], aa: u8) -> Unit {
        let account = account_id_from_pubkey(
            &ed25519_dalek::SigningKey::from_bytes(secret)
                .verifying_key()
                .to_bytes(),
        );
        sign_unit(
            parents,
            Op::Deposit {
                account,
                addr: test_addr(aa),
                amount: USD_SCALE as i128,
                aa_unit: [aa; 32],
            },
            secret,
        )
    }

    #[test]
    fn two_children_deterministic_across_replicas() {
        // Tie-break is plain lexicographic UnitId order (desalted): every
        // replica derives the SAME order regardless of finalization state.
        let mut dag = Dag::new();
        let g = genesis_id();
        let u1 = deposit(vec![g], &sk(1), 1);
        let u2 = deposit(vec![g], &sk(2), 2);
        dag.insert(u2.clone()).unwrap();
        dag.insert(u1.clone()).unwrap();
        let expect = dag.ready_linearized();
        let mut dag2 = Dag::new();
        dag2.insert(u1.clone()).unwrap();
        dag2.insert(u2.clone()).unwrap();
        assert_eq!(dag2.ready_linearized(), expect);
        // Same total set either way.
        let mut s1 = expect.clone();
        s1.sort_by_key(|a| a.0);
        let mut s2 = vec![unit_id(&u1), unit_id(&u2)];
        s2.sort_by_key(|a| a.0);
        assert_eq!(s1, s2);
    }

    #[test]
    fn ready_order_is_salt_independent_and_lex() {
        // The eviction salt must NOT reorder ready units (desalting): two
        // engines with different salts produce identical execution order.
        let g = genesis_id();
        let mk = |dag: &mut Dag| -> Vec<UnitId> {
            let secret = [7u8; 32];
            let u1 = deposit(vec![g], &secret, 1);
            let u2 = deposit(vec![g], &secret, 2);
            dag.insert(u1.clone()).unwrap();
            dag.insert(u2.clone()).unwrap();
            dag.ready_linearized()
        };
        let mut d1 = Dag::new();
        let o1 = mk(&mut d1);
        let mut d2 = Dag::new();
        d2.set_eviction_salt([0x99; 32]);
        assert_eq!(mk(&mut d2), o1, "salt must not affect ready order");
        // And the order is exactly lexicographic by UnitId.
        let mut lex = o1.clone();
        lex.sort();
        assert_eq!(o1, lex);
    }

    #[test]
    fn missing_parent_rejected() {
        let mut dag = Dag::new();
        let fake = UnitId([9; 32]);
        let u = deposit(vec![fake], &sk(1), 1);
        assert_eq!(dag.insert(u), Err(DagError::MissingParent));
    }

    #[test]
    fn bad_parent_count_rejected() {
        let mut dag = Dag::new();
        let g = genesis_id();
        let account = account_id_from_pubkey(
            &ed25519_dalek::SigningKey::from_bytes(&sk(1))
                .verifying_key()
                .to_bytes(),
        );
        let u = sign_unit(
            vec![g, g, g],
            Op::Deposit {
                account,
                addr: test_addr(1),
                amount: 1,
                aa_unit: [1; 32],
            },
            &sk(1),
        );
        assert!(matches!(
            dag.insert(u),
            Err(DagError::TooManyParents) | Err(DagError::BadParents)
        ));
        let u2 = sign_unit(
            vec![],
            Op::Deposit {
                account,
                addr: test_addr(2),
                amount: 1,
                aa_unit: [2; 32],
            },
            &sk(1),
        );
        assert_eq!(dag.insert(u2), Err(DagError::EmptyParents));
    }

    /// H4 (#47): an id seeded as a pre-snapshot ancestor was already
    /// executed before the restart. Re-sending that old unit must be refused
    /// as Duplicate (not linked + re-executed), while new children of it
    /// still link normally.
    #[test]
    fn pre_snapshot_ancestor_resend_is_duplicate() {
        let g = genesis_id();
        let old = deposit(vec![g], &sk(1), 1);
        let old_id = unit_id(&old);
        let mut dag = Dag::new();
        dag.mark_ancestor_known(old_id);
        assert!(dag.is_executed(old_id), "ancestor must count as executed");
        assert_eq!(dag.insert(old), Err(DagError::Duplicate));
        assert!(
            dag.ready_linearized().is_empty(),
            "re-sent pre-snapshot unit must not become ready again"
        );
        let child = deposit(vec![old_id], &sk(1), 2);
        let cid = dag.insert(child).unwrap();
        assert_eq!(dag.ready_linearized(), vec![cid]);
    }

    #[test]
    fn out_of_order_ingest_recovered() {
        let mut dag = Dag::new();
        let g = genesis_id();
        // child first: parent unknown -> buffered orphan, Err(MissingParent)
        let parent = deposit(vec![g], &sk(1), 1);
        let pid = unit_id(&parent);
        let child = deposit(vec![pid], &sk(1), 2);
        assert_eq!(dag.insert(child.clone()), Err(DagError::MissingParent));
        // retry of the same orphan reports acceptance (still pending)
        assert_eq!(dag.insert(child.clone()), Ok(unit_id(&child)));
        // parent arrives: both become known; after executing the parent the
        // child is linked and ready.
        dag.insert(parent).unwrap();
        assert!(dag.ready_linearized().contains(&pid));
        dag.mark_executed(pid);
        let ready = dag.ready_linearized();
        assert!(ready.contains(&unit_id(&child)), "orphan must be recovered");
    }

    #[test]
    fn orphan_reverse_index_links_multi_and_chained() {
        let mut dag = Dag::new();
        let g = genesis_id();
        // Two missing parents, then a child waiting on the first child.
        let p1 = deposit(vec![g], &sk(1), 1);
        let id1 = unit_id(&p1);
        let p2 = deposit(vec![g], &sk(2), 2);
        let id2 = unit_id(&p2);
        let mut mparents = vec![id1, id2];
        mparents.sort();
        let mid = deposit(mparents, &sk(3), 3);
        let mid_id = unit_id(&mid);
        let leaf = deposit(vec![mid_id], &sk(4), 4);
        let leaf_id = unit_id(&leaf);
        assert_eq!(dag.insert(leaf.clone()), Err(DagError::MissingParent));
        assert_eq!(dag.insert(mid.clone()), Err(DagError::MissingParent));
        // First parent alone must not link `mid` (second parent still missing).
        dag.insert(p1).unwrap();
        dag.mark_executed(id1);
        assert!(dag.get(mid_id).is_none(), "mid still misses a parent");
        // Second parent arrives: mid links via the reverse index, which in
        // turn unblocks leaf (chained fixpoint).
        dag.insert(p2).unwrap();
        dag.mark_executed(id2);
        assert!(dag.get(mid_id).is_some(), "indexed orphan must link");
        assert!(dag.get(leaf_id).is_some(), "chained orphan must link");
        assert!(dag.waiting.is_empty(), "index must not leak entries");
    }

    #[test]
    fn gov_deposit_addr_in_canonical_bytes() {
        let account = account_id_from_pubkey(
            &ed25519_dalek::SigningKey::from_bytes(&sk(5))
                .verifying_key()
                .to_bytes(),
        );
        let mk = |addr: String| {
            sign_unit(
                vec![genesis_id()],
                Op::GovDeposit {
                    account,
                    addr,
                    amount: 7,
                    aa_unit: [9; 32],
                },
                &sk(5),
            )
        };
        let u1 = mk(test_addr(6));
        let u2 = mk(test_addr(7));
        // Distinct addresses must yield distinct unit ids (addr is covered
        // by the signature preimage).
        assert_ne!(unit_id(&u1), unit_id(&u2));
        assert_ne!(u1.sig, u2.sig);
    }
    #[test]
    fn oversized_deposit_addr_rejected() {
        let account = account_id_from_pubkey(
            &ed25519_dalek::SigningKey::from_bytes(&sk(6))
                .verifying_key()
                .to_bytes(),
        );
        // 129 chars > MAX_ADDR_LEN (128): must bounce before any buffering.
        let long = "A".repeat(129);
        let u = sign_unit(
            vec![genesis_id()],
            Op::Deposit {
                account,
                addr: long.clone(),
                amount: 1,
                aa_unit: [1; 32],
            },
            &sk(6),
        );
        assert_eq!(dag_insert_check(u), Err(DagError::AddrTooLong));
        // GovDeposit is bound by the same cap.
        let ug = sign_unit(
            vec![genesis_id()],
            Op::GovDeposit {
                account,
                addr: long,
                amount: 1,
                aa_unit: [1; 32],
            },
            &sk(6),
        );
        assert_eq!(dag_insert_check(ug), Err(DagError::AddrTooLong));
        // Boundary: exactly 128 chars is legal.
        let ok = sign_unit(
            vec![genesis_id()],
            Op::Deposit {
                account,
                addr: "A".repeat(MAX_ADDR_LEN),
                amount: 1,
                aa_unit: [1; 32],
            },
            &sk(6),
        );
        assert!(dag_insert_check(ok).is_ok());
    }

    /// insert() recomputes the id from canonical bytes; to exercise the
    /// caller-supplied-id path (insert_verified) with a MISMATCHING id we
    /// pass a deliberately wrong id directly.
    fn dag_insert_check(u: Unit) -> Result<UnitId, DagError> {
        let mut dag = Dag::new();
        dag.insert(u)
    }

    #[test]
    fn orphan_retry_with_different_payload_rejected() {
        let mut dag = Dag::new();
        let fake = UnitId([9; 32]);
        let child = deposit(vec![fake], &sk(3), 1);
        assert_eq!(dag.insert(child.clone()), Err(DagError::MissingParent));
        // Same id, different canonical payload (amount tampered): the
        // retry must not be silently accepted as the buffered copy.
        let account = account_id_from_pubkey(
            &ed25519_dalek::SigningKey::from_bytes(&sk(3))
                .verifying_key()
                .to_bytes(),
        );
        let impostor = sign_unit(
            vec![fake],
            Op::Deposit {
                account,
                addr: test_addr(1),
                amount: 2 * USD_SCALE as i128,
                aa_unit: [1; 32],
            },
            &sk(3),
        );
        // Force the impostor through the caller-supplied-id path with the
        // ORIGINAL unit's id (signature no longer matches, but insert_verified
        // is the DAG-level gate and must still catch the payload swap).
        let original_id = unit_id(&child);
        assert_eq!(
            dag.insert_verified(impostor, original_id),
            Err(DagError::RetryMismatch)
        );
        // The genuine retry still succeeds.
        assert_eq!(dag.insert(child), Ok(original_id));
    }

    // ---- R2-R-5/6/7/13 (round 2 of #47) ----

    /// Execute everything ready, the way `Engine::apply_ready` does.
    fn run(dag: &mut Dag) -> Vec<UnitId> {
        let ready = dag.ready_linearized();
        for id in &ready {
            dag.mark_executed(*id);
        }
        ready
    }

    fn dep_n(parents: Vec<UnitId>, n: u32) -> Unit {
        let secret = sk(7);
        let account = account_id_from_pubkey(
            &ed25519_dalek::SigningKey::from_bytes(&secret)
                .verifying_key()
                .to_bytes(),
        );
        let mut aa = [0u8; 32];
        aa[..4].copy_from_slice(&n.to_le_bytes());
        sign_unit(
            parents,
            Op::Deposit {
                account,
                addr: test_addr(1),
                amount: USD_SCALE as i128 + n as i128,
                aa_unit: aa,
            },
            &secret,
        )
    }

    /// Execute a chain of `n` units on top of `tip`; returns their ids.
    fn chain(dag: &mut Dag, mut tip: UnitId, n: u32, salt: u32) -> Vec<UnitId> {
        let mut ids = Vec::new();
        for i in 0..n {
            let u = dep_n(vec![tip], salt * 1000 + i);
            tip = dag.insert(u).unwrap();
            assert_eq!(run(dag), vec![tip]);
            ids.push(tip);
        }
        ids
    }

    /// R3-R-5: bodies of executed units that leave the parent window before
    /// they were exported stay available to batch export (but are no
    /// longer DAG members); exporting releases them, and in-window
    /// exported units are dropped, not retained, when they leave.
    #[test]
    fn r3r5_unbatched_bodies_survive_window_until_released() {
        let g = genesis_id();
        let mut dag = Dag::with_parent_window(3);
        let ids = chain(&mut dag, g, 8, 3);
        for id in &ids {
            assert!(dag.batch_body(*id).is_some());
        }
        assert!(dag.get(ids[0]).is_none(), "not a DAG member any more");
        assert_eq!(dag.retained_count(), 5);
        // Still not a valid parent.
        assert!(dag.insert(dep_n(vec![ids[0]], 77)).is_err());
        dag.release_batched(&ids[..6]);
        assert_eq!(dag.retained_count(), 0);
        assert!(dag.batch_body(ids[0]).is_none());
        assert!(dag.batch_body(ids[5]).is_some(), "in window");
        chain(&mut dag, ids[7], 3, 4);
        // ids[5] was exported: dropped. ids[6], ids[7] were not: retained.
        assert!(dag.batch_body(ids[5]).is_none());
        assert!(dag.batch_body(ids[6]).is_some() && dag.batch_body(ids[7]).is_some());
        assert_eq!(dag.retained_count(), 2);
        // A relay that never exports can switch retention off.
        dag.set_retain_unbatched(false);
        assert_eq!(dag.retained_count(), 0);
    }

    #[test]
    fn parent_window_matches_snapshot_anchor_ring() {
        assert_eq!(PARENT_WINDOW, 2 * minuend_types::BATCH_MAX_UNITS as usize);
        assert_eq!(Dag::new().parent_window, PARENT_WINDOW);
    }

    /// R2-R-6: an old `parents == [genesis]` unit re-sent after it left the
    /// window must never execute again — neither on the node that ran it
    /// (its body was pruned) nor on a node restored from a snapshot.
    #[test]
    fn genesis_parent_unit_resent_after_window_is_not_reexecuted() {
        let g = genesis_id();
        let mut dag = Dag::with_parent_window(3);
        let old = dep_n(vec![g], 1);
        let old_id = dag.insert(old.clone()).unwrap();
        assert_eq!(run(&mut dag), vec![old_id]);
        let later = chain(&mut dag, old_id, 3, 1);
        // `old` left the 3-wide window: pruned, and genesis is stale too.
        assert!(dag.get(old_id).is_none());
        assert_eq!(dag.insert(old.clone()), Err(DagError::StaleParent));
        assert!(run(&mut dag).is_empty());
        // Any NEW genesis-parent unit is refused once the window is full.
        assert_eq!(dag.insert(dep_n(vec![g], 99)), Err(DagError::StaleParent));

        // A node restored from the snapshot anchors (the same 3 ids) agrees.
        let mut restored = Dag::with_parent_window(3);
        for id in &later {
            restored.mark_ancestor_known(*id);
        }
        assert_eq!(restored.insert(old), Err(DagError::StaleParent));
        assert!(run(&mut restored).is_empty());
        // Children of in-window units still link and run on both.
        let c = dep_n(vec![later[0]], 50);
        let cid = dag.insert(c.clone()).unwrap();
        assert_eq!(run(&mut dag), vec![cid]);
        assert_eq!(restored.insert(c).unwrap(), cid);
        assert_eq!(run(&mut restored), vec![cid]);
    }

    /// R2-R-7: a unit naming an ancient parent is refused by the
    /// long-running node too, so it never lands in a batch that a
    /// snapshot-restored replayer cannot link.
    #[test]
    fn ancient_parent_is_refused_by_full_and_restored_nodes_alike() {
        let g = genesis_id();
        let mut full = Dag::with_parent_window(4);
        let ids = chain(&mut full, g, 8, 2);
        let mut restored = Dag::with_parent_window(4);
        for id in &ids[ids.len() - 4..] {
            restored.mark_ancestor_known(*id);
        }
        // ids[0] executed 8 units ago: outside the window on both nodes.
        let ancient = dep_n(vec![ids[0]], 7);
        let full_res = full.insert(ancient.clone());
        let rest_res = restored.insert(ancient);
        assert!(full_res.is_err() && rest_res.is_err());
        assert!(run(&mut full).is_empty() && run(&mut restored).is_empty());
        // ids[4] is the oldest in-window unit: accepted by both.
        let ok = dep_n(vec![ids[4]], 8);
        let a = full.insert(ok.clone()).unwrap();
        let b = restored.insert(ok).unwrap();
        assert_eq!(run(&mut full), vec![a]);
        assert_eq!(run(&mut restored), vec![b]);
        // The DAG no longer keeps the whole history (R2-R-5).
        assert!(full.unit_count() <= 4 + 1);
    }

    /// R2-R-6/7: staleness is judged at execution position, so a parent
    /// that falls out of the window while its child waits in the same
    /// ready pass holds the child back (and the child is purged later).
    #[test]
    fn staleness_is_judged_at_execution_position() {
        let g = genesis_id();
        let mut dag = Dag::with_parent_window(2);
        let a = dep_n(vec![g], 1);
        let aid = unit_id(&a);
        let b = dep_n(vec![aid], 2);
        let bid = unit_id(&b);
        let c = dep_n(vec![bid], 3);
        let cid = unit_id(&c);
        let mut pd = vec![aid, cid];
        pd.sort();
        let d = dep_n(pd, 4);
        // Insert without executing in between (as a batch ingest would).
        for u in [a, b, c, d.clone()] {
            let id = unit_id(&u);
            dag.insert_verified(u, id).unwrap();
        }
        // a@0 b@1 c@2 d@3: a (seq 0) is outside the 2-wide window at 3.
        assert_eq!(run(&mut dag), vec![aid, bid, cid]);
        // d was held back and is purged on the next insert; a retry can
        // never run again (a is gone for good: it is only an orphan now).
        assert!(dag.insert(d).is_err());
        assert_eq!(dag.unit_count(), 2, "held-back d purged");
        assert!(run(&mut dag).is_empty());
    }

    /// R2-R-13: eviction comes from the ordered index — always the orphan
    /// with the smallest salted key — and the index follows salt rotation.
    #[test]
    fn orphan_eviction_uses_ordered_index() {
        let mut dag = Dag::new();
        for i in 0..(ORPHAN_CAP as u32 + 10) {
            let fake = UnitId(sha256(&i.to_le_bytes()));
            let u = dep_n(vec![fake], i);
            if dag.pending_orphans.len() == ORPHAN_CAP {
                let min = *dag
                    .pending_orphans
                    .keys()
                    .min_by_key(|k| dag.eviction_key(**k))
                    .unwrap();
                assert_eq!(dag.insert(u), Err(DagError::MissingParent));
                assert!(!dag.pending_orphans.contains_key(&min), "min key evicted");
            } else {
                assert_eq!(dag.insert(u), Err(DagError::MissingParent));
            }
            assert_eq!(dag.orphan_order.len(), dag.pending_orphans.len());
        }
        assert_eq!(dag.orphan_count(), ORPHAN_CAP);
        dag.set_eviction_salt([5u8; 32]);
        let (k, id) = *dag.orphan_order.iter().next().unwrap();
        assert_eq!(k, dag.eviction_key(id));
        let min = dag
            .pending_orphans
            .keys()
            .map(|x| dag.eviction_key(*x))
            .min()
            .unwrap();
        assert_eq!(k, min);
    }
}
