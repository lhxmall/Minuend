//! Generates a vault-AA withdrawal claim (JSON) for one Obyte address.
//!
//! #47 A2: the vault pays against the finalized WITNESS root (`wit_root_<h>`,
//! Obyte merkle over `minuend_state::wit_leaves`), proving two leaves:
//!   adr:{address}:{account_hex}                      — payee binding
//!   acct:{account_hex}:{collateral}:{perp}:{withdrawn} — balance + W
//! (The 1024-hex aa_forest is no longer payment authority: its leaves are
//! never published, so no dispute could point at a forged forest leaf.)
//!
//! Output JSON shape (obyte-local/withdraw_claim.json):
//! {
//!   "height": 1,
//!   "wit_root": "<44-char base64 witness root>",
//!   "account": "<64-hex account id>",
//!   "collateral": "<decimal>", "perp": "<decimal>", "withdrawn": "<decimal>",
//!   "adr_proof":  { "root", "siblings", "index" },
//!   "acct_proof": { "root", "siblings", "index" }
//! }
//! The vault trigger is {withdraw:1, amount, account, collateral, perp,
//! withdrawn, adr_proof, acct_proof} sent FROM `address`.
//!
//! Usage: cargo run -p minuend-settle --example gen_withdraw_proof -- <obyte_address> [collateral] [perp] [withdrawn]
use minuend_state::{obyte_merkle, wit_leaves, Account, ChainState};
use minuend_types::AccountId;
use std::path::PathBuf;

fn main() {
    let addr = std::env::args()
        .nth(1)
        .expect("usage: gen_withdraw_proof <obyte_address> [collateral] [perp] [withdrawn]");
    let collateral: i128 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000 * 1_000_000);
    let perp: u128 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    // Cumulative sidechain-signed withdrawals (W): the vault enforces
    // "this claim + prior claims <= W".
    let withdrawn: i128 = std::env::args()
        .nth(4)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // A deterministic account id for the claim, bound to `addr` exactly as
    // the engine binds it at the first deposit, plus a decoy peer so every
    // proof carries at least one sibling (ocore bans empty arrays).
    let account = AccountId(minuend_types::sha256(format!("claim:{addr}").as_bytes()));
    let decoy = AccountId([0x5b; 32]);
    let mut state = ChainState::new();
    let mut a = Account::new(account);
    a.collateral = collateral;
    state.accounts.insert(account, a);
    state.perp_balances.insert(account, perp);
    state.withdrawn_total.insert(account, withdrawn);
    state.bind_aa_address(account, &addr);
    let mut d = Account::new(decoy);
    d.collateral = 500;
    state.accounts.insert(decoy, d);
    state.bind_aa_address(decoy, "5B7BJSCMFQYUOLDLJHROMOKC5QCLPZLK");

    let leaves = wit_leaves(&state);
    let acct_hex = hex::encode(account.0);
    let adr_leaf = format!("adr:{addr}:{acct_hex}");
    let acct_leaf = format!("acct:{acct_hex}:{collateral}:{perp}:{withdrawn}");
    let proof_of = |leaf: &str| {
        let i = leaves
            .iter()
            .position(|l| l == leaf)
            .unwrap_or_else(|| panic!("leaf {leaf} missing from the witness tree"));
        let p = obyte_merkle::proof(&leaves, i);
        serde_json::json!({"root": p.root, "siblings": p.siblings, "index": p.index})
    };
    let claim = serde_json::json!({
        "height": 1,
        "wit_root": obyte_merkle::root(&leaves),
        "account": acct_hex,
        "collateral": collateral.to_string(),
        "perp": perp.to_string(),
        "withdrawn": withdrawn.to_string(),
        "adr_proof": proof_of(&adr_leaf),
        "acct_proof": proof_of(&acct_leaf),
    });
    let out =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../obyte-local/withdraw_claim.json");
    std::fs::write(&out, serde_json::to_string_pretty(&claim).unwrap()).expect("write");
    println!("wrote {} (witness root {})", out.display(), claim["wit_root"]);
}
