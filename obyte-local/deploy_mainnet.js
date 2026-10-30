"use strict";

// MINUEND seven-AA deployment — Obyte MAINNET (GBYTE collateral).
//
// Posts the vault BASE, minuend_dispute.aa, minuend_dispute_fill.aa,
// minuend_dispute_bind.aa, minuend_dispute_book.aa, minuend_dispute_claw.aa
// (round 6), minuend_rollup.aa and
// the vault INSTANCE {base_aa, params:{rollup}} via a light headless wallet
// (default mainnet hub), binds all five dispute AAs, smoke-triggers the
// vault, and writes
// obyte-local/deployment.json.
//
//   MINUEND_DEPLOY_MNEMONIC="word word ... " PERP_ASSET_ID=<44-char id> \
//     node obyte-local/deploy_mainnet.js   # run issue_perp.js FIRST
//
// Needs funded GBYTE (definition posts + 2x20000 bind + smoke). Does NOT
// fund the 1000 GBYTE standing pool here — the operator funds {pool:1} after
// verifying deployment.json addresses against the audited sources.

const path = require("path");
const fs = require("fs");

const { boot } = require("./mainnet_wallet.js");
const parseOjson = require("ocore/formula/parse_ojson").parse;

const PERP_ASSET_ID = process.env.PERP_ASSET_ID;
if (!PERP_ASSET_ID || PERP_ASSET_ID === "PERP_ASSET_ID_HERE" || PERP_ASSET_ID.length !== 44)
  throw new Error("PERP_ASSET_ID env (44-char base64 asset id) required — run issue_perp.js first");

const CHAIN_ID = "minuend-v2";
const POOL_FUND_GROSS = 10000000010000; // POOL_MIN 1e12 + 10000 fee for {pool:1}
const CHALLENGE_SECS = 3600;

function readAa(file) {
  return fs.readFileSync(path.join(__dirname, "agents", file), "utf8");
}
function substitute(src, subs) {
  for (const [k, v] of Object.entries(subs)) src = src.split(k).join(v);
  return src;
}
function parseAa(src, file) {
  return new Promise((resolve, reject) =>
    parseOjson(src, (err, res) => (err ? reject(new Error(`${file}: ${err}`)) : resolve(res[1])))
  );
}

async function main() {
  const { wallet, address: fromAddress, composer, network, objectHash } = await boot();
  console.log("deployer:", fromAddress);

  async function postDefinition(defObj, label) {
    // Payload: app "definition", definition = ["autonomous agent", obj] —
    // the array form ocore wants (HeadlessWalletChild.deployAgent).
    const payload = { address: objectHash.getChash160(defObj), definition: defObj };
    const message = {
      app: "definition",
      payload_location: "inline",
      payload_hash: objectHash.getBase64Hash(payload),
      payload,
    };
    const objJoint = await new Promise((resolve, reject) => {
      composer.composeJoint({
        paying_addresses: [fromAddress],
        outputs: [{ address: fromAddress, amount: 0 }],
        messages: [message],
        signer: wallet.signer,
        callbacks: composer.getSavingCallbacks({ ifNotEnoughFunds: reject, ifError: reject, ifOk: resolve }),
      });
    });
    network.broadcastJoint(objJoint);
    console.log(`${label} posted: unit=${objJoint.unit.unit} address=${payload.address}`);
    return { unit: objJoint.unit.unit, address: payload.address };
  }

  function triggerAa({ to, amount, data }, label) {
    // Single multi-payment carrying the data message.
    return new Promise((resolve, reject) => {
      const messages = [{
        app: "data",
        payload_location: "inline",
        payload_hash: objectHash.getBase64Hash(data),
        payload: data,
      }];
      wallet.issueChangeAddressAndSendMultiPayment(
        { to_address: to, amount, messages },
        (err, unit) => (err ? reject(new Error(`${label} failed: ${err}`)) : (console.log(`${label}: ${unit}`), resolve(unit)))
      );
    });
  }

  function readAaState(address) {
    return network.requestFromLightVendor("light/get_aa_state_vars", { address });
  }

  function waitBeat(unit, label) {
    // Light client: no local stability signal; fixed beat so the unit
    // propagates before the next step that depends on it.
    console.log(`waiting 30s for ${label} ${unit} to propagate...`);
    return new Promise((r) => setTimeout(r, 30000));
  }

  // 1. Dispute AAs FIRST (#13): their definitions carry no rollup address,
  // the rollup hardcodes THEM — mutual hardcoding would be a chash cycle.
  // Round 2 (R2-A-3): vault BASE first (names no address); dispute.aa
  // hardcodes the base and derives the rollup's vault instance.
  const vaultBaseSrc = substitute(readAa("minuend_vault.aa"), { PERP_ASSET_ID_HERE: PERP_ASSET_ID });
  const vaultBaseDef = ["autonomous agent", await parseAa(vaultBaseSrc, "minuend_vault.aa")];
  const vaultBase = await postDefinition(vaultBaseDef, "vault base");
  await waitBeat(vaultBase.unit, "vault base");
  const disputeSrc = substitute(readAa("minuend_dispute.aa"), { VAULT_BASE_HERE: vaultBase.address });
  const fillSrc = readAa("minuend_dispute_fill.aa");
  const disputeDef = ["autonomous agent", await parseAa(disputeSrc, "minuend_dispute.aa")];
  const fillDef = ["autonomous agent", await parseAa(fillSrc, "minuend_dispute_fill.aa")];
  // #47 A2: the binding dispute AA (W / adr: witness pins).
  // R4-A-4: P-adr reads the vault deposit ledger too (derived from the base).
  const bindSrc = substitute(readAa("minuend_dispute_bind.aa"), { VAULT_BASE_HERE: vaultBase.address });
  const bindDef = ["autonomous agent", await parseAa(bindSrc, "minuend_dispute_bind.aa")];
  const dispute = await postDefinition(disputeDef, "dispute");
  const fill = await postDefinition(fillDef, "fill");
  const bindAa = await postDefinition(bindDef, "bind");
  // Round 2: P-ghost / P-skip live in the book dispute AA (ops budget).
  const bookSrc = readAa("minuend_dispute_book.aa");
  const bookDef = ["autonomous agent", await parseAa(bookSrc, "minuend_dispute_book.aa")];
  const bookAa = await postDefinition(bookDef, "book");
  // Round 6: P-claw (both legs of one fill) in the claw dispute AA.
  const clawSrc = readAa("minuend_dispute_claw.aa");
  const clawDef = ["autonomous agent", await parseAa(clawSrc, "minuend_dispute_claw.aa")];
  const clawAa = await postDefinition(clawDef, "claw");
  await waitBeat(dispute.unit, "dispute");

  // 2. Rollup with both dispute addresses hardcoded, then the vault.
  const rollupSrc = substitute(readAa("minuend_rollup.aa"), {
    DISPUTE_AA_HERE: dispute.address,
    DISPUTE_FILL_AA_HERE: fill.address,
    DISPUTE_BIND_AA_HERE: bindAa.address,
    DISPUTE_BOOK_AA_HERE: bookAa.address,
    DISPUTE_CLAW_AA_HERE: clawAa.address,
  });
  const rollupDef = ["autonomous agent", await parseAa(rollupSrc, "minuend_rollup.aa")];
  const rollup = await postDefinition(rollupDef, "rollup");
  await waitBeat(rollup.unit, "rollup");

  const vaultDef = ["autonomous agent", { base_aa: vaultBase.address, params: { rollup: rollup.address } }];
  const vault = await postDefinition(vaultDef, "vault");
  await waitBeat(vault.unit, "vault");

  // 3. Bind all five dispute AAs (20000 each, rollup address in trigger data);
  // assert via AA state.
  await triggerAa(
    { to: dispute.address, amount: 20000, data: { bind: 1, rollup: rollup.address } },
    "dispute bind"
  );
  await triggerAa(
    { to: fill.address, amount: 20000, data: { bind_fill: 1, rollup: rollup.address } },
    "fill bind"
  );
  await triggerAa(
    { to: bindAa.address, amount: 20000, data: { bind_bind: 1, rollup: rollup.address } },
    "binding-dispute bind"
  );
  await triggerAa(
    { to: bookAa.address, amount: 20000, data: { bind_book: 1, rollup: rollup.address } },
    "book-dispute bind"
  );
  await triggerAa(
    { to: clawAa.address, amount: 20000, data: { bind_claw: 1, rollup: rollup.address } },
    "claw-dispute bind"
  );
  await waitBeat("binds", "bind");
  const state = await readAaState(rollup.address);
  if (String(state.dispute_aa) !== String(dispute.address))
    throw new Error("dispute_aa not bound: " + JSON.stringify(state.dispute_aa));
  if (String(state.dispute_fill_aa) !== String(fill.address))
    throw new Error("dispute_fill_aa not bound: " + JSON.stringify(state.dispute_fill_aa));
  if (String(state.dispute_bind_aa) !== String(bindAa.address))
    throw new Error("dispute_bind_aa not bound: " + JSON.stringify(state.dispute_bind_aa));
  if (String(state.dispute_book_aa) !== String(bookAa.address))
    throw new Error("dispute_book_aa not bound: " + JSON.stringify(state.dispute_book_aa));
  if (String(state.dispute_claw_aa) !== String(clawAa.address))
    throw new Error("dispute_claw_aa not bound: " + JSON.stringify(state.dispute_claw_aa));
  console.log("all five dispute AAs bound");

  // 4. Write deployment.json.
  const info = {
    network: "mainnet",
    rollup_aa_address: rollup.address,
    dispute_aa_address: dispute.address,
    dispute_fill_aa_address: fill.address,
    dispute_bind_aa_address: bindAa.address,
    dispute_book_aa_address: bookAa.address,
    dispute_claw_aa_address: clawAa.address,
    vault_aa_address: vault.address,
    vault_base_aa_address: vaultBase.address,
    perp_asset_id: PERP_ASSET_ID,
    chain_id: CHAIN_ID,
    assertion_version: 4,
    pool_fund_gross: POOL_FUND_GROSS,
    challenge_secs: CHALLENGE_SECS,
    deployed_at: new Date().toISOString(),
  };
  fs.writeFileSync(path.join(__dirname, "deployment.json"), JSON.stringify(info, null, 2));
  console.log("deployment.json written");

  // Smoke: 10000+1 byte {deposit:1} to vault. #37-2: a send/network error
  // is NOT evidence the AA responded — the old catch-all printed OK either
  // way. Record the real outcome and only claim the deployment verified
  // when the AA actually accepted the deposit.
  let smokeOutcome;
  try {
    // R3-A-5: a deposit must name the credited sidechain account (64 hex);
    // the smoke byte goes to MINUEND_SMOKE_ACCOUNT (default: the all-zero
    // account no one can sign for — the byte just stays in the vault).
    const smokeAccount = process.env.MINUEND_SMOKE_ACCOUNT || "0".repeat(64);
    const unit = await triggerAa({ to: vault.address, amount: 10001, data: { deposit: 1, account: smokeAccount } }, "vault smoke");
    // Wait a beat, then confirm the vault AA state still answers (the AA
    // existed before the smoke, so a bounced deposit is not detectable from
    // state; the honest claim is "submitted and propagated").
    await waitBeat(unit, "vault smoke");
    smokeOutcome = "submitted";
    console.log("vault smoke submitted:", unit);
  } catch (e) {
    smokeOutcome = "unknown";
    console.warn("vault smoke NOT VERIFIED:", String(e).slice(0, 200));
  }
  if (smokeOutcome === "submitted") {
    console.log("OK: mainnet deploy complete (vault smoke submitted). Fund the 1000 GBYTE standing pool with {pool:1} before submitting.");
  } else {
    console.warn("PARTIAL: definitions deployed and deployment.json written, but the vault smoke did not go through — verify the vault AA manually.");
  }
  process.exit(smokeOutcome === "submitted" ? 0 : 2);
}

main().catch((e) => {
  console.error("DEPLOY FAILED:", e && e.stack ? e.stack : e);
  process.exit(1);
});
