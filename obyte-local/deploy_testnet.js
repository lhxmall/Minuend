"use strict";

// MINUEND vault AA — Obyte TESTNET deployment script.
//
// Deploys the security-hardened minuend_vault.aa to a testnet node, performs an
// initial smoke deposit, and prints the resulting AA address for operators.
//
// Prerequisites:
//   - testnet data dir / node reachable by aa-testkit (see vendor/aa-testkit)
//   - run from obyte-local/:  node deploy_testnet.js
//
// This script does NOT post batches or move real user funds; it is the first
// step of the plan's "达标代码 + 测试网部署脚本" deliverable. Mainnet
// deployment is explicitly out of scope (see plan section E).

const path = require("path");
const fs = require("fs");

// ===== CONFIG: PERP governance asset ================================
// Set to the real PERP asset id once issued, then redeploy the AA.
const PERP_ASSET_ID = "PERP_ASSET_ID_HERE";
// ====================================================================

// Chain id baked into the AA definitions and echoed into deployment.json.
const CHAIN_ID = "minuend-v2";

// The .aa sources carry PERP_ASSET_ID_HERE / DISPUTE_AA_HERE placeholders;
// aa-testkit reads agent definitions from disk, so materialize substituted
// copies and deploy those. #13: the dispute AAs hash FIRST (their defs
// carry no rollup address — mutual hardcoding would be a chash cycle),
// then the rollup is materialized with both dispute addresses hardcoded,
// then the vault with the deployed rollup address.
function resolveAa(agentFile, subs, outName) {
  let src = fs.readFileSync(path.join(__dirname, "agents", agentFile), "utf8");
  for (const [k, v] of Object.entries(subs)) src = src.split(k).join(v);
  const out = path.join(__dirname, "agents", outName);
  fs.writeFileSync(out, src);
  return out;
}
function resolveRollupAa(disputeAddr, fillAddr, bindAddr, bookAddr, clawAddr, xfAddr, mfAddr) {
  return resolveAa("minuend_rollup.aa", {
    DISPUTE_AA_HERE: disputeAddr,
    DISPUTE_FILL_AA_HERE: fillAddr,
    DISPUTE_BIND_AA_HERE: bindAddr,
    DISPUTE_BOOK_AA_HERE: bookAddr,
    DISPUTE_CLAW_AA_HERE: clawAddr,
    DISPUTE_XFRAME_AA_HERE: xfAddr,
    DISPUTE_MFRAME_AA_HERE: mfAddr,
  }, ".minuend_rollup.resolved.aa");
}
function resolveBookAa() {
  return resolveAa("minuend_dispute_book.aa", {}, ".minuend_dispute_book.resolved.aa");
}
// Round 6: P-claw (both legs of one fill) on a fifth dispute AA.
function resolveClawAa() {
  return resolveAa("minuend_dispute_claw.aa", {}, ".minuend_dispute_claw.resolved.aa");
}
// Round 7b: P-xframe (+ P-tsize since round 8) on a sixth dispute AA.
function resolveXframeAa() {
  return resolveAa("minuend_dispute_xframe.aa", {}, ".minuend_dispute_xframe.resolved.aa");
}
// Round 8: P-mframe / P-noband on a seventh dispute AA.
function resolveMframeAa() {
  return resolveAa("minuend_dispute_mframe.aa", {}, ".minuend_dispute_mframe.resolved.aa");
}
// R4-A-4: P-adr derives the vault from the base too (deposit ledger).
function resolveBindAa(vaultBaseAddr) {
  return resolveAa("minuend_dispute_bind.aa", { VAULT_BASE_HERE: vaultBaseAddr }, ".minuend_dispute_bind.resolved.aa");
}
// Round 2 (R2-A-3): the vault is a parameterized instance of a BASE AA
// that names no address; dispute.aa hardcodes the base and derives the
// rollup's vault as chash160(['autonomous agent', {base_aa, params:{rollup}}]).
function resolveDisputeAa(vaultBaseAddr) {
  return resolveAa("minuend_dispute.aa", { VAULT_BASE_HERE: vaultBaseAddr }, ".minuend_dispute.resolved.aa");
}
function resolveVaultBaseAa(perpAssetId) {
  return resolveAa("minuend_vault.aa", { PERP_ASSET_ID_HERE: perpAssetId }, ".minuend_vault_base.resolved.aa");
}
function resolveFillAa() {
  return resolveAa("minuend_dispute_fill.aa", {}, ".minuend_dispute_fill.resolved.aa");
}
const aaRoot = path.join(__dirname, "..", "vendor", "aa-testkit");
const nm = path.join(aaRoot, "node_modules");
process.env.NODE_PATH = [nm, process.env.NODE_PATH].filter(Boolean).join(path.delimiter);
require("module").Module._initPaths();
process.env.testnet = "1";
delete process.env.devnet;

const { Testkit } = require(path.join(aaRoot, "main.js"));
const objectHash = require("ocore/object_hash.js");
const parseOjson = require("ocore/formula/parse_ojson").parse;
const { Network } = Testkit({
  TESTDATA_DIR: path.join(__dirname, "testdata-testnet"),
});

async function main() {
  if (PERP_ASSET_ID === "PERP_ASSET_ID_HERE")
    throw new Error("Set PERP_ASSET_ID to the issued asset id before deploying");
  console.log("deploying minuend_rollup.aa / minuend_dispute.aa / minuend_vault.aa to TESTNET ...");
  // #13 order: dispute AAs hash first (no rollup in their defs), then the
  // rollup hardcodes them, then vault + binds (rollup rides trigger data).
  const fillPath = resolveFillAa();
  const chashOf = (file) => {
    let parsed = null;
    parseOjson(fs.readFileSync(file, "utf8"), (err, res) => {
      if (err) throw err;
      parsed = res[1];
    });
    return objectHash.getChash160(["autonomous agent", parsed]);
  };
  const vaultBasePath = resolveVaultBaseAa(PERP_ASSET_ID);
  const vaultBaseAddr = chashOf(vaultBasePath);
  const disputePath = resolveDisputeAa(vaultBaseAddr);
  const disputeAddr = chashOf(disputePath);
  const bookPath = resolveBookAa();
  const bookAddr = chashOf(bookPath);
  const fillAddr = chashOf(fillPath);
  const bindPath = resolveBindAa(vaultBaseAddr);
  const bindAddr = chashOf(bindPath);
  const clawPath = resolveClawAa();
  const clawAddr = chashOf(clawPath);
  const xfPath = resolveXframeAa();
  const xfAddr = chashOf(xfPath);
  const mfPath = resolveMframeAa();
  const mfAddr = chashOf(mfPath);
  const rollupPath = resolveRollupAa(disputeAddr, fillAddr, bindAddr, bookAddr, clawAddr, xfAddr, mfAddr);

  const network = await Network.create()
    .with.agent({ vaultBase: vaultBasePath })
    .with.agent({ rollup: rollupPath })
    .with.wallet({ operator: 1e14 })
    .run();
  const rollup = network.agent.rollup;
  const operator = network.wallet.operator;
  console.log("rollup AA address:", rollup);

  const network2 = await Network.create()
    .with.agent({ dispute: disputePath })
    .with.agent({ fill: fillPath })
    .with.agent({ bind: bindPath })
    .with.agent({ book: bookPath })
    .with.agent({ claw: clawPath })
    .with.agent({ xframe: xfPath })
    .with.agent({ mframe: mfPath })
    .with.agent({ vault: { base_aa: vaultBaseAddr, params: { rollup } } })
    .with.wallet({ operator: 1e14 })
    .run();
  const dispute = network2.agent.dispute;
  const fill = network2.agent.fill;
  const bindAa = network2.agent.bind;
  const bookAa = network2.agent.book;
  const clawAa = network2.agent.claw;
  const xfAa = network2.agent.xframe;
  const mfAa = network2.agent.mframe;
  const vault = network2.agent.vault;
  console.log("dispute AA address:", dispute);
  console.log("fill AA address   :", fill);
  console.log("vault AA address  :", vault);
  // Bind both dispute AAs; the rollup refuses verdicts from any other
  // address afterwards.
  const { unit, error } = await operator.triggerAaWithData({
    toAddress: dispute,
    amount: 20000,
    data: { bind: 1, rollup },
  });
  if (error || !unit) throw new Error("dispute bind failed: " + error);
  await network2.witnessUntilStable(unit);
  console.log("dispute bound; unit =", unit);
  const op2 = network2.wallet.operator;
  const fb = await op2.triggerAaWithData({
    toAddress: fill,
    amount: 20000,
    data: { bind_fill: 1, rollup },
  });
  if (fb.error || !fb.unit) throw new Error("fill bind failed: " + fb.error);
  await network2.witnessUntilStable(fb.unit);
  console.log("fill bound; unit =", fb.unit);
  const bb = await op2.triggerAaWithData({
    toAddress: bindAa,
    amount: 20000,
    data: { bind_bind: 1, rollup },
  });
  if (bb.error || !bb.unit) throw new Error("binding-dispute bind failed: " + bb.error);
  await network2.witnessUntilStable(bb.unit);
  console.log("binding dispute bound; unit =", bb.unit);
  const kb = await op2.triggerAaWithData({
    toAddress: bookAa,
    amount: 20000,
    data: { bind_book: 1, rollup },
  });
  if (kb.error || !kb.unit) throw new Error("book-dispute bind failed: " + kb.error);
  await network2.witnessUntilStable(kb.unit);
  console.log("book dispute bound; unit =", kb.unit);
  const cb = await op2.triggerAaWithData({
    toAddress: clawAa,
    amount: 20000,
    data: { bind_claw: 1, rollup },
  });
  if (cb.error || !cb.unit) throw new Error("claw-dispute bind failed: " + cb.error);
  await network2.witnessUntilStable(cb.unit);
  console.log("claw dispute bound; unit =", cb.unit);
  const xb = await op2.triggerAaWithData({
    toAddress: xfAa,
    amount: 20000,
    data: { bind_xframe: 1, rollup },
  });
  if (xb.error || !xb.unit) throw new Error("xframe-dispute bind failed: " + xb.error);
  await network2.witnessUntilStable(xb.unit);
  console.log("xframe dispute bound; unit =", xb.unit);
  const mb = await op2.triggerAaWithData({
    toAddress: mfAa,
    amount: 20000,
    data: { bind_mframe: 1, rollup },
  });
  if (mb.error || !mb.unit) throw new Error("mframe-dispute bind failed: " + mb.error);
  await network2.witnessUntilStable(mb.unit);
  console.log("mframe dispute bound; unit =", mb.unit);

  const v = await operator.readAAStateVars(rollup);
  const vars_ = v.vars || v;
  if (String(vars_.dispute_aa) !== String(dispute))
    throw new Error("dispute_aa not bound: " + JSON.stringify(vars_.dispute_aa));
  if (String(vars_.dispute_fill_aa) !== String(fill))
    throw new Error("dispute_fill_aa not bound: " + JSON.stringify(vars_.dispute_fill_aa));
  if (String(vars_.dispute_bind_aa) !== String(bindAa))
    throw new Error("dispute_bind_aa not bound: " + JSON.stringify(vars_.dispute_bind_aa));
  if (String(vars_.dispute_book_aa) !== String(bookAa))
    throw new Error("dispute_book_aa not bound: " + JSON.stringify(vars_.dispute_book_aa));
  if (String(vars_.dispute_claw_aa) !== String(clawAa))
    throw new Error("dispute_claw_aa not bound: " + JSON.stringify(vars_.dispute_claw_aa));
  if (String(vars_.dispute_xframe_aa) !== String(xfAa))
    throw new Error("dispute_xframe_aa not bound: " + JSON.stringify(vars_.dispute_xframe_aa));
  if (String(vars_.dispute_mframe_aa) !== String(mfAa))
    throw new Error("dispute_mframe_aa not bound: " + JSON.stringify(vars_.dispute_mframe_aa));
  if (Number(vars_.last_submitted || 0) !== 0)
    throw new Error("boot last_submitted wrong");
  if (Number(vars_.last_finalized || 0) !== 0)
    throw new Error("boot last_finalized wrong");

  // persist deployment info for the operator tooling
  const info = {
    network: "testnet",
    rollup_aa_address: rollup,
    dispute_aa_address: dispute,
    dispute_fill_aa_address: fill,
    dispute_bind_aa_address: bindAa,
    dispute_book_aa_address: bookAa,
    dispute_claw_aa_address: clawAa,
    dispute_xframe_aa_address: xfAa,
    dispute_mframe_aa_address: mfAa,
    vault_aa_address: vault,
    vault_base_aa_address: vaultBaseAddr,
    perp_asset_id: PERP_ASSET_ID,
    challenge_secs: 3600,
    chain_id: CHAIN_ID,
    assertion_version: 6,
    pool_fund_gross: 10000000010000,
    deployed_at: new Date().toISOString(),
  };
  // #47 B5: the info object used to be built and never written, leaving a
  // stale pre-#44 record in deployment.json.
  fs.writeFileSync(path.join(__dirname, "deployment.json"), JSON.stringify(info, null, 2) + "\n");
  console.log("deployment.json written");
  console.log("NOTE: mainnet deployment requires a formal AA audit.");
  await network.stop();
  await network2.stop();
  process.exit(0);
}

main().catch(async (e) => {
  console.error("DEPLOY FAILED:", e && e.stack ? e.stack : e);
  process.exit(1);
});
