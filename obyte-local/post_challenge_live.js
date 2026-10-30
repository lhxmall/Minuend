"use strict";

// MINUEND live challenge poster (#47 L5) — posts one fraud-predicate
// challenge to a LIVE dispute AA through a light headless wallet.
//
// The watcher (minuend-watch) spawns this when MINUEND_WATCH_MNEMONIC is
// set. post_challenge.js stays the local aa-testkit drill.
//
// Usage: node obyte-local/post_challenge_live.js --height H --pred P \
//          --proof proof.json --target main|book|fill|bind [--network mainnet|testnet] \
//          [--rollup ADDR] [--dispute-address ADDR]
//
// Environment:
//   MINUEND_WATCH_MNEMONIC   watcher wallet (12+ words; legacy OPERP_* accepted)
//   MINUEND_WATCH_NETWORK    mainnet (default) | testnet
//   MINUEND_WATCH_HUB        hub override (default obyte.org/bb[-test])
//   MINUEND_ROLLUP_AA        when --rollup is not given
//
// Addresses (R2-R-8): the rollup is --rollup (minuend-watch always passes
// the rollup it watches) > MINUEND_ROLLUP_AA > deployment.json, the last
// only when its `network` matches. The dispute AA is the one the rollup has
// bound in its dispute_aa / dispute_book_aa / dispute_fill_aa / dispute_bind_aa state var;
// --dispute-address, when given, must equal it.
//
// Safety (B10, 600 s margin): the dispute AAs judge the challenge unit's own
// timestamp against submitted_at + 3600. After the wallet has booted (which
// can take minutes) the script re-reads submitted_at_<h> / frozen_<h> from
// the rollup and re-checks the margin with a FRESH clock immediately before
// broadcasting; inside the margin it refuses (exit 3) instead of paying for
// a challenge that would bounce as too late.
//
// Exit codes: 0 = challenge broadcast (verdict observed or still pending),
//             3 = refused by the window/margin/frozen gate (nothing sent),
//             1 = error (nothing sent, or send failed).

const fs = require("fs");
const path = require("path");
const {
  envCompat,
  challengeGate,
  disputeTarget,
  resolveLiveRollup,
  pickDisputeAddress,
  buildChallengeData,
  hubFor,
} = require("./script_helpers");

function arg(name, def) {
  const i = process.argv.indexOf("--" + name);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : def;
}

const EXIT_REFUSED = 3;

// R2-A-13: `--claim` sends {claim:'slash'} from the wallet's main address
// (the address every live challenge pays from).
async function claimSlash() {
  const network = arg("network", envCompat("MINUEND_WATCH_NETWORK") || "mainnet");
  let deploy = {};
  try {
    deploy = JSON.parse(fs.readFileSync(path.join(__dirname, "deployment.json"), "utf8"));
  } catch (_) { /* --rollup / env still work without the file */ }
  const rollup = resolveLiveRollup({ cli: arg("rollup"), deploy, network });
  const { boot } = require("./mainnet_wallet.js");
  const w = await boot({ mnemonicEnv: "MINUEND_WATCH_MNEMONIC", network, hub: hubFor(network, envCompat("MINUEND_WATCH_HUB")) });
  const owed = (await w.network.requestFromLightVendor("light/get_aa_state_vars", { address: rollup, var_prefix: "slash_reward_" + w.address }))["slash_reward_" + w.address];
  if (!Number(owed)) { console.log(`nothing to claim for ${w.address}`); process.exit(0); }
  const messages = [{ app: "data", payload_location: "inline", payload_hash: w.objectHash.getBase64Hash({ claim: "slash" }), payload: { claim: "slash" } }];
  const unit = await new Promise((resolve, reject) => w.wallet.sendMultiPayment(
    { paying_addresses: [w.address], change_address: w.address, to_address: rollup, amount: 10000, messages },
    (err, u) => (err ? reject(new Error("claim failed: " + err)) : resolve(u))));
  console.log(`claim sent: ${unit} (owed ${owed} to ${w.address})`);
  process.exit(0);
}

async function main() {
  if (process.argv.includes("--claim")) return claimSlash();
  const height = Number(arg("height"));
  const pred = arg("pred");
  const proofFile = arg("proof");
  const target = arg("target", "main");
  const network = arg("network", envCompat("MINUEND_WATCH_NETWORK") || "mainnet");
  if (!Number.isInteger(height) || height < 1 || !pred || !proofFile)
    throw new Error("usage: node post_challenge_live.js --height N --pred P --proof proof.json --target main|book|fill|bind [--network mainnet|testnet]");
  let deploy = {};
  try {
    deploy = JSON.parse(fs.readFileSync(path.join(__dirname, "deployment.json"), "utf8"));
  } catch (_) { /* --rollup / env still work without the file */ }
  const rollup = resolveLiveRollup({ cli: arg("rollup"), deploy, network });
  // Target metadata only (state var name); the address comes from the rollup.
  const t = disputeTarget(target, {}, {}, () => {});
  const proof = JSON.parse(fs.readFileSync(proofFile, "utf8"));
  const data = buildChallengeData({ height, pred, rollup, proof });

  const { boot } = require("./mainnet_wallet.js");
  const w = await boot({
    mnemonicEnv: "MINUEND_WATCH_MNEMONIC",
    network,
    hub: hubFor(network, envCompat("MINUEND_WATCH_HUB")),
  });
  const readVars = (address, prefix) =>
    w.network.requestFromLightVendor("light/get_aa_state_vars", { address, var_prefix: prefix });

  // R2-R-8: post to the dispute AA the rollup actually accepts verdicts from.
  const bound = await readVars(rollup, t.rollupVar);
  const disputeAddress = pickDisputeAddress({
    cli: arg("dispute-address"),
    bound: bound[t.rollupVar],
    rollupVar: t.rollupVar,
  });
  console.log(`watcher wallet ${w.address} on ${network}; rollup ${rollup}; target ${target} AA ${disputeAddress}`);

  // Fresh on-chain window facts + fresh clock, right before sending.
  const sa = (await readVars(rollup, "submitted_at_" + height))["submitted_at_" + height];
  const fr = (await readVars(rollup, "frozen_" + height))["frozen_" + height];
  const gate = challengeGate({ now: Math.floor(Date.now() / 1000), submittedAt: sa, frozen: fr });
  if (!gate.ok) {
    console.error(`REFUSED: h=${height} ${gate.reason} — challenge NOT sent`);
    process.exit(EXIT_REFUSED);
  }
  console.log(`window ok (${gate.reason}); sending ${pred} challenge for h=${height}`);

  const unit = await new Promise((resolve, reject) => {
    const messages = [{
      app: "data",
      payload_location: "inline",
      payload_hash: w.objectHash.getBase64Hash(data),
      payload: data,
    }];
    // R2-A-13: pay FROM the wallet's main address (and keep change there):
    // the rollup credits slash_reward_<trigger.address> and only that
    // address can {claim:'slash'} it.
    w.wallet.sendMultiPayment(
      { paying_addresses: [w.address], change_address: w.address, to_address: disputeAddress, amount: 20000, messages },
      (err, u) => (err ? reject(new Error("send failed: " + err)) : resolve(u)),
    );
  });
  console.log("challenge broadcast:", unit, "challenger:", w.address);
  // R2-A-13: durable record of who can claim the slash reward.
  try {
    fs.appendFileSync(path.join(__dirname, "challenges.jsonl"),
      JSON.stringify({ height, pred, target, unit, challenger: w.address, rollup, ts: Math.floor(Date.now() / 1000) }) + "\n");
  } catch (e) { console.error("warning: could not record challenge:", e.message); }

  // Observe the outcome for up to 10 minutes: a verdict sets frozen_<h>=2.
  const until = Date.now() + 600 * 1000;
  while (Date.now() < until) {
    await new Promise((r) => setTimeout(r, 20000));
    const f = (await readVars(rollup, "frozen_" + height).catch(() => ({})))["frozen_" + height];
    if (Number(f) === 2) {
      console.log(`VERDICT: h=${height} frozen=2 (fraud accepted). Claim: node post_challenge_live.js --claim --network ${network} (from ${w.address}).`);
      process.exit(0);
    }
  }
  console.log(`challenge ${unit} broadcast; no verdict observed yet (the predicate may have bounced 'no fraud' — check the AA response).`);
  process.exit(0);
}

main().catch((e) => {
  console.error("LIVE CHALLENGE FAILED:", e && e.stack ? e.stack : e);
  process.exit(1);
});
