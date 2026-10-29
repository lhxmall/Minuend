"use strict";

// MINUEND live challenge poster (#47 L5) — posts one fraud-predicate
// challenge to a LIVE dispute AA through a light headless wallet.
//
// The watcher (minuend-watch) spawns this when MINUEND_WATCH_MNEMONIC is
// set. post_challenge.js stays the local aa-testkit drill.
//
// Usage: node obyte-local/post_challenge_live.js --height H --pred P \
//          --proof proof.json --target main|fill|bind [--network mainnet|testnet]
//
// Environment:
//   MINUEND_WATCH_MNEMONIC   watcher wallet (12+ words; legacy OPERP_* accepted)
//   MINUEND_WATCH_NETWORK    mainnet (default) | testnet
//   MINUEND_WATCH_HUB        hub override (default obyte.org/bb[-test])
//   MINUEND_ROLLUP_AA / MINUEND_DISPUTE_AA / MINUEND_DISPUTE_FILL_AA /
//   MINUEND_DISPUTE_BIND_AA  when deployment.json carries no address
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
  buildChallengeData,
  hubFor,
} = require("./script_helpers");

function arg(name, def) {
  const i = process.argv.indexOf("--" + name);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : def;
}

const EXIT_REFUSED = 3;

async function main() {
  const height = Number(arg("height"));
  const pred = arg("pred");
  const proofFile = arg("proof");
  const target = arg("target", "main");
  const network = arg("network", envCompat("MINUEND_WATCH_NETWORK") || "mainnet");
  if (!Number.isInteger(height) || height < 1 || !pred || !proofFile)
    throw new Error("usage: node post_challenge_live.js --height N --pred P --proof proof.json --target main|fill|bind [--network mainnet|testnet]");
  const deploy = JSON.parse(fs.readFileSync(path.join(__dirname, "deployment.json"), "utf8"));
  const rollup = deploy.rollup_aa_address || envCompat("MINUEND_ROLLUP_AA");
  const t = disputeTarget(target, deploy);
  if (!rollup || !t.address)
    throw new Error(`rollup / ${target} dispute AA address missing (deployment.json or ${t.env})`);
  const proof = JSON.parse(fs.readFileSync(proofFile, "utf8"));
  const data = buildChallengeData({ height, pred, rollup, proof });

  const { boot } = require("./mainnet_wallet.js");
  const w = await boot({
    mnemonicEnv: "MINUEND_WATCH_MNEMONIC",
    network,
    hub: hubFor(network, envCompat("MINUEND_WATCH_HUB")),
  });
  console.log(`watcher wallet ${w.address} on ${network}; target ${target} AA ${t.address}`);
  const readVars = (address, prefix) =>
    w.network.requestFromLightVendor("light/get_aa_state_vars", { address, var_prefix: prefix });

  // The rollup must accept verdicts from this dispute AA at all.
  const bound = await readVars(rollup, t.rollupVar);
  if (String(bound[t.rollupVar] || "") !== t.address)
    throw new Error(`rollup ${rollup} has ${t.rollupVar}=${JSON.stringify(bound[t.rollupVar])}, not ${t.address}`);

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
    w.wallet.issueChangeAddressAndSendMultiPayment(
      { to_address: t.address, amount: 20000, messages },
      (err, u) => (err ? reject(new Error("send failed: " + err)) : resolve(u)),
    );
  });
  console.log("challenge broadcast:", unit);

  // Observe the outcome for up to 10 minutes: a verdict sets frozen_<h>=2.
  const until = Date.now() + 600 * 1000;
  while (Date.now() < until) {
    await new Promise((r) => setTimeout(r, 20000));
    const f = (await readVars(rollup, "frozen_" + height).catch(() => ({})))["frozen_" + height];
    if (Number(f) === 2) {
      console.log(`VERDICT: h=${height} frozen=2 (fraud accepted). Claim with {claim:'slash'}.`);
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
