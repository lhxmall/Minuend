"use strict";

// MINUEND dispute prover — posts a one-shot fraud predicate to the dispute AA
// instead of the legacy pay-to-kill {challenge:1}. A failed predicate
// bounces ('no fraud') and coins return; a proven one forwards
// {verdict:'fraud', height, challenger} to the rollup AA which fails the
// height and slashes half the submit bond to the challenger.
//
// Usage: cd obyte-local && node post_challenge.js \
//          --height 1 --pred deposit --proof proof.json
//
// proof.json carries everything the predicate needs: k, op, ops_proof,
// pre_wit, pre_proof (k>0), post_wit, post_proof, pre_leaf, post_leaf,
// pre_leaf_proof, post_leaf_proof (shape per agents/minuend_dispute.aa).
// The watcher builds these from the temp_data DA package.

const path = require("path");
const fs = require("fs");
const { envCompat, disputeTarget, targetForPred } = require("./script_helpers");

const aaRoot = path.join(__dirname, "..", "vendor", "aa-testkit");
const nm = path.join(aaRoot, "node_modules");
process.env.NODE_PATH = [nm, process.env.NODE_PATH].filter(Boolean).join(path.delimiter);
require("module").Module._initPaths();

const { Testkit } = require(path.join(aaRoot, "main.js"));
const { Network } = Testkit({
  TESTDATA_DIR: path.join(__dirname, "testdata-challenger"),
});

function arg(name, def) {
  const i = process.argv.indexOf("--" + name);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : def;
}
function flag(name) {
  return process.argv.indexOf("--" + name) > -1;
}

let network;

async function main() {
  const deploy = JSON.parse(fs.readFileSync(path.join(__dirname, "deployment.json"), "utf8"));
  // --fill → fill_math AA, --bind → #47 A2 binding AA (wpin/adr).
  // Round 2: ghost/skip live on the book dispute AA; with no explicit flag
  // the predicate name picks the AA (the watcher's devnet drill passes no
  // flag for book proofs).
  const target = flag("bind") ? "bind" : flag("fill") ? "fill" : flag("book") ? "book" : targetForPred(arg("pred", "deposit"));
  const t = disputeTarget(target, deploy);
  const dispute = t.address;
  const rollup = deploy.rollup_aa_address || envCompat("MINUEND_ROLLUP_AA");
  if (!dispute || !rollup) throw new Error("deployment.json dispute_aa_address/rollup_aa_address missing");
  const height = Number(arg("height"));
  const pred = arg("pred", "deposit");
  const proofFile = arg("proof");
  if (!height || !proofFile) throw new Error("usage: node post_challenge.js --height N --pred deposit --proof proof.json [--fill|--bind|--book]");
  // #37-2: the proof path used to be stored and never read — the script
  // then referenced an undefined `proof` and threw ReferenceError before
  // sending anything. Read and shape-check it here.
  const proof = (() => {
    const parsed = JSON.parse(fs.readFileSync(proofFile, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      throw new Error(`proof file ${proofFile} must contain a JSON object`);
    return parsed;
  })();
  // #37-2: this script only drives a local aa-testkit devnet; accepting
  // --hub / a mnemonic silently would report a local drill as if it were a
  // live challenge. L5 (#47): live challenges go through
  // post_challenge_live.js; the watcher calls THIS script only for an
  // explicit MINUEND_WATCH_DEVNET_CHALLENGE=1 drill, without --hub and with
  // the mnemonic stripped from the child environment.
  const hubArg = arg("hub");
  const mnemonicArg = arg("mnemonic") || envCompat("MINUEND_WATCH_MNEMONIC");
  if (hubArg || mnemonicArg) {
    console.error(
      "post_challenge.js is not wired to a live hub: --hub/mnemonic are unsupported " +
      "(this script runs a local aa-testkit network only). Refusing to run rather than " +
      "reporting a local drill as a production challenge.",
    );
    process.exit(1);
  }

  network = await Network.create()
    .with.wallet({ challenger: 1e7 })
    .run();
  const challenger = network.wallet.challenger;
  console.log("dispute", dispute, "height", height, "pred", pred);

  // Bind only when the rollup has no dispute AA registered yet (double
  // bind bounces 'not authorized' — the rollup keeps the first binder).
  const rv = await challenger.readAAStateVars(rollup);
  const rvars = rv.vars || rv;
  const boundKey = t.rollupVar;
  if (!rvars[boundKey]) {
    const bind = await challenger.triggerAaWithData({
      toAddress: dispute,
      amount: 20000,
      data: Object.assign({ rollup }, t.bind),
    });
    if (bind.error) throw new Error("bind failed: " + bind.error);
    await network.witnessUntilStable(bind.unit);
    console.log("dispute bound");
  } else {
    console.log("dispute already bound:", rvars[boundKey]);
  }

  // The rollup address rides every challenge (#13: the rollup hardcodes
  // the dispute addresses, the disputes reference the rollup per-trigger).
  const data = Object.assign({ height, pred, rollup }, proof);
  const r = await challenger.triggerAaWithData({
    toAddress: dispute,
    amount: 20000,
    data,
  });
  if (r.error) throw new Error("challenge failed: " + r.error);
  await network.witnessUntilStable(r.unit);
  await new Promise((res) => setTimeout(res, 3000));
  const v = await challenger.readAAStateVars(rollup);
  const vars_ = v.vars || v;
  const frozen = vars_["frozen_" + height];
  console.log("challenge posted:", r.unit, "frozen_" + height + "=", frozen);
  if (Number(frozen) === 2) {
    console.log("VERDICT: fraud accepted, height failed. slash_reward_ claimable by challenger.");
  } else {
    console.log("predicate bounced ('no fraud' path) — assertion stands, coins returned.");
  }
  await network.stop();
  process.exit(0);
}

main().catch(async (e) => {
  console.error("CHALLENGE FAILED:", e && e.stack ? e.stack : e);
  try { if (network) await network.stop(); } catch (_) {}
  process.exit(1);
});
