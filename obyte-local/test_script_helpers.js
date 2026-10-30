"use strict";

const assert = require("assert");
const {
  envCompat,
  finalizeReached,
  challengeGate,
  disputeTarget,
  resolveLiveRollup,
  pickDisputeAddress,
  buildChallengeData,
  hubFor,
  daBindHash,
  targetForPred,
  CHALLENGE_SAFETY_MARGIN_SECS,
} = require("./script_helpers");

// B9: new name wins; legacy falls back with one deprecation warning.
{
  const logs = [];
  const warn = (m) => logs.push(m);
  assert.strictEqual(envCompat("MINUEND_ROLLUP_AA", { MINUEND_ROLLUP_AA: "NEW" }, warn), "NEW");
  assert.strictEqual(logs.length, 0);
  assert.strictEqual(envCompat("MINUEND_DISPUTE_AA", { OPERP_DISPUTE_AA: "OLD" }, warn), "OLD");
  assert.ok(/deprecated/.test(logs[0]));
  // warned once per variable
  envCompat("MINUEND_DISPUTE_AA", { OPERP_DISPUTE_AA: "OLD" }, warn);
  assert.strictEqual(logs.length, 1);
  assert.strictEqual(
    envCompat("MINUEND_WATCH_MNEMONIC", { MINUEND_WATCH_MNEMONIC: "n", OPERP_WATCH_MNEMONIC: "o" }, warn),
    "n",
  );
  assert.ok(/ignoring OPERP_WATCH_MNEMONIC/.test(logs[1]));
  assert.strictEqual(envCompat("MINUEND_VAULT_AA", { MINUEND_VAULT_AA: "", OPERP_VAULT_AA: "" }, warn), undefined);
  assert.strictEqual(envCompat("MINUEND_DEPLOY_MNEMONIC", { MINUEND_DEPLOY_MNEMONIC: "", OPERP_DEPLOY_MNEMONIC: "x" }, warn), "x");
  assert.throws(() => envCompat("PATH", {}, warn));
}

// L6: finalize check is >=, not ===.
assert.strictEqual(finalizeReached(5, 5), true);
assert.strictEqual(finalizeReached("7", 5), true, "concurrent finalize past our height is success");
assert.strictEqual(finalizeReached(4, 5), false);
assert.strictEqual(finalizeReached(undefined, 5), false);
assert.strictEqual(finalizeReached("NaN", 5), false);

// L5 (#47): live challenge gate keeps the 600 s safety margin.
{
  assert.strictEqual(CHALLENGE_SAFETY_MARGIN_SECS, 600);
  const sa = 1_000_000;
  assert.strictEqual(challengeGate({ now: sa + 10, submittedAt: sa, frozen: 0 }).ok, true);
  assert.strictEqual(challengeGate({ now: sa + 3600 - 601, submittedAt: sa, frozen: 0 }).ok, true);
  const edge = challengeGate({ now: sa + 3600 - 600, submittedAt: sa, frozen: 0 });
  assert.strictEqual(edge.ok, false);
  assert.ok(/600s/.test(edge.reason));
  assert.strictEqual(challengeGate({ now: sa + 3600, submittedAt: sa, frozen: 0 }).reason, "challenge window closed");
  assert.strictEqual(challengeGate({ now: sa + 10, submittedAt: sa, frozen: 2 }).ok, false);
  assert.strictEqual(challengeGate({ now: sa + 10, submittedAt: 0, frozen: 0 }).ok, false);
  assert.strictEqual(challengeGate({ now: sa + 10, submittedAt: undefined, frozen: 0 }).ok, false);
}
{
  const silent = () => {};
  const deploy = { dispute_aa_address: "M".repeat(32), dispute_bind_aa_address: null };
  assert.strictEqual(disputeTarget("main", deploy, {}, silent).address, "M".repeat(32));
  assert.strictEqual(disputeTarget("bind", deploy, { MINUEND_DISPUTE_BIND_AA: "B".repeat(32) }, silent).address, "B".repeat(32));
  assert.deepStrictEqual(disputeTarget("fill", {}, {}, silent).bind, { bind_fill: 1 });
  assert.strictEqual(disputeTarget("fill", {}, {}, silent).address, null);
  assert.throws(() => disputeTarget("other", {}, {}, silent));
  const rollup = "R".repeat(32);
  const d = buildChallengeData({ height: 4, pred: "wpin", rollup, proof: { k: 1, op: "x" } });
  assert.deepStrictEqual(d, { k: 1, op: "x", height: 4, pred: "wpin", rollup });
  assert.throws(() => buildChallengeData({ height: 4, pred: "wpin", rollup, proof: { height: 5 } }), /overrides/);
  assert.throws(() => buildChallengeData({ height: 4, pred: "wpin", rollup, proof: [] }));
  assert.throws(() => buildChallengeData({ height: 0, pred: "wpin", rollup, proof: {} }));
  assert.strictEqual(hubFor("mainnet"), "obyte.org/bb");
  assert.strictEqual(hubFor("testnet"), "obyte.org/bb-test");
  assert.strictEqual(hubFor("testnet", "my.hub/bb"), "my.hub/bb");
  assert.throws(() => hubFor("devnet"));
}

// R2-R-8: the live poster challenges the WATCHED rollup, never a
// deployment.json address for another network/deployment.
{
  const silent = () => {};
  const X = "X".repeat(32), Y = "Y".repeat(32), E = "E".repeat(32);
  const deploy = { network: "testnet", rollup_aa_address: Y };
  assert.strictEqual(resolveLiveRollup({ cli: X, deploy, network: "mainnet", env: {}, warn: silent }), X);
  assert.strictEqual(resolveLiveRollup({ cli: X, deploy, network: "testnet", env: { MINUEND_ROLLUP_AA: E }, warn: silent }), X);
  assert.strictEqual(resolveLiveRollup({ deploy, network: "mainnet", env: { MINUEND_ROLLUP_AA: E }, warn: silent }), E);
  assert.strictEqual(resolveLiveRollup({ deploy, network: "testnet", env: {}, warn: silent }), Y);
  assert.throws(() => resolveLiveRollup({ deploy, network: "mainnet", env: {}, warn: silent }), /network/);
  assert.throws(() => resolveLiveRollup({ deploy: { rollup_aa_address: Y, network: null }, network: "mainnet", env: {}, warn: silent }));
  assert.throws(() => resolveLiveRollup({ deploy: {}, network: "mainnet", env: {}, warn: silent }), /--rollup/);
  const B = "B".repeat(32);
  assert.strictEqual(pickDisputeAddress({ bound: B, rollupVar: "dispute_aa" }), B);
  assert.strictEqual(pickDisputeAddress({ cli: B, bound: B, rollupVar: "dispute_aa" }), B);
  assert.throws(() => pickDisputeAddress({ cli: X, bound: B, rollupVar: "dispute_aa" }), /not the rollup/);
  assert.throws(() => pickDisputeAddress({ bound: undefined, rollupVar: "dispute_bind_aa" }), /no dispute_bind_aa/);
}

// R2-R-4: frame stamping keeps frames byte-for-byte (own test file).
require("./test_frame_stamp");

// R2-R-1: DA binding hash — pinned to the same vector as the Rust test
// minuend_settle::tests::da_bind_hash_format_is_pinned.
{
  const crypto = require("crypto");
  const f = {
    chain_id: "minuend-v2", height: 7,
    prev_state_hash: "01".repeat(32), state_root: "02".repeat(32), aa_root: "a".repeat(64),
    wit_root: "W".repeat(44), trace_root: "T".repeat(44), units_root: "U".repeat(44),
    units_set_root: "S".repeat(44), ops_root: "O".repeat(44), fills_root: "F".repeat(44),
    counts_root: "C".repeat(44), unit_count: 3, wit_count: 11, fill_count: 2,
    assertion_version: 6, data_root: "d".repeat(64),
  };
  const s = ["minuend-da-v1", "minuend-v2", "7", "01".repeat(32), "02".repeat(32), "a".repeat(64),
    "W".repeat(44), "T".repeat(44), "U".repeat(44), "S".repeat(44), "O".repeat(44), "F".repeat(44),
    "C".repeat(44), "3", "11", "2", "6", "d".repeat(64)].join("|");
  assert.strictEqual(daBindHash(f), crypto.createHash("sha256").update(s).digest("hex"));
  assert.throws(() => daBindHash(Object.assign({}, f, { data_root: undefined })), /missing data_root/);
  // Round 2 routing: ghost/skip -> book AA, binding preds -> bind AA.
  assert.strictEqual(targetForPred("ghost"), "book");
  assert.strictEqual(targetForPred("skip"), "book");
  assert.strictEqual(targetForPred("mbind"), "book"); // R4-A-1
  assert.strictEqual(targetForPred("fsane"), "book"); // R5-A-2
  assert.strictEqual(targetForPred("claw"), "claw"); // round 6 P-claw
  for (const p of ["xframe", "tsize"]) assert.strictEqual(targetForPred(p), "xframe"); // round 7b
  for (const p of ["mframe", "noband"]) assert.strictEqual(targetForPred(p), "mframe"); // round 8
  assert.strictEqual(targetForPred("fill_math"), "fill");
  for (const p of ["wpin", "adr", "tip", "keep", "mirror", "frame"]) assert.strictEqual(targetForPred(p), "bind");
  assert.strictEqual(targetForPred("deposit"), "main");
  assert.strictEqual(targetForPred("opbind"), "main"); // round 7 P-opbind
  assert.strictEqual(disputeTarget("book", { dispute_book_aa_address: "B".repeat(32) }).address, "B".repeat(32));
  const claw = disputeTarget("claw", { dispute_claw_aa_address: "C".repeat(32) });
  assert.strictEqual(claw.address, "C".repeat(32));
  assert.strictEqual(claw.rollupVar, "dispute_claw_aa");
  assert.deepStrictEqual(claw.bind, { bind_claw: 1 });
  const xf = disputeTarget("xframe", { dispute_xframe_aa_address: "X".repeat(32) });
  assert.strictEqual(xf.address, "X".repeat(32));
  assert.strictEqual(xf.rollupVar, "dispute_xframe_aa");
  assert.deepStrictEqual(xf.bind, { bind_xframe: 1 });
  const mf = disputeTarget("mframe", { dispute_mframe_aa_address: "M".repeat(32) });
  assert.strictEqual(mf.address, "M".repeat(32));
  assert.strictEqual(mf.rollupVar, "dispute_mframe_aa");
  assert.deepStrictEqual(mf.bind, { bind_mframe: 1 });
}

console.log("script helper checks passed");
