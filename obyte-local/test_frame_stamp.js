"use strict";

// R2-R-4: frames survive the poster byte-for-byte (big integers included);
// only the APPLIED Deposit frames named by index gain an "e" member (R4-E-1).
const assert = require("assert");
const { stampDepositEvidence } = require("./frame_stamp");

const big = "1152921504606846977"; // 2^60 + 1, not representable as a double
const place = `{"c":"1","o":"x","t":"y","u":{"op":{"Place":{"margin":${big},"qty":${big},"client_seq":${big}}},"parents":["ab"],"pubkey":"cd","sig":"ef"}}`;
const aa = "11".repeat(32);
const deposit = `{"c":"1","o":"x","t":"y","u":{"op":{"Deposit":{"aa_unit":"${aa}","amount":${big}}},"parents":["ab"],"pubkey":"cd","sig":"ef"}}`;
const frontRun = `{"u":{"op":{"Deposit":{"aa_unit":"${aa}","amount":5}}}}`;
const depositArr = `{"u":{"op":{"GovDeposit":{"aa_unit":[${Array(32).fill(34).join(",")}],"amount":5}}}}`;
const embedded = `{"e":{"aa_unit":"${aa}","rust":1},"u":{"op":{"Deposit":{"aa_unit":"${aa}","amount":${big}}}}}`;
const ev = { aa_unit: aa, is_perp: false, joint: { unit: "U" } };
const ev2 = { aa_unit: "22".repeat(32), is_perp: true };

// The front-run frame (index 1) cites the same anchor but is NOT stamped.
const frames = [place, frontRun, deposit, depositArr, embedded];
const out = stampDepositEvidence(frames, new Map([[2, ev], [3, ev2]]));
assert.strictEqual(out[0], place, "non-deposit frame must be byte-identical");
assert.ok(out[0].includes(big));
assert.strictEqual(out[1], frontRun, "same-anchor frame not applied: no evidence");
assert.strictEqual(out[2], deposit.slice(0, -1) + ',"e":' + JSON.stringify(ev) + "}");
assert.ok(out[2].includes(`"amount":${big}`));
assert.deepStrictEqual(JSON.parse(out[2]).e, ev);
assert.strictEqual(out[3], depositArr.slice(0, -1) + ',"e":' + JSON.stringify(ev2) + "}");
assert.strictEqual(out[4], embedded, "Rust-embedded evidence is kept as-is");
assert.strictEqual(out.filter((f) => f.includes('"e":')).length, 3);
// No evidence: unchanged.
assert.strictEqual(stampDepositEvidence([deposit], new Map())[0], deposit);
// Refusals: non-deposit frame, wrong anchor, wrong kind, double stamp, bad index.
assert.throws(() => stampDepositEvidence([place], new Map([[0, ev]])));
assert.throws(() => stampDepositEvidence([depositArr], new Map([[0, ev]])));
assert.throws(() => stampDepositEvidence([deposit], new Map([[0, Object.assign({}, ev, { is_perp: true })]])));
assert.throws(() => stampDepositEvidence([embedded], new Map([[0, ev]])));
assert.throws(() => stampDepositEvidence([deposit], new Map([[1, ev]])));
assert.throws(() => stampDepositEvidence([5], new Map()));
assert.throws(() => stampDepositEvidence([deposit], { 0: ev }));

// The old re-serialisation is what broke: demonstrate the rounding.
assert.notStrictEqual(JSON.stringify(JSON.parse(place)), place);

console.log("test_frame_stamp: ok");
