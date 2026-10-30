"use strict";

// R2-R-4: frames survive the poster byte-for-byte (big integers included);
// only Deposit frames gain an "e" member.
const assert = require("assert");
const { stampDepositEvidence } = require("./frame_stamp");

const big = "1152921504606846977"; // 2^60 + 1, not representable as a double
const place = `{"c":"1","o":"x","t":"y","u":{"op":{"Place":{"margin":${big},"qty":${big},"client_seq":${big}}},"parents":["ab"],"pubkey":"cd","sig":"ef"}}`;
const aa = "11".repeat(32);
const deposit = `{"c":"1","o":"x","t":"y","u":{"op":{"Deposit":{"aa_unit":"${aa}","amount":${big}}},"parents":["ab"],"pubkey":"cd","sig":"ef"}}`;
const depositArr = `{"u":{"op":{"GovDeposit":{"aa_unit":[${Array(32).fill(34).join(",")}],"amount":5}}}}`;
const embedded = `{"e":{"aa_unit":"${aa}","rust":1},"u":{"op":{"Deposit":{"aa_unit":"${aa}","amount":${big}}}}}`;
const ev = { aa_unit: aa, joint: { unit: "U" } };
const ev2 = { aa_unit: "22".repeat(32) };
const m = new Map([[aa, ev], ["22".repeat(32), ev2]]);

const out = stampDepositEvidence([place, deposit, depositArr, embedded, "not json"], m);
assert.strictEqual(out[0], place, "non-deposit frame must be byte-identical");
assert.ok(out[0].includes(big));
assert.strictEqual(out[1], deposit.slice(0, -1) + ',"e":' + JSON.stringify(ev) + "}");
assert.ok(out[1].startsWith(deposit.slice(0, -1)), "deposit bytes preserved, big amount intact");
assert.ok(out[1].includes(`"amount":${big}`));
assert.deepStrictEqual(JSON.parse(out[1]).e, ev);
assert.strictEqual(out[2], depositArr.slice(0, -1) + ',"e":' + JSON.stringify(ev2) + "}");
assert.strictEqual(out[3], embedded, "Rust-embedded evidence is kept as-is");
assert.strictEqual(out[4], "not json");
// No evidence for the anchor: unchanged.
assert.strictEqual(stampDepositEvidence([deposit], new Map())[0], deposit);
assert.throws(() => stampDepositEvidence([5], m));

// The old re-serialisation is what broke: demonstrate the rounding.
assert.notStrictEqual(JSON.stringify(JSON.parse(place)), place);

console.log("test_frame_stamp: ok");
