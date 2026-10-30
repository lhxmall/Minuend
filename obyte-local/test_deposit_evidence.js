"use strict";

// R4 (#47): post_batch.js deposit evidence building (deposit_evidence.js).
// Mirrors the Rust vectors in minuend-settle (r4_vault_rule_vectors and the
// r4_* frame tests): evidence = what the vault records, built only for the
// APPLIED deposit frames, and any failure for an applied deposit throws.
const assert = require("assert");
const d = require("./deposit_evidence");
const { stampDepositEvidence } = require("./frame_stamp");

const VAULT = "B".repeat(32);
const PAYER = "P".repeat(32);
const ACCT = "ab".repeat(32);
const PERP_HEX = "00".repeat(32);
const PERP_B64 = Buffer.from(PERP_HEX, "hex").toString("base64");

const dataMsg = (p) => ({ app: "data", payload: p });
const basePay = (...amts) => ({ app: "payment", payload: { outputs: amts.map((amount) => ({ address: VAULT, amount })) } });
const assetPay = (asset, amount) => ({ app: "payment", payload: { asset, outputs: [{ address: VAULT, amount }] } });
const unit = (messages, extra) => Object.assign({ unit: "U", authors: [{ address: PAYER }], messages }, extra || {});
const vd = (u) => d.vaultDepositOf(u, VAULT, PERP_B64);

// --- Oscript helpers ---------------------------------------------------
assert.strictEqual(d.oscriptToNumber("0"), 0);
assert.strictEqual(d.oscriptToNumber("1e-700"), null);
assert.strictEqual(d.oscriptToNumber("0e-700"), 0);
assert.strictEqual(d.oscriptToNumber("1e400"), null);
assert.strictEqual(d.oscriptToNumber("1."), null);
assert.strictEqual(d.oscriptToNumber("abc"), null);
for (const [v, want] of [[1, true], [0, false], ["0", false], ["0.00", false], ["", false], ["x", true], [false, false], [{}, true], [[], true], [null, "error"], ["y".repeat(4097), "error"]])
  assert.strictEqual(d.oscriptTruthy({ k: v }, "k"), want, JSON.stringify(v));
assert.strictEqual(d.oscriptTruthy({}, "k"), false);
assert.ok(d.vaultAccount(ACCT));
assert.strictEqual(d.vaultAccount("AB".repeat(32)), null);
assert.strictEqual(d.vaultAccount("12".repeat(32)), null, "all-digit account bounces");

// --- vault rule vectors (R4-E-2 / R4-R-3 / R4-A-7) ----------------------
// (a) no deposit key / deposit_perp paying only base / exactly the fee.
assert.strictEqual(vd(unit([dataMsg({ account: ACCT }), basePay(50000)])), null);
assert.strictEqual(vd(unit([dataMsg({ deposit_perp: 1, account: ACCT }), basePay(50000)])), null);
assert.strictEqual(vd(unit([dataMsg({ deposit: 1, account: ACCT }), basePay(10000)])), null);
for (const f of ["0", 0, false, ""])
  assert.strictEqual(vd(unit([dataMsg({ deposit: f, account: ACCT }), basePay(50000)])), null);
// (b) outputs to the vault are SUMMED.
assert.deepStrictEqual(vd(unit([dataMsg({ deposit: 1, account: ACCT }), basePay(5000, 1000000)])),
  { isPerp: false, amount: "995000", payer: PAYER, account: ACCT });
// (c) first data message counts.
assert.strictEqual(vd(unit([dataMsg({ deposit: 1, account: ACCT }), dataMsg({ withdraw: 1 }), basePay(50000)])).amount, "40000");
assert.strictEqual(vd(unit([dataMsg({ withdraw: 1 }), dataMsg({ deposit: 1, account: ACCT }), basePay(50000)])), null);
// (d) PERP: junk asset first, PERP id checked, base bounce fee required.
const junk = assetPay(Buffer.from("07".repeat(32), "hex").toString("base64"), 999);
assert.deepStrictEqual(vd(unit([dataMsg({ deposit_perp: 1, account: ACCT }), junk, assetPay(PERP_B64, 4000), basePay(10000)])),
  { isPerp: true, amount: "4000", payer: PAYER, account: ACCT });
assert.strictEqual(vd(unit([dataMsg({ deposit_perp: 1, account: ACCT }), assetPay(PERP_B64, 4000)])), null);
// both flags → base case wins.
assert.strictEqual(vd(unit([dataMsg({ deposit: 1, deposit_perp: 1, account: ACCT }), assetPay(PERP_B64, 4000), basePay(30000)])).isPerp, false);
// max_aa_responses 0 bounces; all-digit account bounces.
assert.strictEqual(vd(unit([dataMsg({ deposit: 1, account: ACCT }), basePay(50000)], { max_aa_responses: 0 })), null);
assert.strictEqual(vd(unit([dataMsg({ deposit: 1, account: "1".repeat(64) }), basePay(50000)])), null);

// --- buildAppliedEvidences ----------------------------------------------
const A = "11".repeat(32);
const acctArr = `[${Buffer.from(ACCT, "hex").toJSON().data.join(",")}]`;
const depFrame = (aa, amount, kind, addr) =>
  `{"u":{"op":{"${kind || "Deposit"}":{"account":${acctArr},"addr":"${addr || PAYER}","amount":${amount},"aa_unit":"${aa}"}},"parents":[],"pubkey":"","sig":""}}`;
const place = `{"u":{"op":{"Place":{"qty":1}}}}`;
// front-run (index 0, another addr) + applied victim (index 2) + GovDeposit cross-kind (index 3)
const frames = [depFrame(A, 40000, "Deposit", "Q".repeat(32)), place, depFrame(A, 40000), depFrame(A, 40000, "GovDeposit", "Q".repeat(32))];
const goodJoint = unit([dataMsg({ deposit: 1, account: ACCT }), basePay(50000)]);
const applied = [{ index: 2, aa_unit: A, is_perp: false }];
const noSleep = () => Promise.resolve();
const rec = `${PAYER}:40000:${ACCT}`;

(async () => {
  let fetched = 0;
  const m = await d.buildAppliedEvidences(applied, frames, {
    vault: VAULT, perpAsset: PERP_B64, sleep: noSleep,
    fetchJoint: async (aa) => { fetched++; assert.strictEqual(aa, A); return goodJoint; },
    readRecord: async (aa, isPerp) => { assert.strictEqual(isPerp, false); return rec; },
  });
  assert.strictEqual(fetched, 1, "only applied deposits are fetched");
  assert.deepStrictEqual([...m.keys()], [2]);
  const ev = m.get(2);
  assert.deepStrictEqual({ ...ev, joint: undefined }, { aa_unit: A, is_perp: false, amount: "40000", vault_address: VAULT, payer: PAYER, account: ACCT, joint: undefined });
  const out = stampDepositEvidence(frames, m);
  assert.strictEqual(out.filter((f) => f.includes(',"e":')).length, 1, "one evidence for one anchor");
  assert.strictEqual(out[0], frames[0]);
  assert.strictEqual(out[3], frames[3]);

  // Transient errors are retried; NOT FOUND and exhausted errors throw.
  let n = 0;
  const flaky = async () => { if (n++ < 2) throw new Error("hub down"); return goodJoint; };
  assert.strictEqual((await d.buildAppliedEvidences(applied, frames, { vault: VAULT, perpAsset: PERP_B64, sleep: noSleep, fetchJoint: flaky })).size, 1);
  const rejectsWith = async (opts, re, list) => {
    await assert.rejects(d.buildAppliedEvidences(list || applied, frames, Object.assign({ vault: VAULT, perpAsset: PERP_B64, sleep: noSleep }, opts)), re);
  };
  await rejectsWith({ fetchJoint: async () => { throw new Error("hub down"); } }, /fetch failed/);
  await rejectsWith({ fetchJoint: async () => null }, /not found/);
  // Joint is not a vault deposit / of another kind / other amount / record mismatch.
  await rejectsWith({ fetchJoint: async () => unit([dataMsg({ account: ACCT }), basePay(50000)]) }, /not a vault deposit/);
  await rejectsWith({ fetchJoint: async () => unit([dataMsg({ deposit_perp: 1, account: ACCT }), assetPay(PERP_B64, 40000), basePay(10000)]) }, /kind/);
  await rejectsWith({ fetchJoint: async () => unit([dataMsg({ deposit: 1, account: ACCT }), basePay(60000)]) }, /amount/);
  await rejectsWith({ fetchJoint: async () => goodJoint, readRecord: async () => null }, /vault record/);
  await rejectsWith({ fetchJoint: async () => goodJoint, readRecord: async () => `${PAYER}:1:${ACCT}` }, /vault record/);
  // Index / frame consistency.
  await rejectsWith({ fetchJoint: async () => goodJoint }, /does not match/, [{ index: 1, aa_unit: A, is_perp: false }]);
  await rejectsWith({ fetchJoint: async () => goodJoint }, /does not match/, [{ index: 2, aa_unit: A, is_perp: true }]);
  await rejectsWith({ fetchJoint: async () => goodJoint }, /applied twice/, [applied[0], applied[0]]);
  await assert.rejects(d.buildAppliedEvidences(undefined, frames, { vault: VAULT, fetchJoint: async () => goodJoint }), /applied_deposits/);
  // Size caps: a huge joint is refused (per deposit), many applied ones exceed the batch budget.
  const huge = unit([dataMsg({ deposit: 1, account: ACCT }), basePay(50000), { app: "text", payload: "x".repeat(d.DEPOSIT_EVIDENCE_UNIT_MAX_BYTES) }]);
  await rejectsWith({ fetchJoint: async () => huge }, /posting limit/);
  const bigText = { app: "text", payload: "x".repeat(200000) };
  const manyFrames = [];
  const manyApplied = [];
  for (let i = 0; i < 6; i++) {
    const aa = (i + 16).toString(16).padStart(2, "0").repeat(32);
    manyFrames.push(depFrame(aa, 40000));
    manyApplied.push({ index: i, aa_unit: aa, is_perp: false });
  }
  await assert.rejects(d.buildAppliedEvidences(manyApplied, manyFrames, {
    vault: VAULT, perpAsset: PERP_B64, sleep: noSleep,
    fetchJoint: async () => unit([dataMsg({ deposit: 1, account: ACCT }), basePay(50000), bigText]),
  }), /posting limit/);

  // --- R5-E-1 / R5-R-1: one shared set of limits --------------------------
  assert.ok(d.DEPOSIT_EVIDENCE_ADMIT_UNIT_MAX_BYTES < d.DEPOSIT_EVIDENCE_POST_UNIT_MAX_BYTES);
  assert.ok(d.DEPOSIT_EVIDENCE_POST_UNIT_MAX_BYTES < d.DEPOSIT_EVIDENCE_UNIT_MAX_BYTES);
  assert.ok(d.DEPOSIT_EVIDENCE_ADMIT_BATCH_MAX_BYTES < d.DEPOSIT_EVIDENCE_POST_BATCH_MAX_BYTES);
  assert.ok(d.DEPOSIT_EVIDENCE_POST_BATCH_MAX_BYTES < d.DEPOSIT_EVIDENCE_BATCH_MAX_BYTES);
  // Shared size vector (Rust: r5_evidence_size_vector_matches_js).
  const vec = require("./test_vectors/evidence_size.json");
  assert.strictEqual(d.evidenceBytes(vec.evidence), vec.bytes);
  // A joint whose evidence is exactly `target` bytes (text padding).
  const sized = async (target) => {
    const mk = (pad) => unit([dataMsg({ deposit: 1, account: ACCT }), basePay(50000), { app: "text", payload: "x".repeat(pad) }]);
    const ev0 = (await d.buildAppliedEvidences(applied, frames, { vault: VAULT, perpAsset: PERP_B64, sleep: noSleep, fetchJoint: async () => mk(0) })).get(2);
    const j = mk(target - d.evidenceBytes(ev0));
    return j;
  };
  const build = (j) => d.buildAppliedEvidences(applied, frames, { vault: VAULT, perpAsset: PERP_B64, sleep: noSleep, fetchJoint: async () => j });
  // 0.97 x 256 KiB: a watcher would accept it, but the producer does not
  // admit it (Rust r5_admit_limit_below_post_and_verify_limits) AND the
  // poster refuses it: both sides agree.
  await assert.rejects(build(await sized(Math.floor(d.DEPOSIT_EVIDENCE_UNIT_MAX_BYTES * 97 / 100))), /posting limit/);
  // Anything the producer may admit (<= admit limit) is posted.
  const okJ = await sized(d.DEPOSIT_EVIDENCE_ADMIT_UNIT_MAX_BYTES);
  const okM = await build(okJ);
  assert.strictEqual(d.evidenceBytes(okM.get(2)), d.DEPOSIT_EVIDENCE_ADMIT_UNIT_MAX_BYTES);
  // Batch: 0.97 MiB of applied evidence is refused (Rust:
  // r5_batch_total_097_mib_refused_by_admission); the admission budget
  // (960 KiB) is posted.
  const batchOf = async (count, per) => {
    const fr = [];
    const ap = [];
    const mk = (pad) => unit([dataMsg({ deposit: 1, account: ACCT }), basePay(50000), { app: "text", payload: "x".repeat(pad) }]);
    for (let i = 0; i < count; i++) {
      const aa = (i + 32).toString(16).padStart(2, "0").repeat(32);
      fr.push(depFrame(aa, 40000));
      ap.push({ index: i, aa_unit: aa, is_perp: false });
    }
    const probe = await d.buildAppliedEvidences([ap[0]], fr, { vault: VAULT, perpAsset: PERP_B64, sleep: noSleep, fetchJoint: async () => mk(0) });
    const pad = per - d.evidenceBytes(probe.get(0));
    return d.buildAppliedEvidences(ap, fr, { vault: VAULT, perpAsset: PERP_B64, sleep: noSleep, fetchJoint: async () => mk(pad) });
  };
  await assert.rejects(batchOf(5, Math.floor(d.DEPOSIT_EVIDENCE_BATCH_MAX_BYTES * 97 / 100 / 5)), /posting limit/);
  const fit = await batchOf(4, d.DEPOSIT_EVIDENCE_ADMIT_BATCH_MAX_BYTES / 4);
  assert.strictEqual([...fit.values()].reduce((t, e) => t + d.evidenceBytes(e), 0), d.DEPOSIT_EVIDENCE_ADMIT_BATCH_MAX_BYTES);
  // Big amounts (> 2^53) are compared exactly from the frame bytes.
  const bigAmt = "9007199254740993"; // 2^53 + 1
  const bf = [depFrame(A, bigAmt)];
  const bj = unit([dataMsg({ deposit: 1, account: ACCT }), basePay(Number(BigInt(bigAmt) + 10000n))]);
  // JS numbers cannot carry 2^53+1+10000 exactly either way; just check the
  // comparison uses the frame digits (mismatch → throw rather than silently
  // posting a rounded amount).
  await assert.rejects(d.buildAppliedEvidences([{ index: 0, aa_unit: A, is_perp: false }], bf, { vault: VAULT, perpAsset: PERP_B64, sleep: noSleep, fetchJoint: async () => bj }), /amount/);
  console.log("test_deposit_evidence: ok");
})().catch((e) => { console.error(e); process.exit(1); });
