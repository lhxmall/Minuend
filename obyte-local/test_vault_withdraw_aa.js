"use strict";

// MINUEND vault withdrawal E2E — #37-11 (W watermark) + #47 A2 (the vault
// pays against the finalized WITNESS root, not the unpublished aa_forest).
//
// Standalone from test_settlement_aa.js: the withdraw drill needs its own
// short chain (submit h1..h3 carrying REAL witness roots, finalize in
// order, then withdraw against the finalized root). Running it inside the
// settlement suite pushes the shared CI job over its limit, so it lives
// here with per-step logging.
//
// Each height's wit_root is ocore's merkle root over sorted witness leaves
// (the Rust wit_leaves shape): adr:{payee}:{acct}, acct:{acct}:{col}:{perp}:{W}
// plus a decoy account/binding. Flow (micro-base; vault seeded with 1e6):
//   h1: (col=1000000, W=0)        → finalize
//       claim {700000 @ W=0} bounces 'bad claim amount' (nothing debited)
//   h2: (col=300000, W=700000)    → finalize
//       claim {700000 @ W=700000} PAYS → wd_ == 700000
//       replay of the h1 leaf (W=0) bounces (watermark)
//       #47 A2: the decoy's acct leaf claimed by the payee (no adr: leaf
//       binds the payee to it) bounces 'bad binding proof'
//   h3: (col=0, W=1000000)        → finalize
//       claim {300000 @ W=1000000} PAYS → wd_ == 1000000 (no dead-end)
//       replay (amount 1) bounces 'bad claim amount'

if (process.platform === "win32") {
  console.log("SKIP: e2e requires a POSIX env (aa-testkit child env omits APPDATA on win32); see CI e2e job.");
  process.exit(0);
}

const fs = require("fs");
const crypto = require("crypto");
const path = require("path");
const aaRoot = path.join(__dirname, "..", "vendor", "aa-testkit");
const nm = path.join(aaRoot, "node_modules");
process.env.NODE_PATH = [nm, process.env.NODE_PATH].filter(Boolean).join(path.delimiter);
require("module").Module._initPaths();
const { Testkit } = require(path.join(aaRoot, "main.js"));
const { Network } = Testkit({
  TESTDATA_DIR: path.join(__dirname, "testdata-vault-withdraw"),
  NETWORK_PORT: 16617,
});
const objectHash = require("ocore/object_hash.js");
const parseOjson = require("ocore/formula/parse_ojson").parse;

function sha256Hex(s) {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}
function readDef(file) {
  return fs.readFileSync(path.join(__dirname, "agents", file), "utf8");
}
function chashOf(aaSource) {
  let parsed = null;
  parseOjson(aaSource, (err, res) => {
    if (err) throw err;
    parsed = res[1];
  });
  return objectHash.getChash160(["autonomous agent", parsed]);
}
function writeResolved(file, subs, out) {
  let src = readDef(file);
  for (const [k, v] of Object.entries(subs)) src = src.split(k).join(v);
  const p = path.join(__dirname, out);
  fs.writeFileSync(p, src);
  return p;
}

const NO_DISPUTE = {
  DISPUTE_AA_HERE: "00000000000000000000000000000000",
  DISPUTE_FILL_AA_HERE: "00000000000000000000000000000000",
  DISPUTE_BIND_AA_HERE: "00000000000000000000000000000000",
};
const ROLLUP_SRC = writeResolved("minuend_rollup.aa", NO_DISPUTE, ".e2e_vault_rollup.aa");
const ROLLUP_ADDR = chashOf(fs.readFileSync(ROLLUP_SRC, "utf8"));
// Round 2: the vault is a parameterized instance of the base AA.
const VAULT_BASE_SRC = writeResolved("minuend_vault.aa", { PERP_ASSET_ID_HERE: "base" }, ".e2e_vault_withdraw_base.aa");
const VAULT_BASE_ADDR = chashOf(fs.readFileSync(VAULT_BASE_SRC, "utf8"));
const VAULT_DEF = { base_aa: VAULT_BASE_ADDR, params: { rollup: ROLLUP_ADDR } };
const { daBindHash } = require("./script_helpers");

const SUBMIT_FEE = 10000;
const STATE_ROOT = sha256Hex("state-1");
const PREV_ROOT = sha256Hex("genesis");
// 44-char roots for the commitments the vault does not read.
const b64root = (s) => Buffer.from(sha256Hex(s), "hex").toString("base64");
const merkle = require("ocore/merkle.js");
const FOREST = sha256Hex("f0").repeat(16); // informational only since #47 A2

function submitData(height, stateRoot, prev, witRoot) {
  return {
    submit: 1,
    chain_id: "minuend-v2",
    assertion_version: 2,
    height,
    state_root: stateRoot,
    prev_state_hash: prev,
    aa_forest: FOREST,
    aa_root: sha256Hex(FOREST),
    wit_root: witRoot,
    trace_root: b64root("trace-" + height),
    units_root: b64root("units-" + height),
    units_set_root: b64root("set-" + height),
    ops_root: b64root("ops-" + height),
    fills_root: b64root("fills-" + height),
    counts_root: b64root("counts-" + height),
    unit_count: 1,
    wit_count: 1,
    fill_count: 0,
    data_root: sha256Hex("frames-" + height),
  };
}
// R2-R-1: submits carry ONE temp_data header + da_bind over the roots.
function bindSubmit(sd) {
  sd.da_bind = daBindHash(sd);
  const header = Object.assign({}, sd);
  delete header.submit;
  delete header.aa_forest;
  return {
    messages: [
      {
        app: "temp_data",
        payload_location: "inline",
        payload: {
          data_length: require("ocore/object_length.js").getLength(header, true),
          data_hash: require("ocore/object_hash.js").getBase64Hash(header, true),
          data: header,
        },
      },
      { app: "data", payload: sd },
    ],
  };
}

let network;
let failures = 0;
async function trigger(wallet, to, data, amount) {
  console.log("trigger:", JSON.stringify(data).slice(0, 90));
  const r = await wallet.triggerAaWithData({ toAddress: to, amount, data });
  if (r.error) throw new Error(`trigger ${JSON.stringify(data).slice(0, 60)}: ${r.error}`);
  await network.witnessUntilStable(r.unit);
  console.log("  stable:", r.unit);
  return r;
}
async function triggerBounce(wallet, to, data, amount, needle) {
  console.log("expect bounce:", needle, JSON.stringify(data).slice(0, 90));
  const r = await wallet.triggerAaWithData({ toAddress: to, amount, data });
  if (r.error) {
    if (String(r.error).includes(needle)) {
      console.log(`  bounce ok (composer): '${needle}'`);
      return r;
    }
    failures++;
    console.error(`FAIL: expected bounce '${needle}' got error ${r.error}`);
    return r;
  }
  await network.witnessUntilStable(r.unit);
  const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
  const log = JSON.stringify(res || {});
  if (log.includes(needle)) {
    console.log(`  bounce ok: '${needle}'`);
    return r;
  }
  failures++;
  console.error(`FAIL: expected bounce '${needle}' got response ${log.slice(0, 300)}`);
  return r;
}
async function vars(aa) {
  const v = await network.wallet.operator.readAAStateVars(aa);
  return v.vars || v;
}
function bounceDetail(res) {
  const r = (res && res.response) || {};
  const reason = r.bounce_message || r.response_error || "";
  return (reason ? reason + " :: " : "") + JSON.stringify(r).slice(0, 1500);
}

// --- witness tree (mirrors minuend_state::wit_leaves for the leaves the
// vault reads): sorted leaves, ocore merkle (the same is_valid_merkle_proof
// the vault runs). ---
const ACCT = "ab".repeat(32);
const DECOY_ACCT = "cd".repeat(32);
function witTree(payee, col, w, payee2) {
  const DECOY = "5B7BJSCMFQYUOLDLJHROMOKC5QCLPZLK";
  const leaves = [
    ...(payee2 ? [`adr:${payee2}:${ACCT}`] : []),
    `adr:${payee}:${ACCT}`,
    `acct:${ACCT}:${col}:0:${w}`,
    `adr:${DECOY}:${DECOY_ACCT}`,
    `acct:${DECOY_ACCT}:500:0:900000`,
    "meta:1:1:1000:500:5:100:0:100:0:0",
  ].sort();
  const proofOf = (leaf) => {
    const i = leaves.indexOf(leaf);
    if (i < 0) throw new Error("leaf not in tree: " + leaf);
    return merkle.getMerkleProof(leaves, i);
  };
  return {
    root: merkle.getMerkleRoot(leaves),
    adrProof: proofOf(`adr:${payee}:${ACCT}`),
    acctProof: proofOf(`acct:${ACCT}:${col}:0:${w}`),
    decoyProof: proofOf(`acct:${DECOY_ACCT}:500:0:900000`),
    adr2Proof: payee2 ? proofOf(`adr:${payee2}:${ACCT}`) : null,
  };
}

async function main() {
  network = await Network.create()
    .with.agent({ vaultBase: VAULT_BASE_SRC })
    .with.agent({ rollup: ROLLUP_SRC })
    .with.agent({ vault: VAULT_DEF })
    .with.wallet({ operator: 2e14 })
    .with.wallet({ other: 1e9 })
    .run();
  const { operator, other } = network.wallet;
  const otherAddr = await other.getAddress();
  const rollup = network.agent.rollup;
  const vault = network.agent.vault;
  if (rollup !== ROLLUP_ADDR) throw new Error(`rollup address mismatch: ${rollup} != ${ROLLUP_ADDR}`);
  console.log("network up:", { rollup, vault });
  const wdAcct = await operator.getAddress();
  console.log("withdrawer:", wdAcct);

  console.log("step 1: fund pool + seed vault deposit");
  await trigger(operator, rollup, { pool: 1 }, 10000000010000);
  const dep = await operator.triggerAaWithData({
    toAddress: vault, amount: 1000000 + 10000, data: { deposit: 1, account: ACCT },
  });
  if (dep.error) throw new Error("vault deposit failed: " + dep.error);
  await network.witnessUntilStable(dep.unit);
  {
    const vs = await vars(vault);
    // R3-A-5: the record names the payer-chosen sidechain account.
    if (vs["dep_" + dep.unit] !== wdAcct + ":1000000:" + ACCT)
      throw new Error("R2-A-3/R3-A-5: vault dep_ ledger wrong: " + JSON.stringify(vs["dep_" + dep.unit]));
  }
  // R3-A-5: a deposit without a valid account bounces (refund, no record).
  for (const [tag, data] of [["missing", { deposit: 1 }], ["upper-hex", { deposit: 1, account: "AB".repeat(32) }], ["short", { deposit: 1, account: "ab".repeat(31) }]]) {
    const bad = await operator.triggerAaWithData({ toAddress: vault, amount: 50000, data });
    if (bad.error) throw new Error("bad-account deposit compose failed: " + bad.error);
    await network.witnessUntilStable(bad.unit);
    const res = await network.getAaResponseToUnit(bad.unit).catch(() => null);
    if (!(res && res.response && res.response.bounced))
      throw new Error("R3-A-5: deposit with " + tag + " account not bounced");
    const vs = await vars(vault);
    if (vs["dep_" + bad.unit] !== undefined) throw new Error("R3-A-5: bounced deposit recorded");
  }
  console.log("  vault seeded (dep_ ledger recorded with account; account-less deposits bounce)");

  async function submitWit(hh, col, w, payee2) {
    const t = witTree(wdAcct, col, w, payee2);
    console.log(`step: submit h${hh} wit_root (col=${col}, W=${w})`);
    const sd = submitData(hh, STATE_ROOT, hh === 1 ? PREV_ROOT : STATE_ROOT, t.root);
    const m = bindSubmit(sd);
    const r = await operator.sendMulti({ messages: m.messages, base_outputs: [{ address: rollup, amount: SUBMIT_FEE }] });
    if (r.error) throw new Error(`h${hh} submit failed: ` + r.error);
    await network.witnessUntilStable(r.unit);
    const st = await vars(rollup);
    if (Number(st.last_submitted) !== hh) throw new Error(`h${hh} did not land`);
    if (st["wit_root_" + hh] !== t.root) throw new Error(`wit_root_${hh} not stored`);
    return t;
  }
  async function finalize(hh) {
    await network.timetravel({ shift: "3600s" });
    await trigger(operator, rollup, { finalize: 1, height: hh }, 20000);
    const st = await vars(rollup);
    if (Number(st.last_finalized) !== hh) throw new Error(`h${hh} not finalized`);
    console.log(`  h${hh} finalized`);
  }
  const claim = (t, amount, withdrawn, col, extra) => Object.assign({
    withdraw: 1, amount, withdrawn: String(withdrawn), account: ACCT,
    collateral: String(col), perp: "0", adr_proof: t.adrProof, acct_proof: t.acctProof,
  }, extra || {});
  async function withdrawOk(t, amount, withdrawn, col, wantWd, extra) {
    console.log(`step: withdraw amount=${amount} withdrawn=${withdrawn} col=${col} ${JSON.stringify(extra || {})}`);
    const r = await operator.triggerAaWithData({
      toAddress: vault, amount: 20000, data: claim(t, amount, withdrawn, col, extra),
    });
    if (r.error) throw new Error("withdraw trigger failed: " + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    if (JSON.stringify(res || {}).includes('"bounced":true'))
      throw new Error("withdraw bounced: " + bounceDetail(res));
    const st = await vars(vault);
    // R2-A-8: the watermark is per ACCOUNT, not per payee address.
    if (Number(st["wd_" + ACCT] || 0) !== wantWd)
      throw new Error(`wd_ == ${st["wd_" + ACCT]}, want ${wantWd}`);
    console.log(`  paid, wd_ == ${wantWd}`);
  }

  // h1: (col=1e6, W=0) — nothing debited, nothing payable.
  const t1 = await submitWit(1, 1000000, 0);
  await finalize(1);
  await triggerBounce(operator, vault, claim(t1, 700000, 0, 1000000), 20000, "bad claim amount");
  console.log("  h1: zero-W claim refused");

  // h2: (col=300000, W=700000) — the issue's shape pays its pending 700k.
  const t2 = await submitWit(2, 300000, 700000);
  await finalize(2);
  // #47 A2: an acct leaf the payee is NOT bound to (no adr: leaf links the
  // payee to the decoy account) cannot pay, even with a valid acct proof.
  await triggerBounce(operator, vault, {
    withdraw: 1, amount: 1, withdrawn: "900000", account: DECOY_ACCT,
    collateral: "500", perp: "0", adr_proof: t2.adrProof, acct_proof: t2.decoyProof,
  }, 20000, "bad binding proof");
  console.log("  h2: unbound acct leaf refused (A2 binding)");
  // A proof against a non-finalized/other root bounces.
  await triggerBounce(operator, vault, claim(t1, 0, 0, 1000000), 20000, "bad binding proof");
  console.log("  h2: proof against a superseded root refused");
  // h3: (col=0, W=1000000), and a SECOND address bound to the same account.
  const t3 = await submitWit(3, 0, 1000000, otherAddr);
  await finalize(3);
  // R2-A-12: a proof against a recent finalized root (h2) still pays —
  // last_finalized moved on while the claim was in flight.
  await withdrawOk(t2, 700000, 700000, 300000, 700000, { height: 2 });
  console.log("  h3: h2-root claim pays after finalize moved (R2-A-12)");
  await triggerBounce(operator, vault, claim(t2, 1, 700000, 300000, { height: 2 }), 20000, "bad claim amount");
  console.log("  h3: older-root replay bounces on the per-account watermark");
  await triggerBounce(operator, vault, claim(t3, 1, 1000000, 0, { height: 4 }), 20000, "bad height");
  await triggerBounce(operator, vault, claim(t3, 1, 1000000, 0, { height: 1.5 }), 20000, "bad height");
  await withdrawOk(t3, 300000, 1000000, 0, 1000000);
  console.log("  h3: residual pays, deposit fully drained");
  await triggerBounce(operator, vault, claim(t3, 1, 1000000, 0), 20000, "bad claim amount");
  console.log("  h3: post-drain replay bounces");
  // R2-A-8: the second address bound to ACCT cannot spend the same W again.
  {
    const r = await other.triggerAaWithData({
      toAddress: vault, amount: 20000,
      data: { withdraw: 1, amount: 300000, withdrawn: "1000000", account: ACCT, collateral: "0", perp: "0", adr_proof: t3.adr2Proof, acct_proof: t3.acctProof },
    });
    if (r.error && !String(r.error).includes("bad claim amount")) throw new Error("second-address claim: " + r.error);
    if (!r.error) {
      await network.witnessUntilStable(r.unit);
      const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
      if (!JSON.stringify(res || {}).includes("bad claim amount")) {
        failures++;
        console.error("FAIL: second bound address double-spent W: " + JSON.stringify(res || {}).slice(0, 300));
      }
    }
    console.log("  R2-A-8: second bound address refused (per-account wd_)");
  }

  await network.stop();
  process.exit(failures === 0 ? 0 : 1);
}

main().catch(async (e) => {
  console.error("VAULT E2E FAILED:", e && e.stack ? e.stack : e);
  try { if (network) await network.stop(); } catch (_) {}
  process.exit(1);
});
