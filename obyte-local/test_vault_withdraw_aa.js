"use strict";

// MINUEND vault withdrawal E2E — #37 items 4 (forest↔hash fold) + 11 (W watermark).
//
// Standalone from test_settlement_aa.js: the withdraw drill needs its own
// short chain (submit h1..h3 carrying REAL sharded forests, finalize in
// order, then withdraw against the finalized forest). Running it inside
// the settlement suite pushes the shared 20-minute CI job over its limit,
// so it lives here with per-step logging.
//
// Flow (all amounts in micro-base; the vault is seeded with a 1 USD deposit):
//   h1: forest F1 leaf (wdAcct, col=1000000, W=0)   → finalize
//       claim {700000 @ W=0} must bounce 'bad claim amount' (nothing debited)
//   h2: forest F2 leaf (wdAcct, col=300000, W=700000) → finalize
//       claim {700000 @ W=700000} PAYS (the issue's shape: sidechain had
//       already debited the 700000; the old min(col,W) gate refused it)
//       → wd_ == 700000
//       replay F1 leaf (W=0, amount 0) → bounces (watermark)
//   h3: forest F3 leaf (wdAcct, col=0, W=1000000)     → finalize
//       claim {300000 @ W=1000000} PAYS → wd_ == 1000000 (no dead-end)
//       replay F3 leaf (amount 1) → bounces 'bad claim amount'
//
// The forests are built in JS with the SAME fold the vault AA runs
// (leaf = sha256('acct:a:c:p:w'), node = sha256_hex(left||right), odd
// levels duplicate the last element; empty shards commit sha256("empty:i")).
// A decoy peer keeps every touched bucket at >= 2 members (ocore bans
// empty arrays in trigger data).

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

const ROLLUP_ADDR = chashOf(
  readDef("minuend_rollup.aa")
    .split("DISPUTE_AA_HERE").join("00000000000000000000000000000000")
    .split("DISPUTE_FILL_AA_HERE").join("00000000000000000000000000000000")
);
const ROLLUP_SRC = writeResolved("minuend_rollup.aa", {
  DISPUTE_AA_HERE: "00000000000000000000000000000000",
  DISPUTE_FILL_AA_HERE: "00000000000000000000000000000000",
}, ".e2e_vault_rollup.aa");
const VAULT_SRC = writeResolved("minuend_vault.aa", { ROLLUP_AA_HERE: ROLLUP_ADDR, PERP_ASSET_ID_HERE: "base" }, ".e2e_vault_withdraw.aa");

const SUBMIT_FEE = 10000;
const STATE_ROOT = sha256Hex("state-1");
const PREV_ROOT = sha256Hex("genesis");
// 44-char witness roots: content-free here (no dispute predicates run).
const b64root = (s) => Buffer.from(sha256Hex(s), "hex").toString("base64");

function submitData(height, stateRoot, prev, forest) {
  return {
    submit: 1,
    chain_id: "minuend-v2",
    assertion_version: 2,
    height,
    state_root: stateRoot,
    prev_state_hash: prev,
    aa_forest: forest,
    aa_root: sha256Hex(forest),
    wit_root: b64root("wit-" + height),
    trace_root: b64root("trace-" + height),
    units_root: b64root("units-" + height),
    units_set_root: b64root("set-" + height),
    ops_root: b64root("ops-" + height),
    fills_root: b64root("fills-" + height),
    counts_root: b64root("counts-" + height),
    unit_count: 1,
    wit_count: 1,
    fill_count: 0,
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

// --- hex-domain sharded forest (mirrors minuend_state aa_* fns) ---
const wdShard = (addr) => parseInt(sha256Hex(addr).slice(0, 2), 16) & 15;
const hexLeafOf = (addr, col, perp, w) => sha256Hex(`acct:${addr}:${col}:${perp}:${w}`);
const foldLR = (l, r) => sha256Hex(l + r);
function shardRoot(bucket, addr) {
  let level = bucket.map(([a, c, p, w]) => hexLeafOf(a, c, p, w)).sort();
  const leaf = hexLeafOf(addr, ...bucket.find(([a]) => a === addr).slice(1));
  let idx = level.indexOf(leaf);
  const sibs = [];
  while (level.length > 1) {
    if (level.length % 2 === 1) level.push(level[level.length - 1]);
    const pairIdx = idx ^ 1;
    sibs.push({ hash: level[pairIdx], right: pairIdx > idx });
    const nxt = [];
    for (let j = 0; j < level.length; j += 2) nxt.push(foldLR(level[j], level[j + 1]));
    level = nxt;
    idx = idx >> 1;
  }
  return [level[0], sibs];
}
function buildForest(pairs, wdAddr) {
  // ocore fatals on EMPTY arrays in trigger data, so the withdrawer's
  // shard bucket must hold >= 2 members for a non-empty proof (same
  // bucket-padding rule as gen_withdraw_proof.rs): deterministic PAD
  // decoys fill whichever shard lacks a second member.
  const all = pairs.slice();
  let pad = 0;
  const inShard = (a, s) => wdShard(a) === s;
  while (!all.some(([a]) => a !== wdAddr && inShard(a, wdShard(wdAddr)))) {
    pad += 1;
    all.push([`PAD${pad}`.padEnd(32, "0"), 500, 0, 0]);
  }
  const buckets = Array.from({ length: 16 }, () => []);
  for (const pr of all) buckets[wdShard(pr[0])].push(pr);
  const wdBucket = buckets[wdShard(wdAddr)];
  const [wdRoot, sibs] = shardRoot(wdBucket, wdAddr);
  if (sibs.length === 0) throw new Error("withdrawer shard proof is empty after padding");
  const roots = [];
  for (let i = 0; i < 16; i++) {
    if (buckets[i].length === 0) { roots[i] = sha256Hex("empty:" + i); continue; }
    const [r] = shardRoot(buckets[i], buckets[i][0][0]);
    roots[i] = r;
  }
  roots[wdShard(wdAddr)] = wdRoot;
  return { roots, sibs, shard: wdShard(wdAddr) };
}

async function main() {
  network = await Network.create()
    .with.agent({ rollup: ROLLUP_SRC })
    .with.agent({ vault: VAULT_SRC })
    .with.wallet({ operator: 2e14 })
    .run();
  const { operator } = network.wallet;
  const rollup = network.agent.rollup;
  const vault = network.agent.vault;
  if (rollup !== ROLLUP_ADDR) throw new Error(`rollup address mismatch: ${rollup} != ${ROLLUP_ADDR}`);
  console.log("network up:", { rollup, vault });
  const wdAcct = await operator.getAddress();
  const DECOY = "5B7BJSCMFQYUOLDLJHROMOKC5QCLPZLK3UEE4O25";
  console.log("withdrawer:", wdAcct, "shard:", wdShard(wdAcct));

  console.log("step 1: fund pool + seed vault deposit");
  await trigger(operator, rollup, { pool: 1 }, 10000000010000);
  const dep = await operator.triggerAaWithData({
    toAddress: vault, amount: 1000000 + 10000, data: { deposit: 1 },
  });
  if (dep.error) throw new Error("vault deposit failed: " + dep.error);
  await network.witnessUntilStable(dep.unit);
  console.log("  vault seeded");

  async function submitForest(hh, pairs) {
    const forest = buildForest(pairs, wdAcct);
    console.log(`step: submit h${hh} forest (shard ${forest.shard}, ${forest.sibs.length} siblings)`);
    const sd = submitData(hh, STATE_ROOT, hh === 1 ? PREV_ROOT : STATE_ROOT, forest.roots.join(""));
    await trigger(operator, rollup, sd, SUBMIT_FEE);
    const st = await vars(rollup);
    if (Number(st.last_submitted) !== hh) throw new Error(`h${hh} did not land`);
    if (st["aa_root_" + hh] !== sha256Hex(forest.roots.join("")))
      throw new Error(`aa_root_${hh} not stored`);
    return forest;
  }
  async function finalize(hh) {
    await network.timetravel({ shift: "3600s" });
    await trigger(operator, rollup, { finalize: 1, height: hh }, 20000);
    const st = await vars(rollup);
    if (Number(st.last_finalized) !== hh) throw new Error(`h${hh} not finalized`);
    console.log(`  h${hh} finalized`);
  }
  async function withdrawOk(forest, amount, withdrawn, col, wantWd) {
    console.log(`step: withdraw amount=${amount} withdrawn=${withdrawn} col=${col}`);
    const r = await operator.triggerAaWithData({
      toAddress: vault, amount: 20000,
      data: {
        withdraw: 1, amount, withdrawn, leaf_account: wdAcct,
        collateral: String(col), perp: "0", shard: forest.shard, proof: forest.sibs,
      },
    });
    if (r.error) throw new Error("withdraw trigger failed: " + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    if (JSON.stringify(res || {}).includes('"bounced":true'))
      throw new Error("withdraw bounced: " + bounceDetail(res));
    const st = await vars(vault);
    if (Number(st["wd_" + wdAcct] || 0) !== wantWd)
      throw new Error(`wd_ == ${st["wd_" + wdAcct]}, want ${wantWd}`);
    console.log(`  paid, wd_ == ${wantWd}`);
  }

  // h1: (col=1e6, W=0) — nothing debited, nothing payable.
  const f1 = await submitForest(1, [[wdAcct, 1000000, 0, 0], [DECOY, 500, 0, 0]]);
  await finalize(1);
  await triggerBounce(operator, vault, {
    withdraw: 1, amount: 700000, withdrawn: 0, leaf_account: wdAcct,
    collateral: "1000000", perp: "0", shard: f1.shard, proof: f1.sibs,
  }, 20000, "bad claim amount");
  console.log("  h1: zero-W claim refused");

  // h2: (col=300000, W=700000) — the issue's shape pays its pending 700k.
  const f2 = await submitForest(2, [[wdAcct, 300000, 0, 700000], [DECOY, 500, 0, 0]]);
  await finalize(2);
  await withdrawOk(f2, 700000, 700000, 300000, 700000);
  console.log("  h2: issue shape (col=300k, W=700k) pays — no brick");
  await triggerBounce(operator, vault, {
    withdraw: 1, amount: 0, withdrawn: 0, leaf_account: wdAcct,
    collateral: "1000000", perp: "0", shard: f1.shard, proof: f1.sibs,
  }, 20000, "bad claim amount");
  console.log("  h2: stale-leaf replay bounces (watermark)");

  // h3: (col=0, W=1000000) — residual 300k pays, no dead-end.
  const f3 = await submitForest(3, [[wdAcct, 0, 0, 1000000], [DECOY, 500, 0, 0]]);
  await finalize(3);
  await withdrawOk(f3, 300000, 1000000, 0, 1000000);
  console.log("  h3: residual pays, deposit fully drained");
  await triggerBounce(operator, vault, {
    withdraw: 1, amount: 1, withdrawn: 1000000, leaf_account: wdAcct,
    collateral: "0", perp: "0", shard: f3.shard, proof: f3.sibs,
  }, 20000, "bad claim amount");
  console.log("  h3: post-drain replay bounces");

  await network.stop();
  process.exit(failures === 0 ? 0 : 1);
}

main().catch(async (e) => {
  console.error("VAULT E2E FAILED:", e && e.stack ? e.stack : e);
  try { if (network) await network.stop(); } catch (_) {}
  process.exit(1);
});
