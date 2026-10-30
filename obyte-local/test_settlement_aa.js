"use strict";

// MINUEND settlement E2E — three-agent lifecycle (rollup + dispute + vault).
//
// This is the settlement-v2 harness. The vault is pure custody (no submit /
// lock / challenge / finalize), the rollup AA stores bonded assertions,
// and the dispute AA is the only party that can fail a height — via
// one-shot Oscript-verified fraud predicates, never a pay-to-kill bond.
//
// Agent addresses are deterministic (chash160 of the definition), so the
// rollup address is precomputed with the same ocore call the testkit uses
// (objectHash.getChash160(['autonomous agent', def])) and substituted into
// the dispute/vault sources BEFORE Network.create — a single network start.
//
// Scenarios:
//  1.  bind dispute + fill → rollup dispute_aa/_fill set; double bind bounces
//  2.  pool gate: no pool → 'need pool'; {pool:1} funds standing pool
//  3.  combined submit height 1 (10000 fee) → last_submitted=1; resubmit 'bad submit'
//  4.  {lock:1} / {challenge:1} have NO cases → auto-bounce, nothing frozen
//  5.  finalize before 3600s → 'cannot finalize'; after → last_finalized=1, no sbond credit
//  6. omit (forced id missing) now bounces 'no fraud' (#23: force pins a
//      timestamp only, never an existence claim)
//  7. dishonest post collateral → verdict fires: frozen=2, last_submitted
//      rolls back, slash_reward_ 500000000000 claimable, pool slashed 5e11
//  8. honest deposit → 'no fraud', height stays live
//  9-13. fill_math/ghost/skip predicates on h3 chain (unit-bound via
//      units_proof; a fake unit hex bounces 'bad unit')
//  14. two-package (gzip) height deposit fraud → frozen=3
//  15. re-submit + finalize after fraud works
//  16. pipeline h4+h5 with no inter-finalize, then finalize in order
//  17. pool claim: 'pool busy' while live, full claim when idle

// Windows: aa-testkit's runChild replaces the child env wholesale and never
// sets APPDATA, which ocore's desktop_app reads on win32 — the genesis node
// crashes before the network starts. The plan gates e2e on CI (ubuntu);
// skip gracefully on win32 rather than fail.
if (process.platform === "win32") {
  console.log("SKIP: e2e requires a POSIX env (aa-testkit child env omits APPDATA on win32); see CI e2e job.");
  process.exit(0);
}

const fs = require("fs");
const crypto = require("crypto");
const zlib = require("zlib");
const path = require("path");
const aaRoot = path.join(__dirname, "..", "vendor", "aa-testkit");
const nm = path.join(aaRoot, "node_modules");
process.env.NODE_PATH = [nm, process.env.NODE_PATH].filter(Boolean).join(path.delimiter);
require("module").Module._initPaths();
const { Testkit } = require(path.join(aaRoot, "main.js"));
const { Network } = Testkit({
  TESTDATA_DIR: path.join(__dirname, "testdata-settlement"),
  NETWORK_PORT: 16615,
});
const objectHash = require("ocore/object_hash.js");
const parseOjson = require("ocore/formula/parse_ojson").parse;

const PERP_ASSET = "base"; // devnet: no issued asset; deposit_perp branch keyed by data, not asset

function sha256Hex(s) {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}
const merkle = require("ocore/merkle.js");

// ---- agent bootstrap ------------------------------------------------------

function readDef(file) {
  const src = fs.readFileSync(path.join(__dirname, "agents", file), "utf8");
  return src;
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
  const p = path.join(__dirname, "agents", out);
  fs.writeFileSync(p, src);
  return p;
}

// Precompute the rollup address from its definition (no placeholders).
// #13: the rollup hardcodes both dispute addresses (anti-hijack), so they
// hash FIRST. Dispute/fill carry no rollup address in their definitions —
// binds and challenges pass it in trigger data — which is what breaks the
// chash cycle (each address would otherwise be a hash input of the other).
// Round 2 (R2-A-3): the vault is a parameterized instance of a base AA;
// dispute.aa hardcodes the BASE (no addresses inside it) and derives the
// rollup's one genuine vault with chash160 — no cycle.
const VAULT_BASE_SRC = writeResolved("minuend_vault.aa", { PERP_ASSET_ID_HERE: PERP_ASSET }, ".e2e_vault_base.aa");
const VAULT_BASE_ADDR = chashOf(fs.readFileSync(VAULT_BASE_SRC, "utf8"));
const DISPUTE_SRC = writeResolved("minuend_dispute.aa", { VAULT_BASE_HERE: VAULT_BASE_ADDR }, ".e2e_dispute.aa");
const BOOK_SRC = writeResolved("minuend_dispute_book.aa", {}, ".e2e_book.aa");
const BOOK_ADDR = chashOf(fs.readFileSync(BOOK_SRC, "utf8"));
const FILL_SRC = writeResolved("minuend_dispute_fill.aa", {}, ".e2e_fill.aa");
// Round 6: P-claw (both legs of one fill) on the claw dispute AA.
const CLAW_SRC = writeResolved("minuend_dispute_claw.aa", {}, ".e2e_claw.aa");
const CLAW_ADDR = chashOf(fs.readFileSync(CLAW_SRC, "utf8"));
const XF_SRC = writeResolved("minuend_dispute_xframe.aa", {}, ".e2e_xframe.aa");
const XF_ADDR = chashOf(fs.readFileSync(XF_SRC, "utf8"));
// Round 8: P-mframe / P-noband on the m-frame dispute AA.
const MF_SRC = writeResolved("minuend_dispute_mframe.aa", {}, ".e2e_mframe.aa");
const MF_ADDR = chashOf(fs.readFileSync(MF_SRC, "utf8"));
// R4-A-4: P-adr derives the vault from the base (deposit ledger backing).
const BIND_SRC = writeResolved("minuend_dispute_bind.aa", { VAULT_BASE_HERE: VAULT_BASE_ADDR }, ".e2e_bind.aa");
const DISPUTE_ADDR = chashOf(fs.readFileSync(DISPUTE_SRC, "utf8"));
const FILL_ADDR = chashOf(fs.readFileSync(FILL_SRC, "utf8"));
const BIND_ADDR = chashOf(fs.readFileSync(BIND_SRC, "utf8"));
const ROLLUP_SRC = writeResolved("minuend_rollup.aa", {
  DISPUTE_AA_HERE: DISPUTE_ADDR,
  DISPUTE_FILL_AA_HERE: FILL_ADDR,
  DISPUTE_BIND_AA_HERE: BIND_ADDR,
  DISPUTE_BOOK_AA_HERE: BOOK_ADDR,
  DISPUTE_CLAW_AA_HERE: CLAW_ADDR,
  DISPUTE_XFRAME_AA_HERE: XF_ADDR,
  DISPUTE_MFRAME_AA_HERE: MF_ADDR,
}, ".e2e_rollup.aa");
const ROLLUP_ADDR = chashOf(fs.readFileSync(ROLLUP_SRC, "utf8"));
const VAULT_DEF = { base_aa: VAULT_BASE_ADDR, params: { rollup: ROLLUP_ADDR } };
const VAULT_ADDR = objectHash.getChash160(["autonomous agent", VAULT_DEF]);
const { daBindHash } = require("./script_helpers");
const POOL_FUND_GROSS = 50000000010000; // 50x POOL_MIN net: survives all fraud slashes in this run
const SUBMIT_FEE = 10000; // submits pay only the bounce fee; pool gates
const RACE_REWARD = 20000;
const SLASH_HALF = 500000000000;
// R2-A-9: the challenger is credited 1/5 of the seized amount.
const slashReward = (seized) => Math.floor(seized / 5);
const SLASH_REWARD = slashReward(SLASH_HALF);

let network;
let failures = 0;
async function trigger(wallet, to, data, amount) {
  const r = await wallet.triggerAaWithData({ toAddress: to, amount, data });
  if (r.error) throw new Error(`trigger ${JSON.stringify(data).slice(0, 60)}: ${r.error}`);
  await network.witnessUntilStable(r.unit);
  return r;
}

async function triggerBounce(wallet, to, data, amount, needle) {
  const r = await wallet.triggerAaWithData({ toAddress: to, amount, data });
  if (r.error) {
    // Direct composer/wallet error already carries the bounce reason.
    if (String(r.error).includes(needle)) {
      console.log(`bounce ok: '${needle}'`);
      return r;
    }
    failures++;
    console.error(`FAIL: expected bounce '${needle}' got error ${r.error} for ${JSON.stringify(data).slice(0, 80)}`);
    return r;
  }
  await network.witnessUntilStable(r.unit);
  // Bounces surface on the AA response unit, not the trigger result.
  const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
  const log = JSON.stringify(res || {});
  if (log.includes(needle)) {
    console.log(`bounce ok: '${needle}'`);
    return r;
  }
  failures++;
  console.error(`FAIL: expected bounce '${needle}' got response ${log.slice(0, 200)} for ${JSON.stringify(data).slice(0, 80)}`);
  console.error(`FULL RESPONSE: ${log.slice(0, 2000)}`);
  return r;
}

async function vars(aa) {
  const v = await (network.wallet.operator || network.wallet.challenger).readAAStateVars(aa);
  return v.vars || v;
}

// Full bounce diagnostics: reason first, then the response (never sliced
// short — CI failures must be diagnosable from one log line).
function bounceDetail(res) {
  const r = (res && res.response) || {};
  const reason = r.bounce_message || r.response_error || "";
  return (reason ? reason + " :: " : "") + JSON.stringify(r).slice(0, 1500);
}

// Genesis witness tree: the height-1 submit commits WIT_ROOT, so every
// k==0 predicate (pre_wit == wit_root_1) proves leaves against this tree.
// Deposit scenario uses DEP_ACCT (old account, pre col 1000000); fill
// scenarios use FILL_TAKER (flat) + META1. All proofs below are real
// merkle.getMerkleProof paths — no dummy self-proofs.
const DEP_ACCT = "a".repeat(64);
const DEP_PRE = `acct:${DEP_ACCT}:1000000:0:0`;
const FILL_TAKER = "b".repeat(64);
const FILL_TAKER_PRE = `acct:${FILL_TAKER}:0:0:0`;
const META1 = `meta:1:1:1000:500:5:100:0:100:0:0`;
const META2 = `meta:2:1:1000:500:5:100:0:100:0:0`;
const POS2 = `pos:${FILL_TAKER}:2:50000000:90000000:0:0`;
const GENESIS_LEAVES = [DEP_PRE, FILL_TAKER_PRE, META1, META2, POS2].sort();
const WIT_ROOT = merkle.getMerkleRoot(GENESIS_LEAVES);
const GEN_WIT_COUNT = GENESIS_LEAVES.length;
// ocore canonical JSON bans empty arrays: a single-leaf merkle proof has
// `"siblings":[]` and the whole trigger is uncomposable. Pad every proof
// array to >= 2 leaves so every proof carries >= 1 sibling. 'pad:' sorts
// after all leaf domains (acct/f/meta/ord), keeping after-max geometry.
function pad2(arr, tag) {
  if (arr.length >= 2) return arr;
  return arr.concat([`pad:${tag}:${"z".repeat(16)}`]);
}
// fills_root tree (mirrors Rust fills_root_elements): the raw fills plus
// one trailing length sentinel `n:{len}` — the trailing fill's right
// neighbor. The sentinel also guarantees >= 2 leaves, so fills proofs
// always carry >= 1 sibling (canonical JSON bans empty sibling arrays).
const fillsTree = (a) => a.concat("n:" + a.length);
function b6444(seed) {
  const h = crypto.createHash("sha256").update(seed, "utf8").digest("base64");
  return h; // exactly 44 chars
}

const TRACE_ROOT = b6444("trace-root");
const UNITS_ROOT = b6444("units-root");
const UNITS_SET_ROOT = b6444("units-set-root");
const OPS_ROOT = b6444("ops-root");
const FILLS_ROOT = b6444("fills-root");
const COUNTS_ROOT = b6444("counts-root");
const STATE_ROOT = sha256Hex("state-1");
const PREV_ROOT = sha256Hex("genesis");
const FOREST = sha256Hex("f0").repeat(16); // 1024 hex

var submitData;
function submitDataBase(height, stateRoot, prev) {
  return {
    submit: 1,
    chain_id: "minuend-v2",
    assertion_version: 6,
    height,
    state_root: stateRoot,
    prev_state_hash: prev,
    aa_forest: FOREST,
    // #37-4: real fold binding — forest hash must equal sha256(forest).
    aa_root: sha256Hex(FOREST),
    wit_root: WIT_ROOT,
    trace_root: TRACE_ROOT,
    units_root: UNITS_ROOT,
    units_set_root: UNITS_SET_ROOT,
    ops_root: OPS_ROOT,
    fills_root: FILLS_ROOT,
    counts_root: COUNTS_ROOT,
    unit_count: 1,
    wit_count: GEN_WIT_COUNT,
    fill_count: 0,
  };
}
// R2-R-1: a raw submitData() carries a valid data_root + da_bind so gate
// bounces ('need pool', 'bad submit') stay reachable; headerFromSubmit()
// re-binds after callers mutate the roots.
function rebind(sd) {
  if (!sd.data_root) sd.data_root = sha256Hex("frames-" + sd.height);
  sd.da_bind = daBindHash(sd);
  return sd;
}
const submitDataRaw = submitDataBase;
submitData = function (height, stateRoot, prev) { return rebind(submitDataRaw(height, stateRoot, prev)); };
// Single-package inline DA: full header scalars + frames_blob (gzip of the
// `\n`-joined frames, base64). Derived from the submit so header roots match
// the commitment; the AA only reads the submit, but the blob path is exercised.
function headerFromSubmit(sd, frameOp) {
  const frame = JSON.stringify({ u: { op: "x" }, t: sd.trace_root, o: frameOp || "x", c: "1" });
  const blob = zlib.gzipSync(Buffer.from(frame, "utf8")).toString("base64");
  const raw = zlib.gunzipSync(Buffer.from(blob, "base64"));
  const h = {
    chain_id: sd.chain_id || "minuend-v2",
    height: sd.height,
    prev_state_hash: sd.prev_state_hash,
    state_root: sd.state_root,
    aa_root: sha256Hex(sd.aa_forest || ""),
    aa_shard_roots: Array(16).fill(sha256Hex("shard")),
    last_unit: sha256Hex("last"),
    seq: sd.height,
    fill_count: sd.fill_count || 0,
    fills_hash: sha256Hex("fills"),
    assertion_version: sd.assertion_version || 5,
    wit_root: sd.wit_root,
    trace_root: sd.trace_root,
    units_root: sd.units_root,
    units_set_root: sd.units_set_root,
    unit_count: sd.unit_count,
    wit_count: sd.wit_count,
    ops_root: sd.ops_root,
    fills_root: sd.fills_root,
    counts_root: sd.counts_root,
    frames_blob: blob,
    data_root: crypto.createHash("sha256").update(raw).digest("hex"),
  };
  // R2-R-1: the submit commits the header's data_root and the binding hash
  // over every root; the header repeats da_bind.
  sd.data_root = h.data_root;
  rebind(sd);
  h.da_bind = sd.da_bind;
  return h;
}
function tempDataMsg(data) {
  return {
    app: "temp_data",
    payload_location: "inline",
    payload: {
      data_length: require("ocore/object_length.js").getLength(data, true),
      data_hash: require("ocore/object_hash.js").getBase64Hash(data, true),
      data,
    },
  };
}
async function sendCombinedSubmit(wallet, height, stateRoot, prev) {
  const sd = submitData(height, stateRoot, prev);
  const header = headerFromSubmit(sd);
  const r = await wallet.sendMulti({
    messages: [
      tempDataMsg(header),
      { app: "data", payload: sd },
    ],
    base_outputs: [{ address: ROLLUP_ADDR, amount: SUBMIT_FEE }],
  });
  if (r.error) throw new Error("combined submit failed: " + r.error);
  await network.witnessUntilStable(r.unit);
  // sendMulti reports composer errors only; the AA bounce surfaces on the
  // response unit — fail fast here instead of cascading 'no height' later.
  const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
  const log = JSON.stringify(res || {});
  if (log.includes('"bounced":true')) {
    throw new Error("combined submit bounced: " + log.slice(0, 1500));
  }
  return r;
}

async function main() {
  console.log("rollup address (precomputed):", ROLLUP_ADDR);
  console.log("dispute address (precomputed):", DISPUTE_ADDR);
  console.log("fill address (precomputed):", FILL_ADDR);

  network = await Network.create()
    .with.agent({ vaultBase: VAULT_BASE_SRC })
    .with.agent({ rollup: ROLLUP_SRC })
    .with.agent({ book: BOOK_SRC })
    .with.agent({ dispute: DISPUTE_SRC })
    .with.agent({ fill: FILL_SRC })
    .with.agent({ bind: BIND_SRC })
    .with.agent({ claw: CLAW_SRC })
    .with.agent({ xframe: XF_SRC })
    .with.agent({ mframe: MF_SRC })
    .with.agent({ vault: VAULT_DEF })
    .with.wallet({ operator: 2e14 })
    .with.wallet({ challenger: 1e13 })
    .run();
  const { operator, challenger } = network.wallet;
  const rollup = network.agent.rollup;
  const dispute = network.agent.dispute;
  const fill = network.agent.fill;
  const bindAa = network.agent.bind;
  const vault = network.agent.vault;
  const book = network.agent.book;
  const claw = network.agent.claw;
  const xframe = network.agent.xframe;
  if (xframe !== XF_ADDR) throw new Error(`xframe address mismatch: ${xframe} != ${XF_ADDR}`);
  const mframe = network.agent.mframe;
  if (mframe !== MF_ADDR) throw new Error(`mframe address mismatch: ${mframe} != ${MF_ADDR}`);
  if (claw !== CLAW_ADDR) throw new Error(`claw address mismatch: ${claw} != ${CLAW_ADDR}`);
  if (vault !== VAULT_ADDR) throw new Error(`vault address mismatch: ${vault} != ${VAULT_ADDR}`);
  if (rollup !== ROLLUP_ADDR) throw new Error(`rollup address mismatch: ${rollup} != ${ROLLUP_ADDR}`);
  console.log("network up:", { rollup, dispute, fill, vault });

  // ---- 1. bind dispute + fill ------------------------------------------------
  await trigger(operator, dispute, { bind: 1, rollup: ROLLUP_ADDR }, 20000);
  await trigger(operator, fill, { bind_fill: 1, rollup: ROLLUP_ADDR }, 20000);
  await trigger(operator, bindAa, { bind_bind: 1, rollup: ROLLUP_ADDR }, 20000);
  await trigger(operator, book, { bind_book: 1, rollup: ROLLUP_ADDR }, 20000);
  await trigger(operator, claw, { bind_claw: 1, rollup: ROLLUP_ADDR }, 20000);
  await trigger(operator, xframe, { bind_xframe: 1, rollup: ROLLUP_ADDR }, 20000);
  await trigger(operator, mframe, { bind_mframe: 1, rollup: ROLLUP_ADDR }, 20000);
  let st = await vars(rollup);
  if (String(st.dispute_mframe_aa) !== mframe) throw new Error("dispute_mframe_aa not set: " + JSON.stringify(st.dispute_mframe_aa));
  if (String(st.dispute_xframe_aa) !== xframe) throw new Error("dispute_xframe_aa not set: " + JSON.stringify(st.dispute_xframe_aa));
  if (String(st.dispute_claw_aa) !== claw) throw new Error("dispute_claw_aa not set: " + JSON.stringify(st.dispute_claw_aa));
  if (String(st.dispute_book_aa) !== book) throw new Error("dispute_book_aa not set: " + JSON.stringify(st.dispute_book_aa));
  if (String(st.dispute_bind_aa) !== bindAa) throw new Error("dispute_bind_aa not set: " + JSON.stringify(st.dispute_bind_aa));
  if (String(st.dispute_aa) !== dispute) throw new Error("dispute_aa not set: " + JSON.stringify(st.dispute_aa));
  if (String(st.dispute_fill_aa) !== fill) throw new Error("dispute_fill_aa not set: " + JSON.stringify(st.dispute_fill_aa));
  console.log("1. bind ok — dispute_aa + dispute_fill_aa set");
  // #13: a foreign sender (wallet or any other AA) cannot set_dispute —
  // the rollup only accepts the two addresses hardcoded into its def.
  await triggerBounce(operator, rollup, { set_dispute: 1 }, 20000, "not authorized");
  await triggerBounce(operator, rollup, { set_dispute_fill: 1 }, 20000, "not authorized");
  await triggerBounce(operator, rollup, { set_dispute_bind: 1 }, 20000, "not authorized");
  await triggerBounce(operator, rollup, { set_dispute_book: 1 }, 20000, "not authorized");
  await triggerBounce(operator, rollup, { set_dispute_claw: 1 }, 20000, "not authorized");
  await triggerBounce(operator, rollup, { set_dispute_xframe: 1 }, 20000, "not authorized");
  await triggerBounce(operator, rollup, { set_dispute_mframe: 1 }, 20000, "not authorized");
  // A second bind succeeds on the dispute AA (it just re-forwards), but the
  // rollup bounces the secondary 'not authorized' verdict — dispute_aa var
  // must be unchanged afterwards.
  await trigger(operator, dispute, { bind: 1, rollup: ROLLUP_ADDR }, 20000);
  st = await vars(rollup);
  if (String(st.dispute_aa) !== dispute) throw new Error("double bind overwrote dispute_aa!");

  // ---- 2. pool gate: no pool → 'need pool'; fund {pool:1} → gate passes ----
  const sd = submitData(1, STATE_ROOT, PREV_ROOT);
  await triggerBounce(operator, rollup, Object.assign({}, sd, { height: 1 }), 20000, "need pool");
  await trigger(operator, rollup, { pool: 1 }, POOL_FUND_GROSS);
  st = await vars(rollup);
  if (Number(st["pool_" + (await operator.getAddress())] || 0) < 1000000000000)
    throw new Error("pool not funded: " + JSON.stringify(st["pool_" + (await operator.getAddress())]));
  console.log("2. pool gate ok — funded standing pool");

  // ---- 3. combined submit height 1 --------------------------------------
  await sendCombinedSubmit(operator, 1, STATE_ROOT, PREV_ROOT);
  st = await vars(rollup);
  if (Number(st.last_submitted) !== 1) throw new Error("last_submitted != 1: " + st.last_submitted);
  if (st.state_root_1 !== STATE_ROOT) throw new Error("state_root_1 mismatch");
  if (st.da_unit_1 === undefined) throw new Error("da_unit_1 not pinned");
  // resubmit same height → 'bad submit' (h != last_submitted+1; the
  // 'height taken' gate only applies to a fresh h == last_submitted+1)
  await triggerBounce(operator, rollup, submitData(1, STATE_ROOT, PREV_ROOT), SUBMIT_FEE, "bad submit");
  console.log("3. combined submit ok, resubmit rejected");

  // ---- 4. lock/challenge are dead paths ---------------------------------
  await triggerBounce(operator, rollup, { lock: 1, height: 1 }, 20000, "neither case is true in messages");
  await triggerBounce(operator, rollup, { challenge: 1, height: 1 }, 1000000000000, "neither case is true in messages");
  st = await vars(rollup);
  if (Number(st.frozen_1 || 0) !== 0) throw new Error("height 1 frozen by dead path!");
  console.log("4. lock/challenge have no cases — assertion untouched");

  // ---- 5. finalize windows ----------------------------------------------
  await triggerBounce(operator, rollup, { finalize: 1, height: 1 }, 20000, "cannot finalize");
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 1 }, 20000);
  st = await vars(rollup);
  if (Number(st.last_finalized) !== 1) throw new Error("last_finalized != 1");
  if (Number(st["reward_" + (await operator.getAddress())] || 0) !== RACE_REWARD)
    throw new Error("operator race reward not accrued");
  console.log("5. finalize ok, race reward accrued, no sbond credit");
  if (Number(st["sbond_" + (await operator.getAddress())] || 0) !== 0)
    throw new Error("finalize must not credit sbond under pool model");

  // ---- 6. honest deposit predicate bounces 'no fraud' --------------------
  // All proofs are real merkle.getMerkleProof paths. post_wit commits a
  // single-leaf post tree [postLeaf]; pre leaves prove in GENESIS_LEAVES.
  const acct = DEP_ACCT;
  // R2-A-3: a credited deposit must cite a payment the vault recorded:
  // the operator pays the vault 100000 (+10000 bounce fee) and the op
  // carries that unit as its anchor.
  const opAddr0 = await operator.getAddress();
  // R3-A-5: the payer names the credited sidechain account.
  const depUnit = (await trigger(operator, vault, { deposit: 1, account: acct }, 110000)).unit;
  st = await vars(vault);
  if (st["dep_" + depUnit] !== opAddr0 + ":100000:" + acct) throw new Error("vault dep_ ledger wrong: " + JSON.stringify(st["dep_" + depUnit]));
  const opD = `d:${acct}:100000:${opAddr0}:${depUnit}`;
  const preLeaf = DEP_PRE;
  const postLeaf = `acct:${acct}:1100000:0:0`;
  const OPS1 = pad2([opD], "ops1");
  const POST1 = pad2([postLeaf], "post1");
  const POST_WIT1 = merkle.getMerkleRoot(POST1);
  const TRACE1 = pad2([POST_WIT1], "trace1");
  const OPS_ROOT1 = merkle.getMerkleRoot(OPS1);
  const TRACE_ROOT1 = merkle.getMerkleRoot(TRACE1);
  // Height 2 submit carrying the REAL roots the predicates stale-check.
  // Each scenario needs a FRESH height-2 candidate: a second submit to the
  // same live height bounces 'height taken' and the AA keeps the ORIGINAL
  // committed roots, so every predicate would stale-root. Pattern: submit →
  // prove fraud (frozen=2, height reopens) → next scenario re-submits.
  async function submitH2(opsRoot, traceRoot, unitsSetRoot, fillsRoot, witRoot, witCount) {
    const sd = submitData(2, STATE_ROOT, STATE_ROOT);
    sd.ops_root = opsRoot;
    sd.trace_root = traceRoot;
    sd.units_root = UNITS_SET_ROOT;
    sd.units_set_root = unitsSetRoot;
    sd.fills_root = fillsRoot;
    sd.unit_count = 1;
    sd.wit_root = witRoot || WIT_ROOT;
    sd.wit_count = witCount || GEN_WIT_COUNT;
    const h2header = headerFromSubmit(sd);
    const r = await operator.sendMulti({
      messages: [
        tempDataMsg(h2header),
        { app: "data", payload: sd },
      ],
      base_outputs: [{ address: rollup, amount: SUBMIT_FEE }],
    });
    if (r.error) throw new Error("h2 submit failed: " + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    if (res && res.response && res.response.bounced)
      throw new Error("h2 submit bounced: " + bounceDetail(res));
  }
  // H3 pre-tree (genesis leaves + two live orders) is hoisted here because
  // scenario 8's honest h2 submit must ALREADY commit it as wit_root_2:
  // every h3 k=0 predicate anchors pre_wit on wit_root_2.
  const MAKER_ORD = `ord:${"d".repeat(64)}:1:1:100000000:7:5:${"c".repeat(64)}:0:0`;
  const BETTER_ORD = `ord:${"e".repeat(63)}f:1:1:90000000:6:9:${"c".repeat(64)}:0:0`;
  const H3_PRE = [DEP_PRE, FILL_TAKER_PRE, META1, META2, POS2, MAKER_ORD, BETTER_ORD].sort();
  const H3_PRE_WIT = merkle.getMerkleRoot(H3_PRE);
  const H3_PRE_IDX = {};
  H3_PRE.forEach((l, i) => { H3_PRE_IDX[l] = i; });
  // h3 commits ONE real unit: fill predicates bind $F[1] to units_root via
  // units_proof (index == k), so the committed root must be a genuine
  // merkle root over a unit-hex array, not a seed hash.
  const H3_UNIT_HEX = sha256Hex("h3-unit");
  const UNITS3 = pad2([H3_UNIT_HEX], "units3");
  const UNITS3_ROOT = merkle.getMerkleRoot(UNITS3);
  const UNITS3_PROOF = merkle.getMerkleProof(UNITS3, 0);
  async function triggerVerdict(wallet, to, data, amount, what) {
    const t = await trigger(wallet, to, data, amount);
    const r = await network.getAaResponseToUnit(t.unit).catch(() => null);
    const inner = r && r.response && (r.response.response || r.response);
    if (r && r.response && r.response.bounced)
      throw new Error(what + " bounced: " + bounceDetail(r));
    await network.witnessUntilStable(r.response.response_unit);
  }
  const forcedOmit = sha256Hex("forced-unit");
  await trigger(operator, rollup, { force: 1, unit_id: forcedOmit }, 20000);
  await network.timetravel({ shift: "60s" }); // force ts strictly < inbox_upto_2
  const otherId = sha256Hex("other-unit");
  const SET1 = pad2([otherId], "set1");
  const SET_ROOT1 = merkle.getMerkleRoot(SET1);
  // ---- 6. omit: force empty hole (#23) → 'no fraud', height stays live ----
  // The LIAR trace commits here once: scenario 6 cannot freeze, and 7 must
  // not re-submit the same live height ('height taken').
  // #47: col 1050000 is neither pre (1000000 = the honest REJECTED-deposit
  // shape, which now bounces) nor pre+amount (1100000).
  const LIAR_POST1 = pad2([`acct:${acct}:1050000:0:0`], "liar1");
  const LIAR_WIT1 = merkle.getMerkleRoot(LIAR_POST1);
  const LIAR_TRACE1 = pad2([LIAR_WIT1], "liartrace1");
  const LIAR_TRACE_ROOT1 = merkle.getMerkleRoot(LIAR_TRACE1);
  await submitH2(OPS_ROOT1, LIAR_TRACE_ROOT1, SET_ROOT1, FILLS_ROOT);
  const omitProof = {
    rollup: ROLLUP_ADDR,
    trace_root: LIAR_TRACE_ROOT1,
    ops_root: OPS_ROOT1,
    units_root: UNITS_SET_ROOT,
    units_set_root: SET_ROOT1,
    fills_root: FILLS_ROOT,
    unit_id: forcedOmit,
    left: otherId,
    left_proof: merkle.getMerkleProof(SET1, 0),
  };
  await triggerBounce(challenger, dispute, Object.assign({ pred: "omit", height: 2 }, omitProof), 20000, "no fraud");
  st = await vars(rollup);
  if (Number(st.frozen_2 || 0) !== 0) throw new Error("omit force-hole froze the height!");
  console.log("6. omit force-hole bounced 'no fraud' — height live");

  const depPreIdx = GENESIS_LEAVES.indexOf(preLeaf);

  // ---- 7. deposit fraud on the committed LIAR trace → verdict, slash ----
  const fraudProof = {
    rollup: ROLLUP_ADDR,
    k: 0,
    op: opD,
    ops_proof: merkle.getMerkleProof(OPS1, 0),
    trace_root: LIAR_TRACE_ROOT1,
    ops_root: OPS_ROOT1,
    units_root: UNITS_SET_ROOT,
    units_set_root: SET_ROOT1,
    fills_root: FILLS_ROOT,
    pre_wit: WIT_ROOT,
    post_wit: LIAR_WIT1,
    post_proof: merkle.getMerkleProof(LIAR_TRACE1, 0),
    pre_leaf: preLeaf,
    post_leaf: LIAR_POST1[0], // col off by 50000 from pre+amount
    pre_leaf_proof: merkle.getMerkleProof(GENESIS_LEAVES, depPreIdx),
    post_leaf_proof: merkle.getMerkleProof(LIAR_POST1, 0),
  };
  await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 2 }, fraudProof), 20000, "deposit fraud predicate");
  st = await vars(rollup);
  // Batch-B scenarios re-commit the SAME LIAR fixture at later fresh
  // heights, so the deposit predicate's stale-root check passes.
  async function submitLiarAt(hh) {
    const sd = submitData(hh, STATE_ROOT, STATE_ROOT);
    sd.ops_root = OPS_ROOT1;
    sd.trace_root = LIAR_TRACE_ROOT1;
    sd.units_root = UNITS_SET_ROOT;
    sd.units_set_root = SET_ROOT1;
    sd.fills_root = FILLS_ROOT;
    sd.wit_root = WIT_ROOT;
    sd.wit_count = GEN_WIT_COUNT;
    const header = headerFromSubmit(sd);
    const r = await operator.sendMulti({
      messages: [tempDataMsg(header), { app: "data", payload: sd }],
      base_outputs: [{ address: rollup, amount: SUBMIT_FEE }],
    });
    if (r.error) throw new Error(`h${hh} LIAR submit failed: ` + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    if (res && res.response && res.response.bounced)
      throw new Error(`h${hh} LIAR submit bounced: ` + bounceDetail(res));
  }
  const chAddr = await challenger.getAddress();
  // First verdict of the run (scenario 6 no longer pays out).
  if (Number(st["slash_reward_" + chAddr] || 0) !== SLASH_REWARD)
    throw new Error("slash reward wrong: " + JSON.stringify(st["slash_reward_" + chAddr]));
  // Verdict slashes the standing pool by 5e11 per fraud (1 so far).
  const opAddr = await operator.getAddress();
  const poolNet = POOL_FUND_GROSS - 10000; // {pool:1} credits net of bounce fee
  if (Number(st["pool_" + opAddr] || 0) !== Number(poolNet - SLASH_HALF))
    throw new Error("pool not slashed by fraud: " + JSON.stringify(st["pool_" + opAddr]));
  // Challenger withdraws the banked slash: payout + zeroed key (no double-claim).
  await trigger(challenger, rollup, { claim: "slash" }, 20000);
  st = await vars(rollup);
  if (Number(st["slash_reward_" + chAddr] || 0) !== 0) throw new Error("slash not paid out");
  console.log("7. deposit fraud verdict: height failed, slashed, challenger paid");

  // ---- 8. honest deposit → 'no fraud' (height stays live) ------------------
  // This assertion ALSO commits wit_root_2 = H3_PRE_WIT: every h3 k=0
  // predicate anchors pre_wit on it.
  await submitH2(OPS_ROOT1, TRACE_ROOT1, SET_ROOT1, FILLS_ROOT, H3_PRE_WIT, H3_PRE.length);
  const honestProof = {
    rollup: ROLLUP_ADDR,
    k: 0,
    op: opD,
    ops_proof: merkle.getMerkleProof(OPS1, 0),
    trace_root: TRACE_ROOT1,
    ops_root: OPS_ROOT1,
    units_root: UNITS_SET_ROOT,
    units_set_root: SET_ROOT1,
    fills_root: FILLS_ROOT,
    pre_wit: WIT_ROOT, // k=0, h=2 -> wit_root_1 (genesis tree)
    post_wit: POST_WIT1,
    post_proof: merkle.getMerkleProof(TRACE1, 0),
    pre_leaf: preLeaf,
    post_leaf: postLeaf,
    pre_leaf_proof: merkle.getMerkleProof(GENESIS_LEAVES, depPreIdx),
    post_leaf_proof: merkle.getMerkleProof(POST1, 0),
  };
  await triggerBounce(challenger, dispute, Object.assign({ pred: "deposit", height: 2 }, honestProof), 20000, "no fraud");
  st = await vars(rollup);
  if (Number(st.frozen_2 || 0) !== 0) throw new Error("honest predicate froze the height!");
  console.log("8. honest deposit predicate bounced 'no fraud' — height live");

  // ---- 9. finalize h2, proceed on h3 with real trees -----------------------
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 2 }, 20000);
  st = await vars(rollup);
  // ---- 10. submit h3 committing the honest post tree (taker col -500) ----
  // exp = -500 (flat pre col 0, 5 bps fee on the 1e6 notional): a negative
  // expected post is exactly the claw-bail shape — a committed lie at this
  // shape is deliberately unchallengeable (an honest loser can stay
  // negative when the winner cannot pay the claw); verdict coverage for
  // provable lies moved to 19a (isolated) and 19b (cross, empty range).
  const takerH = FILL_TAKER;
  const fillStr = `f:${H3_UNIT_HEX}:0:${takerH}:${"c".repeat(64)}:${"d".repeat(64)}:${"e".repeat(64)}:1:100000000:100000000:9:0:0:0`;
  const FILLS1 = [fillStr];
  const FILLS1_TREE = fillsTree(FILLS1);
  const FILLS_ROOT1 = merkle.getMerkleRoot(FILLS1_TREE);
  // h3 heights commit a PLACE op at k (cross): the fill_math taker leg
  // proves the unit op is this fill's own p: Place and reads its isolated
  // flag; deposit heights (h2) keep OPS_ROOT1's d: op.
  // #47 A3: p: ops end with {tif}:{typ} (typ 0 = Limit).
  const FILL_OP = `p:${takerH}:1:0:100000000:100000000:0:0:0:0`;
  const OPS3 = pad2([FILL_OP], "ops3");
  const OPS3_ROOT = merkle.getMerkleRoot(OPS3);
  const OPS3_PROOF = merkle.getMerkleProof(OPS3, 0);
  const POST_H = [`acct:${takerH}:-500:0:0`, META1, `pos:${takerH}:1:100000000:100000000:0:0`].sort();
  const POST_H_WIT = merkle.getMerkleRoot(POST_H);
  const TRACE_H = pad2([POST_H_WIT], "traceh");
  const TRACE_H_ROOT = merkle.getMerkleRoot(TRACE_H);
  const sd3 = submitData(3, STATE_ROOT, STATE_ROOT);
  sd3.wit_root = H3_PRE_WIT;
  sd3.wit_count = H3_PRE.length;
  sd3.trace_root = TRACE_H_ROOT;
  sd3.fills_root = FILLS_ROOT1;
  sd3.ops_root = OPS3_ROOT;
  sd3.units_root = UNITS3_ROOT;
  sd3.fill_count = 1;
  rebind(sd3);
  {
    const h3data = { chain_id: "minuend-v2", height: 3 };
    const r = await operator.sendMulti({
      messages: [
        { app: "temp_data", payload_location: "inline", payload: {
          data_length: require("ocore/object_length.js").getLength(h3data, true),
          data_hash: require("ocore/object_hash.js").getBase64Hash(h3data, true),
          data: h3data } },
        { app: "data", payload: sd3 },
      ],
      base_outputs: [{ address: rollup, amount: SUBMIT_FEE }],
    });
    if (r.error) throw new Error("h3 submit failed: " + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    if (res && res.response && res.response.bounced)
      throw new Error("h3 submit bounced: " + bounceDetail(res));
  }

  // ---- 11. fill_math honest cross (bail: exp < 0) ------------------------
  // price=1e8 qty=1e8 -> notional 1e6, fee 5bps=500 -> exp col -500.
  // The committed leaves are honest AND the shape is the claw-bail one:
  // the AA bounces 'no fraud' before any identity comparison (an honest
  // loser can remain negative when the winner cannot pay the claw —
  // minuend-state::claw_cannot_cover_leaves_both_negative).
  const fillBase = {
    rollup: ROLLUP_ADDR,
    k: 0,
    trace_root: TRACE_H_ROOT,
    fills_root: FILLS_ROOT1,
    ops_root: OPS3_ROOT,
    units_root: UNITS3_ROOT,
    units_proof: UNITS3_PROOF,
    fill: fillStr,
    fill_proof: merkle.getMerkleProof(FILLS1_TREE, 0),
    op: FILL_OP,
    ops_proof: OPS3_PROOF,
    right: FILLS1_TREE[1],
    right_proof: merkle.getMerkleProof(FILLS1_TREE, 1),
    pre_wit: H3_PRE_WIT,
    post_wit: POST_H_WIT,
    post_proof: merkle.getMerkleProof(TRACE_H, 0),
    pre_acct: FILL_TAKER_PRE,
    pre_acct_proof: merkle.getMerkleProof(H3_PRE, H3_PRE_IDX[FILL_TAKER_PRE]),
    post_acct: `acct:${takerH}:-500:0:0`, // engine identity: 0 - 500 fee
    post_acct_proof: merkle.getMerkleProof(POST_H, POST_H.indexOf(`acct:${takerH}:-500:0:0`)),
    post_pos: `pos:${takerH}:1:100000000:100000000:0:0`,
    post_pos_proof: merkle.getMerkleProof(POST_H, POST_H.indexOf(`pos:${takerH}:1:100000000:100000000:0:0`)),
    pre_meta: META1,
    pre_meta_proof: merkle.getMerkleProof(H3_PRE, H3_PRE_IDX[META1]),
    pos_absent: true,
    // Claimed-absent pre pos (market 1): prefix-range neighbors over H3_PRE —
    // BETTER_ORD < pos:{taker}:1: < POS2(market 2)? No: ord < pos always
    // ('o'<'p'), and the pos range sits between BETTER_ORD and POS2.
    pleft: BETTER_ORD,
    pleft_proof: merkle.getMerkleProof(H3_PRE, H3_PRE_IDX[BETTER_ORD]),
    pright: POS2,
    pright_proof: merkle.getMerkleProof(H3_PRE, H3_PRE_IDX[POS2]),
    who: "taker",
  };
  await triggerBounce(challenger, fill, Object.assign({ pred: "fill_math", height: 3 }, fillBase), 20000, "no fraud");
  st = await vars(rollup);
  if (Number(st.frozen_3 || 0) !== 0) throw new Error("honest fill_math froze h3!");
  console.log("11. fill_math (exp<0) bounced 'no fraud' — height live");

  async function submitH3(traceRoot, fillsRoot) {
    const s = submitData(3, STATE_ROOT, STATE_ROOT);
    s.wit_root = H3_PRE_WIT;
    s.wit_count = H3_PRE.length;
    s.trace_root = traceRoot;
    s.fills_root = fillsRoot;
    s.ops_root = OPS3_ROOT;
    s.units_root = UNITS3_ROOT;
    s.fill_count = 1;
    const h3header = headerFromSubmit(s);
    const r = await operator.sendMulti({
      messages: [
        tempDataMsg(h3header),
        { app: "data", payload: s },
      ],
      base_outputs: [{ address: rollup, amount: SUBMIT_FEE }],
    });
    if (r.error) throw new Error("h3 submit failed: " + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    if (res && res.response && res.response.bounced)
      throw new Error("h3 submit bounced: " + bounceDetail(res));
  }
  // k=1 two-unit submit: unit 0 is a padding unit (its trace entry carries
  // the pre tree), unit 1 is the challenged unit. Lets batch C+D scenarios
  // run on fresh heights past the h3 window: k=1 predicates anchor pre_wit
  const K1_PAD_HEX = sha256Hex("k1-pad-unit-2"); // sorts AFTER H3_UNIT_HEX: the challenged unit sits at index 1 == k
  const K1_UNITS = [K1_PAD_HEX, H3_UNIT_HEX].sort();
  const K1_UNITS_ROOT = merkle.getMerkleRoot(K1_UNITS);
  const K1_UNITS_PROOF = merkle.getMerkleProof(K1_UNITS, K1_UNITS.indexOf(H3_UNIT_HEX));
  async function submitK1(hh, preWit, postWit, fillsRoot, opsRoot) {
    const trace = [preWit, postWit];
    const traceRoot = merkle.getMerkleRoot(trace);
    const s = submitData(hh, STATE_ROOT, STATE_ROOT);
    s.wit_root = preWit;
    s.wit_count = 2;
    s.trace_root = traceRoot;
    s.fills_root = fillsRoot;
    s.ops_root = opsRoot;
    s.units_root = K1_UNITS_ROOT;
    s.unit_count = 2;
    s.fill_count = 1;
    const header = headerFromSubmit(s);
    const r = await operator.sendMulti({
      messages: [tempDataMsg(header), { app: "data", payload: s }],
      base_outputs: [{ address: rollup, amount: SUBMIT_FEE }],
    });
    if (r.error) throw new Error(`h${hh} k1 submit failed: ` + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    if (res && res.response && res.response.bounced)
      throw new Error(`h${hh} k1 submit bounced: ` + bounceDetail(res));
    return { trace, traceRoot };
  }
  // ---- 12. ghost: maker order absent → fraud -------------------------------
  // maker id "e"*64 has no ord leaf in H3_PRE. Sorted H3_PRE runs
  // ... MAKER_ORD(ord:d, idx4), BETTER_ORD(ord:eee..f, idx5), POS2(idx6):
  // the whole ord:{e*64}: range sits between MAKER_ORD and BETTER_ORD.
  const ghostOrd = `ord:${"e".repeat(64)}:1:1:100000000:9:3:${"c".repeat(64)}:0:0`;
  const gSorted = H3_PRE;
  const gMaker = gSorted.indexOf(MAKER_ORD);
  const gBetter = gSorted.indexOf(BETTER_ORD);
  if (gBetter !== gMaker + 1) throw new Error("ghost fixture not adjacent");
  const ghostLo = `ord:${"e".repeat(64)}:`;
  const ghostHi = `ord:${"e".repeat(64)};`;
  if (!(gSorted[gMaker] < ghostLo && ghostHi <= gSorted[gBetter])) throw new Error("ghost fixture not straddling");
  const ghostProof = {
    rollup: ROLLUP_ADDR,
    k: 0,
    trace_root: TRACE_H_ROOT,
    fills_root: FILLS_ROOT1,
    ops_root: OPS3_ROOT,
    units_root: UNITS3_ROOT,
    units_proof: UNITS3_PROOF,
    fill: fillStr,
    fill_proof: merkle.getMerkleProof(FILLS1_TREE, 0),
    pre_wit: H3_PRE_WIT,
    maker_ord: ghostOrd,
    left: gSorted[gMaker],
    left_proof: merkle.getMerkleProof(gSorted, gMaker),
    right: gSorted[gBetter],
    right_proof: merkle.getMerkleProof(gSorted, gBetter),
  };
  await triggerVerdict(challenger, book, Object.assign({ pred: "ghost", height: 3 }, ghostProof), 20000, "ghost predicate");
  st = await vars(rollup);
  if (Number(st.frozen_3) !== 2) throw new Error("ghost fraud did not freeze height");
  console.log("12. ghost (absent maker) → frozen=3");

  // ---- 13. skip: better live order ignored → fraud -------------------------
  const SKIP_TRACE4 = pad2([`skip-post-wit`], "skiptrace4");
  const SKIP_TRACE4_ROOT = merkle.getMerkleRoot(SKIP_TRACE4);
  const SKIP_FILLS = [`f:${H3_UNIT_HEX}:0:${FILL_TAKER}:${"c".repeat(64)}:${"d".repeat(64)}:${"d".repeat(64)}:1:100000000:50000000:7:0:0:0`];
  const SKIP_FILLS_TREE = fillsTree(SKIP_FILLS);
  const SKIP_FILLS_ROOT = merkle.getMerkleRoot(SKIP_FILLS_TREE);
  // h3 was frozen by ghost: re-submit carrying the skip assertion's roots.
  await submitH3(SKIP_TRACE4_ROOT, SKIP_FILLS_ROOT);
  const skipProof = {
    rollup: ROLLUP_ADDR,
    k: 0,
    trace_root: SKIP_TRACE4_ROOT,
    fills_root: SKIP_FILLS_ROOT,
    ops_root: OPS3_ROOT,
    units_root: UNITS3_ROOT,
    units_proof: UNITS3_PROOF,
    fill: SKIP_FILLS[0],
    fill_proof: merkle.getMerkleProof(SKIP_FILLS_TREE, 0),
    // #37-9: single-fill completeness — the sole fill's right neighbor
    // is the fills_root length sentinel.
    right: SKIP_FILLS_TREE[1],
    right_proof: merkle.getMerkleProof(SKIP_FILLS_TREE, 1),
    pre_wit: H3_PRE_WIT,
    maker_ord: MAKER_ORD,
    maker_proof: merkle.getMerkleProof(H3_PRE, H3_PRE.indexOf(MAKER_ORD)),
    better_ord: BETTER_ORD,
    better_proof: merkle.getMerkleProof(H3_PRE, H3_PRE.indexOf(BETTER_ORD)),
  };
  await triggerVerdict(challenger, book, Object.assign({ pred: "skip", height: 3 }, skipProof), 20000, "skip predicate");
  st = await vars(rollup);
  if (Number(st.frozen_3) !== 2) throw new Error("skip fraud did not freeze height");
  console.log("13. skip (better order ignored) → frozen=3");
  // ---- 13a. fill with a FAKE unit hex → 'bad unit', no verdict (#1) -------
  // NEG_FILL's unit hex is u*64, not the h3 unit committed in units_root:
  // units_proof cannot verify it, so the predicate must bounce before any
  // math. This is the exact class the old AA let through to a verdict.
  const NEG_FILL = `f:${"u".repeat(64)}:0:${takerH}:${"c".repeat(64)}:${"d".repeat(64)}:${"e".repeat(64)}:1:-100000000:100000000:9:0:0:0`;
  const NEG_FILLS = [NEG_FILL];
  const NEG_FILLS_TREE = fillsTree(NEG_FILLS);
  const NEG_FILLS_ROOT = merkle.getMerkleRoot(NEG_FILLS_TREE);
  const NEG_POST_LIAR = [`acct:${takerH}:-499:0:0`, META1, `pos:${takerH}:1:100000000:-100000000:0:0`].sort();
  const NEG_POST_LIAR_WIT = merkle.getMerkleRoot(NEG_POST_LIAR);
  const NEG_TRACE = pad2([NEG_POST_LIAR_WIT], "negtrace");
  const NEG_TRACE_ROOT = merkle.getMerkleRoot(NEG_TRACE);
  await submitH3(NEG_TRACE_ROOT, NEG_FILLS_ROOT);
  const negBase = Object.assign({}, fillBase, {
    trace_root: NEG_TRACE_ROOT,
    fills_root: NEG_FILLS_ROOT,
    fill: NEG_FILL,
    fill_proof: merkle.getMerkleProof(NEG_FILLS_TREE, 0),
    right: NEG_FILLS_TREE[1],
    right_proof: merkle.getMerkleProof(NEG_FILLS_TREE, 1),
    post_wit: NEG_POST_LIAR_WIT,
    post_proof: merkle.getMerkleProof(NEG_TRACE, 0),
    post_acct: `acct:${takerH}:-499:0:0`,
    post_acct_proof: merkle.getMerkleProof(NEG_POST_LIAR, NEG_POST_LIAR.indexOf(`acct:${takerH}:-499:0:0`)),
    post_pos: `pos:${takerH}:1:100000000:-100000000:0:0`,
    post_pos_proof: merkle.getMerkleProof(NEG_POST_LIAR, NEG_POST_LIAR.indexOf(`pos:${takerH}:1:100000000:-100000000:0:0`)),
  });
  await triggerBounce(challenger, fill, Object.assign({ pred: "fill_math", height: 3 }, negBase), 20000, "bad unit");
  console.log("13a. fake unit hex bounced 'bad unit' — no verdict");
  // ---- 14. two-package height: deposit-fraud predicate fires, height fails --
  // 13a's NEG submit left last_submitted=3 (a bounce rolls nothing back), so
  // the two-package assertion goes to h4: prev=STATE_ROOT == state_root_3.
  // Two 1-unit packages post first (JS join+base64, no helper binary), then
  // the da_unit header nails the real package hashes + data_root. The fraud
  // verdict proves the multi-package DA reveal feeds the same predicate path
  // as single-package inline.
  const PKG_OP = "d:" + DEP_ACCT + ":100000";
  const PKG_OPS = pad2([PKG_OP], "pkgops");
  const PKG_OPS_ROOT = merkle.getMerkleRoot(PKG_OPS);
  const PKG_POST = pad2([`acct:${DEP_ACCT}:1050000:0:0`], "pkgpost");
  const PKG_WIT = merkle.getMerkleRoot(PKG_POST);
  const PKG_TRACE = pad2([PKG_WIT], "pkgtrace");
  const PKG_TRACE_ROOT = merkle.getMerkleRoot(PKG_TRACE);
  const frameA = JSON.stringify({ u: { op: "a" }, t: PKG_TRACE_ROOT, o: PKG_OP, c: "1" });
  const frameB = JSON.stringify({ u: { op: "b" }, t: PKG_TRACE_ROOT, o: PKG_OP, c: "1" });
  const blobA = zlib.gzipSync(Buffer.from(frameA, "utf8")).toString("base64");
  const blobB = zlib.gzipSync(Buffer.from(frameB, "utf8")).toString("base64");
  const rawA = zlib.gunzipSync(Buffer.from(blobA, "base64"));
  const rawB = zlib.gunzipSync(Buffer.from(blobB, "base64"));
  const shaHex = (b) => crypto.createHash("sha256").update(b).digest("hex");
  const sd4pkg = submitData(4, STATE_ROOT, STATE_ROOT);
  sd4pkg.ops_root = PKG_OPS_ROOT;
  sd4pkg.trace_root = PKG_TRACE_ROOT;
  sd4pkg.units_root = UNITS_SET_ROOT;
  sd4pkg.units_set_root = SET_ROOT1;
  // Full header scalars from the submit (same helper as single-package),
  // then packages = REAL package unit hashes (pr.unit) so watchers can
  // get_joint each entry; data_root = sha256 of concatenated blob bytes.
  const h4pkg = headerFromSubmit(sd4pkg, PKG_OP);
  h4pkg.data_root = shaHex(Buffer.concat([rawA, rawB]));
  {
    const pkgMsg = (blob) => ({ app: "temp_data", payload_location: "inline", payload: {
      data_length: require("ocore/object_length.js").getLength({ package_blob: blob }, true),
      data_hash: require("ocore/object_hash.js").getBase64Hash({ package_blob: blob }, true),
      data: { package_blob: blob } } });
    const pr1 = await operator.sendMulti({
      messages: [pkgMsg(blobA)],
      base_outputs: [{ address: await operator.getAddress(), amount: 10000 }],
    });
    if (pr1.error) throw new Error("package 1 post failed: " + pr1.error);
    await network.witnessUntilStable(pr1.unit);
    const pr2 = await operator.sendMulti({
      messages: [pkgMsg(blobB)],
      base_outputs: [{ address: await operator.getAddress(), amount: 10000 }],
    });
    if (pr2.error) throw new Error("package 2 post failed: " + pr2.error);
    await network.witnessUntilStable(pr2.unit);
    delete h4pkg.frames_blob;
    h4pkg.packages = [pr1.unit, pr2.unit];
    rebind(sd4pkg);
    h4pkg.da_bind = sd4pkg.da_bind;
    const r3p = await operator.sendMulti({
      messages: [
        tempDataMsg(h4pkg),
        { app: "data", payload: sd4pkg },
      ],
      base_outputs: [{ address: rollup, amount: SUBMIT_FEE }],
    });
    if (r3p.error) throw new Error("h4 2-package submit failed: " + r3p.error);
    await network.witnessUntilStable(r3p.unit);
    const res3p = await network.getAaResponseToUnit(r3p.unit).catch(() => null);
    if (res3p && res3p.response && res3p.response.bounced)
      throw new Error("h4 2-package submit bounced: " + bounceDetail(res3p));
  }
  const pkgFraud = {
    rollup: ROLLUP_ADDR,
    k: 0,
    op: PKG_OP,
    ops_proof: merkle.getMerkleProof(PKG_OPS, 0),
    trace_root: PKG_TRACE_ROOT,
    ops_root: PKG_OPS_ROOT,
    units_root: UNITS_SET_ROOT,
    units_set_root: SET_ROOT1,
    fills_root: FILLS_ROOT,
    pre_wit: H3_PRE_WIT,
    post_wit: PKG_WIT,
    post_proof: merkle.getMerkleProof(PKG_TRACE, 0),
    pre_leaf: DEP_PRE,
    post_leaf: PKG_POST[0],
    pre_leaf_proof: merkle.getMerkleProof(H3_PRE, H3_PRE_IDX[DEP_PRE]),
    post_leaf_proof: merkle.getMerkleProof(PKG_POST, 0),
  };
  await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 4 }, pkgFraud), 20000, "2-package deposit fraud predicate");
  st = await vars(rollup);
  if (Number(st.frozen_4) !== 2) throw new Error("2-package fraud did not freeze height");
  console.log("14. 2-package height deposit fraud → frozen=4");
  // ---- 15. re-submit + finalize after fraud works -------------------------
  await sendCombinedSubmit(operator, 4, STATE_ROOT, STATE_ROOT);
  await network.timetravel({ shift: "3600s" });
  // Heights finalize in order: h3 (the NEG-submit height, never frauded
  // away) first, then the re-submitted h4.
  await trigger(operator, rollup, { finalize: 1, height: 3 }, 20000);
  await trigger(operator, rollup, { finalize: 1, height: 4 }, 20000);
  st = await vars(rollup);
  if (Number(st.last_finalized) !== 4) throw new Error("re-finalize after fraud failed");
  console.log("15. re-submit + finalize after fraud ok");
  // ---- 16. pipeline: h5 + h6 with no finalize between ---------------------
  // Occupancy is last_submitted-last_finalized = 2 < 50, so the second submit
  // must NOT bounce. Then timetravel once, finalize in order.
  await sendCombinedSubmit(operator, 5, STATE_ROOT, STATE_ROOT);
  await sendCombinedSubmit(operator, 6, STATE_ROOT, STATE_ROOT);
  st = await vars(rollup);
  if (Number(st.last_submitted) !== 6) throw new Error("pipeline submits failed: " + st.last_submitted);
  if (Number(st.last_finalized) !== 4) throw new Error("pipeline must not finalize early");
  console.log("16. pipeline h5+h6 submitted with no inter-finalize");
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 5 }, 20000);
  await trigger(operator, rollup, { finalize: 1, height: 6 }, 20000);
  st = await vars(rollup);
  if (Number(st.last_finalized) !== 6) throw new Error("pipelined finalize failed");
  console.log("16a. pipelined h5+h6 finalized in order");
  // ---- 17. pool claim when chain idle; pool busy otherwise -----------------
  // Chain idle (ls==lf==6): operator claims the standing pool back.
  const poolBefore = Number(st["pool_" + (await operator.getAddress())] || 0);
  if (!(poolBefore >= 1000000000000)) throw new Error("pool below floor after slashes: " + poolBefore);
  await sendCombinedSubmit(operator, 7, STATE_ROOT, STATE_ROOT);
  await triggerBounce(operator, rollup, { claim: "pool" }, 20000, "pool busy");
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 7 }, 20000);
  await trigger(operator, rollup, { claim: "pool" }, 20000);
  st = await vars(rollup);
  if (Number(st["pool_" + (await operator.getAddress())] || 0) !== 0)
    throw new Error("pool not zeroed after claim");
  console.log("17. pool claim ok when idle, busy otherwise");
  // ---- 18. depleted pool: drained operator bounces 'need pool' --------------
  // Scenario 17 claimed the operator pool to zero — the same state a
  // slash-depleted operator lands in. Its next submit must bounce
  // 'need pool' until a fresh {pool:1} top-up; then the gate reopens.
  await triggerBounce(operator, rollup, submitData(8, STATE_ROOT, STATE_ROOT), 20000, "need pool");
  await trigger(operator, rollup, { pool: 1 }, POOL_FUND_GROSS);
  await sendCombinedSubmit(operator, 8, STATE_ROOT, STATE_ROOT);
  st = await vars(rollup);
  if (Number(st.last_submitted) !== 8) throw new Error("re-submit after pool top-up failed");
  console.log("18. depleted pool bounces 'need pool'; top-up reopens submit");

  // ---- 19. PR 33 residuals: exact identity + sentinel right neighbor ----
  // Fresh heights 9-11 (k=0, pre_wit anchored on wit_root_8 = WIT_ROOT):
  //  19a. isolated taker open that escrowed margin, INFLATED post col
  //       -> verdict (the old >= branch accepted any larger post);
  //  19b. cross taker, post range proven empty, post col = exp + 1
  //       -> verdict (exact empty-range identity);
  //  19c. honest isolated open -> 'no fraud': single-fill completeness
  //       rides the right neighbor, which for the sole fill is the
  //       fills_root length sentinel `n:1`.
  const isoUnit = sha256Hex("iso-unit");
  const isoTOrd = "7".repeat(64);
  const isoMOrd = "3".repeat(64);
  const isoPos = `pos:${DEP_ACCT}:1:100000000:100000000:1:500000`;
  // Engine identity for the isolated open: 1000000 (pre col) - 500000
  // (margin escrowed at place, moved to the bucket, never returned to
  // collateral) - 500 (5bps taker fee on the 1e6 notional) = 499500.
  const isoFill = `f:${isoUnit}:0:${DEP_ACCT}:${"c".repeat(64)}:${isoTOrd}:${isoMOrd}:1:100000000:100000000:9:0:0:500000`;
  const ISO_FILLS = [isoFill];
  const ISO_FILLS_TREE = fillsTree(ISO_FILLS);
  const ISO_FILLS_ROOT = merkle.getMerkleRoot(ISO_FILLS_TREE);
  const isoOp = `p:${DEP_ACCT}:1:0:100000000:100000000:1:500000:0:0`;
  const ISO_OPS = pad2([isoOp], "isoops");
  const ISO_OPS_ROOT = merkle.getMerkleRoot(ISO_OPS);
  const ISO_UNITS = pad2([isoUnit], "isounits");
  const ISO_UNITS_ROOT = merkle.getMerkleRoot(ISO_UNITS);
  const ISO_UNITS_PROOF = merkle.getMerkleProof(ISO_UNITS, 0);
  // #47 claw guard: a collateral verdict needs the counterparty's proven
  // POSITIVE post collateral (no claw can then have moved this leg).
  const CP_LEAF = `acct:${"c".repeat(64)}:1000500:0:0`;
  const isoPostTree = (col) => [`acct:${DEP_ACCT}:${col}:0:0`, CP_LEAF, META1, isoPos].sort();
  const ISO_POST = isoPostTree(499500);
  const ISO_POST_WIT = merkle.getMerkleRoot(ISO_POST);
  const ISO_TRACE = pad2([ISO_POST_WIT], "isotrace");
  const ISO_TRACE_ROOT = merkle.getMerkleRoot(ISO_TRACE);
  const ISO_LIAR = isoPostTree(499507);
  const ISO_LIAR_WIT = merkle.getMerkleRoot(ISO_LIAR);
  const ISO_LIAR_TRACE = pad2([ISO_LIAR_WIT], "isoliartrace");
  const ISO_LIAR_TRACE_ROOT = merkle.getMerkleRoot(ISO_LIAR_TRACE);
  // Isolated open payload: single-fill completeness rides the right
  // neighbor — for this sole fill the fills_root length sentinel `n:1` —
  // plus op + ord absence proofs over the post tree.
  const isoFillPayload = (traceRoot, traceArr, postWit, postTree, col, cpLeaf = CP_LEAF) => {
    const acctLeaf = `acct:${DEP_ACCT}:${col}:0:0`;
    return {
      rollup: ROLLUP_ADDR,
      k: 0,
      trace_root: traceRoot,
      fills_root: ISO_FILLS_ROOT,
      ops_root: ISO_OPS_ROOT,
      units_root: ISO_UNITS_ROOT,
      units_proof: ISO_UNITS_PROOF,
      fill: isoFill,
      fill_proof: merkle.getMerkleProof(ISO_FILLS_TREE, 0),
      right: ISO_FILLS_TREE[1],
      right_proof: merkle.getMerkleProof(ISO_FILLS_TREE, 1),
      op: isoOp,
      ops_proof: merkle.getMerkleProof(ISO_OPS, 0),
      pre_wit: WIT_ROOT,
      post_wit: postWit,
      post_proof: merkle.getMerkleProof(traceArr, 0),
      pre_acct: DEP_PRE,
      pre_acct_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(DEP_PRE)),
      post_acct: acctLeaf,
      post_acct_proof: merkle.getMerkleProof(postTree, postTree.indexOf(acctLeaf)),
      post_pos: isoPos,
      post_pos_proof: merkle.getMerkleProof(postTree, postTree.indexOf(isoPos)),
      pre_meta: META1,
      pre_meta_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(META1)),
      pos_absent: true,
      pleft: META2,
      pleft_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(META2)),
      pright: POS2,
      pright_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(POS2)),
      // Taker-ord absence: META1 < ord:7*64: < isoPos straddle post tree.
      oleft: META1,
      oleft_proof: merkle.getMerkleProof(postTree, postTree.indexOf(META1)),
      oright: isoPos,
      oright_proof: merkle.getMerkleProof(postTree, postTree.indexOf(isoPos)),
      cp_acct: cpLeaf,
      cp_acct_proof: merkle.getMerkleProof(postTree, postTree.indexOf(cpLeaf)),
      who: "taker",
    };
  };
  // A fraud verdict rolls last_submitted back (h-1), so all three run as
  // re-submits of height 9: liar → verdict, cross → verdict, honest →
  // bounce (the only shape that leaves the height live).
  async function submitIsoH(traceRoot, fillsRoot, opsRoot, witCount) {
    const s = submitData(9, STATE_ROOT, STATE_ROOT);
    s.wit_root = WIT_ROOT; // k=0 pre anchors on wit_root_8 (scenario 18)
    s.wit_count = witCount;
    s.trace_root = traceRoot;
    s.fills_root = fillsRoot;
    s.ops_root = opsRoot;
    s.units_root = ISO_UNITS_ROOT;
    s.fill_count = 1;
    const hdr = headerFromSubmit(s);
    const r = await operator.sendMulti({
      messages: [tempDataMsg(hdr), { app: "data", payload: s }],
      base_outputs: [{ address: rollup, amount: SUBMIT_FEE }],
    });
    if (r.error) throw new Error("h9 submit failed: " + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    if (res && res.response && res.response.bounced)
      throw new Error("h9 submit bounced: " + bounceDetail(res));
  }
  // 19a. LIAR isolated open: col 499507 (identity + 7: R3-A-3 tolerance is +-6) -> verdict.
  await submitIsoH(ISO_LIAR_TRACE_ROOT, ISO_FILLS_ROOT, ISO_OPS_ROOT, 4);
  await triggerVerdict(
    challenger,
    fill,
    Object.assign(
      { pred: "fill_math", height: 9 },
      isoFillPayload(ISO_LIAR_TRACE_ROOT, ISO_LIAR_TRACE, ISO_LIAR_WIT, ISO_LIAR, 499507)
    ),
    20000,
    "isolated exact-identity predicate"
  );
  st = await vars(rollup);
  if (Number(st.frozen_9) !== 2) throw new Error("inflated isolated post col did not freeze h9");
  console.log("19a. isolated escrow identity: inflated post col -> frozen=9");

  // 19b. Cross taker, empty range, post col = exp + 7 (> R3-A-3 +-6) -> verdict.
  const crossFill = `f:${isoUnit}:0:${DEP_ACCT}:${"c".repeat(64)}:${"8".repeat(64)}:${isoMOrd}:1:100000000:100000000:9:0:0:0`;
  const CROSS_FILLS = [crossFill];
  const CROSS_FILLS_TREE = fillsTree(CROSS_FILLS);
  const CROSS_FILLS_ROOT = merkle.getMerkleRoot(CROSS_FILLS_TREE);
  const crossOp = `p:${DEP_ACCT}:1:0:100000000:100000000:0:0:0:0`;
  const CROSS_OPS = pad2([crossOp], "crossops");
  const CROSS_OPS_ROOT = merkle.getMerkleRoot(CROSS_OPS);
  const CROSS_POST = [`acct:${DEP_ACCT}:999507:0:0`, CP_LEAF, META1].sort();
  const CROSS_POST_WIT = merkle.getMerkleRoot(CROSS_POST);
  const CROSS_TRACE = pad2([CROSS_POST_WIT], "crosstrace");
  const CROSS_TRACE_ROOT = merkle.getMerkleRoot(CROSS_TRACE);
  await submitIsoH(CROSS_TRACE_ROOT, CROSS_FILLS_ROOT, CROSS_OPS_ROOT, 3);
  const crossPayload = {
    rollup: ROLLUP_ADDR,
    k: 0,
    trace_root: CROSS_TRACE_ROOT,
    fills_root: CROSS_FILLS_ROOT,
    ops_root: CROSS_OPS_ROOT,
    units_root: ISO_UNITS_ROOT,
    units_proof: ISO_UNITS_PROOF,
    fill: crossFill,
    fill_proof: merkle.getMerkleProof(CROSS_FILLS_TREE, 0),
    right: CROSS_FILLS_TREE[1],
    right_proof: merkle.getMerkleProof(CROSS_FILLS_TREE, 1),
    op: crossOp,
    ops_proof: merkle.getMerkleProof(CROSS_OPS, 0),
    pre_wit: WIT_ROOT,
    post_wit: CROSS_POST_WIT,
    post_proof: merkle.getMerkleProof(CROSS_TRACE, 0),
    pre_acct: DEP_PRE,
    pre_acct_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(DEP_PRE)),
    post_acct: `acct:${DEP_ACCT}:999507:0:0`,
    post_acct_proof: merkle.getMerkleProof(CROSS_POST, CROSS_POST.indexOf(`acct:${DEP_ACCT}:999507:0:0`)),
    pre_meta: META1,
    pre_meta_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(META1)),
    pos_absent: true,
    pleft: META2,
    pleft_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(META2)),
    pright: POS2,
    pright_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(POS2)),
    // Empty post range (final tree, k+1==n): only a left neighbor below.
    eleft: META1,
    eleft_proof: merkle.getMerkleProof(CROSS_POST, CROSS_POST.indexOf(META1)),
    cp_acct: CP_LEAF,
    cp_acct_proof: merkle.getMerkleProof(CROSS_POST, CROSS_POST.indexOf(CP_LEAF)),
    who: "taker",
  };
  await triggerVerdict(
    challenger,
    fill,
    Object.assign({ pred: "fill_math", height: 9 }, crossPayload),
    20000,
    "cross exact-identity predicate"
  );
  st = await vars(rollup);
  if (Number(st.frozen_9) !== 2) throw new Error("cross exp+1 empty-range col did not freeze h9");
  console.log("19b. cross empty-range exact identity: exp+1 -> frozen=9");

  // 19c. HONEST isolated open: same payload shape, matching post col —
  // completeness rides the `n:1` sentinel right neighbor, then the exact
  // identity bounces 'no fraud'.
  await submitIsoH(ISO_TRACE_ROOT, ISO_FILLS_ROOT, ISO_OPS_ROOT, 4);
  await triggerBounce(
    challenger,
    fill,
    Object.assign(
      { pred: "fill_math", height: 9 },
      isoFillPayload(ISO_TRACE_ROOT, ISO_TRACE, ISO_POST_WIT, ISO_POST, 499500)
    ),
    20000,
    "no fraud"
  );
  st = await vars(rollup);
  if (Number(st.frozen_9 || 0) !== 0) throw new Error("honest isolated open froze h9!");
  if (Number(st.last_submitted) !== 9) throw new Error("honest h9 re-submit did not land");
  console.log("19c. honest isolated open bounced 'no fraud' via sentinel right neighbor");

  // ===== Batch B (#37): 4 aa_root binding / 6 slash debt cap / 7 ls pins //
  // ===== + pool drain / 11 vault balance formula + freshness lock       //
  // ---- 20. aa_root fold binding: bogus (forest, root) pair bounces -----
  // The 1024-hex forest is bound to one sha256 fold the operator cannot
  // decouple (pre-fix the submit gate only length-checked aa_root and
  // stored any pair; finalize/vault trusted the stored 1024-hex forest,
  // letting a detached corpus pay the vault — #37-4's exploit).
  {
    const sdWrong = submitData(10, STATE_ROOT, STATE_ROOT);
    sdWrong.aa_root = sha256Hex("wrong-fold"); // length ok, fold wrong
    await triggerBounce(operator, rollup, sdWrong, SUBMIT_FEE, "bad submit");
    // The right fold stays the same FOREST everywhere else: every other
    // submit in this run (helper submitData) already carries the real
    // fold — assert a correct one is ACCEPTED here, h10 fresh.
    st = await vars(rollup);
    if (Number(st.last_submitted) !== 9) throw new Error("h10 wrong-fold submit must not advance ls: " + st.last_submitted);
    await sendCombinedSubmit(operator, 10, STATE_ROOT, STATE_ROOT);
    st = await vars(rollup);
    if (Number(st.last_submitted) !== 10) throw new Error("h10 honest submit failed");
    if (st.aa_root_10 !== sha256Hex(FOREST)) throw new Error("aa_root_10 fold not stored");
  }
  console.log("20. aa_root fold bound at submit: bogus pair bounces, honest pair lands");

  // ---- 21. slash debt is bounded by the ACTUALLY-seized pool (#37-6) ----
  // Verdict credit must be exactly min(5e11, pool-before-verdict):
  //  21a. pool 49e12 → v(h11) seizes 5e11 (debt 5e11, pool 48.5e12);
  //  21b. drain-by-claim: resubmit h11 honestly (frozen branch), finalize
  //       8..11 so the chain turns idle, {claim:'pool'} drains to 0;
  //  21c. partial-seize needle: pool = 1.4e12; verdicts at h12/h13 seize
  //       5e11 each; verdict at h14 hits a 4e11 pool and must move the
  //       debt by EXACTLY 4e11 (pre-fix credited the fixed 5e11 — the
  //       delta 1e11 = the very overpayment that drained honest pools).
  // Challenger debt baseline: 5 unclaimed earlier verdicts = 2.5e12.
  let debt = 5 * SLASH_REWARD;
  let pool = 49e12;
  async function oneFraud(hh, preDebt, prePool) {
    await submitLiarAt(hh);
    await triggerVerdict(
      challenger,
      dispute,
      Object.assign({ pred: "deposit", height: hh }, fraudProof),
      20000,
      "deposit fraud predicate h" + hh
    );
    st = await vars(rollup);
    if (Number(st["frozen_" + hh]) !== 2) throw new Error("h" + hh + " verdict did not freeze");
    const seized = Math.min(SLASH_HALF, prePool);
    const afterDebt = Number(st["slash_reward_" + chAddr] || 0);
    const afterPool = Number(st["pool_" + opAddr] || 0);
    if (afterDebt !== preDebt + slashReward(seized))
      throw new Error(`h${hh} debt ${afterDebt} != banked ${preDebt} + seized ${seized} (pool was ${prePool})`);
    if (afterPool !== prePool - seized)
      throw new Error(`h${hh} pool ${afterPool} != ${prePool} - ${seized}`);
    console.log(`21. h${hh}: seized ${seized}, debt ${afterDebt}, pool ${afterPool}`);
    return [afterDebt, afterPool];
  }
  // Verdict WITHOUT the submit (heights were pipelined earlier).
  async function oneVerdictOnly(hh, preDebt, prePool) {
    await triggerVerdict(
      challenger,
      dispute,
      Object.assign({ pred: "deposit", height: hh }, fraudProof),
      20000,
      "deposit fraud predicate h" + hh
    );
    st = await vars(rollup);
    if (Number(st["frozen_" + hh]) !== 2) throw new Error("h" + hh + " verdict did not freeze");
    const seized = Math.min(SLASH_HALF, prePool);
    const afterDebt = Number(st["slash_reward_" + chAddr] || 0);
    const afterPool = Number(st["pool_" + opAddr] || 0);
    if (afterDebt !== preDebt + slashReward(seized))
      throw new Error(`h${hh} debt ${afterDebt} != banked ${preDebt} + seized ${seized} (pool was ${prePool})`);
    if (afterPool !== prePool - seized)
      throw new Error(`h${hh} pool ${afterPool} != ${prePool} - ${seized}`);
    console.log(`21. h${hh}: seized ${seized}, debt ${afterDebt}, pool ${afterPool}`);
    return [afterDebt, afterPool];
  }

  [debt, pool] = await oneFraud(11, debt, 49e12);
  // 21b. resubmit h11 honestly, finalize 8..11, claim the pool to 0.
  await sendCombinedSubmit(operator, 11, STATE_ROOT, STATE_ROOT);
  st = await vars(rollup);
  if (Number(st["frozen_11"] || 0) !== 0) throw new Error("h11 resubmit did not un-freeze");
  await network.timetravel({ shift: "3600s" });
  for (const fh of [8, 9, 10, 11]) await trigger(operator, rollup, { finalize: 1, height: fh }, 20000);
  await trigger(operator, rollup, { claim: "pool" }, 20000);
  st = await vars(rollup);
  pool = Number(st["pool_" + opAddr] || 0);
  if (pool !== 0) throw new Error("pool not drained by claim: " + pool);
  console.log("21. pool drained to 0 via idle-chain claim");
  // 21c. PIPELINED multi-height drill (the red-green needle): fund 1e12,
  // submit THREE adjacent LIAR heights (12/13/14) with no interim verdict,
  // then challenge them TOP-DOWN. verdicts seize min(5e11, pool):
  //   v(12): seize 5e11 → pool .5e12;
  //   v(13): seize the residual 5e11 → pool 0;
  //   v(14): pool is EMPTY — must credit ZERO (pre-fix minted a fixed 5e11
  //   out of the shared pool — the run goes red there on debt).
  await trigger(operator, rollup, { pool: 1 }, 1000000010000); // gross 1e12+fee → net +1e12
  pool += 1e12;
  await submitLiarAt(12);
  await submitLiarAt(13);
  await submitLiarAt(14);
  [debt, pool] = await oneVerdictOnly(12, debt, pool);
  [debt, pool] = await oneVerdictOnly(13, debt, pool);
  [debt, pool] = await oneVerdictOnly(14, debt, pool);
  if (pool !== 0 || debt !== 8 * SLASH_REWARD)
    throw new Error(`empty-pool debt wrong: pool=${pool} debt=${debt}`);
  console.log("21. empty-pool verdict credits zero; debt == cumulative seizure");
  // Close out: bank the challenger debt (== cumulative seizure).
  await trigger(challenger, rollup, { claim: "slash" }, 20000);
  st = await vars(rollup);
  if (Number(st["slash_reward_" + chAddr] || 0) !== 0) throw new Error("debt claim did not zero");
  console.log("21. debt paid == cumulative seizure; claim zeroes the ledger");
  // Leave the chain recoverable for scenario 22: the last verdict froze
  // h13; 22's prep resubmits it and finalizes through it.

  // ---- 22. failed height pins the pool; stale heights are dead (#37-7) ---
  // Prep: h12/h13/h14 sit frozen from scenario 21 — resubmit them BOTTOM-UP
  // (each frozen branch binds prev to the predecessor's resubmitted root),
  // finalize 12..14 so lf == 14 == h15-1, then prove:
  //  22a. verdict at h15 keeps last_submitted = 15 (no rollback);
  //  22b. {claim:'pool'} BOUNCES 'pool busy' while the top height is
  //       fraud-failed (pre-fix: ls rolled back to 14 == lf, gate passed,
  //       the pool backing the chain was drained);
  //  22c. a fresh FORWARD submit at h16 is refused while h15 is failed
  //       (pre-fix let a submit chain resume past the failed top);
  //  22d. honest h15 resubmit un-freezes, finalizes, and pool claims work
  //       again.
  await trigger(operator, rollup, { pool: 1 }, POOL_FUND_GROSS); // fund for resubmits
  await sendCombinedSubmit(operator, 12, STATE_ROOT, STATE_ROOT);
  await sendCombinedSubmit(operator, 13, STATE_ROOT, STATE_ROOT);
  await sendCombinedSubmit(operator, 14, STATE_ROOT, STATE_ROOT);
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 12 }, 20000);
  await trigger(operator, rollup, { finalize: 1, height: 13 }, 20000);
  await trigger(operator, rollup, { finalize: 1, height: 14 }, 20000);
  await trigger(operator, rollup, { claim: "pool" }, 20000); // idle chain: drain
  st = await vars(rollup);
  if (Number(st.last_finalized) !== 14) throw new Error("prep finalize failed: " + st.last_finalized);
  await trigger(operator, rollup, { pool: 1 }, 10000000010000); // 10e12 fund (any >= floor works)
  // h15 commits the LIAR fixture → verdict.
  await submitLiarAt(15);
  await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 15 }, fraudProof), 20000, "h15 verdict");
  st = await vars(rollup);
  if (Number(st["frozen_15"]) !== 2) throw new Error("h15 verdict did not freeze");
  if (Number(st.last_submitted) !== 15) throw new Error("verdict must PIN last_submitted at 15, got " + st.last_submitted);
  // 22b. pool claim refused while the failed top stands.
  await triggerBounce(operator, rollup, { claim: "pool" }, 20000, "pool busy");
  // 22c. forward submit past the failed top is refused.
  await triggerBounce(operator, rollup, submitData(16, STATE_ROOT, STATE_ROOT), SUBMIT_FEE, "prev mismatch");
  // 22d. resubmit h15 honestly (frozen branch, prev == state_root_14).
  await sendCombinedSubmit(operator, 15, STATE_ROOT, STATE_ROOT);
  st = await vars(rollup);
  if (Number(st["frozen_15"] || 0) !== 0) throw new Error("h15 resubmit did not un-freeze");
  if (Number(st.last_submitted) !== 15) throw new Error("h15 resubmit lost the height");
  await network.timetravel({ shift: "3600s" });
  await trigger(operator, rollup, { finalize: 1, height: 15 }, 20000);
  await trigger(operator, rollup, { claim: "pool" }, 20000);
  st = await vars(rollup);
  if (Number(st.last_finalized) !== 15) throw new Error("h15 finalize failed");
  if (Number(st["pool_" + opAddr] || 0) !== 0) throw new Error("pool claim after recovery failed");
  console.log("22. failed top pins ls, blocks pool drain and forward submits; resubmit recovers");
  // Scenario 22 drained the pool to 0 — fund the floor for 24..32.
  await trigger(operator, rollup, { pool: 1 }, POOL_FUND_GROSS);
  // ---- 24. honest GovDeposit batches never freeze (#37-5) -----------------
  // D: moves PERP (col pinned): the pre-fix AA judged it by collateral
  // math and verdict-froze the honest height. Post-fix the gov arm
  // compares the PERP column and bounces 'no fraud'.
  // Fixture: DEP_ACCT pre (col=1000000, perp=0) → post (col=1000000,
  // perp=50000) with op D:{acct}:50000, committed at fresh h16.
  // LIAR first (verdict freezes h16), honest second (frozen-branch
  // resubmit, then 'no fraud'): a live height cannot be submitted twice.
  const govAcct = DEP_ACCT;
  // R3-A-7: D: carries its vault anchor; the vault records the PERP
  // deposit (devnet PERP = base) as depp_<unit> = payer:amount:account.
  const govPayer = await operator.getAddress();
  const govUnit = (await trigger(operator, vault, { deposit_perp: 1, account: govAcct }, 50000)).unit;
  {
    const vs = await vars(vault);
    if (vs["depp_" + govUnit] !== govPayer + ":50000:" + govAcct)
      throw new Error("R3-A-7: vault depp_ ledger wrong: " + JSON.stringify(vs["depp_" + govUnit]));
    // R5-A-5: the vault tracks every recorded PERP deposit against the
    // sidechain's PERP_SUPPLY_MAX (deposits past it bounce and refund).
    if (Number(vs.pperp_total) !== 50000)
      throw new Error("R5-A-5: vault pperp_total wrong: " + JSON.stringify(vs.pperp_total));
  }
  const govOp = `D:${govAcct}:50000:${govPayer}:${govUnit}`;
  const GOV_OPS = pad2([govOp], "govops");
  const GOV_OPS_ROOT = merkle.getMerkleRoot(GOV_OPS);
  const GOV_POST = pad2([`acct:${govAcct}:1000000:50000:0`], "govpost");
  const GOV_WIT = merkle.getMerkleRoot(GOV_POST);
  const GOV_TRACE = pad2([GOV_WIT], "govtrace");
  const GOV_TRACE_ROOT = merkle.getMerkleRoot(GOV_TRACE);
  const GOV_LIAR = pad2([`acct:${govAcct}:1000000:50001:0`], "govliar");
  const GOV_LIAR_WIT = merkle.getMerkleRoot(GOV_LIAR);
  const GOV_LIAR_TRACE = pad2([GOV_LIAR_WIT], "govliartrace");
  const GOV_LIAR_TRACE_ROOT = merkle.getMerkleRoot(GOV_LIAR_TRACE);
  async function submitGovAt(traceRoot, opsRoot) {
    const sd = submitData(16, STATE_ROOT, STATE_ROOT);
    sd.ops_root = opsRoot || GOV_OPS_ROOT;
    sd.trace_root = traceRoot;
    sd.units_root = UNITS_SET_ROOT;
    sd.units_set_root = SET_ROOT1;
    sd.fills_root = FILLS_ROOT;
    sd.wit_root = WIT_ROOT;
    sd.wit_count = GEN_WIT_COUNT;
    const header = headerFromSubmit(sd);
    const r = await operator.sendMulti({
      messages: [tempDataMsg(header), { app: "data", payload: sd }],
      base_outputs: [{ address: rollup, amount: SUBMIT_FEE }],
    });
    if (r.error) throw new Error("h16 gov submit failed: " + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    if (res && res.response && res.response.bounced)
      throw new Error("h16 gov submit bounced: " + bounceDetail(res));
  }
  const govHonest = {
    rollup: ROLLUP_ADDR,
    k: 0,
    op: govOp,
    ops_proof: merkle.getMerkleProof(GOV_OPS, 0),
    trace_root: GOV_TRACE_ROOT,
    ops_root: GOV_OPS_ROOT,
    units_root: UNITS_SET_ROOT,
    units_set_root: SET_ROOT1,
    fills_root: FILLS_ROOT,
    pre_wit: WIT_ROOT,
    post_wit: GOV_WIT,
    post_proof: merkle.getMerkleProof(GOV_TRACE, 0),
    pre_leaf: DEP_PRE,
    post_leaf: GOV_POST[0],
    pre_leaf_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(DEP_PRE)),
    post_leaf_proof: merkle.getMerkleProof(GOV_POST, 0),
  };
  // ---- 25. forged gov leg verdicts (#37-5) --------------------------------
  // The LIAR commitment goes first: proven post PERP 50001 (off by one).
  await submitGovAt(GOV_LIAR_TRACE_ROOT);
  await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 16 }, govHonest, {
    trace_root: GOV_LIAR_TRACE_ROOT,
    post_wit: GOV_LIAR_WIT,
    post_proof: merkle.getMerkleProof(GOV_LIAR_TRACE, 0),
    post_leaf: GOV_LIAR[0],
    post_leaf_proof: merkle.getMerkleProof(GOV_LIAR, 0),
  }), 20000, "gov liar predicate");
  st = await vars(rollup);
  if (Number(st.frozen_16) !== 2) throw new Error("forged gov PERP did not freeze h16");
  console.log("25. forged gov PERP (+1) → frozen=16");
  // ---- 25b. #47 B6: gov op on a PRE-ABSENT account ------------------------
  // Gov ops never create an account (and a PERP-only holder has no acct
  // leaf), so ANY post acct leaf for it is fabricated. The liar books a
  // W: on a fresh account with the old AA's own "expected" perp (0 + 100)
  // — pre-fix that bounced 'no fraud' (sign opposite to the Rust mirror,
  // which expects 0 - 100); now it verdicts.
  {
    const FRESH = "e".repeat(64);
    const freshOp = `W:${FRESH}:100:1`;
    const FRESH_OPS = pad2([freshOp], "freshops");
    const FRESH_OPS_ROOT = merkle.getMerkleRoot(FRESH_OPS);
    const FRESH_POST = pad2([`acct:${FRESH}:0:100:0`], "freshpost");
    const FRESH_WIT = merkle.getMerkleRoot(FRESH_POST);
    const FRESH_TRACE = pad2([FRESH_WIT], "freshtrace");
    const FRESH_TRACE_ROOT = merkle.getMerkleRoot(FRESH_TRACE);
    await submitGovAt(FRESH_TRACE_ROOT, FRESH_OPS_ROOT);
    // acct:eee…: sits strictly between the ADJACENT genesis leaves
    // acct:bbb… (FILL_TAKER_PRE) and meta:1.
    const li = GENESIS_LEAVES.indexOf(FILL_TAKER_PRE);
    const ri = GENESIS_LEAVES.indexOf(META1);
    if (ri !== li + 1) throw new Error("fixture: fresh-account neighbors not adjacent");
    await triggerVerdict(challenger, dispute, Object.assign({ pred: "withdraw", height: 16 }, {
      rollup: ROLLUP_ADDR,
      k: 0,
      op: freshOp,
      ops_proof: merkle.getMerkleProof(FRESH_OPS, 0),
      trace_root: FRESH_TRACE_ROOT,
      ops_root: FRESH_OPS_ROOT,
      units_root: UNITS_SET_ROOT,
      units_set_root: SET_ROOT1,
      fills_root: FILLS_ROOT,
      pre_wit: WIT_ROOT,
      post_wit: FRESH_WIT,
      post_proof: merkle.getMerkleProof(FRESH_TRACE, 0),
      pre_absent: true,
      left: GENESIS_LEAVES[li],
      left_proof: merkle.getMerkleProof(GENESIS_LEAVES, li),
      right: GENESIS_LEAVES[ri],
      right_proof: merkle.getMerkleProof(GENESIS_LEAVES, ri),
      post_leaf: FRESH_POST[0],
      post_leaf_proof: merkle.getMerkleProof(FRESH_POST, 0),
    }), 20000, "gov fresh-account predicate");
    st = await vars(rollup);
    if (Number(st.frozen_16) !== 2) throw new Error("fabricated fresh gov leaf did not freeze h16");
    console.log("25b. gov W: on a pre-absent account with a post leaf → frozen=16");
  }
  // ---- 24. honest GovDeposit resubmit never freezes (#37-5) ---------------
  // Frozen-branch resubmit of the honest roots, then the same proof shape
  // bounces 'no fraud' — the pre-fix AA judged D: by collateral math and
  // froze this height.
  await submitGovAt(GOV_TRACE_ROOT);
  await triggerBounce(challenger, dispute, Object.assign({ pred: "deposit", height: 16 }, govHonest), 20000, "no fraud");
  st = await vars(rollup);
  if (Number(st.frozen_16 || 0) !== 0) throw new Error("honest gov deposit froze h16!");
  console.log("24. honest GovDeposit bounces 'no fraud' — gov arm compares PERP");
  // ---- 26-31 on fresh heights via k=1 two-unit submits --------------------
  // h3 is long finalized: k=1 predicates anchor pre_wit through pre_proof
  // (trace[0] membership), so the H3_PRE tree rides fresh heights 17..22.
  // Each verdict freezes its height; bounce scenarios resubmit cleanly.
  // K1 ops tree: [pad-op, FILL_OP] — the challenged unit (k=1) carries the
  // Place op the taker leg models.
  const K1_PAD_OP = "x";
  const K1_OPS = [K1_PAD_OP, FILL_OP];
  const K1_OPS_ROOT = merkle.getMerkleRoot(K1_OPS);
  const K1_OPS_PROOF = merkle.getMerkleProof(K1_OPS, 1);
  // Fixtures for the k=1 drills (same shapes as the h3-window originals).
  const SELF_BETTER = `ord:${"e".repeat(63)}f:1:1:90000000:6:9:${FILL_TAKER}:0:0`;
  // #47 B7: the taker's own ESCROWED better ask (isolated, margin_left 100).
  const SELF_BETTER_ESC = `ord:${"e".repeat(62)}fe:1:1:90000000:5:9:${FILL_TAKER}:1:100`;
  const SELF_PRE = [DEP_PRE, FILL_TAKER_PRE, META1, META2, POS2, MAKER_ORD, SELF_BETTER, SELF_BETTER_ESC].sort();
  const SELF_PRE_WIT = merkle.getMerkleRoot(SELF_PRE);
  const SELF_PRE_IDX = {};
  SELF_PRE.forEach((l, i) => { SELF_PRE_IDX[l] = i; });
  const MFILL0 = SKIP_FILLS[0];
  const MFILL1 = `f:${H3_UNIT_HEX}:1:${FILL_TAKER}:${"c".repeat(64)}:${"d".repeat(64)}:${"d".repeat(64)}:1:100000000:50000000:7:0:0:0`;
  const MFILLS = [MFILL0, MFILL1];
  const MFILLS_TREE = fillsTree(MFILLS);
  const MFILLS_ROOT = merkle.getMerkleRoot(MFILLS_TREE);
  const ADL_FILL = `f:${H3_UNIT_HEX}:0:${takerH}:${"c".repeat(64)}:${"d".repeat(64)}:${"e".repeat(64)}:1:100000000:100000000:9:0:2:0`;
  const ADL_FILLS = [ADL_FILL];
  const ADL_TREE = fillsTree(ADL_FILLS);
  const ADL_ROOT = merkle.getMerkleRoot(ADL_TREE);
  const k1fillBase = (hh, traceRoot, trace, fillsRoot, fillsTree, fill, postWit, postTree, postLeaf, posLeaf) => ({
    rollup: ROLLUP_ADDR,
    k: 1,
    trace_root: traceRoot,
    fills_root: fillsRoot,
    ops_root: K1_OPS_ROOT,
    units_root: K1_UNITS_ROOT,
    units_proof: K1_UNITS_PROOF,
    fill,
    fill_proof: merkle.getMerkleProof(fillsTree, 0),
    op: FILL_OP,
    ops_proof: K1_OPS_PROOF,
    right: fillsTree[1],
    right_proof: merkle.getMerkleProof(fillsTree, 1),
    pre_wit: H3_PRE_WIT,
    pre_proof: merkle.getMerkleProof(trace, 0),
    post_wit: postWit,
    post_proof: merkle.getMerkleProof(trace, 1),
    pre_acct: FILL_TAKER_PRE,
    pre_acct_proof: merkle.getMerkleProof(H3_PRE, H3_PRE_IDX[FILL_TAKER_PRE]),
    post_acct: postLeaf,
    post_acct_proof: merkle.getMerkleProof(postTree, postTree.indexOf(postLeaf)),
    post_pos: posLeaf,
    post_pos_proof: posLeaf ? merkle.getMerkleProof(postTree, postTree.indexOf(posLeaf)) : { root: postWit, siblings: ["x"], index: 0 },
    pre_meta: META1,
    pre_meta_proof: merkle.getMerkleProof(H3_PRE, H3_PRE_IDX[META1]),
    pos_absent: true,
    pleft: BETTER_ORD,
    pleft_proof: merkle.getMerkleProof(H3_PRE, H3_PRE_IDX[BETTER_ORD]),
    pright: POS2,
    pright_proof: merkle.getMerkleProof(H3_PRE, H3_PRE_IDX[POS2]),
    who: "taker",
  });
  // 26/27. PERP-only / withdrawn-only post tamper verdicts (#37-17).
  // Isolated-open shape (honest post col 499500, expectation non-negative
  // so the claw-bail gate stays shut): the proven post leaf drifts ONLY in
  // perp (26: perp 7) or ONLY in W (27: W 9). Collateral/pos math is
  // untouched, yet the fill AA must verdict — pre-fix it compared
  // collateral alone and bounced 'no fraud'.
  // k=1 on fresh heights: pre side anchors on the GENESIS tree through
  // pre_proof (trace[0]); the iso unit rides its own K1 units root with
  // the challenged unit at index 1.
  const K1_ISO_PAD = sha256Hex("k1-pad-unit-2"); // sorts before iso-unit: ISO at index 1
  const K1_ISO_UNITS = [K1_ISO_PAD, isoUnit].sort();
  const K1_ISO_ROOT = merkle.getMerkleRoot(K1_ISO_UNITS);
  const K1_ISO_PROOF = merkle.getMerkleProof(K1_ISO_UNITS, K1_ISO_UNITS.indexOf(isoUnit));
  const K1_ISO_OPS = [K1_PAD_OP, isoOp];
  const K1_ISO_OPS_ROOT = merkle.getMerkleRoot(K1_ISO_OPS);
  const K1_ISO_OPS_PROOF = merkle.getMerkleProof(K1_ISO_OPS, 1);
  const k1isoBase = (traceRoot, trace, postWit, postTree, postLeaf) => ({
    rollup: ROLLUP_ADDR,
    k: 1,
    trace_root: traceRoot,
    fills_root: ISO_FILLS_ROOT,
    ops_root: K1_ISO_OPS_ROOT,
    units_root: K1_ISO_ROOT,
    units_proof: K1_ISO_PROOF,
    fill: isoFill,
    fill_proof: merkle.getMerkleProof(ISO_FILLS_TREE, 0),
    op: isoOp,
    ops_proof: K1_ISO_OPS_PROOF,
    right: ISO_FILLS_TREE[1],
    right_proof: merkle.getMerkleProof(ISO_FILLS_TREE, 1),
    pre_wit: WIT_ROOT,
    pre_proof: merkle.getMerkleProof(trace, 0),
    post_wit: postWit,
    post_proof: merkle.getMerkleProof(trace, 1),
    pre_acct: DEP_PRE,
    pre_acct_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(DEP_PRE)),
    post_acct: postLeaf,
    post_acct_proof: merkle.getMerkleProof(postTree, postTree.indexOf(postLeaf)),
    post_pos: isoPos,
    post_pos_proof: merkle.getMerkleProof(postTree, postTree.indexOf(isoPos)),
    pre_meta: META1,
    pre_meta_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(META1)),
    pos_absent: true,
    pleft: META2,
    pleft_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(META2)),
    pright: POS2,
    pright_proof: merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(POS2)),
    oleft: META1,
    oleft_proof: merkle.getMerkleProof(postTree, postTree.indexOf(META1)),
    oright: isoPos,
    oright_proof: merkle.getMerkleProof(postTree, postTree.indexOf(isoPos)),
    who: "taker",
  });
  async function submitK1Iso(hh, preWit, postWit, fillsRoot) {
    const trace = [preWit, postWit];
    const traceRoot = merkle.getMerkleRoot(trace);
    const s = submitData(hh, STATE_ROOT, STATE_ROOT);
    s.wit_root = preWit;
    s.wit_count = 2;
    s.trace_root = traceRoot;
    s.fills_root = fillsRoot;
    s.ops_root = K1_ISO_OPS_ROOT;
    s.units_root = K1_ISO_ROOT;
    s.unit_count = 2;
    s.fill_count = 1;
    const header = headerFromSubmit(s);
    const r = await operator.sendMulti({
      messages: [tempDataMsg(header), { app: "data", payload: s }],
      base_outputs: [{ address: rollup, amount: SUBMIT_FEE }],
    });
    if (r.error) throw new Error(`h${hh} k1-iso submit failed: ` + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    if (res && res.response && res.response.bounced)
      throw new Error(`h${hh} k1-iso submit bounced: ` + bounceDetail(res));
    return { trace, traceRoot };
  }
  // A verdict freezes its height: the next forward height cannot submit
  // past a failed top, so resurrect h17 honestly before drilling h18.
  const ISO_HONEST = [`acct:${DEP_ACCT}:499500:0:0`, META1, isoPos].sort();
  const ISO_HONEST_WIT = merkle.getMerkleRoot(ISO_HONEST);
  for (const [tag, hh, perp, w] of [["26-perp", 17, 7, 0], ["27-wd", 18, 0, 9]]) {
    const leaf = `acct:${DEP_ACCT}:499500:${perp}:${w}`;
    const tree = [leaf, META1, isoPos].sort();
    const wit = merkle.getMerkleRoot(tree);
    const { trace, traceRoot } = await submitK1Iso(hh, WIT_ROOT, wit, ISO_FILLS_ROOT);
    await triggerVerdict(challenger, fill, Object.assign({ pred: "fill_math", height: hh }, k1isoBase(traceRoot, trace, wit, tree, leaf)), 20000, tag + " tamper predicate");
    st = await vars(rollup);
    if (Number(st["frozen_" + hh]) !== 2) throw new Error(tag + " tamper did not freeze h" + hh);
    console.log(tag + ": perp/W-only post drift → frozen=" + hh);
    // Resurrect honestly (frozen branch) so the next height can submit.
    await submitK1Iso(hh, WIT_ROOT, ISO_HONEST_WIT, ISO_FILLS_ROOT);
    st = await vars(rollup);
    if (Number(st["frozen_" + hh] || 0) !== 0) throw new Error(tag + " honest resubmit did not un-freeze h" + hh);
  }
  // 28. self-owned CROSS better-order skip → 'no fraud' (#37-9).
  // 28b. self-owned ESCROWED better order on a Place fill → verdict (#47
  //      B7: SelfTrade::Reject would have rejected the whole Place).
  {
    const hh = 19;
    const { trace, traceRoot } = await submitK1(hh, SELF_PRE_WIT, SELF_PRE_WIT, SKIP_FILLS_ROOT, K1_OPS_ROOT);
    const selfSkip = (better) => ({
      rollup: ROLLUP_ADDR,
      k: 1,
      trace_root: traceRoot,
      fills_root: SKIP_FILLS_ROOT,
      ops_root: K1_OPS_ROOT,
      units_root: K1_UNITS_ROOT,
      units_proof: K1_UNITS_PROOF,
      fill: SKIP_FILLS[0],
      fill_proof: merkle.getMerkleProof(SKIP_FILLS_TREE, 0),
      pre_wit: SELF_PRE_WIT,
      pre_proof: merkle.getMerkleProof(trace, 0),
      maker_ord: MAKER_ORD,
      maker_proof: merkle.getMerkleProof(SELF_PRE, SELF_PRE_IDX[MAKER_ORD]),
      better_ord: better,
      better_proof: merkle.getMerkleProof(SELF_PRE, SELF_PRE_IDX[better]),
    });
    await triggerBounce(challenger, book, Object.assign({ pred: "skip", height: hh }, selfSkip(SELF_BETTER)), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st["frozen_" + hh] || 0) !== 0) throw new Error("self-owned skip froze h" + hh + "!");
    console.log("28. self-owned cross better order bounces 'no fraud' — height live");
    await triggerVerdict(challenger, book, Object.assign({ pred: "skip", height: hh }, selfSkip(SELF_BETTER_ESC)), 20000, "escrowed self-order skip predicate");
    st = await vars(rollup);
    if (Number(st["frozen_" + hh]) !== 2) throw new Error("escrowed self-order skip did not freeze h" + hh);
    console.log("28b. fill past the taker's own ESCROWED better order → frozen=" + hh);
    await submitK1(hh, SELF_PRE_WIT, SELF_PRE_WIT, SKIP_FILLS_ROOT, K1_OPS_ROOT); // resurrect
  }
  // 29. multi-fill skip (#47 B3): idx 1 still fails closed ('no fraud'),
  //     but the FIRST fill (idx 0) of a multi-fill unit is checkable —
  //     pre_wit is the book matching started from → verdict.
  {
    const hh = 20;
    const { trace, traceRoot } = await submitK1(hh, H3_PRE_WIT, H3_PRE_WIT, MFILLS_ROOT, K1_OPS_ROOT);
    const mSkip = (idx) => ({
      rollup: ROLLUP_ADDR,
      k: 1,
      trace_root: traceRoot,
      fills_root: MFILLS_ROOT,
      ops_root: K1_OPS_ROOT,
      units_root: K1_UNITS_ROOT,
      units_proof: K1_UNITS_PROOF,
      fill: MFILLS[idx],
      fill_proof: merkle.getMerkleProof(MFILLS_TREE, idx),
      pre_wit: H3_PRE_WIT,
      pre_proof: merkle.getMerkleProof(trace, 0),
      maker_ord: MAKER_ORD,
      maker_proof: merkle.getMerkleProof(H3_PRE, H3_PRE_IDX[MAKER_ORD]),
      better_ord: BETTER_ORD,
      better_proof: merkle.getMerkleProof(H3_PRE, H3_PRE_IDX[BETTER_ORD]),
    });
    await triggerBounce(challenger, book, Object.assign({ pred: "skip", height: hh }, mSkip(1)), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st["frozen_" + hh] || 0) !== 0) throw new Error("idx-1 skip froze h" + hh + "!");
    console.log("29. multi-fill idx 1 skip bounces 'no fraud' — fail closed");
    await triggerVerdict(challenger, book, Object.assign({ pred: "skip", height: hh }, mSkip(0)), 20000, "multi-fill idx-0 skip predicate");
    st = await vars(rollup);
    if (Number(st["frozen_" + hh]) !== 2) throw new Error("multi-fill idx-0 skip did not freeze h" + hh);
    console.log("29. multi-fill idx 0 skip → frozen=" + hh);
    await submitK1(hh, H3_PRE_WIT, H3_PRE_WIT, MFILLS_ROOT, K1_OPS_ROOT); // resurrect
  }
  // 30/31. kind-2 ADL on the REAL engine shape (#47 B1/B2): a Liquidate
  // unit `L:{caller}:{target}:{market}` on the order-book path — taker =
  // target T (cross long 1 @1.1 closed at mark 1.0), maker = ADL
  // counterparty C (short 1 @1.1), maker order id all-zero, fee 0, keeper
  // reward 1% of the 1.0 notional (10000) seized from T and credited to
  // the caller K (!= C). T: 1000000 - 100000 pnl - 10000 keeper = 890000;
  // C: 1000000 + 100000 = 1100000 (> 0: no claw touched T).
  {
    const T = FILL_TAKER;
    const C = "c".repeat(64);
    const K = "9".repeat(64);
    const T_PRE = `acct:${T}:1000000:0:0`;
    const T_POS = `pos:${T}:1:100000000:110000000:0:0`;
    const C_PRE = `acct:${C}:1000000:0:0`;
    const C_POS = `pos:${C}:1:-100000000:110000000:0:0`;
    const ADL_PRE = [T_PRE, T_POS, C_PRE, C_POS, META1].sort();
    const ADL_PRE_WIT = merkle.getMerkleRoot(ADL_PRE);
    const ADL_OP = `L:${K}:${T}:1`;
    const ADL_OPS = [K1_PAD_OP, ADL_OP];
    const ADL_OPS_ROOT = merkle.getMerkleRoot(ADL_OPS);
    const ADL_FILL2 = `f:${H3_UNIT_HEX}:0:${T}:${C}:${"a".repeat(64)}:${"0".repeat(64)}:1:100000000:100000000:9:1:2:0`;
    const ADL_TREE2 = fillsTree([ADL_FILL2]);
    const ADL_ROOT2 = merkle.getMerkleRoot(ADL_TREE2);
    // A foreign position after every pos:{T|C} range closes the straddle.
    const FILLER = `pos:${"d".repeat(64)}:2:1:1:0:0`;
    const C_POST = `acct:${C}:1100000:0:0`;
    const adlPayload = (trace, traceRoot, tree, wit, tLeaf) => ({
      rollup: ROLLUP_ADDR,
      k: 1,
      trace_root: traceRoot,
      fills_root: ADL_ROOT2,
      ops_root: ADL_OPS_ROOT,
      units_root: K1_UNITS_ROOT,
      units_proof: K1_UNITS_PROOF,
      fill: ADL_FILL2,
      fill_proof: merkle.getMerkleProof(ADL_TREE2, 0),
      right: ADL_TREE2[1],
      right_proof: merkle.getMerkleProof(ADL_TREE2, 1),
      op: ADL_OP,
      ops_proof: merkle.getMerkleProof(ADL_OPS, 1),
      pre_wit: ADL_PRE_WIT,
      pre_proof: merkle.getMerkleProof(trace, 0),
      post_wit: wit,
      post_proof: merkle.getMerkleProof(trace, 1),
      pre_acct: T_PRE,
      pre_acct_proof: merkle.getMerkleProof(ADL_PRE, ADL_PRE.indexOf(T_PRE)),
      pre_pos: T_POS,
      pre_pos_proof: merkle.getMerkleProof(ADL_PRE, ADL_PRE.indexOf(T_POS)),
      post_acct: tLeaf,
      post_acct_proof: merkle.getMerkleProof(tree, tree.indexOf(tLeaf)),
      pre_meta: META1,
      pre_meta_proof: merkle.getMerkleProof(ADL_PRE, ADL_PRE.indexOf(META1)),
      cp_acct: C_POST,
      cp_acct_proof: merkle.getMerkleProof(tree, tree.indexOf(C_POST)),
      // Flat close: T's market-1 pos range is empty on the post tree
      // (R5-A-2: the AA's acct-wide arm is gone; the market straddle
      // META1 < pos:T:1: .. pos:T:1; <= FILLER proves the same).
      post_pleft: META1,
      post_pleft_proof: merkle.getMerkleProof(tree, tree.indexOf(META1)),
      post_pright: FILLER,
      post_pright_proof: merkle.getMerkleProof(tree, tree.indexOf(FILLER)),
      who: "taker",
    });
    {
      const hh = 21;
      const tLeaf = `acct:${T}:890000:0:0`;
      const tree = [tLeaf, C_POST, `acct:${K}:10000:0:0`, META1, FILLER].sort();
      const wit = merkle.getMerkleRoot(tree);
      const { trace, traceRoot } = await submitK1(hh, ADL_PRE_WIT, wit, ADL_ROOT2, ADL_OPS_ROOT);
      await triggerBounce(challenger, fill, Object.assign({ pred: "fill_math", height: hh }, adlPayload(trace, traceRoot, tree, wit, tLeaf)), 20000, "no fraud");
      st = await vars(rollup);
      if (Number(st["frozen_" + hh] || 0) !== 0) throw new Error("honest ADL froze h" + hh + "!");
      console.log("30. honest kind-2 ADL target leg (L: op, keeper seized) bounces 'no fraud'");
    }
    {
      const hh = 22;
      // Liar skips the keeper seize: T keeps 900000.
      const tLeaf = `acct:${T}:900000:0:0`;
      const tree = [tLeaf, C_POST, META1, FILLER].sort();
      const wit = merkle.getMerkleRoot(tree);
      const { trace, traceRoot } = await submitK1(hh, ADL_PRE_WIT, wit, ADL_ROOT2, ADL_OPS_ROOT);
      await triggerVerdict(challenger, fill, Object.assign({ pred: "fill_math", height: hh }, adlPayload(trace, traceRoot, tree, wit, tLeaf)), 20000, "adl liar predicate");
      st = await vars(rollup);
      if (Number(st["frozen_" + hh]) !== 2) throw new Error("liar ADL did not freeze h" + hh);
      console.log("31. liar kind-2 ADL (keeper not seized) → frozen=" + hh);
    }
  }
  // ---- 32. adjacent heights fraud in turn, then recover in order (#37-8) --
  // h23/h24 pipeline LIAR submits, verdicts h23 then h24. #47 A1: the
  // verdict sets last_submitted = min(ls, h) — h23 pins ls=23 and the
  // later verdict on the (now dead) h24 must NOT raise it back to 24.
  // h24 cannot be re-submitted before h23 (its prev is gone), then both
  // resubmit honestly bottom-up and finalize in order.
  // 31 left h22 frozen: resurrect it honestly first so h23 can submit.
  await trigger(operator, rollup, { pool: 1 }, POOL_FUND_GROSS);
  await sendCombinedSubmit(operator, 22, STATE_ROOT, STATE_ROOT);
  st = await vars(rollup);
  if (Number(st.frozen_22 || 0) !== 0) throw new Error("h22 resurrect did not un-freeze");
  await submitLiarAt(23);
  await submitLiarAt(24);
  await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 23 }, fraudProof), 20000, "h23 verdict");
  st = await vars(rollup);
  if (Number(st.frozen_23) !== 2) throw new Error("h23 verdict did not freeze");
  if (Number(st.last_submitted) !== 23) throw new Error("h23 verdict must pin ls=23, got " + st.last_submitted);
  await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 24 }, fraudProof), 20000, "h24 verdict");
  st = await vars(rollup);
  if (Number(st.frozen_24) !== 2) throw new Error("h24 verdict did not freeze");
  if (Number(st.last_submitted) !== 23) throw new Error("#47 A1: verdict on dead h24 must keep ls=23, got " + st.last_submitted);
  console.log("32. h23+h24 fraud in turn, ls stays at the lowest failed height (23)");
  // Out-of-order resubmit of h24 first: prev == state_root_23 is zeroed.
  await triggerBounce(operator, rollup, submitData(24, STATE_ROOT, STATE_ROOT), SUBMIT_FEE, "prev mismatch");
  // Recover bottom-up: h23 first (prev == state_root_22 resubmitted below), then h24
  // (prev == the RESUBMITTED state_root_23).
  await sendCombinedSubmit(operator, 23, STATE_ROOT, STATE_ROOT);
  st = await vars(rollup);
  if (Number(st.frozen_23 || 0) !== 0) throw new Error("h23 resubmit did not un-freeze");
  await sendCombinedSubmit(operator, 24, STATE_ROOT, STATE_ROOT);
  st = await vars(rollup);
  if (Number(st.frozen_24 || 0) !== 0) throw new Error("h24 resubmit did not un-freeze");
  await network.timetravel({ shift: "3600s" });
  // Heights 16..22 were never finalized (the drills only froze/resurrected
  // them): advance last_finalized in order before 23/24 can finalize.
  for (let fh = 16; fh <= 22; fh++) {
    await trigger(operator, rollup, { finalize: 1, height: fh }, 20000);
  }
  await trigger(operator, rollup, { finalize: 1, height: 23 }, 20000);
  await trigger(operator, rollup, { finalize: 1, height: 24 }, 20000);
  st = await vars(rollup);
  if (Number(st.last_finalized) !== 24) throw new Error("post-recovery finalize stalled at " + st.last_finalized);
  console.log("32. resubmit bottom-up + finalize in order — chain recovers");
  // ---- 33. #47 A1 halt drill: stale verdict / frozen resubmit above a gap --
  // Attack from the issue: h25 (fraud), h26, h27 built on it, h28 (fraud).
  // v(25) → ls=25; v(28) on the dead h28 keeps ls=25 (pre-fix: ls=28).
  // Re-submitting the frozen h28 straight away (prev == the STALE
  // state_root_27, non-zero) must bounce 'bad submit' — pre-fix it landed,
  // re-raised ls to 28, and h26 (prev != resubmitted root_25) could never
  // finalize ('stale height') nor be re-opened: permanent halt.
  // Recovery: resubmit h25, forward-submit 26/27/28 over the dead data,
  // finalize all four.
  await trigger(operator, rollup, { pool: 1 }, POOL_FUND_GROSS);
  await submitLiarAt(25);
  await sendCombinedSubmit(operator, 26, STATE_ROOT, STATE_ROOT);
  await sendCombinedSubmit(operator, 27, STATE_ROOT, STATE_ROOT);
  await submitLiarAt(28);
  await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 25 }, fraudProof), 20000, "h25 verdict");
  await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 28 }, fraudProof), 20000, "h28 stale verdict");
  st = await vars(rollup);
  if (Number(st.frozen_28) !== 2) throw new Error("h28 verdict did not freeze");
  if (Number(st.last_submitted) !== 25) throw new Error("#47 A1: stale verdict raised ls to " + st.last_submitted);
  await triggerBounce(operator, rollup, submitData(28, STATE_ROOT, STATE_ROOT), SUBMIT_FEE, "bad submit");
  await triggerBounce(operator, rollup, { finalize: 1, height: 26 }, 20000, "not submitted");
  await sendCombinedSubmit(operator, 25, STATE_ROOT, STATE_ROOT);
  for (const fh of [26, 27, 28]) await sendCombinedSubmit(operator, fh, STATE_ROOT, STATE_ROOT);
  st = await vars(rollup);
  if (Number(st.last_submitted) !== 28 || Number(st.frozen_28 || 0) !== 0)
    throw new Error("A1 recovery submits failed: ls=" + st.last_submitted);
  await network.timetravel({ shift: "3600s" });
  for (const fh of [25, 26, 27, 28]) await trigger(operator, rollup, { finalize: 1, height: fh }, 20000);
  st = await vars(rollup);
  if (Number(st.last_finalized) !== 28) throw new Error("A1 drill finalize stalled at " + st.last_finalized);
  console.log("33. stale verdict keeps ls at the failed tip; gap resubmit refused; chain recovers to 28");
  // ===== #47 integration: cross-PR consistency + A2 binding predicates ====
  async function submitAt(hh, o) {
    const sd = submitData(hh, STATE_ROOT, STATE_ROOT);
    sd.ops_root = o.opsRoot;
    sd.trace_root = o.traceRoot;
    sd.units_root = o.unitsRoot || UNITS_SET_ROOT;
    sd.units_set_root = SET_ROOT1;
    sd.fills_root = o.fillsRoot || FILLS_ROOT;
    sd.fill_count = o.fillCount || 0;
    sd.unit_count = o.unitCount || 1; // round 7b: multi-unit trees (exact proof depth)
    sd.wit_root = o.witRoot || WIT_ROOT; // k=0 drills anchor on the genesis tree unless a drill commits its own pre tree
    sd.wit_count = GEN_WIT_COUNT;
    const header = headerFromSubmit(sd);
    const r = await operator.sendMulti({
      messages: [tempDataMsg(header), { app: "data", payload: sd }],
      base_outputs: [{ address: rollup, amount: SUBMIT_FEE }],
    });
    if (r.error) throw new Error(`h${hh} submit failed: ` + r.error);
    await network.witnessUntilStable(r.unit);
    const res = await network.getAaResponseToUnit(r.unit).catch(() => null);
    if (res && res.response && res.response.bounced)
      throw new Error(`h${hh} submit bounced: ` + bounceDetail(res));
  }
  const oneUnit = (tag, op, postLeaves) => {
    const ops = pad2([op], tag + "-ops");
    const post = pad2(postLeaves.slice().sort(), tag + "-post");
    const wit = merkle.getMerkleRoot(post);
    const trace = pad2([wit], tag + "-trace");
    return {
      op, ops, post, wit, trace,
      opsRoot: merkle.getMerkleRoot(ops),
      traceRoot: merkle.getMerkleRoot(trace),
      leafProof: (leaf) => merkle.getMerkleProof(post, post.indexOf(leaf)),
    };
  };
  const genProof = (leaf) => merkle.getMerkleProof(GENESIS_LEAVES, GENESIS_LEAVES.indexOf(leaf));
  const depositPayload = (u, postLeaf) => ({
    rollup: ROLLUP_ADDR,
    k: 0,
    op: u.op,
    ops_proof: merkle.getMerkleProof(u.ops, 0),
    trace_root: u.traceRoot,
    ops_root: u.opsRoot,
    units_root: UNITS_SET_ROOT,
    units_set_root: SET_ROOT1,
    fills_root: FILLS_ROOT,
    pre_wit: WIT_ROOT,
    post_wit: u.wit,
    post_proof: merkle.getMerkleProof(u.trace, 0),
    pre_leaf: DEP_PRE,
    pre_leaf_proof: genProof(DEP_PRE),
    post_leaf: postLeaf,
    post_leaf_proof: u.leafProof(postLeaf),
  });

  // ---- 34. a REJECTED withdraw is committed too: unchanged leaf = honest --
  // Rejected units are part of every batch (one trace entry per executed
  // unit). #49 made more withdraws reject (spot reserve, nonce watermark);
  // the pre-fix predicate verdicted every one of them (post != pre - amt).
  {
    const opW = `w:${DEP_ACCT}:5000000:1`;
    const liarLeaf = `acct:${DEP_ACCT}:999999:0:0`;
    const liar = oneUnit("rejw-liar", opW, [liarLeaf]);
    await submitAt(29, liar);
    await triggerVerdict(challenger, dispute, Object.assign({ pred: "withdraw", height: 29 }, depositPayload(liar, liarLeaf)), 20000, "withdraw liar predicate");
    st = await vars(rollup);
    if (Number(st.frozen_29) !== 2) throw new Error("withdraw liar (neither pre nor pre-amt) did not freeze h29");
    const honest = oneUnit("rejw", opW, [DEP_PRE]);
    await submitAt(29, honest);
    await triggerBounce(challenger, dispute, Object.assign({ pred: "withdraw", height: 29 }, depositPayload(honest, DEP_PRE)), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_29 || 0) !== 0) throw new Error("honest rejected withdraw froze h29!");
    console.log("34. rejected withdraw (leaf unchanged) bounces 'no fraud'; a third value verdicts");
  }

  // ---- 35. claw guard (owner item): winner leg clawed by a negative party --
  // Isolated open (identity 499500) whose maker ended the fill negative and
  // clawed 100 back: taker 499400, maker leaf at 0. Pre-fix: verdict on an
  // honest unit. Now: no proven positive counterparty -> 'no fraud'.
  {
    const CLAW_CP = `acct:${"c".repeat(64)}:0:0:0`;
    const tree = [`acct:${DEP_ACCT}:499400:0:0`, CLAW_CP, META1, isoPos].sort();
    const wit = merkle.getMerkleRoot(tree);
    const trace = pad2([wit], "claw-trace");
    const traceRoot = merkle.getMerkleRoot(trace);
    await submitAt(30, { opsRoot: ISO_OPS_ROOT, traceRoot, fillsRoot: ISO_FILLS_ROOT, unitsRoot: ISO_UNITS_ROOT, fillCount: 1 });
    const payload = isoFillPayload(traceRoot, trace, wit, tree, 499400, CLAW_CP);
    await triggerBounce(challenger, fill, Object.assign({ pred: "fill_math", height: 30 }, payload), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_30 || 0) !== 0) throw new Error("honest clawed winner leg froze h30!");
    console.log("35. clawed winner leg (counterparty at 0) bounces 'no fraud'");
  }

  // ---- 36. A2 P-wpin: W moved outside the account's own withdraw ----------
  {
    const forged = `acct:${DEP_ACCT}:1000000:0:777`;
    const liar = oneUnit("wpin-liar", "x:" + sha256Hex("wpin-unit"), [forged]);
    await submitAt(31, liar);
    const wpin = (u, leaf) => ({
      rollup: ROLLUP_ADDR,
      k: 0,
      op: u.op,
      ops_proof: merkle.getMerkleProof(u.ops, 0),
      trace_root: u.traceRoot,
      ops_root: u.opsRoot,
      pre_wit: WIT_ROOT,
      post_wit: u.wit,
      post_proof: merkle.getMerkleProof(u.trace, 0),
      post_leaf: leaf,
      post_leaf_proof: u.leafProof(leaf),
      pre_leaf: DEP_PRE,
      pre_leaf_proof: genProof(DEP_PRE),
    });
    await triggerVerdict(challenger, bindAa, Object.assign({ pred: "wpin", height: 31 }, wpin(liar, forged)), 20000, "wpin liar predicate");
    st = await vars(rollup);
    if (Number(st.frozen_31) !== 2) throw new Error("forged W did not freeze h31");
    const paid = `acct:${DEP_ACCT}:999900:0:100`;
    const honest = oneUnit("wpin", `w:${DEP_ACCT}:100:1`, [paid]);
    await submitAt(31, honest);
    await triggerBounce(challenger, bindAa, Object.assign({ pred: "wpin", height: 31 }, wpin(honest, paid)), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_31 || 0) !== 0) throw new Error("honest withdraw W froze h31!");
    console.log("36. P-wpin: forged W -> frozen; own withdraw W+amount -> 'no fraud'");
  }

  // ---- 37. A2 P-adr: a new address binding needs the account's deposit ----
  {
    const PAYEE = "Q".repeat(32);
    const adr = `adr:${PAYEE}:${DEP_ACCT}`;
    const li = GENESIS_LEAVES.indexOf(FILL_TAKER_PRE);
    const ri = GENESIS_LEAVES.indexOf(META1);
    if (ri !== li + 1) throw new Error("fixture: adr neighbors not adjacent");
    const adrPayload = (u, leaf = adr) => ({
      rollup: ROLLUP_ADDR,
      k: 0,
      op: u.op,
      ops_proof: merkle.getMerkleProof(u.ops, 0),
      trace_root: u.traceRoot,
      ops_root: u.opsRoot,
      pre_wit: WIT_ROOT,
      post_wit: u.wit,
      post_proof: merkle.getMerkleProof(u.trace, 0),
      post_leaf: leaf,
      post_leaf_proof: u.leafProof(leaf),
      left: GENESIS_LEAVES[li],
      left_proof: genProof(GENESIS_LEAVES[li]),
      right: GENESIS_LEAVES[ri],
      right_proof: genProof(GENESIS_LEAVES[ri]),
    });
    const liar = oneUnit("adr-liar", "x:" + sha256Hex("adr-unit"), [adr, DEP_PRE]);
    await submitAt(32, liar);
    await triggerVerdict(challenger, bindAa, Object.assign({ pred: "adr", height: 32 }, adrPayload(liar)), 20000, "adr liar predicate");
    st = await vars(rollup);
    if (Number(st.frozen_32) !== 2) throw new Error("unbacked adr binding did not freeze h32");
    // R4-A-4: a new binding also needs the vault's dep_ record of the
    // anchor, paid by that address for that account — the honest binding
    // is the operator's own real deposit designating DEP_ACCT.
    const payer37 = await operator.getAddress();
    const dep37 = (await trigger(operator, vault, { deposit: 1, account: DEP_ACCT }, 10100)).unit; // 100 for DEP_ACCT
    const adrOk = `adr:${payer37}:${DEP_ACCT}`;
    const honest = oneUnit("adr", `d:${DEP_ACCT}:100:${payer37}:${dep37}`, [adrOk, `adrx:${DEP_ACCT}:${payer37}`, `acct:${DEP_ACCT}:1000100:0:0`]);
    await submitAt(32, honest);
    await triggerBounce(challenger, bindAa, Object.assign({ pred: "adr", height: 32 }, adrPayload(honest, adrOk)), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_32 || 0) !== 0) throw new Error("honest first binding froze h32!");
    console.log("37. P-adr: binding without its deposit -> frozen; d: with that address -> 'no fraud'");
  }
  // ===================== ROUND 2 (fix/47-r2-aa) =========================
  const opAddrR2 = await operator.getAddress();
  const freshWU = (hh, tag, op, leaves, extra) => Object.assign(oneUnit(tag, op, leaves), extra || {});
  const wpinPayload = (u, leaf, pre) => Object.assign({
    rollup: ROLLUP_ADDR,
    k: 0,
    op: u.op,
    ops_proof: merkle.getMerkleProof(u.ops, 0),
    trace_root: u.traceRoot,
    ops_root: u.opsRoot,
    pre_wit: WIT_ROOT,
    post_wit: u.wit,
    post_proof: merkle.getMerkleProof(u.trace, 0),
    post_leaf: leaf,
    post_leaf_proof: u.leafProof(leaf),
  }, pre);

  // ---- 45. R2-R-1: da_bind + single temp_data enforced at submit ---------
  {
    const sd = submitData(33, STATE_ROOT, STATE_ROOT);
    const header = headerFromSubmit(sd);
    const bad = Object.assign({}, sd, { da_bind: sha256Hex("wrong-bind") });
    const r1 = await operator.sendMulti({
      messages: [tempDataMsg(header), { app: "data", payload: bad }],
      base_outputs: [{ address: rollup, amount: SUBMIT_FEE }],
    });
    if (r1.error) throw new Error("bad-bind submit compose failed: " + r1.error);
    await network.witnessUntilStable(r1.unit);
    let res = await network.getAaResponseToUnit(r1.unit).catch(() => null);
    if (!(res && res.response && res.response.bounced && JSON.stringify(res.response).includes("bad da_bind")))
      throw new Error("R2-R-1: wrong da_bind not bounced: " + bounceDetail(res));
    const r2 = await operator.sendMulti({
      messages: [tempDataMsg(header), tempDataMsg(Object.assign({}, header, { seq: 999 })), { app: "data", payload: sd }],
      base_outputs: [{ address: rollup, amount: SUBMIT_FEE }],
    });
    if (r2.error) throw new Error("two-temp_data submit compose failed: " + r2.error);
    await network.witnessUntilStable(r2.unit);
    res = await network.getAaResponseToUnit(r2.unit).catch(() => null);
    if (!(res && res.response && res.response.bounced && JSON.stringify(res.response).includes("need one temp_data")))
      throw new Error("R2-R-1: two temp_data not bounced: " + bounceDetail(res));
    console.log("45. R2-R-1: wrong da_bind / two temp_data messages bounce at submit");
  }

  // ---- 39. R2-A-2: P-wpin judges W jointly with collateral ---------------
  {
    const FRESH = "1f".repeat(32); // not all-digit: Oscript reads an all-digit field as a number
    const mintOp = `w:${FRESH}:1000000000:1`;
    const mintLeaf = `acct:${FRESH}:0:0:1000000000`;
    const mint = oneUnit("r2w-mint", mintOp, [mintLeaf]);
    await submitAt(33, mint);
    st = await vars(rollup);
    for (const k of ["da_bind_33", "da_hash_33", "counts_root_33", "data_root_33"])
      if (!st[k]) throw new Error("R2-R-1: " + k + " not stored");
    // pre absent: before-min (acct:999..; <= acct:aaa.. at index 0)
    await triggerVerdict(challenger, bindAa, Object.assign({ pred: "wpin", height: 33 }, wpinPayload(mint, mintLeaf, {
      left: GENESIS_LEAVES[0], left_proof: genProof(GENESIS_LEAVES[0]),
    })), 20000, "R2-A-2 fresh-account W mint predicate");
    st = await vars(rollup);
    if (Number(st.frozen_33) !== 2) throw new Error("R2-A-2: W minted on a rejected (fresh) withdraw did not freeze h33");
    const opW = `w:${DEP_ACCT}:100:1`;
    for (const [tag, leaf] of [["noDebit", `acct:${DEP_ACCT}:1000000:0:100`], ["burn", `acct:${DEP_ACCT}:999900:0:0`]]) {
      const u = oneUnit("r2w-" + tag, opW, [leaf]);
      await submitAt(33, u);
      await triggerVerdict(challenger, bindAa, Object.assign({ pred: "wpin", height: 33 }, wpinPayload(u, leaf, {
        pre_leaf: DEP_PRE, pre_leaf_proof: genProof(DEP_PRE),
      })), 20000, "R2-A-2 " + tag + " predicate");
      st = await vars(rollup);
      if (Number(st.frozen_33) !== 2) throw new Error("R2-A-2: " + tag + " did not freeze h33");
    }
    const okLeaf = `acct:${DEP_ACCT}:999900:0:100`;
    const ok = oneUnit("r2w-ok", opW, [okLeaf]);
    await submitAt(33, ok);
    await triggerBounce(challenger, bindAa, Object.assign({ pred: "wpin", height: 33 }, wpinPayload(ok, okLeaf, {
      pre_leaf: DEP_PRE, pre_leaf_proof: genProof(DEP_PRE),
    })), 20000, "no fraud");
    console.log("39. R2-A-2: fresh-account W mint / W without debit / debit without W → frozen; joint accept → 'no fraud'");
  }

  // ---- 40. R2-A-3: a credited deposit must be backed by the vault ledger --
  const dep2 = (await trigger(operator, vault, { deposit: 1, account: DEP_ACCT }, 60000)).unit; // records 50000 for DEP_ACCT
  const MARK2 = "dep:" + dep2;
  {
    const credited = `acct:${DEP_ACCT}:1050000:0:0`;
    const cases = [
      ["unbacked", `d:${DEP_ACCT}:50000:${opAddrR2}:${b6444("never-paid")}`, credited, true],
      ["overclaim", `d:${DEP_ACCT}:60000:${opAddrR2}:${dep2}`, `acct:${DEP_ACCT}:1060000:0:0`, true],
      ["payer", `d:${DEP_ACCT}:50000:${"Q".repeat(32)}:${dep2}`, credited, true],
    ];
    for (const [tag, op, leaf] of cases) {
      const u = oneUnit("r2d-" + tag, op, [leaf, "dep:" + op.split(":")[4]]);
      await submitAt(34, u);
      await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 34 }, depositPayload(u, leaf)), 20000, "R2-A-3 " + tag + " predicate");
      st = await vars(rollup);
      if (Number(st.frozen_34) !== 2) throw new Error("R2-A-3: " + tag + " credit did not freeze h34");
    }
    // backed credit, but the post tree lacks the dep: marker → fraud
    const goodOp = `d:${DEP_ACCT}:50000:${opAddrR2}:${dep2}`;
    const nm = oneUnit("r2d-nomark", goodOp, [credited]);
    await submitAt(34, nm);
    const nmLeaves = nm.post; // [credited, pad:...] — dep:... sits between
    if (!(nmLeaves[0] < MARK2 && MARK2 < nmLeaves[1])) throw new Error("fixture: nomark straddle");
    await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 34 }, depositPayload(nm, credited), {
      dleft: nmLeaves[0], dleft_proof: nm.leafProof(nmLeaves[0]),
      dright: nmLeaves[1], dright_proof: nm.leafProof(nmLeaves[1]),
    }), 20000, "R2-A-3 missing-marker predicate");
    st = await vars(rollup);
    if (Number(st.frozen_34) !== 2) throw new Error("R2-A-3: missing dep marker did not freeze h34");
    const good = oneUnit("r2d-good", goodOp, [credited, MARK2]);
    await submitAt(34, good);
    await triggerBounce(challenger, dispute, Object.assign({ pred: "deposit", height: 34 }, depositPayload(good, credited)), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_34 || 0) !== 0) throw new Error("R2-A-3: honest backed deposit froze h34!");
    console.log("40. R2-A-3: unbacked / over-claimed / foreign-payer / unmarked credits → frozen; backed → 'no fraud'");
  }
  // h35 commits a pre tree that already holds the dep2 marker (consumed).
  const DUP_PRE = [DEP_PRE, META1, MARK2].sort();
  const DUP_PRE_WIT = merkle.getMerkleRoot(DUP_PRE);
  await submitAt(35, Object.assign(oneUnit("r2-dup-commit", "x:" + sha256Hex("dupc"), [DEP_PRE]), { witRoot: DUP_PRE_WIT }));
  {
    const goodOp = `d:${DEP_ACCT}:50000:${opAddrR2}:${dep2}`;
    const credited = `acct:${DEP_ACCT}:1050000:0:0`;
    const dup = oneUnit("r2d-dup", goodOp, [credited, MARK2]);
    await submitAt(36, dup);
    await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 36 }, depositPayload(dup, credited), {
      pre_wit: DUP_PRE_WIT,
      pre_leaf_proof: merkle.getMerkleProof(DUP_PRE, DUP_PRE.indexOf(DEP_PRE)),
      dep_pre_proof: merkle.getMerkleProof(DUP_PRE, DUP_PRE.indexOf(MARK2)),
    }), 20000, "R2-A-3 re-credit predicate");
    st = await vars(rollup);
    if (Number(st.frozen_36) !== 2) throw new Error("R2-A-3: re-credited anchor did not freeze h36");
    // P-keep: the consumed marker vanished from the post tree.
    const drop = oneUnit("r2-keep", "x:" + sha256Hex("keep"), [DEP_PRE]);
    await submitAt(36, drop);
    if (!(drop.post[0] < MARK2 && MARK2 < drop.post[1])) throw new Error("fixture: keep straddle");
    await triggerVerdict(challenger, bindAa, {
      pred: "keep", height: 36, rollup: ROLLUP_ADDR, k: 0,
      trace_root: drop.traceRoot, pre_wit: DUP_PRE_WIT, post_wit: drop.wit,
      post_proof: merkle.getMerkleProof(drop.trace, 0),
      leaf: MARK2, leaf_proof: merkle.getMerkleProof(DUP_PRE, DUP_PRE.indexOf(MARK2)),
      left: drop.post[0], left_proof: drop.leafProof(drop.post[0]),
      right: drop.post[1], right_proof: drop.leafProof(drop.post[1]),
    }, 20000, "P-keep predicate");
    st = await vars(rollup);
    if (Number(st.frozen_36) !== 2) throw new Error("P-keep: dropped dep marker did not freeze h36");
    // Honest: the duplicate is REJECTED — leaf unchanged, marker kept.
    const rej = oneUnit("r2d-rej", goodOp, [DEP_PRE, MARK2]);
    await submitAt(36, rej);
    await triggerBounce(challenger, dispute, Object.assign({ pred: "deposit", height: 36 }, depositPayload(rej, DEP_PRE), {
      pre_wit: DUP_PRE_WIT,
      pre_leaf_proof: merkle.getMerkleProof(DUP_PRE, DUP_PRE.indexOf(DEP_PRE)),
    }), 20000, "no fraud");
    console.log("40b. R2-A-3 re-credit + P-keep dropped marker → frozen; rejected duplicate → 'no fraud'");
  }

  // ---- 41. R2-A-4: an EXISTING account cannot be "proven" absent ----------
  {
    const okLeaf = `acct:${DEP_ACCT}:999900:0:100`;
    const u = oneUnit("r2-a4", `w:${DEP_ACCT}:100:7`, [okLeaf]);
    await submitAt(37, u);
    // Pre-fix: ghost 'acct:aaa..:' < DEP_PRE (its own leaf, index 0) → "absent".
    await triggerBounce(challenger, dispute, Object.assign({ pred: "withdraw", height: 37 }, depositPayload(u, okLeaf), {
      pre_absent: true, left: DEP_PRE, left_proof: genProof(DEP_PRE),
    }), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_37 || 0) !== 0) throw new Error("R2-A-4: honest withdraw slashed via own-leaf absence!");
    console.log("41. R2-A-4: own-leaf 'absence' of an existing account bounces 'no fraud'");
  }

  // ---- 42. R2-A-5: fractional index / internal node never prove absence ---
  {
    const L = (c) => `acct:${c.repeat(64)}:5:0:0`;
    const FRAC_PRE = [L("1"), L("5"), DEP_PRE, L("c"), META1].sort();
    if (FRAC_PRE[2] !== DEP_PRE) throw new Error("fixture: DEP_PRE must sit at index 2");
    const FRAC_WIT = merkle.getMerkleRoot(FRAC_PRE);
    await submitAt(38, Object.assign(oneUnit("r2-frac-commit", "x:" + sha256Hex("fracc"), [DEP_PRE]), { witRoot: FRAC_WIT }));
    const okLeaf = `acct:${DEP_ACCT}:999900:0:100`;
    const u = oneUnit("r2-a5", `w:${DEP_ACCT}:100:8`, [okLeaf]);
    await submitAt(39, u);
    const lp = merkle.getMerkleProof(FRAC_PRE, 1); lp.index = 1.5;
    const rp = merkle.getMerkleProof(FRAC_PRE, 3); rp.index = 2.5;
    if (!merkle.verifyMerkleProof(FRAC_PRE[1], lp) || !merkle.verifyMerkleProof(FRAC_PRE[3], rp))
      throw new Error("fixture: fractional-index proofs must verify in ocore (that is the attack)");
    const base = Object.assign(depositPayload(u, okLeaf), { pre_wit: FRAC_WIT, pre_absent: true });
    await triggerBounce(challenger, dispute, Object.assign({ pred: "withdraw", height: 39 }, base, {
      left: FRAC_PRE[1], left_proof: lp, right: FRAC_PRE[3], right_proof: rp,
    }), 20000, "no fraud");
    // Internal node as "leaf": level-1 node H(l0)||H(l1) with one sibling less.
    const hh = (x) => crypto.createHash("sha256").update(x, "utf8").digest("base64");
    const node = hh(FRAC_PRE[0]) + hh(FRAC_PRE[1]);
    const full = merkle.getMerkleProof(FRAC_PRE, 0);
    const np = { root: full.root, siblings: full.siblings.slice(1), index: 0 };
    if (!merkle.verifyMerkleProof(node, np)) throw new Error("fixture: node-as-leaf proof must verify in ocore");
    if (`acct:${DEP_ACCT};` <= node) {
      await triggerBounce(challenger, dispute, Object.assign({ pred: "withdraw", height: 39 }, base, {
        left: node, left_proof: np,
      }), 20000, "no fraud");
      console.log("42. R2-A-5: internal-node 'leaf' bounces 'no fraud'");
    } else {
      console.log("42. (node-as-leaf sorts below the key in this fixture — before-min arm not applicable; skipped)");
    }
    st = await vars(rollup);
    if (Number(st.frozen_39 || 0) !== 0) throw new Error("R2-A-5: honest withdraw slashed via forged absence!");
    console.log("42. R2-A-5: fractional-index straddle bounces 'no fraud'");
  }

  // ---- 43. R2-A-6: ADL fills have no maker order — ghost bounces ----------
  {
    const Z = "0".repeat(64);
    const adl = `f:${H3_UNIT_HEX}:0:${DEP_ACCT}:${FILL_TAKER}:${"7".repeat(64)}:${Z}:1:100000000:100000000:9:0:2:0`;
    const tree = fillsTree([adl]);
    const u = Object.assign(oneUnit("r2-adl", `L:${FILL_TAKER}:${DEP_ACCT}:1`, [DEP_PRE]), {
      fillsRoot: merkle.getMerkleRoot(tree), unitsRoot: UNITS3_ROOT, fillCount: 1,
    });
    await submitAt(40, u);
    const gi = GENESIS_LEAVES.indexOf(META2);
    if (!(GENESIS_LEAVES[gi] < `ord:${Z}:` && `ord:${Z};` <= GENESIS_LEAVES[gi + 1])) throw new Error("fixture: adl ghost straddle");
    await triggerBounce(challenger, book, {
      pred: "ghost", height: 40, rollup: ROLLUP_ADDR, k: 0,
      trace_root: u.traceRoot, fills_root: u.fillsRoot, ops_root: u.opsRoot, units_root: UNITS3_ROOT,
      units_proof: UNITS3_PROOF, fill: adl, fill_proof: merkle.getMerkleProof(tree, 0),
      pre_wit: WIT_ROOT,
      maker_ord: `ord:${Z}:1:1:100000000:9:1:${FILL_TAKER}:0:0`,
      left: GENESIS_LEAVES[gi], left_proof: genProof(GENESIS_LEAVES[gi]),
      right: GENESIS_LEAVES[gi + 1], right_proof: genProof(GENESIS_LEAVES[gi + 1]),
    }, 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_40 || 0) !== 0) throw new Error("R2-A-6: honest ADL fill slashed via ghost!");
    console.log("43. R2-A-6: ghost on an ADL (kind 2, zero maker id) fill bounces 'no fraud'");
  }

  // ---- 44. R2-A-8: P-mirror (adr <-> adrx) + already-bound account --------
  {
    const PAYEE = "Q".repeat(32);
    const adr = `adr:${PAYEE}:${DEP_ACCT}`;
    const adrx = `adrx:${DEP_ACCT}:${PAYEE}`;
    const liar = oneUnit("r2-mirror", "x:" + sha256Hex("mirror"), [DEP_PRE, adr, META1]);
    await submitAt(41, liar);
    const ai = liar.post.indexOf(adr);
    if (!(liar.post[ai] < adrx && adrx < liar.post[ai + 1])) throw new Error("fixture: mirror straddle");
    const mirrorPayload = (u) => ({
      pred: "mirror", height: 41, rollup: ROLLUP_ADDR, k: 0,
      trace_root: u.traceRoot, post_wit: u.wit, post_proof: merkle.getMerkleProof(u.trace, 0),
      leaf: adr, leaf_proof: u.leafProof(adr),
      left: u.post[u.post.indexOf(adr)], left_proof: u.leafProof(adr),
      right: u.post[u.post.indexOf(adr) + 1], right_proof: u.leafProof(u.post[u.post.indexOf(adr) + 1]),
    });
    await triggerVerdict(challenger, bindAa, mirrorPayload(liar), 20000, "P-mirror predicate");
    st = await vars(rollup);
    if (Number(st.frozen_41) !== 2) throw new Error("P-mirror: adr without adrx did not freeze h41");
    // already-bound: pre holds adrx:{DEP}:{OTHER}; a new adr:{PAYEE}:{DEP} → fraud.
    const OTHER = "R".repeat(32);
    const XPRE = [DEP_PRE, `adr:${OTHER}:${DEP_ACCT}`, `adrx:${DEP_ACCT}:${OTHER}`, META1].sort();
    const honest = oneUnit("r2-mirror-ok", "x:" + sha256Hex("mirror-ok"), [DEP_PRE, adr, adrx, META1]);
    await submitAt(41, Object.assign(honest, { witRoot: merkle.getMerkleRoot(XPRE) }));
    const hp = mirrorPayload(honest);
    await triggerBounce(challenger, bindAa, Object.assign(hp, {
      left: honest.post[honest.post.indexOf(adrx) - 1], left_proof: honest.leafProof(honest.post[honest.post.indexOf(adrx) - 1]),
      right: adrx, right_proof: honest.leafProof(adrx),
    }), 20000, "no fraud");
    const rebind = oneUnit("r2-rebind", `d:${DEP_ACCT}:100:${PAYEE}:${b6444("rb")}`, [adr, adrx, `acct:${DEP_ACCT}:1000100:0:0`]);
    await submitAt(42, rebind);
    const XW = merkle.getMerkleRoot(XPRE);
    // pre: adr:{PAYEE}: absent from XPRE (adjacent straddle) but DEP already bound (adrx member)
    const pi = XPRE.findIndex((l) => l > `adr:${PAYEE};`);
    await triggerVerdict(challenger, bindAa, {
      pred: "adr", height: 42, rollup: ROLLUP_ADDR, k: 0,
      op: rebind.op, ops_proof: merkle.getMerkleProof(rebind.ops, 0),
      trace_root: rebind.traceRoot, ops_root: rebind.opsRoot,
      pre_wit: XW, post_wit: rebind.wit, post_proof: merkle.getMerkleProof(rebind.trace, 0),
      post_leaf: adr, post_leaf_proof: rebind.leafProof(adr),
      left: XPRE[pi - 1], left_proof: merkle.getMerkleProof(XPRE, pi - 1),
      right: XPRE[pi], right_proof: merkle.getMerkleProof(XPRE, pi),
      xleaf: `adrx:${DEP_ACCT}:${OTHER}`, xleaf_proof: merkle.getMerkleProof(XPRE, XPRE.indexOf(`adrx:${DEP_ACCT}:${OTHER}`)),
    }, 20000, "R2-A-8 already-bound predicate");
    st = await vars(rollup);
    if (Number(st.frozen_42) !== 2) throw new Error("R2-A-8: second binding of a bound account did not freeze h42");
    await submitAt(42, Object.assign(oneUnit("r2-after", "x:" + sha256Hex("after"), [DEP_PRE]), {}));
    console.log("44. R2-A-8: adr without adrx → frozen; second address on a bound account → frozen");
  }

  // ---- 38. R2-A-1: wit_root must be the trace's last element (P-tip) -----
  {
    const u = oneUnit("r2-tip", "x:" + sha256Hex("tip"), [DEP_PRE]);
    await submitAt(43, u); // commits wit_root = WIT_ROOT != trace[0]
    const tipPayload = (proofIdx) => {
      const tp = merkle.getMerkleProof(u.trace, 0);
      if (proofIdx !== undefined) tp.index = proofIdx;
      return { pred: "tip", height: 43, rollup: ROLLUP_ADDR, tip: u.trace[0], tip_proof: tp };
    };
    await triggerBounce(challenger, bindAa, tipPayload(0.5), 20000, "bad tip proof");
    await triggerVerdict(challenger, bindAa, tipPayload(), 20000, "P-tip predicate");
    st = await vars(rollup);
    if (Number(st.frozen_43) !== 2) throw new Error("R2-A-1: wit_root off the trace tip did not freeze h43");
    await submitAt(43, Object.assign(u, { witRoot: u.wit }));
    await triggerBounce(challenger, bindAa, tipPayload(), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_43 || 0) !== 0) throw new Error("R2-A-1: honest tip froze h43!");
    if (Number(st.slash_burned || 0) <= 0) throw new Error("R2-A-9: slash_burned not accounted");
    console.log("38. R2-A-1: P-tip — wit_root off the trace tip → frozen; honest tip → 'no fraud'");
  }

  // ===================== ROUND 3 (fix/47-r3-aa) =========================
  // h44 re-anchors the k=0 pre tree on the genesis WIT_ROOT (h43 committed
  // its own post tree as wit_root).
  await submitAt(44, oneUnit("r3-commit", "x:" + sha256Hex("r3c"), [DEP_PRE]));
  const opA3 = await operator.getAddress();

  // ---- 46. R3-A-1: an ACCEPTED withdrawal never overdraws ----------------
  {
    const opW = `w:${DEP_ACCT}:2000000:1`;
    const over = `acct:${DEP_ACCT}:-1000000:0:2000000`; // balance 1000000
    const u = oneUnit("r3-over", opW, [over]);
    await submitAt(45, u);
    await triggerVerdict(challenger, dispute, Object.assign({ pred: "withdraw", height: 45 }, depositPayload(u, over)), 20000, "R3-A-1 overdraft P-withdraw predicate");
    st = await vars(rollup);
    if (Number(st.frozen_45) !== 2) throw new Error("R3-A-1: overdraft withdraw (P-withdraw) did not freeze h45");
    await submitAt(45, u);
    await triggerVerdict(challenger, bindAa, Object.assign({ pred: "wpin", height: 45 }, wpinPayload(u, over, {
      pre_leaf: DEP_PRE, pre_leaf_proof: genProof(DEP_PRE),
    })), 20000, "R3-A-1 overdraft P-wpin predicate");
    st = await vars(rollup);
    if (Number(st.frozen_45) !== 2) throw new Error("R3-A-1: overdraft withdraw (P-wpin) did not freeze h45");
    // Honest: withdrawing the WHOLE balance (col 0) is accepted by both.
    const fullOp = `w:${DEP_ACCT}:1000000:1`;
    const full = `acct:${DEP_ACCT}:0:0:1000000`;
    const ok = oneUnit("r3-full", fullOp, [full]);
    await submitAt(45, ok);
    await triggerBounce(challenger, dispute, Object.assign({ pred: "withdraw", height: 45 }, depositPayload(ok, full)), 20000, "no fraud");
    await triggerBounce(challenger, bindAa, Object.assign({ pred: "wpin", height: 45 }, wpinPayload(ok, full, {
      pre_leaf: DEP_PRE, pre_leaf_proof: genProof(DEP_PRE),
    })), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_45 || 0) !== 0) throw new Error("R3-A-1: honest full-balance withdraw froze h45!");
    // A pre-absent account can only have its withdrawal REJECTED.
    const F = "1f".repeat(32);
    const fOp = `w:${F}:100:1`;
    const fLeaf = `acct:${F}:-100:0:100`;
    const fu = oneUnit("r3-absent-w", fOp, [fLeaf]);
    await submitAt(46, fu);
    await triggerVerdict(challenger, dispute, Object.assign({ pred: "withdraw", height: 46 }, depositPayload(fu, fLeaf), {
      pre_absent: true, left: GENESIS_LEAVES[0], left_proof: genProof(GENESIS_LEAVES[0]),
    }), 20000, "R3-A-1 pre-absent withdraw predicate");
    st = await vars(rollup);
    if (Number(st.frozen_46) !== 2) throw new Error("R3-A-1: accepted withdraw on a pre-absent account did not freeze h46");
    await submitAt(46, oneUnit("r3-absent-ok", fOp, [DEP_PRE]));
    console.log("46. R3-A-1: overdraft (P-withdraw + P-wpin) and pre-absent accepted withdraw → frozen; full-balance withdraw → 'no fraud'");
  }

  // ---- 47. R3-A-2: P-escrow judges only `acct:` leaves --------------------
  {
    const OID = "9".repeat(63) + "e";
    const PAYEE = "Q".repeat(32);
    const ESC_ORD = `ord:${OID}:1:0:100000000:3:5:${DEP_ACCT}:1:20`;
    const ADR = `adr:${PAYEE}:${DEP_ACCT}`;
    const ADRX = `adrx:${DEP_ACCT}:${PAYEE}`;
    const ESC_PRE = [DEP_PRE, ESC_ORD, ADR, ADRX, META1].sort();
    const ESC_WIT = merkle.getMerkleRoot(ESC_PRE);
    await submitAt(47, Object.assign(oneUnit("r3-esc-commit", "x:" + sha256Hex("escc"), [DEP_PRE]), { witRoot: ESC_WIT }));
    const cOp = `c:${DEP_ACCT}:${OID}`;
    const escPayload = (u, postLeaf) => ({
      rollup: ROLLUP_ADDR, k: 0, op: u.op, ops_proof: merkle.getMerkleProof(u.ops, 0),
      trace_root: u.traceRoot, ops_root: u.opsRoot, units_root: UNITS_SET_ROOT,
      units_set_root: SET_ROOT1, fills_root: FILLS_ROOT,
      pre_wit: ESC_WIT, post_wit: u.wit, post_proof: merkle.getMerkleProof(u.trace, 0),
      pre_leaf: DEP_PRE, pre_leaf_proof: merkle.getMerkleProof(ESC_PRE, ESC_PRE.indexOf(DEP_PRE)),
      post_leaf: postLeaf, post_leaf_proof: u.leafProof(postLeaf),
      pre_ord: ESC_ORD, pre_ord_proof: merkle.getMerkleProof(ESC_PRE, ESC_PRE.indexOf(ESC_ORD)),
    });
    const refunded = `acct:${DEP_ACCT}:1000020:0:0`;
    const liarLeaf = `acct:${DEP_ACCT}:1000021:0:0`;
    const liar = oneUnit("r3-esc-liar", cOp, [liarLeaf, ADR, ADRX, META1]);
    await submitAt(48, liar);
    await triggerVerdict(challenger, dispute, Object.assign({ pred: "escrow", height: 48 }, escPayload(liar, liarLeaf)), 20000, "escrow liar predicate");
    st = await vars(rollup);
    if (Number(st.frozen_48) !== 2) throw new Error("escrow: wrong refund did not freeze h48");
    const honest = oneUnit("r3-esc", cOp, [refunded, ADR, ADRX, META1]);
    await submitAt(48, honest);
    // Pre-fix: adrx:{acct}:{addr} as post_leaf parsed col1 = '' → verdict.
    await triggerBounce(challenger, dispute, Object.assign({ pred: "escrow", height: 48 }, escPayload(honest, ADRX)), 20000, "bad leaf");
    await triggerBounce(challenger, dispute, Object.assign({ pred: "escrow", height: 48 }, escPayload(honest, refunded)), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_48 || 0) !== 0) throw new Error("R3-A-2: honest cancel slashed via adrx leaf!");
    console.log("47. R3-A-2: adrx post leaf on an honest cancel bounces 'bad leaf'; wrong refund → frozen");
  }

  // ---- 48. R3-A-4/5: a credit must go to the payer's account + binding ----
  {
    const dep3 = (await trigger(operator, vault, { deposit: 1, account: DEP_ACCT }, 60000)).unit; // 50000 for DEP_ACCT
    const MARK3 = "dep:" + dep3;
    // (a) the operator credits the payment to ANOTHER account (FILL_TAKER).
    const thiefLeaf = `acct:${FILL_TAKER}:50000:0:0`;
    const tOp = `d:${FILL_TAKER}:50000:${opA3}:${dep3}`;
    const tU = oneUnit("r3-thief", tOp, [thiefLeaf, MARK3, `adr:${opA3}:${FILL_TAKER}`, `adrx:${FILL_TAKER}:${opA3}`]);
    await submitAt(49, tU);
    await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 49 }, depositPayload(tU, thiefLeaf), {
      pre_leaf: FILL_TAKER_PRE, pre_leaf_proof: genProof(FILL_TAKER_PRE),
    }), 20000, "R3-A-4/5 foreign-account credit predicate");
    st = await vars(rollup);
    if (Number(st.frozen_49) !== 2) throw new Error("R3-A-4/5: credit to a non-designated account did not freeze h49");
    // (b) backed + marked, but the payer is not bound to the account.
    const credited = `acct:${DEP_ACCT}:1050000:0:0`;
    const gOp = `d:${DEP_ACCT}:50000:${opA3}:${dep3}`;
    const ak = `adr:${opA3}:${DEP_ACCT}`;
    const nb = oneUnit("r3-noadr", gOp, [credited, MARK3]);
    await submitAt(49, nb);
    if (!(nb.post[0] < ak && ak < nb.post[1])) throw new Error("fixture: noadr straddle");
    await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 49 }, depositPayload(nb, credited), {
      aleft: nb.post[0], aleft_proof: nb.leafProof(nb.post[0]),
      aright: nb.post[1], aright_proof: nb.leafProof(nb.post[1]),
    }), 20000, "R3-A-4 unbound-address credit predicate");
    st = await vars(rollup);
    if (Number(st.frozen_49) !== 2) throw new Error("R3-A-4: credit without the adr binding did not freeze h49");
    // (c) honest: designated account, binding present → no fake absence.
    const good = oneUnit("r3-good", gOp, [credited, MARK3, ak, `adrx:${DEP_ACCT}:${opA3}`]);
    await submitAt(49, good);
    await triggerBounce(challenger, dispute, Object.assign({ pred: "deposit", height: 49 }, depositPayload(good, credited), {
      aleft: credited, aleft_proof: good.leafProof(credited),
      aright: ak, aright_proof: good.leafProof(ak),
    }), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_49 || 0) !== 0) throw new Error("R3-A-4/5: honest designated credit froze h49!");
    console.log("48. R3-A-4/5: foreign-account credit / unbound payer → frozen; designated + bound → 'no fraud'");
  }

  // ---- 49. R3-A-7: a credited PERP deposit (D:) must be vault-backed ------
  {
    const leaf = `acct:${DEP_ACCT}:1000000:50000:0`;
    const ghost = b6444("never-paid-perp");
    const cases = [
      ["unbacked", `D:${DEP_ACCT}:50000:${opA3}:${ghost}`, ghost],
      ["cross-kind", `D:${DEP_ACCT}:50000:${opA3}:${dep2}`, dep2], // a BASE anchor (dep_, no depp_)
    ];
    for (const [tag, op, anchor] of cases) {
      const u = oneUnit("r3-perp-" + tag, op, [leaf, "dep:" + anchor, `adr:${opA3}:${DEP_ACCT}`, `adrx:${DEP_ACCT}:${opA3}`]);
      await submitAt(50, u);
      await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 50 }, depositPayload(u, leaf)), 20000, "R3-A-7 " + tag + " predicate");
      st = await vars(rollup);
      if (Number(st.frozen_50) !== 2) throw new Error("R3-A-7: " + tag + " PERP credit did not freeze h50");
    }
    const okU = oneUnit("r3-perp-ok", govOp, [leaf, "dep:" + govUnit, `adr:${opA3}:${DEP_ACCT}`, `adrx:${DEP_ACCT}:${opA3}`]);
    await submitAt(50, okU);
    await triggerBounce(challenger, dispute, Object.assign({ pred: "deposit", height: 50 }, depositPayload(okU, leaf)), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_50 || 0) !== 0) throw new Error("R3-A-7: honest backed PERP deposit froze h50!");
    console.log("49. R3-A-7: unbacked / cross-kind D: credit → frozen; depp_-backed D: → 'no fraud'");
  }

  // ---- 50. R3-A-6: an account leaf never vanishes (P-keep acct:) ---------
  {
    const drop = oneUnit("r3-keep-acct", "x:" + sha256Hex("keepacct"), [FILL_TAKER_PRE, META1]);
    await submitAt(51, drop);
    const hi = `acct:${DEP_ACCT};`;
    if (!(hi <= drop.post[0])) throw new Error("fixture: keep-acct before-min");
    const keepPayload = (u, left) => ({
      pred: "keep", height: 51, rollup: ROLLUP_ADDR, k: 0,
      trace_root: u.traceRoot, pre_wit: WIT_ROOT, post_wit: u.wit,
      post_proof: merkle.getMerkleProof(u.trace, 0),
      leaf: DEP_PRE, leaf_proof: genProof(DEP_PRE),
      left, left_proof: u.leafProof(left),
    });
    await triggerVerdict(challenger, bindAa, keepPayload(drop, drop.post[0]), 20000, "R3-A-6 P-keep acct predicate");
    st = await vars(rollup);
    if (Number(st.frozen_51) !== 2) throw new Error("R3-A-6: dropped account leaf did not freeze h51");
    // Honest: the account changed but is still there → no absence proof.
    const keptLeaf = `acct:${DEP_ACCT}:999:0:0`;
    const kept = oneUnit("r3-keep-ok", "x:" + sha256Hex("keepok"), [keptLeaf, FILL_TAKER_PRE, META1]);
    await submitAt(51, kept);
    await triggerBounce(challenger, bindAa, keepPayload(kept, kept.post[0]), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_51 || 0) !== 0) throw new Error("R3-A-6: honest changed account froze h51!");
    console.log("50. R3-A-6: account leaf dropped from the post tree → frozen; changed-but-present → 'no fraud'");
  }

  // ---- 51. R3-A-3: an honest fill whose Oscript math rounds 1 off --------
  // qty 10001 x price 999900009999 = 2e16*500 - 1 exactly: ocore's
  // 15-digit product rounds it UP, so the AA's notional/fee is 500 where
  // the engine's exact i128 fee is 499 (honest post col 1000000 - 499).
  // Pre-fix the exact identity verdicted this honest height.
  {
    const Q = 10001;
    const P = 999900009999;
    const rFill = `f:${isoUnit}:0:${DEP_ACCT}:${"c".repeat(64)}:${"6".repeat(64)}:${isoMOrd}:1:${P}:${Q}:9:0:0:0`;
    const R_TREE = fillsTree([rFill]);
    const rOp = `p:${DEP_ACCT}:1:0:${P}:${Q}:0:0:0:0`;
    const rPos = `pos:${DEP_ACCT}:1:${Q}:${P}:0:0`;
    const rPayload = (u, col) => {
      const acctLeaf = `acct:${DEP_ACCT}:${col}:0:0`;
      return {
        pred: "fill_math", height: 52, rollup: ROLLUP_ADDR, k: 0,
        trace_root: u.traceRoot, fills_root: merkle.getMerkleRoot(R_TREE), ops_root: u.opsRoot,
        units_root: ISO_UNITS_ROOT, units_proof: ISO_UNITS_PROOF,
        fill: rFill, fill_proof: merkle.getMerkleProof(R_TREE, 0),
        right: R_TREE[1], right_proof: merkle.getMerkleProof(R_TREE, 1),
        op: u.op, ops_proof: merkle.getMerkleProof(u.ops, 0),
        pre_wit: WIT_ROOT, post_wit: u.wit, post_proof: merkle.getMerkleProof(u.trace, 0),
        pre_acct: DEP_PRE, pre_acct_proof: genProof(DEP_PRE),
        post_acct: acctLeaf, post_acct_proof: u.leafProof(acctLeaf),
        post_pos: rPos, post_pos_proof: u.leafProof(rPos),
        pre_meta: META1, pre_meta_proof: genProof(META1),
        pos_absent: true,
        pleft: META2, pleft_proof: genProof(META2),
        pright: POS2, pright_proof: genProof(POS2),
        cp_acct: CP_LEAF, cp_acct_proof: u.leafProof(CP_LEAF),
        who: "taker",
      };
    };
    const mk = (tag, col) => Object.assign(oneUnit(tag, rOp, [`acct:${DEP_ACCT}:${col}:0:0`, CP_LEAF, META1, rPos]), {
      unitsRoot: ISO_UNITS_ROOT, fillsRoot: merkle.getMerkleRoot(R_TREE), fillCount: 1,
    });
    const liar = mk("r3-round-liar", 999401); // 100 below the identity
    await submitAt(52, liar);
    await triggerVerdict(challenger, fill, rPayload(liar, 999401), 20000, "R3-A-3 liar fill predicate");
    st = await vars(rollup);
    if (Number(st.frozen_52) !== 2) throw new Error("R3-A-3: a real collateral lie on the crafted fill did not freeze h52");
    const honest = mk("r3-round", 999501);
    await submitAt(52, honest);
    await triggerBounce(challenger, fill, rPayload(honest, 999501), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_52 || 0) !== 0) throw new Error("R3-A-3: honest fill slashed on Oscript rounding!");
    console.log("51. R3-A-3: honest fill with a 15-digit rounding (AA fee 500, engine 499) → 'no fraud'; real lie → frozen");
  }

  // ===================== ROUND 4 (fix/47-r4-aa) =========================
  // Exact non-membership helper over a sorted tree: adjacent straddle or
  // before-min (the shapes P-frame / P-keep accept).
  const absentIn = (tree, leaf) => {
    const i = tree.findIndex((l) => l > leaf);
    if (i < 0) throw new Error("fixture: no right neighbour for " + leaf);
    if (tree.includes(leaf)) throw new Error("fixture: leaf present " + leaf);
    return i === 0
      ? { left: tree[0], left_proof: merkle.getMerkleProof(tree, 0) }
      : {
          left: tree[i - 1], left_proof: merkle.getMerkleProof(tree, i - 1),
          right: tree[i], right_proof: merkle.getMerkleProof(tree, i),
        };
  };
  // R7b-N2: P-frame's acct: arm lives in the x-frame AA (P-xframe) for
  // c:/d:/D:/w:/W:/p:/L: units — pre/post pair of one account.
  const xfNx = (h, u, preTree, preWit, a, extra) => {
    const post = u.post.find((l) => l.startsWith(`acct:${a}:`));
    if (!post) throw new Error("fixture: no post acct leaf of " + a);
    const pre = preTree.find((l) => l.startsWith(`acct:${a}:`));
    const d = {
      pred: "xframe", height: h, rollup: ROLLUP_ADDR, k: 0, trace_root: u.traceRoot, ops_root: u.opsRoot,
      units_root: u.unitsRoot || UNITS_SET_ROOT, op: u.op, ops_proof: merkle.getMerkleProof(u.ops, 0),
      pre_wit: preWit, post_wit: u.wit, post_proof: merkle.getMerkleProof(u.trace, 0),
      post_acct: post, post_acct_proof: u.leafProof(post),
    };
    if (pre) Object.assign(d, { pre_acct: pre, pre_acct_proof: merkle.getMerkleProof(preTree, preTree.indexOf(pre)) });
    else Object.assign(d, absentIn(preTree, `acct:${a}:`));
    return Object.assign(d, extra || {});
  };
  const opA4 = await operator.getAddress();

  // ---- 52. R4-A-1: a fill must be its maker order (P-mbind, book AA) ------
  {
    // h53 commits a pre tree holding FILL_TAKER's resting ask O_B
    // (market 1, price 1e8, remaining 5e7).
    const OB = "4b".repeat(32);
    const ORD_B = `ord:${OB}:1:1:100000000:3:50000000:${FILL_TAKER}:0:0`;
    const MB_PRE = GENESIS_LEAVES.concat([ORD_B]).sort();
    const MB_WIT = merkle.getMerkleRoot(MB_PRE);
    await submitAt(53, Object.assign(oneUnit("r4-mb-commit", "x:" + sha256Hex("mbc"), [DEP_PRE]), { witRoot: MB_WIT }));
    // f:{unit}:{idx}:{taker}:{maker}:{t_ord}:{m_ord}:{mkt}:{price}:{qty}:{seq}:{side}:{kind}:{tpost}
    const mkFill = (maker, price, qty, side) =>
      `f:${isoUnit}:0:${DEP_ACCT}:${maker}:${"5".repeat(64)}:${OB}:1:${price}:${qty}:9:${side}:0:0`;
    const mbUnit = (tag, f) => {
      const tree = fillsTree([f]);
      return Object.assign(oneUnit(tag, `p:${DEP_ACCT}:1:0:100000000:50000000:0:0:1:0`, [DEP_PRE]), {
        unitsRoot: ISO_UNITS_ROOT, fillsRoot: merkle.getMerkleRoot(tree), fillCount: 1, tree,
      });
    };
    const mbPayload = (u, f) => ({
      pred: "mbind", height: 54, rollup: ROLLUP_ADDR, k: 0,
      trace_root: u.traceRoot, fills_root: u.fillsRoot, units_root: ISO_UNITS_ROOT,
      units_proof: ISO_UNITS_PROOF, fill: f, fill_proof: merkle.getMerkleProof(u.tree, 0),
      pre_wit: MB_WIT, maker_ord: ORD_B, maker_ord_proof: merkle.getMerkleProof(MB_PRE, MB_PRE.indexOf(ORD_B)),
    });
    const liars = [
      ["owner", mkFill(FILL_TAKER.replace(/b/g, "c"), 100000000, 50000000, 0)], // victim as maker
      ["price", mkFill(FILL_TAKER, 100000000000000, 50000000, 0)],               // arbitrary price
      ["qty", mkFill(FILL_TAKER, 100000000, 50000001, 0)],                       // beyond remaining
      ["side", mkFill(FILL_TAKER, 100000000, 50000000, 1)],                      // maker's own side
    ];
    for (const [tag, f] of liars) {
      const u = mbUnit("r4-mb-" + tag, f);
      await submitAt(54, u);
      await triggerVerdict(challenger, book, mbPayload(u, f), 20000, "R4-A-1 " + tag + " mbind predicate");
      st = await vars(rollup);
      if (Number(st.frozen_54) !== 2) throw new Error("R4-A-1: " + tag + " fill off its maker order did not freeze h54");
    }
    const okF = mkFill(FILL_TAKER, 100000000, 50000000, 0);
    const okU = mbUnit("r4-mb-ok", okF);
    await submitAt(54, okU);
    await triggerBounce(challenger, book, mbPayload(okU, okF), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_54 || 0) !== 0) throw new Error("R4-A-1: honest fill froze h54!");
    console.log("52. R4-A-1: fill with foreign owner / off price / qty > remaining / same side → frozen; matching fill → 'no fraud'");
  }

  // ---- 53. R4-A-3: positions/orders frozen across c:/d:/w: (P-frame) -----
  {
    const OV = "6a".repeat(32); // DEP_ACCT's own order (the c: target)
    const OX = "6b".repeat(32); // FILL_TAKER's order (never touched)
    const ORD_V = `ord:${OV}:1:0:90000000:4:10:${DEP_ACCT}:0:0`;
    const ORD_X = `ord:${OX}:1:1:110000000:5:10:${FILL_TAKER}:0:0`;
    // Real witness trees end with the `~:end` max sentinel (R2-A-10).
    const FR_PRE = GENESIS_LEAVES.concat([ORD_V, ORD_X, "~:end"]).sort();
    const FR_WIT = merkle.getMerkleRoot(FR_PRE);
    await submitAt(55, Object.assign(oneUnit("r4-fr-commit", "x:" + sha256Hex("frc"), [DEP_PRE]), { witRoot: FR_WIT }));
    const cOp = `c:${DEP_ACCT}:${OV}`;
    const base = FR_PRE.filter((l) => l !== ORD_V); // honest post: own order cancelled
    const frPayload = (u, leaf, ins) => Object.assign({
      pred: "frame", height: 56, rollup: ROLLUP_ADDR, k: 0,
      trace_root: u.traceRoot, ops_root: u.opsRoot, op: u.op, ops_proof: merkle.getMerkleProof(u.ops, 0),
      pre_wit: FR_WIT, post_wit: u.wit, post_proof: merkle.getMerkleProof(u.trace, 0),
      leaf, ins,
      leaf_proof: ins ? u.leafProof(leaf) : merkle.getMerkleProof(FR_PRE, FR_PRE.indexOf(leaf)),
    }, absentIn(ins ? FR_PRE : u.post, leaf));
    // (a) entry of FILL_TAKER's position rewritten (1e7x) under a cancel.
    const POS2_FAKE = `pos:${FILL_TAKER}:2:50000000:900000000000000:0:0`;
    const a = oneUnit("r4-fr-entry", cOp, base.filter((l) => l !== POS2).concat([POS2_FAKE]));
    await submitAt(56, a);
    await triggerVerdict(challenger, bindAa, frPayload(a, POS2, false), 20000, "R4-A-3 rewritten pos frame predicate");
    st = await vars(rollup);
    if (Number(st.frozen_56) !== 2) throw new Error("R4-A-3: rewritten position did not freeze h56");
    // (b) a foreign order deleted by someone else's cancel.
    const b = oneUnit("r4-fr-del", cOp, base.filter((l) => l !== ORD_X));
    await submitAt(56, b);
    await triggerVerdict(challenger, bindAa, frPayload(b, ORD_X, false), 20000, "R4-A-3 deleted order frame predicate");
    st = await vars(rollup);
    if (Number(st.frozen_56) !== 2) throw new Error("R4-A-3: deleted foreign order did not freeze h56");
    // (c) a fake order of the victim inserted (the R4-A-1 bypass).
    const FAKE = `ord:${"6c".repeat(32)}:1:0:100000000000000:6:100000000:${DEP_ACCT}:0:0`;
    const c = oneUnit("r4-fr-ins", cOp, base.concat([FAKE]));
    await submitAt(56, c);
    await triggerVerdict(challenger, bindAa, frPayload(c, FAKE, true), 20000, "R4-A-3 inserted order frame predicate");
    st = await vars(rollup);
    if (Number(st.frozen_56) !== 2) throw new Error("R4-A-3: inserted order did not freeze h56");
    // Honest: the cancel removes exactly its own order.
    const ok = oneUnit("r4-fr-ok", cOp, base);
    await submitAt(56, ok);
    await triggerBounce(challenger, bindAa, frPayload(ok, ORD_V, false), 20000, "no fraud");
    // An untouched leaf cannot be proven absent (its neighbours do not straddle).
    const pi = ok.post.indexOf(POS2);
    await triggerBounce(challenger, bindAa, Object.assign(frPayload(ok, ORD_V, false), {
      leaf: POS2, leaf_proof: merkle.getMerkleProof(FR_PRE, FR_PRE.indexOf(POS2)),
      left: ok.post[pi - 1], left_proof: ok.leafProof(ok.post[pi - 1]),
      right: ok.post[pi], right_proof: ok.leafProof(ok.post[pi]),
    }), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_56 || 0) !== 0) throw new Error("R4-A-3: honest cancel froze h56!");
    console.log("53. R4-A-3: pos rewritten / foreign order deleted / fake order inserted under c: → frozen; own-order cancel → 'no fraud'");
  }

  // ---- 54. R4-A-4: a new binding needs a vault-backed deposit (P-adr) ----
  {
    const depV = (await trigger(operator, vault, { deposit: 1, account: DEP_ACCT }, 60000)).unit; // 50000 FOR DEP_ACCT
    const adr = (x) => `adr:${opA4}:${x}`;
    const li = GENESIS_LEAVES.indexOf(FILL_TAKER_PRE);
    if (GENESIS_LEAVES[li + 1] !== META1 || !(FILL_TAKER_PRE < `adr:${opA4}:` && `adr:${opA4};` <= META1))
      throw new Error("fixture: adr straddle");
    const adrPayload = (u, x) => ({
      pred: "adr", height: 57, rollup: ROLLUP_ADDR, k: 0,
      op: u.op, ops_proof: merkle.getMerkleProof(u.ops, 0),
      trace_root: u.traceRoot, ops_root: u.opsRoot,
      pre_wit: WIT_ROOT, post_wit: u.wit, post_proof: merkle.getMerkleProof(u.trace, 0),
      post_leaf: adr(x), post_leaf_proof: u.leafProof(adr(x)),
      left: FILL_TAKER_PRE, left_proof: genProof(FILL_TAKER_PRE),
      right: META1, right_proof: genProof(META1),
    });
    const liars = [
      // the payer designated DEP_ACCT; the operator binds it to FILL_TAKER
      // (rejected deposit, collateral unchanged — R4-A-4's exploit).
      ["foreign", `d:${FILL_TAKER}:50000:${opA4}:${depV}`, FILL_TAKER],
      ["unbacked", `d:${DEP_ACCT}:50000:${opA4}:${b6444("never-paid-adr")}`, DEP_ACCT],
      ["cross-kind", `D:${DEP_ACCT}:50000:${opA4}:${depV}`, DEP_ACCT], // dep_ only, no depp_
    ];
    for (const [tag, op, x] of liars) {
      const u = oneUnit("r4-adr-" + tag, op, [adr(x), `adrx:${x}:${opA4}`, DEP_PRE, FILL_TAKER_PRE]);
      await submitAt(57, u);
      await triggerVerdict(challenger, bindAa, adrPayload(u, x), 20000, "R4-A-4 " + tag + " adr predicate");
      st = await vars(rollup);
      if (Number(st.frozen_57) !== 2) throw new Error("R4-A-4: " + tag + " binding did not freeze h57");
    }
    const okU = oneUnit("r4-adr-ok", `d:${DEP_ACCT}:50000:${opA4}:${depV}`,
      [adr(DEP_ACCT), `adrx:${DEP_ACCT}:${opA4}`, `acct:${DEP_ACCT}:1050000:0:0`, "dep:" + depV, FILL_TAKER_PRE]);
    await submitAt(57, okU);
    await triggerBounce(challenger, bindAa, adrPayload(okU, DEP_ACCT), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_57 || 0) !== 0) throw new Error("R4-A-4: honest backed binding froze h57!");
    console.log("54. R4-A-4: binding to a non-designated account / unbacked / cross-kind anchor → frozen; backed binding → 'no fraud'");
  }

  // ---- 55. R4-A-5: the near-zero collateral gate keeps the position leg --
  {
    // FILL_TAKER (pre col 0) buys 1e8 @ 1e8 on market 1: fill-stage
    // collateral 0 - 500 fee < 6 → the collateral leg is skipped, but the
    // position leg must still be judged (pre-fix: whole predicate bounced).
    const tOrd = "8".repeat(64);
    const f = `f:${isoUnit}:0:${FILL_TAKER}:${"c".repeat(64)}:${tOrd}:${isoMOrd}:1:100000000:100000000:9:0:0:0`;
    const tree = fillsTree([f]);
    const op = `p:${FILL_TAKER}:1:0:100000000:100000000:0:0:0:0`;
    const acctLeaf = `acct:${FILL_TAKER}:-500:0:0`;
    const mk = (tag, posLeaf) => Object.assign(oneUnit(tag, op, [acctLeaf, CP_LEAF, META1, posLeaf, POS2]), {
      unitsRoot: ISO_UNITS_ROOT, fillsRoot: merkle.getMerkleRoot(tree), fillCount: 1,
    });
    const payload = (u, posLeaf) => ({
      pred: "fill_math", height: 58, rollup: ROLLUP_ADDR, k: 0,
      trace_root: u.traceRoot, fills_root: u.fillsRoot, ops_root: u.opsRoot,
      units_root: ISO_UNITS_ROOT, units_proof: ISO_UNITS_PROOF,
      fill: f, fill_proof: merkle.getMerkleProof(tree, 0),
      right: tree[1], right_proof: merkle.getMerkleProof(tree, 1),
      op: u.op, ops_proof: merkle.getMerkleProof(u.ops, 0),
      pre_wit: WIT_ROOT, post_wit: u.wit, post_proof: merkle.getMerkleProof(u.trace, 0),
      pre_acct: FILL_TAKER_PRE, pre_acct_proof: genProof(FILL_TAKER_PRE),
      post_acct: acctLeaf, post_acct_proof: u.leafProof(acctLeaf),
      post_pos: posLeaf, post_pos_proof: u.leafProof(posLeaf),
      pre_meta: META1, pre_meta_proof: genProof(META1),
      pos_absent: true,
      pleft: META2, pleft_proof: genProof(META2),
      pright: POS2, pright_proof: genProof(POS2),
      cp_acct: CP_LEAF, cp_acct_proof: u.leafProof(CP_LEAF),
      who: "taker",
    });
    const liarPos = `pos:${FILL_TAKER}:1:200000000:100000000:0:0`; // double qty
    const liar = mk("r4-a5-liar", liarPos);
    await submitAt(58, liar);
    await triggerVerdict(challenger, fill, payload(liar, liarPos), 20000, "R4-A-5 position leg under the collateral gate");
    st = await vars(rollup);
    if (Number(st.frozen_58) !== 2) throw new Error("R4-A-5: position lie under the near-zero collateral gate did not freeze h58");
    const okPos = `pos:${FILL_TAKER}:1:100000000:100000000:0:0`;
    const okU = mk("r4-a5-ok", okPos);
    await submitAt(58, okU);
    await triggerBounce(challenger, fill, payload(okU, okPos), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_58 || 0) !== 0) throw new Error("R4-A-5: honest near-zero fill froze h58!");
    console.log("55. R4-A-5: position lie with collateral gated (fill-stage < 6) → frozen; honest → 'no fraud'");
  }

  // ---- 56. R4-A-6: PERP column within the engine's < 1e14 supply cap -----
  {
    const P0 = "99999999999990"; // 14 digits
    const PP_PRE = [`acct:${DEP_ACCT}:1000000:${P0}:0`, META1].sort();
    const PP_WIT = merkle.getMerkleRoot(PP_PRE);
    await submitAt(59, Object.assign(oneUnit("r4-pp-commit", "x:" + sha256Hex("ppc"), [DEP_PRE]), { witRoot: PP_WIT }));
    const op = `D:${DEP_ACCT}:10:${opA4}:${govUnit}`;
    const ppPayload = (u, leaf) => Object.assign({ pred: "deposit", height: 60 }, depositPayload(u, leaf), {
      pre_wit: PP_WIT, pre_leaf: PP_PRE[PP_PRE.indexOf(`acct:${DEP_ACCT}:1000000:${P0}:0`)],
      pre_leaf_proof: merkle.getMerkleProof(PP_PRE, PP_PRE.indexOf(`acct:${DEP_ACCT}:1000000:${P0}:0`)),
    });
    // Liar: lifts the PERP column to 1e14 (past the engine cap; numerically
    // P0 + 10) — the engine rejects that deposit, so the AA must not accept
    // the arithmetic.
    const big = `acct:${DEP_ACCT}:1000000:100000000000000:0`;
    const liar = oneUnit("r4-pp-liar", op, [big, META1]);
    await submitAt(60, liar);
    await triggerVerdict(challenger, dispute, ppPayload(liar, big), 20000, "R4-A-6 PERP past the cap");
    st = await vars(rollup);
    if (Number(st.frozen_60) !== 2) throw new Error("R4-A-6: PERP column past the supply cap did not freeze h60");
    // Honest: the over-cap deposit is REJECTED — column unchanged.
    const same = `acct:${DEP_ACCT}:1000000:${P0}:0`;
    const okU = oneUnit("r4-pp-ok", op, [same, META1]);
    await submitAt(60, okU);
    await triggerBounce(challenger, dispute, ppPayload(okU, same), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_60 || 0) !== 0) throw new Error("R4-A-6: honest rejected over-cap deposit froze h60!");
    console.log("56. R4-A-6: PERP column lifted past the < 1e14 cap → frozen; rejected (unchanged) → 'no fraud'");
  }

  // ===================== ROUND 5 (fix/47-r5-aa) =========================
  // ---- 57. R5-A-1: foreign acct leaves frozen across c:/d:/w: (P-xframe since R7b-N2) --
  {
    const xframe57 = network.agent.xframe;
    const frPayload5 = (u, leaf, ins) => Object.assign({
      pred: "frame", height: 61, rollup: ROLLUP_ADDR, k: 0,
      trace_root: u.traceRoot, ops_root: u.opsRoot, op: u.op, ops_proof: merkle.getMerkleProof(u.ops, 0),
      pre_wit: WIT_ROOT, post_wit: u.wit, post_proof: merkle.getMerkleProof(u.trace, 0),
      leaf, ins,
      leaf_proof: ins ? u.leafProof(leaf) : genProof(leaf),
    }, absentIn(ins ? GENESIS_LEAVES : u.post, leaf));
    const keep = GENESIS_LEAVES.filter((l) => l !== FILL_TAKER_PRE && l !== DEP_PRE);
    // (a) c: — the victim FILL_TAKER's collateral rewritten (0 → 777).
    const cOp = `c:${DEP_ACCT}:${"6a".repeat(32)}`;
    const a = oneUnit("r5-fr-col", cOp, keep.concat([DEP_PRE, `acct:${FILL_TAKER}:777:0:0`]));
    await submitAt(61, a);
    await triggerBounce(challenger, bindAa, frPayload5(a, FILL_TAKER_PRE, false), 20000, "bad leaf");
    await triggerVerdict(challenger, xframe57, xfNx(61, a, GENESIS_LEAVES, WIT_ROOT, FILL_TAKER), 20000, "R5-A-1 foreign collateral under c: (P-xframe)");
    st = await vars(rollup);
    if (Number(st.frozen_61) !== 2) throw new Error("R5-A-1: foreign collateral change under c: did not freeze h61");
    // (b) d: — a third party's PERP column changed.
    const dOp = `d:${DEP_ACCT}:50000:${opA4}:${b6444("r5-frame-dep")}`;
    const pLeaf = `acct:${FILL_TAKER}:0:5:0`;
    const b = oneUnit("r5-fr-perp", dOp, keep.concat([`acct:${DEP_ACCT}:1050000:0:0`, pLeaf]));
    await submitAt(61, b);
    await triggerVerdict(challenger, xframe57, xfNx(61, b, GENESIS_LEAVES, WIT_ROOT, FILL_TAKER), 20000, "R5-A-1 foreign PERP under d: (P-xframe)");
    st = await vars(rollup);
    if (Number(st.frozen_61) !== 2) throw new Error("R5-A-1: foreign PERP change under d: did not freeze h61");
    // (c) w: — a fabricated third account credited (before-min absence).
    const wOp = `w:${DEP_ACCT}:100:1`;
    const fake = `acct:${"8f".repeat(32)}:5000:0:0`;
    const c = oneUnit("r5-fr-ins", wOp, GENESIS_LEAVES.concat([fake]));
    await submitAt(61, c);
    await triggerVerdict(challenger, xframe57, xfNx(61, c, GENESIS_LEAVES, WIT_ROOT, "8f".repeat(32)), 20000, "R5-A-1 fabricated account under w: (P-xframe)");
    st = await vars(rollup);
    if (Number(st.frozen_61) !== 2) throw new Error("R5-A-1: fabricated account under w: did not freeze h61");
    // Honest: the op account's OWN leaf may change (P-deposit / P-escrow
    // judge it) and an untouched foreign leaf cannot be proven absent.
    const ownLeaf = `acct:${DEP_ACCT}:1000001:0:0`;
    const ok = oneUnit("r5-fr-ok", cOp, keep.concat([ownLeaf, FILL_TAKER_PRE]));
    await submitAt(61, ok);
    await triggerBounce(challenger, xframe57, xfNx(61, ok, GENESIS_LEAVES, WIT_ROOT, DEP_ACCT), 20000, "no fraud");
    await triggerBounce(challenger, xframe57, xfNx(61, ok, GENESIS_LEAVES, WIT_ROOT, FILL_TAKER), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_61 || 0) !== 0) throw new Error("R5-A-1: honest own-account change froze h61!");
    console.log("57. R5-A-1: foreign collateral (c:) / foreign PERP (d:) / fabricated account (w:) → frozen; own account → 'no fraud'");
  }

  // ---- 58. R5-A-2: collateral skips no longer operator-triggerable ------
  {
    // (a) zero-balance taker, cross Place the engine rejects (no IM), fake
    // fill minting 1e12 to the taker: fill-stage -500 used to skip the
    // collateral leg; the claw range caps it at 0.
    const tOrd = "8".repeat(64);
    const f = `f:${isoUnit}:0:${FILL_TAKER}:${"c".repeat(64)}:${tOrd}:${isoMOrd}:1:100000000:100000000:9:0:0:0`;
    const tree = fillsTree([f]);
    const op = `p:${FILL_TAKER}:1:0:100000000:100000000:0:0:0:0`;
    const posLeaf = `pos:${FILL_TAKER}:1:100000000:100000000:0:0`;
    const mintLeaf = `acct:${FILL_TAKER}:1000000000000:0:0`;
    const mk = (tag, acctLeaf) => Object.assign(oneUnit(tag, op, [acctLeaf, CP_LEAF, META1, posLeaf, POS2]), {
      unitsRoot: ISO_UNITS_ROOT, fillsRoot: merkle.getMerkleRoot(tree), fillCount: 1,
    });
    const fmPayload = (u, acctLeaf) => ({
      pred: "fill_math", height: 62, rollup: ROLLUP_ADDR, k: 0,
      trace_root: u.traceRoot, fills_root: u.fillsRoot, ops_root: u.opsRoot,
      units_root: ISO_UNITS_ROOT, units_proof: ISO_UNITS_PROOF,
      fill: f, fill_proof: merkle.getMerkleProof(tree, 0),
      right: tree[1], right_proof: merkle.getMerkleProof(tree, 1),
      op: u.op, ops_proof: merkle.getMerkleProof(u.ops, 0),
      pre_wit: WIT_ROOT, post_wit: u.wit, post_proof: merkle.getMerkleProof(u.trace, 0),
      pre_acct: FILL_TAKER_PRE, pre_acct_proof: genProof(FILL_TAKER_PRE),
      post_acct: acctLeaf, post_acct_proof: u.leafProof(acctLeaf),
      post_pos: posLeaf, post_pos_proof: u.leafProof(posLeaf),
      pre_meta: META1, pre_meta_proof: genProof(META1),
      pos_absent: true,
      pleft: META2, pleft_proof: genProof(META2),
      pright: POS2, pright_proof: genProof(POS2),
      cp_acct: CP_LEAF, cp_acct_proof: u.leafProof(CP_LEAF),
      who: "taker",
    });
    const mint = mk("r5-a2-mint", mintLeaf);
    await submitAt(62, mint);
    await triggerVerdict(challenger, fill, fmPayload(mint, mintLeaf), 20000, "R5-A-2 mint under the near-zero gate");
    st = await vars(rollup);
    if (Number(st.frozen_62) !== 2) throw new Error("R5-A-2: zero-balance fake-fill mint did not freeze h62");
    // P-fsane (book AA): fills the engine never emits.
    const fsUnit = (tag, fill, opStr) => {
      const t = fillsTree([fill]);
      return Object.assign(oneUnit(tag, opStr, [DEP_PRE, CP_LEAF, META1]), {
        unitsRoot: ISO_UNITS_ROOT, fillsRoot: merkle.getMerkleRoot(t), fillCount: 1, ftree: t, fill,
      });
    };
    const fsPayload = (u, extra) => Object.assign({
      pred: "fsane", height: 62, rollup: ROLLUP_ADDR, k: 0,
      trace_root: u.traceRoot, fills_root: u.fillsRoot, ops_root: u.opsRoot, units_root: ISO_UNITS_ROOT,
      units_proof: ISO_UNITS_PROOF, fill: u.fill, fill_proof: merkle.getMerkleProof(u.ftree, 0),
      pre_wit: WIT_ROOT,
    }, extra || {});
    const fsLiars = [
      // (b) kind-3 liquidation fill with taker_post 1e14 (opened the old
      // bucket-skip gate): taker_post of a liquidation is always 0.
      ["kind3-tpost", fsUnit("r5-fs-k3", `f:${isoUnit}:0:${FILL_TAKER}:${"c".repeat(64)}:${tOrd}:${isoMOrd}:1:100000000:100000000:9:0:3:100000000000000`, `L:${DEP_ACCT}:${FILL_TAKER}:1`), null],
      // (c) isolated Place whose margin exceeds the taker's pre collateral
      // (0): the engine rejects it, so the unit has no fill.
      ["iso-margin", fsUnit("r5-fs-margin", `f:${isoUnit}:0:${FILL_TAKER}:${"c".repeat(64)}:${tOrd}:${isoMOrd}:1:100000000:100000000:9:0:0:500000`, `p:${FILL_TAKER}:1:0:100000000:100000000:1:500000:0:0`),
        (u) => ({ op: u.op, ops_proof: merkle.getMerkleProof(u.ops, 0), pre_acct: FILL_TAKER_PRE, pre_acct_proof: genProof(FILL_TAKER_PRE) })],
      // (d) kind 1 (funding cash) on a regular market (usd_per_unit 0).
      ["kind1", fsUnit("r5-fs-k1", `f:${isoUnit}:0:${DEP_ACCT}:${"c".repeat(64)}:${tOrd}:${isoMOrd}:1:100000000:100000000:9:0:1:0`, `p:${DEP_ACCT}:1:0:100000000:100000000:0:0:0:0`),
        () => ({ pre_meta: META1, pre_meta_proof: genProof(META1) })],
      // (e) taker with no account in the pre tree (a fresh account cannot open).
      ["absent", fsUnit("r5-fs-absent", `f:${isoUnit}:0:${"9a".repeat(32)}:${"c".repeat(64)}:${tOrd}:${isoMOrd}:1:100000000:100000000:9:0:0:0`, `p:${"9a".repeat(32)}:1:0:100000000:100000000:0:0:0:0`),
        () => Object.assign({ who: "taker" }, absentIn(GENESIS_LEAVES, `acct:${"9a".repeat(32)}:`))],
    ];
    for (const [tag, u, extra] of fsLiars) {
      await submitAt(62, u);
      await triggerVerdict(challenger, book, fsPayload(u, extra ? extra(u) : null), 20000, "R5-A-2 fsane " + tag);
      st = await vars(rollup);
      if (Number(st.frozen_62) !== 2) throw new Error("R5-A-2: fsane " + tag + " did not freeze h62");
    }
    // Honest: an isolated Place within the pre collateral (DEP_ACCT 1e6,
    // margin 5e5), a kind-0 fill on a regular market, a present taker.
    const okFs = fsUnit("r5-fs-ok", isoFill, isoOp);
    await submitAt(62, okFs);
    await triggerBounce(challenger, book, fsPayload(okFs, {
      op: okFs.op, ops_proof: merkle.getMerkleProof(okFs.ops, 0), pre_acct: DEP_PRE, pre_acct_proof: genProof(DEP_PRE),
      pre_meta: META1, pre_meta_proof: genProof(META1),
    }), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_62 || 0) !== 0) throw new Error("R5-A-2: honest fill froze h62 via fsane!");
    console.log("58. R5-A-2: zero-balance mint / kind-3 taker_post / over-collateral iso margin / kind 1 on a regular market / absent taker → frozen; honest → 'no fraud'");
  }

  // ---- 59. R5-A-3: P-mbind compares quantities numerically --------------
  {
    const OB = "4c".repeat(32);
    const ORD_B = `ord:${OB}:1:1:100000000:3:100000000:${FILL_TAKER}:0:0`;
    const MB_PRE = GENESIS_LEAVES.concat([ORD_B]).sort();
    const MB_WIT = merkle.getMerkleRoot(MB_PRE);
    await submitAt(63, Object.assign(oneUnit("r5-mb-commit", "x:" + sha256Hex("r5mbc"), [DEP_PRE]), { witRoot: MB_WIT }));
    const mkFill = (qty) =>
      `f:${isoUnit}:0:${DEP_ACCT}:${FILL_TAKER}:${"5".repeat(64)}:${OB}:1:100000000:${qty}:9:0:0:0`;
    const mbUnit = (tag, f) => {
      const tree = fillsTree([f]);
      return Object.assign(oneUnit(tag, `p:${DEP_ACCT}:1:0:100000000:100000000:0:0:1:0`, [DEP_PRE]), {
        unitsRoot: ISO_UNITS_ROOT, fillsRoot: merkle.getMerkleRoot(tree), fillCount: 1, tree,
      });
    };
    const mbPayload = (u, f) => ({
      pred: "mbind", height: 64, rollup: ROLLUP_ADDR, k: 0,
      trace_root: u.traceRoot, fills_root: u.fillsRoot, units_root: ISO_UNITS_ROOT,
      units_proof: ISO_UNITS_PROOF, fill: f, fill_proof: merkle.getMerkleProof(u.tree, 0),
      pre_wit: MB_WIT, maker_ord: ORD_B, maker_ord_proof: merkle.getMerkleProof(MB_PRE, MB_PRE.indexOf(ORD_B)),
    });
    for (const q of ["1e30", "1e21", "-50000000", "0"]) {
      const f = mkFill(q);
      const u = mbUnit("r5-mb-" + q, f);
      await submitAt(64, u);
      await triggerVerdict(challenger, book, mbPayload(u, f), 20000, "R5-A-3 qty " + q);
      st = await vars(rollup);
      if (Number(st.frozen_64) !== 2) throw new Error("R5-A-3: qty " + q + " did not freeze h64");
    }
    const okF = mkFill("100000000");
    const okU = mbUnit("r5-mb-ok", okF);
    await submitAt(64, okU);
    await triggerBounce(challenger, book, mbPayload(okU, okF), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_64 || 0) !== 0) throw new Error("R5-A-3: honest fill froze h64!");
    console.log("59. R5-A-3: qty 1e30 / 1e21 / negative / 0 → frozen; qty == remaining → 'no fraud'");
  }

  // ---- 60. R5-A-4: an honest add at a price <= -1e14 is not fraud -------
  {
    // DEP_ACCT long 1 @ -886454204619215 adds 14 @ -737631817583682 (the
    // reviewer's c5 vector): exact vwap -747553310052717, Oscript's
    // 15-digit floor lands 4 away — the |price| >= 1e14 guard must skip the
    // entry compare. Collateral: 1e6 - fee 516 (notional 1032684).
    const P = "-737631817583682";
    const NO = "4d".repeat(32);
    const MK = "c".repeat(64);
    const NORD = `ord:${NO}:1:1:${P}:3:14:${MK}:0:0`;
    const NPOS = `pos:${DEP_ACCT}:1:1:-886454204619215:0:0`;
    const NP_PRE = [DEP_PRE, CP_LEAF, META1, NPOS, NORD].sort();
    const NP_WIT = merkle.getMerkleRoot(NP_PRE);
    const npProof = (l) => merkle.getMerkleProof(NP_PRE, NP_PRE.indexOf(l));
    await submitAt(65, Object.assign(oneUnit("r5-np-commit", "x:" + sha256Hex("r5npc"), [DEP_PRE]), { witRoot: NP_WIT }));
    const f = `f:${isoUnit}:0:${DEP_ACCT}:${MK}:${"8".repeat(64)}:${NO}:1:${P}:14:9:0:0:0`;
    const tree = fillsTree([f]);
    const op = `p:${DEP_ACCT}:1:0:${P}:14:0:0:1:1`;
    const postPos = `pos:${DEP_ACCT}:1:15:-747553310052717:0:0`;
    const mk = (tag, col) => Object.assign(oneUnit(tag, op, [`acct:${DEP_ACCT}:${col}:0:0`, CP_LEAF, META1, postPos]), {
      unitsRoot: ISO_UNITS_ROOT, fillsRoot: merkle.getMerkleRoot(tree), fillCount: 1,
    });
    const npPayload = (u, col) => {
      const acctLeaf = `acct:${DEP_ACCT}:${col}:0:0`;
      return {
        pred: "fill_math", height: 66, rollup: ROLLUP_ADDR, k: 0,
        trace_root: u.traceRoot, fills_root: u.fillsRoot, ops_root: u.opsRoot,
        units_root: ISO_UNITS_ROOT, units_proof: ISO_UNITS_PROOF,
        fill: f, fill_proof: merkle.getMerkleProof(tree, 0),
        right: tree[1], right_proof: merkle.getMerkleProof(tree, 1),
        op: u.op, ops_proof: merkle.getMerkleProof(u.ops, 0),
        pre_wit: NP_WIT, post_wit: u.wit, post_proof: merkle.getMerkleProof(u.trace, 0),
        pre_acct: DEP_PRE, pre_acct_proof: npProof(DEP_PRE),
        pre_pos: NPOS, pre_pos_proof: npProof(NPOS),
        post_acct: acctLeaf, post_acct_proof: u.leafProof(acctLeaf),
        post_pos: postPos, post_pos_proof: u.leafProof(postPos),
        pre_meta: META1, pre_meta_proof: npProof(META1),
        maker_ord: NORD, maker_ord_proof: npProof(NORD),
        cp_acct: CP_LEAF, cp_acct_proof: u.leafProof(CP_LEAF),
        who: "taker",
      };
    };
    const liar = mk("r5-np-liar", 999584); // collateral +100
    await submitAt(66, liar);
    await triggerVerdict(challenger, fill, npPayload(liar, 999584), 20000, "R5-A-4 collateral lie on a negative-price add");
    st = await vars(rollup);
    if (Number(st.frozen_66) !== 2) throw new Error("R5-A-4: collateral lie on the negative-price add did not freeze h66");
    const ok = mk("r5-np-ok", 999484);
    await submitAt(66, ok);
    await triggerBounce(challenger, fill, npPayload(ok, 999484), 20000, "no fraud");
    st = await vars(rollup);
    if (Number(st.frozen_66 || 0) !== 0) throw new Error("R5-A-4: honest negative-price add froze h66!");
    console.log("60. R5-A-4: honest add at price <= -1e14 (vwap rounds 4 off in Oscript) → 'no fraud'; collateral lie → frozen");
  }

  // ===================== ROUND 6 (fix/47-r6-claw) =========================
  // ---- 61. P-claw: both legs of one fill (claw AA) -----------------------
  // Real numbers on market 1 (META1: fee 5 bps, keeper 100 bps). Each pre
  // tree is committed as wit_root of a filler height, the challenged unit
  // is k=0 of the next height.
  {
    const T = "e1".repeat(32);
    const M = "e2".repeat(32);
    const K = "e3".repeat(32);
    const TO = "e4".repeat(32);
    const END = "~:end";
    const acct = (a, c) => `acct:${a}:${c}:0:0`;
    const clawSetup = async (hCommit, tag, leaves) => {
      const pre = leaves.slice().sort();
      const wit = merkle.getMerkleRoot(pre);
      await submitAt(hCommit, Object.assign(oneUnit(tag + "-commit", "x:" + sha256Hex(tag), [DEP_PRE]), { witRoot: wit }));
      return { pre, wit, proof: (l) => merkle.getMerkleProof(pre, pre.indexOf(l)) };
    };
    // Every case commits its pre tree's root as wit_root, so the next
    // height's k=0 unit can be judged against the same pre tree.
    const clawUnit = (P, tag, op, fills, post) => {
      const tree = fillsTree(fills);
      return Object.assign(oneUnit(tag, op, post), {
        unitsRoot: ISO_UNITS_ROOT, fillsRoot: merkle.getMerkleRoot(tree), fillCount: fills.length, tree, fill: fills[0],
        witRoot: P.wit,
      });
    };
    const legFields = (P, u, x, a) => {
      const pre = P.pre.find((l) => l.startsWith(`acct:${a}:`));
      const post = u.post.find((l) => l.startsWith(`acct:${a}:`));
      if (!pre || !post) throw new Error("fixture: acct leaf of " + a);
      const o = {};
      o[x + "_pre_acct"] = pre; o[x + "_pre_acct_proof"] = P.proof(pre);
      o[x + "_post_acct"] = post; o[x + "_post_acct_proof"] = u.leafProof(post);
      const lo = `pos:${a}:1:`;
      const pos = P.pre.find((l) => l.startsWith(lo));
      if (pos) {
        o[x + "_pre_pos"] = pos; o[x + "_pre_pos_proof"] = P.proof(pos);
      } else {
        const i = P.pre.findIndex((l) => l > lo);
        if (i < 1 || !(P.pre[i] >= `pos:${a}:1;`)) throw new Error("fixture: pos straddle of " + a);
        o[x + "_pleft"] = P.pre[i - 1]; o[x + "_pleft_proof"] = P.proof(P.pre[i - 1]);
        o[x + "_pright"] = P.pre[i]; o[x + "_pright_proof"] = P.proof(P.pre[i]);
      }
      return o;
    };
    const clawPayload = (P, h, u, mord) => Object.assign({
      pred: "claw", height: h, rollup: ROLLUP_ADDR, k: 0,
      trace_root: u.traceRoot, fills_root: u.fillsRoot, ops_root: u.opsRoot, units_root: ISO_UNITS_ROOT,
      units_proof: ISO_UNITS_PROOF, fill: u.fill, fill_proof: merkle.getMerkleProof(u.tree, 0),
      right: u.tree[1], right_proof: merkle.getMerkleProof(u.tree, 1),
      pre_wit: P.wit, post_wit: u.wit, post_proof: merkle.getMerkleProof(u.trace, 0),
      op: u.op, ops_proof: merkle.getMerkleProof(u.ops, 0),
      pre_meta: META1, pre_meta_proof: P.proof(META1),
    }, mord ? { maker_ord: mord, maker_ord_proof: P.proof(mord) } : {},
      legFields(P, u, "t", T), legFields(P, u, "m", M));
    const frozen = async (h, what) => {
      const s = await vars(rollup);
      if (Number(s["frozen_" + h]) !== 2) throw new Error("P-claw: " + what + " did not freeze h" + h);
    };
    const live = async (h, what) => {
      const s = await vars(rollup);
      if (Number(s["frozen_" + h] || 0) !== 0) throw new Error("P-claw: " + what + " froze h" + h + "!");
    };

    // (a) kind 0 — maker M long 1 @ 100k with 1000 USD; its resting ask @
    // 90k is hit by cross taker T (50k USD). M's 10k loss: fill stage
    // -9000 USD, clawed from T (fill stage 50000 - 45 fee).
    const MO = "e5".repeat(32);
    const MORD = `ord:${MO}:1:1:9000000000000:3:100000000:${M}:0:0`;
    const P1 = await clawSetup(67, "r6-claw-p1", [
      acct(T, 50000000000), acct(M, 1000000000), META1, MORD,
      `pos:${M}:1:100000000:10000000000000:0:0`, END,
    ]);
    const f1 = `f:${isoUnit}:0:${T}:${M}:${TO}:${MO}:1:9000000000000:100000000:9:0:0:0`;
    const op1 = `p:${T}:1:0:9000000000000:100000000:0:0:0:0`;
    const tPos1 = `pos:${T}:1:100000000:9000000000000:0:0`;
    const post1 = (tc, mc) => [acct(T, tc), acct(M, mc), META1, tPos1, END];
    // Money print (the R5 residual): T keeps its whole fill stage, M is
    // still lifted to 0 — 9000 USD out of nowhere.
    const print = clawUnit(P1, "r6-claw-print", op1, [f1], post1(49955000000, 0));
    await submitAt(68, print);
    // fill_math alone cannot see it: each leg sits inside its claw range.
    const pl = P1.pre.findIndex((l) => l > `pos:${T}:1:`);
    await triggerBounce(challenger, fill, {
      pred: "fill_math", height: 68, rollup: ROLLUP_ADDR, k: 0,
      trace_root: print.traceRoot, fills_root: print.fillsRoot, ops_root: print.opsRoot,
      units_root: ISO_UNITS_ROOT, units_proof: ISO_UNITS_PROOF,
      fill: f1, fill_proof: merkle.getMerkleProof(print.tree, 0),
      right: print.tree[1], right_proof: merkle.getMerkleProof(print.tree, 1),
      op: print.op, ops_proof: merkle.getMerkleProof(print.ops, 0),
      pre_wit: P1.wit, post_wit: print.wit, post_proof: merkle.getMerkleProof(print.trace, 0),
      pre_acct: acct(T, 50000000000), pre_acct_proof: P1.proof(acct(T, 50000000000)),
      post_acct: acct(T, 49955000000), post_acct_proof: print.leafProof(acct(T, 49955000000)),
      post_pos: tPos1, post_pos_proof: print.leafProof(tPos1),
      pre_meta: META1, pre_meta_proof: P1.proof(META1),
      pos_absent: true,
      pleft: P1.pre[pl - 1], pleft_proof: P1.proof(P1.pre[pl - 1]),
      pright: P1.pre[pl], pright_proof: P1.proof(P1.pre[pl]),
      maker_ord: MORD, maker_ord_proof: P1.proof(MORD),
      cp_acct: acct(M, 0), cp_acct_proof: print.leafProof(acct(M, 0)),
      who: "taker",
    }, 20000, "no fraud");
    await triggerVerdict(challenger, claw, clawPayload(P1, 68, print, MORD), 20000, "P-claw money print (kind 0)");
    await frozen(68, "kind-0 money print");
    // Burn: T pays the 9000, M is not credited.
    const burn = clawUnit(P1, "r6-claw-burn", op1, [f1], post1(40955000000, -9000000000));
    await submitAt(68, burn);
    await triggerVerdict(challenger, claw, clawPayload(P1, 68, burn, MORD), 20000, "P-claw burn (kind 0)");
    await frozen(68, "kind-0 burn");
    // Honest: T pays exactly the 9000 that lifts M to 0.
    const ok1 = clawUnit(P1, "r6-claw-ok1", op1, [f1], post1(40955000000, 0));
    await submitAt(68, ok1);
    await triggerBounce(challenger, claw, clawPayload(P1, 68, ok1, MORD), 20000, "no fraud");
    await live(68, "honest kind-0 claw");
    // Isolated IOC taker for 2 (margin 20000 USD): one fills, its share
    // (10000) moves to the bucket, the unfilled half's 10000 returns AFTER
    // the claw — honest post 50000 - 20000 - 45 - 9000 + 10000.
    const fIso = `f:${isoUnit}:0:${T}:${M}:${TO}:${MO}:1:9000000000000:100000000:9:0:0:10000000000`;
    const opIso = `p:${T}:1:0:9000000000000:200000000:1:20000000000:1:0`;
    const isoU = clawUnit(P1, "r6-claw-iso", opIso, [fIso],
      [acct(T, 30955000000), acct(M, 0), META1, `pos:${T}:1:100000000:9000000000000:1:10000000000`, END]);
    await submitAt(69, isoU);
    await triggerBounce(challenger, claw, clawPayload(P1, 69, isoU, MORD), 20000, "no fraud");
    await live(69, "honest isolated-taker claw");
    // A multi-fill unit is not judged (single-fill completeness), even with
    // the money-print post.
    const f1b = `f:${isoUnit}:1:${T}:${M}:${TO}:${MO}:1:9000000000000:1:9:0:0:0`;
    const multi = clawUnit(P1, "r6-claw-multi", op1, [f1, f1b], post1(49955000000, 0));
    await submitAt(70, multi);
    await triggerBounce(challenger, claw, clawPayload(P1, 70, multi, MORD), 20000, "no fraud");
    await live(70, "multi-fill unit");

    // (b) kind 3 — liquidation of T (long 1 @ 100k, 15000 USD) at a crashed
    // mark into M's resting bid @ 1 USD (M 50000 USD, no position): T's
    // fill stage -84999000500 is clawed from M, which can only pay 50000
    // USD; keeper K gets nothing (T stays negative).
    const MO2 = "e6".repeat(32);
    const MORD2 = `ord:${MO2}:1:0:100000000:4:100000000:${M}:0:0`;
    const P2 = await clawSetup(71, "r6-claw-p2", [
      acct(T, 15000000000), acct(M, 50000000000), META1, MORD2,
      `pos:${T}:1:100000000:10000000000000:0:0`, END,
    ]);
    const LO = "e7".repeat(32);
    const f2 = `f:${isoUnit}:0:${T}:${M}:${LO}:${MO2}:1:100000000:100000000:9:1:3:0`;
    const op2 = `L:${K}:${T}:1`;
    const mPos2 = `pos:${M}:1:100000000:100000000:0:0`;
    const post2 = (tc, mc) => [acct(T, tc), acct(M, mc), META1, mPos2, END];
    const print2 = clawUnit(P2, "r6-claw-print2", op2, [f2], post2(-34999000500, 50000000000));
    await submitAt(72, print2);
    await triggerVerdict(challenger, claw, clawPayload(P2, 72, print2, MORD2), 20000, "P-claw money print (kind 3)");
    await frozen(72, "kind-3 money print");
    const burn2 = clawUnit(P2, "r6-claw-burn2", op2, [f2], post2(-84999000500, 0));
    await submitAt(72, burn2);
    await triggerVerdict(challenger, claw, clawPayload(P2, 72, burn2, MORD2), 20000, "P-claw burn (kind 3)");
    await frozen(72, "kind-3 burn");
    const ok2 = clawUnit(P2, "r6-claw-ok2", op2, [f2], post2(-34999000500, 0));
    await submitAt(72, ok2);
    await triggerBounce(challenger, claw, clawPayload(P2, 72, ok2, MORD2), 20000, "no fraud");
    await live(72, "honest partial claw (kind 3)");
    // Multi-fill (a second fill of the same unit follows): not judged.
    const f2b = `f:${isoUnit}:1:${T}:${K}:${LO}:${"e8".repeat(32)}:1:100000000:1:9:1:3:0`;
    const multi2 = clawUnit(P2, "r6-claw-multi2", op2, [f2, f2b], post2(-34999000500, 50000000000));
    await submitAt(73, multi2);
    await triggerBounce(challenger, claw, clawPayload(P2, 73, multi2, MORD2), 20000, "no fraud");
    await live(73, "multi-fill liquidation unit");

    // (c) kind 2 — ADL of T (long 1 @ 100k, 15000 USD) at mark 86k onto
    // M (short 1 @ 100k, 1M USD), M also the caller (keeper): no claw, the
    // keeper reward 860 USD is seized from T and credited to M.
    const P3 = await clawSetup(74, "r6-claw-p3", [
      acct(T, 15000000000), acct(M, 1000000000000), META1,
      `pos:${T}:1:100000000:10000000000000:0:0`, `pos:${M}:1:-100000000:10000000000000:0:0`, END,
    ]);
    const f3 = `f:${isoUnit}:0:${T}:${M}:${LO}:${"0".repeat(64)}:1:8600000000000:100000000:9:1:2:0`;
    const op3 = `L:${M}:${T}:1`;
    const post3 = (tc, mc) => [acct(T, tc), acct(M, mc), META1, END];
    const over3 = clawUnit(P3, "r6-claw-keep-over", op3, [f3], post3(140000000, 1015720000000));
    await submitAt(75, over3);
    await triggerVerdict(challenger, claw, clawPayload(P3, 75, over3, null), 20000, "P-claw keeper credit doubled (kind 2)");
    await frozen(75, "kind-2 doubled keeper credit");
    const ok3 = clawUnit(P3, "r6-claw-ok3", op3, [f3], post3(140000000, 1014860000000));
    await submitAt(75, ok3);
    await triggerBounce(challenger, claw, clawPayload(P3, 75, ok3, null), 20000, "no fraud");
    await live(75, "honest ADL with keeper = maker");
    console.log("61. P-claw: kind-0 / kind-3 money print and burn, doubled ADL keeper credit → frozen; honest isolated-taker claw, honest ADL keeper, multi-fill → 'no fraud' (fill_math alone: 'no fraud' on the print)");

    // Pool occupancy gate (ls - lf < 50): heights 29..75 were never
    // finalized, so 6b's heights 76..82 would bounce 'pool occupancy'.
    // Finalize the live drill heights in order first.
    {
      await network.timetravel({ shift: "3600s" });
      let s0 = await vars(rollup);
      for (let fh = Number(s0.last_finalized) + 1; fh <= 60; fh++) {
        await trigger(operator, rollup, { finalize: 1, height: fh }, 20000);
        s0 = await vars(rollup);
        if (Number(s0.last_finalized) !== fh) break;
      }
      console.log(`6b prep: ls=${s0.last_submitted} lf=${s0.last_finalized}`);
      if (Number(s0.last_finalized) < 40) throw new Error("6b prep: finalize stalled at " + s0.last_finalized);
    }
    // ===================== ROUND 6b (fix/47-r6b) ==========================
    const C = "e9".repeat(32);
    const Z = "0".repeat(64);
    // P-frame (binding AA) payload for a Place / Liquidate unit: the leaf,
    // its exact absence in the other tree, and the fill-count evidence.
    const pfPayload = (P, h, u, leaf, ins) => {
      const tree = u.tree;
      const ri = u.fill ? 1 : 0;
      return Object.assign({
        pred: "frame", height: h, rollup: ROLLUP_ADDR, k: 0,
        trace_root: u.traceRoot, ops_root: u.opsRoot, op: u.op, ops_proof: merkle.getMerkleProof(u.ops, 0),
        pre_wit: P.wit, post_wit: u.wit, post_proof: merkle.getMerkleProof(u.trace, 0),
        leaf, ins, leaf_proof: ins ? u.leafProof(leaf) : P.proof(leaf),
        fills_root: u.fillsRoot, units_root: ISO_UNITS_ROOT, unit: isoUnit, units_proof: ISO_UNITS_PROOF,
        pre_meta: META1, pre_meta_proof: P.proof(META1),
      }, tree.length > 1 ? { fright: tree[ri], fright_proof: merkle.getMerkleProof(tree, ri) } : {},
        u.fill ? { fill: tree[0], fill_proof: merkle.getMerkleProof(tree, 0) } : {},
        absentIn(ins ? P.pre : u.post, leaf));
    };

    // R7b-N2: the acct: frame of a Place / Liquidate unit (P-xframe), with
    // P-frame's fill-count evidence.
    const pxPayload = (P, h, u, a) => {
      const tree = u.tree;
      const ri = u.fill ? 1 : 0;
      return xfNx(h, u, P.pre, P.wit, a, Object.assign({
        fills_root: u.fillsRoot, units_root: ISO_UNITS_ROOT, unit: isoUnit, units_proof: ISO_UNITS_PROOF,
        pre_meta: META1, pre_meta_proof: P.proof(META1),
      }, tree.length > 1 ? { fright: tree[ri], fright_proof: merkle.getMerkleProof(tree, ri) } : {},
        u.fill ? { fill: tree[0], fill_proof: merkle.getMerkleProof(tree, 0) } : {}));
    };

    // ---- 62/63a. R6-C1 relabels + R6-C2 third-party credit (kind 0) ------
    // The (a) kind-0 claw tree plus a bystander C (7000 USD).
    const P5 = await clawSetup(76, "r6b-p5", [
      acct(T, 50000000000), acct(M, 1000000000), acct(C, 7000000000), META1, MORD,
      `pos:${M}:1:100000000:10000000000000:0:0`, END,
    ]);
    const post5 = (tc, mc, cc) => [acct(T, tc), acct(M, mc), acct(C, cc), META1, tPos1, END];
    // (a) kind 0 -> 3 under the Place + money print: the claw AA used to
    // bounce on the op shape; now the fill/op mismatch alone is the fraud.
    const f1k3 = `f:${isoUnit}:0:${T}:${M}:${TO}:${MO}:1:9000000000000:100000000:9:0:3:0`;
    const rel = clawUnit(P5, "r6b-rel03", op1, [f1k3], post5(49955000000, 0, 7000000000));
    await submitAt(77, rel);
    await triggerVerdict(challenger, claw, {
      pred: "claw", height: 77, rollup: ROLLUP_ADDR, k: 0,
      trace_root: rel.traceRoot, fills_root: rel.fillsRoot, ops_root: rel.opsRoot, units_root: ISO_UNITS_ROOT,
      units_proof: ISO_UNITS_PROOF, fill: rel.fill, fill_proof: merkle.getMerkleProof(rel.tree, 0),
      op: rel.op, ops_proof: merkle.getMerkleProof(rel.ops, 0),
    }, 20000, "R6-C1 kind 0->3 relabel (no state leaves)");
    await frozen(77, "kind 0->3 relabel");
    // (c) the Place op committed as `x:{unit}` (item 10 route): only Place
    // and Liquidate emit fills.
    const xop = clawUnit(P5, "r6b-xop", "x:" + isoUnit, [f1], post5(49955000000, 0, 7000000000));
    await submitAt(77, xop);
    await triggerVerdict(challenger, claw, clawPayload(P5, 77, xop, MORD), 20000, "R6-C1 x: op with a fill");
    await frozen(77, "x: op with a fill");
    // A multi-fill unit whose first fill is not its op's: also fraud now.
    const xmulti = clawUnit(P5, "r6b-xmulti", "x:" + isoUnit, [f1, f1b], post5(49955000000, 0, 7000000000));
    await submitAt(77, xmulti);
    await triggerVerdict(challenger, claw, clawPayload(P5, 77, xmulti, MORD), 20000, "R6-C1 x: op, multi-fill");
    await frozen(77, "x: op on a multi-fill unit");
    // R6-C2 (a): honest single-fill Place, bystander C credited 1e6 USD.
    const tp3 = clawUnit(P5, "r6b-3p", op1, [f1], post5(40955000000, 0, 1007000000000));
    await submitAt(77, tp3);
    await triggerBounce(challenger, claw, clawPayload(P5, 77, tp3, MORD), 20000, "no fraud");
    await triggerBounce(challenger, bindAa, pfPayload(P5, 77, tp3, acct(C, 1007000000000), true), 20000, "bad leaf");
    await triggerVerdict(challenger, xframe, pxPayload(P5, 77, tp3, C), 20000, "R6-C2 third-party credit (single-fill Place, P-xframe)");
    await frozen(77, "third-party credit in a Place unit");
    // Honest: the claw bounces, and P-frame bounces on the maker's leaf
    // (an allowed account) and cannot prove C's untouched leaf absent.
    const ok5 = clawUnit(P5, "r6b-ok5", op1, [f1], post5(40955000000, 0, 7000000000));
    await submitAt(77, ok5);
    await triggerBounce(challenger, claw, clawPayload(P5, 77, ok5, MORD), 20000, "no fraud");
    await triggerBounce(challenger, xframe, pxPayload(P5, 77, ok5, M), 20000, "no fraud");
    await triggerBounce(challenger, xframe, pxPayload(P5, 77, ok5, C), 20000, "no fraud");
    await live(77, "honest kind-0 Place (shape + frame)");
    // (b) zero-fill Place (a cross bid rests): only T may change. The
    // height has fill_count 0, so no fills evidence is needed (the one-leaf
    // tree `n:0` has no sendable proof).
    const restOp = `p:${T}:1:0:8000000000000:100000000:0:0:0:0`;
    const tOrd = `ord:${"ea".repeat(32)}:1:0:8000000000000:9:100000000:${T}:0:0`;
    const zpost = (cc) => P5.pre.filter((l) => l !== acct(C, 7000000000)).concat([acct(C, cc), tOrd]);
    const z3p = clawUnit(P5, "r6b-z3p", restOp, [], zpost(7000000005));
    await submitAt(78, z3p);
    await triggerVerdict(challenger, xframe, pxPayload(P5, 78, z3p, C), 20000, "R6-C2 third-party credit (zero-fill Place, P-xframe)");
    if (pxPayload(P5, 78, z3p, C).fright) throw new Error("fixture: one-leaf fills tree");
    await frozen(78, "third-party credit in a zero-fill Place");
    const zok = clawUnit(P5, "r6b-zok", restOp, [], zpost(7000000000));
    await submitAt(78, zok);
    await triggerBounce(challenger, bindAa, pfPayload(P5, 78, zok, tOrd, true), 20000, "no fraud");
    await live(78, "honest zero-fill Place");
    console.log("62. R6-C1: kind 0→3 relabel (no state needed), x: op on a single- and a multi-fill unit → frozen; honest Place → 'no fraud'");

    // ---- 62b/63c. kind 3 -> 0, keeper / insurance credit, ghost account --
    // T long 1 @ 100k (15000 USD) liquidated into M's bid @ 90k by keeper
    // K (no account yet): T 15000 - 10000 - 45 fee - 900 kpay = 4055,
    // M unchanged (opens long, cross), insurance +45, K +900.
    const MO3 = "eb".repeat(32);
    const MORD3 = `ord:${MO3}:1:0:9000000000000:4:100000000:${M}:0:0`;
    const P6 = await clawSetup(79, "r6b-p6", [
      acct(T, 15000000000), acct(M, 50000000000), acct(Z, 1000000000), META1, MORD3,
      `pos:${T}:1:100000000:10000000000000:0:0`, END,
    ]);
    const f6 = `f:${isoUnit}:0:${T}:${M}:${LO}:${MO3}:1:9000000000000:100000000:9:1:3:0`;
    const op6 = `L:${K}:${T}:1`;
    const mPos6 = `pos:${M}:1:100000000:9000000000000:0:0`;
    const post6 = (tc, zc, kc, extra) => [acct(T, tc), acct(M, 50000000000), acct(Z, zc), META1, mPos6, END]
      .concat(kc === null ? [] : [acct(K, kc)]).concat(extra || []);
    const xFields = (P, u, who, a) => {
      const post = u.post.find((l) => l.startsWith(`acct:${a}:`));
      const o = { x_who: who, x_post_acct: post, x_post_acct_proof: u.leafProof(post) };
      const pre = P.pre.find((l) => l.startsWith(`acct:${a}:`));
      if (pre) {
        o.x_pre_acct = pre; o.x_pre_acct_proof = P.proof(pre);
      } else {
        const i = P.pre.findIndex((l) => l > `acct:${a}:`);
        o.x_pleft = P.pre[i - 1]; o.x_pleft_proof = P.proof(P.pre[i - 1]);
        o.x_pright = P.pre[i]; o.x_pright_proof = P.proof(P.pre[i]);
      }
      return o;
    };
    // (b) kind 3 -> 0 under the Liquidate.
    const f6k0 = `f:${isoUnit}:0:${T}:${M}:${LO}:${MO3}:1:9000000000000:100000000:9:1:0:0`;
    const rel30 = clawUnit(P6, "r6b-rel30", op6, [f6k0], post6(4055000000, 1045000000, 900000000));
    await submitAt(80, rel30);
    await triggerVerdict(challenger, claw, clawPayload(P6, 80, rel30, MORD3), 20000, "R6-C1 kind 3->0 relabel");
    await frozen(80, "kind 3->0 relabel");
    // Keeper credited 10x its reward (the target pays it once).
    const kOver = clawUnit(P6, "r6b-kover", op6, [f6], post6(4055000000, 1045000000, 9000000000));
    await submitAt(80, kOver);
    await triggerBounce(challenger, claw, clawPayload(P6, 80, kOver, MORD3), 20000, "no fraud");
    await triggerVerdict(challenger, claw, Object.assign(clawPayload(P6, 80, kOver, MORD3), xFields(P6, kOver, "c", K)), 20000, "R6-C2 keeper over-credit");
    await frozen(80, "keeper over-credit");
    // Insurance inflated by 1e6 USD.
    const iOver = clawUnit(P6, "r6b-iover", op6, [f6], post6(4055000000, 1001045000000, 900000000));
    await submitAt(80, iOver);
    await triggerVerdict(challenger, claw, Object.assign(clawPayload(P6, 80, iOver, MORD3), xFields(P6, iOver, "i", Z)), 20000, "R6-C2 insurance inflation");
    await frozen(80, "insurance inflation");
    // A ghost account appears in the liquidation unit.
    const GH = acct("5e".repeat(32), 1000000000000);
    const ghost = clawUnit(P6, "r6b-ghost", op6, [f6], post6(4055000000, 1045000000, 900000000, [GH]));
    await submitAt(80, ghost);
    await triggerVerdict(challenger, xframe, pxPayload(P6, 80, ghost, "5e".repeat(32)), 20000, "R6-C2 ghost account (Liquidate, P-xframe)");
    await frozen(80, "ghost account in a Liquidate unit");
    const ok6 = clawUnit(P6, "r6b-ok6", op6, [f6], post6(4055000000, 1045000000, 900000000));
    await submitAt(80, ok6);
    await triggerBounce(challenger, claw, Object.assign(clawPayload(P6, 80, ok6, MORD3), xFields(P6, ok6, "c", K)), 20000, "no fraud");
    await triggerBounce(challenger, claw, Object.assign(clawPayload(P6, 80, ok6, MORD3), xFields(P6, ok6, "i", Z)), 20000, "no fraud");
    await triggerBounce(challenger, xframe, pxPayload(P6, 80, ok6, K), 20000, "no fraud");
    await live(80, "honest liquidation with a third-party keeper");
    console.log("63. R6-C1 kind 3→0; R6-C2 bystander credit (single- and zero-fill Place), keeper 10x credit, insurance inflation, ghost account → frozen; honest Place / resting bid / keeper liquidation → 'no fraud'");

    // ---- 64. R6-H1: exact flip / close below QTY_CAP (1e15) --------------
    // M long 4e14 (isolated, bucket 1000 USD) asks 4e14 + 1 (escrow 500
    // USD) at 0.00001 USD; cross taker T buys it all: M closes 4e14 and
    // opens 1 short — its escrow goes to the NEW bucket, the old bucket
    // returns: M 10000 + 1000 = 11000 USD; T pays the 0.02 USD fee.
    const MO7 = "ec".repeat(32);
    const Q = "400000000000001";
    const MORD7 = `ord:${MO7}:1:1:1000:5:${Q}:${M}:1:500000000`;
    const P7 = await clawSetup(81, "r6b-p7", [
      acct(T, 10000000000), acct(M, 10000000000), META1, MORD7,
      `pos:${M}:1:400000000000000:1000:1:1000000000`, END,
    ]);
    const f7 = `f:${isoUnit}:0:${T}:${M}:${TO}:${MO7}:1:1000:${Q}:9:0:0:0`;
    const op7 = `p:${T}:1:0:1000:${Q}:0:0:1:0`;
    const post7 = (tc, mc) => [acct(T, tc), acct(M, mc), META1, `pos:${T}:1:${Q}:1000:0:0`, `pos:${M}:1:-1:1000:1:500000000`, END];
    // The pre-cap model (escrow back to collateral, as if a pure close).
    const h1lie = clawUnit(P7, "r6b-h1lie", op7, [f7], post7(9999980000, 11500000000));
    await submitAt(82, h1lie);
    await triggerVerdict(challenger, claw, clawPayload(P7, 82, h1lie, MORD7), 20000, "R6-H1 escrow share returned on a flip");
    await frozen(82, "flip escrow returned to collateral");
    // A fill at the cap is never emitted (P-claw shape + P-fsane).
    const capQ = "1000000000000000";
    const fcap = `f:${isoUnit}:0:${T}:${M}:${TO}:${MO7}:1:1000:${capQ}:9:0:0:0`;
    const cap = clawUnit(P7, "r6b-cap", `p:${T}:1:0:1000:${capQ}:0:0:1:0`, [fcap], post7(9999980000, 11000000000));
    await submitAt(82, cap);
    await triggerVerdict(challenger, book, {
      pred: "fsane", height: 82, rollup: ROLLUP_ADDR, k: 0,
      trace_root: cap.traceRoot, fills_root: cap.fillsRoot, ops_root: cap.opsRoot, units_root: ISO_UNITS_ROOT,
      units_proof: ISO_UNITS_PROOF, fill: fcap, fill_proof: merkle.getMerkleProof(cap.tree, 0), pre_wit: P7.wit,
    }, 20000, "R6-H1 fill qty at the cap (fsane)");
    await frozen(82, "fill qty 1e15 (fsane)");
    await submitAt(82, cap);
    await triggerVerdict(challenger, claw, clawPayload(P7, 82, cap, MORD7), 20000, "R6-H1 fill qty at the cap (claw)");
    await frozen(82, "fill qty 1e15 (claw)");
    const ok7 = clawUnit(P7, "r6b-ok7", op7, [f7], post7(9999980000, 11000000000));
    await submitAt(82, ok7);
    await triggerBounce(challenger, claw, clawPayload(P7, 82, ok7, MORD7), 20000, "no fraud");
    await live(82, "honest maker flip 1 below the cap");
    console.log("64. R6-H1: flip of |pos| 4e14 by 4e14+1 judged exactly (escrow to the new bucket), fill qty 1e15 → frozen (claw + fsane); honest flip → 'no fraud'");

    // ===================== ROUND 7 (fix/47-r7) ============================
    // ---- 65. P-opbind (未修复项 10): the ops leaf must be the unit's own ----
    // descriptor. A unit id is sha256("mnu3|" hex(canonical) "|" E); the
    // challenger sends the text split at its second '|'.
    const opUnit = (tag, uPre, uOp, op) => {
      const id = sha256Hex(uPre + uOp);
      const units = pad2([id], tag + "-units");
      return Object.assign(oneUnit(tag, op, [acct(T, 1), END]), {
        id, uPre, uOp, units, unitsRoot: merkle.getMerkleRoot(units),
      });
    };
    const obPayload = (h, u) => ({
      pred: "opbind", height: h, rollup: ROLLUP_ADDR, k: 0,
      ops_root: u.opsRoot, units_root: u.unitsRoot,
      op: u.op, ops_proof: merkle.getMerkleProof(u.ops, 0),
      units_proof: merkle.getMerkleProof(u.units, 0),
      u_pre: u.uPre, u_op: u.uOp,
    });
    const PRE7 = "mnu3|" + "01ab".repeat(40) + "|";
    // (a) the Place committed as `x:{unit}` (10 (a): third parties of a
    // zero-fill unit would escape P-frame).
    const obx = opUnit("r7-obx", PRE7, op1, "x:" + sha256Hex(PRE7 + op1));
    await submitAt(83, obx);
    await triggerVerdict(challenger, dispute, obPayload(83, obx), 20000, "P-opbind: Place committed as x:");
    await frozen(83, "Place committed as x:");
    // (b) margin / isolated rewritten in the p: leaf (R6-M1).
    const op1m = `p:${T}:1:0:9000000000000:100000000:1:49955000000:0:0`;
    const obm = opUnit("r7-obm", PRE7, op1, op1m);
    await submitAt(83, obm);
    await triggerVerdict(challenger, dispute, obPayload(83, obm), 20000, "P-opbind: p: margin rewritten");
    await frozen(83, "p: margin rewritten");
    // (c) an `x` unit (no descriptor) committed as a p: leaf.
    const obxp = opUnit("r7-obxp", PRE7, "x", op1);
    await submitAt(83, obxp);
    await triggerVerdict(challenger, dispute, obPayload(83, obxp), 20000, "P-opbind: x unit committed as p:");
    await frozen(83, "x unit committed as p:");
    // Honest: the leaf is the descriptor / `x:{id}`; a re-split text (a
    // descriptor holding '|') never frames it.
    const obok = opUnit("r7-obok", PRE7, op1, op1);
    await submitAt(83, obok);
    await triggerBounce(challenger, dispute, obPayload(83, obok), 20000, "no fraud");
    const odd = `d:${T}:5:A|B:${"A".repeat(43)}=`;
    const obodd = opUnit("r7-obodd", PRE7, odd, odd);
    await submitAt(84, obodd);
    await triggerBounce(challenger, dispute, obPayload(84, obodd), 20000, "no fraud");
    const cut = odd.indexOf("|") + 1;
    await triggerBounce(challenger, dispute, Object.assign(obPayload(84, obodd), {
      u_pre: PRE7 + odd.slice(0, cut), u_op: odd.slice(cut),
    }), 20000, "bad unit text");
    const obxok = opUnit("r7-obxok", PRE7, "x", "x:" + sha256Hex(PRE7 + "x"));
    await submitAt(85, obxok);
    await triggerBounce(challenger, dispute, obPayload(85, obxok), 20000, "no fraud");
    await live(83, "honest descriptor");
    await live(84, "honest odd address");
    await live(85, "honest ops leaves (descriptor, x:{id}, '|' address)");
    console.log("65. P-opbind: Place as x:, p: margin rewritten, x unit as p: → frozen; honest descriptor / x:{id} / '|' address → 'no fraud', re-split → 'bad unit text'");

    // ---- 66. one fill per unit (未修复项 19): a second fill is fraud ------
    const f1x = f1.replace(`f:${isoUnit}:0:`, `f:${isoUnit}:1:`);
    const fsPayload = (h, u, f, i) => ({
      pred: "fsane", height: h, rollup: ROLLUP_ADDR, k: 0,
      trace_root: u.traceRoot, fills_root: u.fillsRoot, ops_root: u.opsRoot, units_root: ISO_UNITS_ROOT,
      units_proof: ISO_UNITS_PROOF, fill: f, fill_proof: merkle.getMerkleProof(u.tree, i), pre_wit: WIT_ROOT, // wit_root_85 (oneUnit commits no witRoot)
    });
    // The single-fill Place of 62 with a fabricated second fill (the
    // "make it multi-fill to escape P-claw / P-frame" route).
    const fab = clawUnit(P5, "r7-fab", op1, [f1, f1x], post5(49955000000, 0, 7000000000));
    await submitAt(86, fab);
    await triggerVerdict(challenger, book, fsPayload(86, fab, f1x, 1), 20000, "fabricated second fill (fsane idx)");
    await frozen(86, "fabricated second fill");
    const one = clawUnit(P5, "r7-one", op1, [f1], post5(40955000000, 0, 7000000000));
    await submitAt(86, one);
    await triggerBounce(challenger, book, fsPayload(86, one, f1, 0), 20000, "no fraud");
    await live(86, "honest single fill");
    console.log("66. one fill per unit: a fabricated idx-1 fill → frozen (P-fsane); honest idx-0 fill → 'no fraud'");

    // ---- 67. ADL price bound to clamp(mark, band) (未修复项 28) ----------
    // 61 (c)'s ADL (T long 1 @ 100k ADL'd onto M, keeper M) with the pre
    // meta's mark at 86k and the market's band leaf in the pre tree.
    const META8 = `meta:1:1:1000:500:5:100:0:8600000000000:0:0`;
    const BAND8 = `band:1:0:0`;
    const P8 = await clawSetup(87, "r7-p8", [
      acct(T, 15000000000), acct(M, 1000000000000), META8, BAND8,
      `pos:${T}:1:100000000:10000000000000:0:0`, `pos:${M}:1:-100000000:10000000000000:0:0`, END,
    ]);
    const post8 = (tc, mc) => [acct(T, tc), acct(M, mc), META8, BAND8, END];
    const bandFields = (P) => ({ band: BAND8, band_proof: P.proof(BAND8) });
    // clawPayload proves META1; this pre tree carries META8 instead.
    const soft = (P) => Object.assign({}, P, { proof: (l) => (P.pre.indexOf(l) < 0 ? null : P.proof(l)) });
    const clawPayload8 = (P, h, u) => Object.assign(clawPayload(soft(P), h, u, null), { pre_meta: META8, pre_meta_proof: P.proof(META8) }, bandFields(P));
    // ADL printed at 90k (above the 86k mark, no band): T keeps 4k more.
    const f8bad = `f:${isoUnit}:0:${T}:${M}:${LO}:${"0".repeat(64)}:1:9000000000000:100000000:9:1:2:0`;
    const adlBad = clawUnit(P8, "r7-adl-bad", op3, [f8bad], post8(4100000000, 1010900000000));
    await submitAt(88, adlBad);
    await triggerVerdict(challenger, claw, clawPayload8(P8, 88, adlBad), 20000, "ADL price off clamp(mark, band)");
    await frozen(88, "ADL price off the mark");
    const adlOk = clawUnit(P8, "r7-adl-ok", op3, [f3], post8(140000000, 1014860000000));
    await submitAt(88, adlOk);
    await triggerBounce(challenger, claw, clawPayload8(P8, 88, adlOk), 20000, "no fraud");
    await live(88, "honest ADL at the mark");
    console.log("67. ADL at 90k with mark 86k (band leaf proven) → frozen (P-claw); honest ADL at the mark → 'no fraud'");

    // ===================== ROUND 7b (fix/47-r7b) ===========================
    // Pool occupancy (ls - lf < 50): finalize the live drill heights first.
    {
      await network.timetravel({ shift: "3600s" });
      let s0 = await vars(rollup);
      for (let fh = Number(s0.last_finalized) + 1; fh <= 88; fh++) {
        await trigger(operator, rollup, { finalize: 1, height: fh }, 20000);
        s0 = await vars(rollup);
        if (Number(s0.last_finalized) !== fh) break;
      }
      console.log(`7b prep: ls=${s0.last_submitted} lf=${s0.last_finalized}`);
      if (Number(s0.last_finalized) < 45) throw new Error("7b prep: finalize stalled at " + s0.last_finalized);
    }
    const b64h = (x) => crypto.createHash("sha256").update(x, "utf8").digest("base64");
    // Internal Merkle node of a proof's first level, posed as a leaf
    // (R7-C1 / R7-C2 PoC, work/r7-review-oscr/mk_opbind_poc.js).
    const nodeAsLeaf = (tree, j) => {
      const full = merkle.getMerkleProof(tree, 2 * j);
      return { el: b64h(tree[2 * j]) + b64h(tree[2 * j + 1]), proof: { root: full.root, index: j, siblings: full.siblings.slice(1) } };
    };
    if (!merkle.verifyMerkleProof(nodeAsLeaf(["a:1", "b:2", "c:3", "d:4"], 0).el, nodeAsLeaf(["a:1", "b:2", "c:3", "d:4"], 0).proof))
      throw new Error("fixture: node-as-leaf must pass ocore verifyMerkleProof");
    const tsPayload = (h, tree, el, proof) => ({ pred: "tsize", height: h, rollup: ROLLUP_ADDR, tree, el, el_proof: proof });

    // ---- 68. R7-C1: node-as-leaf can no longer frame an honest batch ------
    // A 4-unit honest batch of x units (ops leaf x:{id}, id = sha256(text)).
    const texts4 = [0, 1, 2, 3].map((i) => "mnu3|" + "4f44583101" + "ab".repeat(32) + "12" + "cd".repeat(40 + i) + "|");
    const ids4 = texts4.map((t) => sha256Hex(t + "x"));
    const ops4 = ids4.map((id) => "x:" + id);
    const b4 = {
      opsRoot: merkle.getMerkleRoot(ops4), unitsRoot: merkle.getMerkleRoot(ids4),
      traceRoot: merkle.getMerkleRoot([0, 1, 2, 3].map((i) => b64h("r7b-trace-" + i))), unitCount: 4,
    };
    const ob4 = (h, k, op, opsProof) => ({
      pred: "opbind", height: h, rollup: ROLLUP_ADDR, k, ops_root: b4.opsRoot, units_root: b4.unitsRoot,
      op, ops_proof: opsProof, units_proof: merkle.getMerkleProof(ids4, k), u_pre: texts4[k], u_op: "x",
    });
    await submitAt(89, b4);
    await triggerBounce(challenger, dispute, ob4(89, 1, ops4[1], merkle.getMerkleProof(ops4, 1)), 20000, "no fraud");
    const nal = nodeAsLeaf(ops4, 0);
    // Before round 7b this exact payload verdicted (op != x:{id}).
    await triggerBounce(challenger, dispute, ob4(89, 0, nal.el, nal.proof), 20000, "bad proof depth");
    await triggerBounce(challenger, xframe, tsPayload(89, "ops", ops4[2], merkle.getMerkleProof(ops4, 2)), 20000, "no fraud");
    await triggerBounce(challenger, xframe, tsPayload(89, "ops", nal.el, nal.proof), 20000, "bad element proof");
    await triggerBounce(challenger, xframe, tsPayload(89, "units", ids4[3], merkle.getMerkleProof(ids4, 3)), 20000, "no fraud");
    await live(89, "honest 4-unit batch vs node-as-leaf");
    // A tree larger than the committed unit_count (honest-depth proofs would
    // all bounce) is P-tsize fraud.
    const ops5 = ops4.concat(["x:" + sha256Hex("r7b-extra")]);
    await submitAt(90, Object.assign({}, b4, { opsRoot: merkle.getMerkleRoot(ops5) }));
    await triggerBounce(challenger, dispute, Object.assign(ob4(90, 1, ops5[1], merkle.getMerkleProof(ops5, 1)), { ops_root: merkle.getMerkleRoot(ops5) }), 20000, "bad proof depth");
    await triggerVerdict(challenger, xframe, tsPayload(90, "ops", ops5[1], merkle.getMerkleProof(ops5, 1)), 20000, "P-tsize: 5 ops leaves under unit_count 4");
    await frozen(90, "ops tree larger than unit_count");
    await submitAt(90, Object.assign({}, b4, { witRoot: P5.wit }));
    await live(90, "honest resubmit");
    console.log("68. R7-C1: node-as-leaf op (P-opbind) / element (P-tsize) → 'bad proof depth' / 'bad element proof'; honest 4-unit batch → 'no fraud'; 5 ops leaves under unit_count 4 → frozen (P-tsize)");

    // ---- 69. R7-C2 + fsane sentinel: node-as-leaf vs P-claw, n: vs P-fsane --
    // The honest single-fill Place of 62 (ok5) as unit 0 of a 4-unit batch.
    const ops4c = [op1].concat(ops4.slice(1));
    const ids4c = [isoUnit].concat(ids4.slice(1));
    const trace4c = [ok5.wit].concat([1, 2, 3].map((i) => b64h("r7b-ctrace-" + i)));
    const c4 = Object.assign({}, ok5, {
      ops: ops4c, opsRoot: merkle.getMerkleRoot(ops4c), unitsRoot: merkle.getMerkleRoot(ids4c),
      trace: trace4c, traceRoot: merkle.getMerkleRoot(trace4c), unitCount: 4,
    });
    const claw4 = () => Object.assign(clawPayload(P5, 91, c4, MORD), { units_root: c4.unitsRoot, units_proof: merkle.getMerkleProof(ids4c, 0) });
    await submitAt(91, c4);
    await triggerBounce(challenger, claw, claw4(), 20000, "no fraud");
    const naop = nodeAsLeaf(ops4c, 0);
    // Before round 7b: `$op` is neither p: nor L: → immediate verdict.
    await triggerBounce(challenger, claw, Object.assign(claw4(), { op: naop.el, ops_proof: naop.proof }), 20000, "bad proof depth");
    // The honest `n:1` length sentinel is not a fill (the old shape rule
    // verdicted every batch with a fill).
    await triggerBounce(challenger, book, {
      pred: "fsane", height: 91, rollup: ROLLUP_ADDR, k: 0,
      trace_root: c4.traceRoot, fills_root: c4.fillsRoot, ops_root: c4.opsRoot, units_root: c4.unitsRoot,
      fill: c4.tree[1], fill_proof: merkle.getMerkleProof(c4.tree, 1), pre_wit: P5.wit,
    }, 20000, "bad fill proof");
    await live(91, "honest claw unit vs node-as-leaf / sentinel");
    console.log("69. R7-C2: node-as-leaf op (P-claw) → 'bad proof depth', honest claw → 'no fraud'; fills sentinel n:1 (P-fsane) → 'bad fill proof'");

    // ---- 70. R7-C3: bystander frame of x: units (P-xframe) ---------------
    const BAND1 = "band:1:0:0";
    const posM9 = `pos:${M}:1:100000000:10000000000000:0:0`;
    const tA = (c, p) => `acct:${T}:${c}:${p}:0`;
    const mA = (c) => `acct:${M}:${c}:0:0`;
    const P9 = await clawSetup(92, "r7b-p9", [tA(1000000000, 60000), mA(2000000000), META1, BAND1, posM9, END]);
    const xText = (tag) => "mnu3|" + "4f44583101" + "ab".repeat(32) + tag + T + "00".repeat(8) + "|";
    const xUnit = (tag, name, post) => {
      const uPre = xText(tag);
      const id = sha256Hex(uPre + "x");
      const units = pad2([id], name + "-units");
      return Object.assign(oneUnit(name, "x:" + id, post), { id, uPre, units, unitsRoot: merkle.getMerkleRoot(units), witRoot: P9.wit });
    };
    const xfBase = (pred, h, u) => ({
      pred, height: h, rollup: ROLLUP_ADDR, k: 0, trace_root: u.traceRoot, ops_root: u.opsRoot, units_root: u.unitsRoot,
      op: u.op, ops_proof: merkle.getMerkleProof(u.ops, 0), pre_wit: P9.wit, post_wit: u.wit, post_proof: merkle.getMerkleProof(u.trace, 0),
      unit: u.id, units_proof: merkle.getMerkleProof(u.units, 0), u_pre: u.uPre,
    });
    const xfAcct = (h, u, a) => {
      const post = u.post.find((l) => l.startsWith(`acct:${a}:`));
      const pre = P9.pre.find((l) => l.startsWith(`acct:${a}:`));
      return Object.assign(xfBase("xframe", h, u), { post_acct: post, post_acct_proof: u.leafProof(post), pre_acct: pre, pre_acct_proof: P9.proof(pre) });
    };
    // R8-C6: "no position in the op's market" (xText reports market 0).
    const noPos = (a) => {
      const i = P9.pre.findIndex((l) => l > `pos:${a}:0:`);
      return { fmkt: 0, pleft: P9.pre[i - 1], pleft_proof: P9.proof(P9.pre[i - 1]), pright: P9.pre[i], pright_proof: P9.proof(P9.pre[i]) };
    };
    const xfLeaf = (pred, h, u, leaf, ins) => Object.assign(xfBase(pred, h, u), {
      leaf, ins, leaf_proof: ins ? u.leafProof(leaf) : P9.proof(leaf),
    }, absentIn(ins ? P9.pre : u.post, leaf));
    // (a) StakeOracle (0e) by T credits bystander M 1e6 USD.
    const mint = xUnit("0e", "r7b-mint", [tA(1000000000, 10000), mA(1002000000000), META1, BAND1, posM9, END]);
    await submitAt(93, mint);
    await triggerVerdict(challenger, xframe, xfAcct(93, mint, M), 20000, "P-xframe: bystander credit in a Stake unit");
    await frozen(93, "bystander credit in an x: unit");
    // (b) a position rewritten in an x: unit.
    const posLie = xUnit("0e", "r7b-poslie", [tA(1000000000, 10000), mA(2000000000), META1, BAND1, `pos:${M}:1:200000000:10000000000000:0:0`, END]);
    await submitAt(93, posLie);
    await triggerVerdict(challenger, xframe, xfLeaf("xframe", 93, posLie, posM9, false), 20000, "P-xframe: position rewritten in a Stake unit");
    await frozen(93, "position rewritten in an x: unit");
    // (c) ReportPrice (06): collateral of an account with NO position moved.
    const fundLie = xUnit("06", "r7b-fundlie", [tA(1500000000, 60000), mA(2000000000), META1, BAND1, posM9, END]);
    await submitAt(93, fundLie);
    await triggerBounce(challenger, xframe, xfAcct(93, fundLie, T), 20000, "no fraud");
    await triggerVerdict(challenger, xframe, Object.assign(xfAcct(93, fundLie, T), noPos(T)), 20000, "P-xframe: funding paid to an account without a position");
    await frozen(93, "funding to an account without a position");
    // Honest: the Stake moves only T's own PERP (60000 -> 10000).
    const stakeOk = xUnit("0e", "r7b-stake", [tA(1000000000, 10000), mA(2000000000), META1, BAND1, posM9, END]);
    await submitAt(93, stakeOk);
    await triggerBounce(challenger, xframe, xfAcct(93, stakeOk, T), 20000, "no fraud");
    await triggerBounce(challenger, xframe, xfAcct(93, stakeOk, M), 20000, "no fraud");
    await live(93, "honest Stake unit");
    // Honest ReportPrice: funding moves the position holder M's collateral
    // (every x: unit here commits P9's root as wit_root, so h94's pre tree
    // is P9 again).
    const fundOk = xUnit("06", "r7b-fundok", [tA(1000000000, 60000), mA(1999000000), META1, BAND1, posM9, END]);
    await submitAt(94, fundOk);
    await triggerBounce(challenger, xframe, xfAcct(94, fundOk, M), 20000, "no fraud");
    await live(94, "honest funding to a position holder");
    console.log("70. R7-C3: bystander credit / position rewrite in a Stake unit, funding to a position-less account in a ReportPrice unit → frozen (P-xframe); honest Stake (own PERP), funding to a position holder → 'no fraud'");

    // ---- 71. R7-H2: band: / meta: frame (P-mframe) and P-noband ----------
    const P9b = P9;
    const bandLie = xUnit("0e", "r7b-bandlie", [tA(1000000000, 10000), mA(2000000000), META1, "band:1:0:5", posM9, END]);
    await submitAt(95, bandLie);
    await triggerVerdict(challenger, mframe, xfLeaf("mframe", 95, bandLie, BAND1, false), 20000, "P-mframe: band rewritten");
    await frozen(95, "band rewritten");
    const noBand = xUnit("0e", "r7b-noband", [tA(1000000000, 10000), mA(2000000000), META1, posM9, END]);
    await submitAt(95, noBand);
    const nbi = noBand.post.findIndex((l) => l > "band:1:");
    await triggerVerdict(challenger, mframe, Object.assign(xfBase("noband", 95, noBand), {
      meta: META1, meta_proof: noBand.leafProof(META1),
      left: noBand.post[nbi - 1], left_proof: noBand.leafProof(noBand.post[nbi - 1]),
      right: noBand.post[nbi], right_proof: noBand.leafProof(noBand.post[nbi]),
    }), 20000, "P-noband: market without its band");
    await frozen(95, "band deleted");
    const META1m = "meta:1:1:1000:500:5:100:0:105:0:0";
    const markLie = xUnit("0e", "r7b-marklie", [tA(1000000000, 10000), mA(2000000000), META1m, BAND1, posM9, END]);
    const metaPair = (h, u) => Object.assign(xfBase("mframe", h, u), {
      pre_meta: META1, pre_meta_proof: P9b.proof(META1), post_meta: META1m, post_meta_proof: u.leafProof(META1m),
    });
    await submitAt(95, markLie);
    await triggerVerdict(challenger, mframe, metaPair(95, markLie), 20000, "P-mframe: mark moved by a Stake");
    await frozen(95, "mark moved outside a price op");
    // R8-H1: a ReportPrice moves only its own market's mark (u32 LE after
    // the oracle account), here market 1, within 10 %.
    const markOk = Object.assign(xUnit("06", "r7b-markok", [tA(1000000000, 60000), mA(2000000000), META1m, BAND1, posM9, END]), {});
    {
      const uPre = "mnu3|" + "4f44583101" + "ab".repeat(32) + "06" + T + "01000000" + "6900000000000000" + "|";
      markOk.uPre = uPre;
      markOk.id = sha256Hex(uPre + "x");
      const mo = oneUnit("r7b-markok", "x:" + markOk.id, markOk.post);
      Object.assign(markOk, mo, { units: pad2([markOk.id], "r7b-markok-units") });
      markOk.unitsRoot = merkle.getMerkleRoot(markOk.units);
    }
    await submitAt(95, markOk);
    await triggerBounce(challenger, mframe, metaPair(95, markOk), 20000, "no fraud");
    await live(95, "honest mark update by ReportPrice");
    console.log("71. R7-H2: band rewritten / band deleted / mark moved by a Stake → frozen (P-mframe / P-noband); mark moved by ReportPrice → 'no fraud'");

    // ---- 72. R7b-N2: oracle bond returned at the batch boundary ---------
    // prune_oracle_unbonding runs at batch commit, after the batch's last
    // trace leaf, so the returned bond (+ORACLE_BOND_PERP = 50000) first
    // shows in the NEXT batch's unit 0 post tree, judged against
    // wit_root_{h-1} (here P9: T holds 60000 PERP). Honest whatever op unit
    // 0 carries: the acct: frame is P-xframe's now (P-frame on dispute_bind
    // refuses acct: leaves), which allows exactly +50000 at k == 0.
    const n2 = (name, op, post, extra) => Object.assign(oneUnit(name, op, post), { witRoot: P9.wit }, extra || {});
    const tRel = (c, w) => `acct:${T}:${c}:110000:${w || 0}`;
    const cOp72 = `c:${M}:${"6c".repeat(32)}`;
    const keep72 = [mA(2000000000), META1, BAND1, posM9, END];
    // (a) lies at h96: T credited one PERP unit past the bond (c:), and the
    // op account's own PERP moved by a w: (only D:/W: move PERP).
    const over72 = n2("r7c-over", cOp72, [`acct:${T}:1000000000:110001:0`].concat(keep72));
    await submitAt(96, over72);
    await triggerVerdict(challenger, xframe, xfNx(96, over72, P9.pre, P9.wit, T), 20000, "R7b-N2: bystander PERP past the bond (c:)");
    await frozen(96, "bystander PERP past the bond");
    const wOp72 = `w:${T}:100:1`;
    const wLie = n2("r7c-wlie", wOp72, [`acct:${T}:999999900:120000:100`].concat(keep72));
    await submitAt(96, wLie);
    await triggerVerdict(challenger, xframe, xfNx(96, wLie, P9.pre, P9.wit, T), 20000, "R7b-N2: op account PERP moved by a w:");
    await frozen(96, "op account PERP under w:");
    // (b) honest c: of M at h96 with T's bond returned.
    const cOk = n2("r7c-cok", cOp72, [tRel(1000000000)].concat(keep72));
    await submitAt(96, cOk);
    await triggerBounce(challenger, xframe, xfNx(96, cOk, P9.pre, P9.wit, T), 20000, "no fraud");
    await triggerBounce(challenger, xframe, xfNx(96, cOk, P9.pre, P9.wit, M), 20000, "no fraud");
    await triggerBounce(challenger, bindAa, Object.assign({
      pred: "frame", height: 96, rollup: ROLLUP_ADDR, k: 0,
      trace_root: cOk.traceRoot, ops_root: cOk.opsRoot, op: cOk.op, ops_proof: merkle.getMerkleProof(cOk.ops, 0),
      pre_wit: P9.wit, post_wit: cOk.wit, post_proof: merkle.getMerkleProof(cOk.trace, 0),
      leaf: tA(1000000000, 60000), ins: false, leaf_proof: P9.proof(tA(1000000000, 60000)),
    }, absentIn(cOk.post, tA(1000000000, 60000))), 20000, "bad leaf");
    await live(96, "honest c: with the bond returned at unit 0");
    // (c) honest zero-fill Place of M at h97 (fill_count 0) with the bond.
    const pOp72 = `p:${M}:1:0:8000000000000:100000000:0:0:0:0`;
    const mOrd72 = `ord:${"ec".repeat(32)}:1:0:8000000000000:9:100000000:${M}:0:0`;
    const pOk = n2("r7c-pok", pOp72, [tRel(1000000000), mOrd72].concat(keep72), { unitsRoot: ISO_UNITS_ROOT });
    await submitAt(97, pOk);
    const pEv = { units_root: ISO_UNITS_ROOT, unit: isoUnit, units_proof: ISO_UNITS_PROOF, fills_root: FILLS_ROOT,
      pre_meta: META1, pre_meta_proof: P9.proof(META1) };
    await triggerBounce(challenger, xframe, xfNx(97, pOk, P9.pre, P9.wit, T, pEv), 20000, "no fraud");
    await live(97, "honest zero-fill Place with the bond returned at unit 0");
    // (d) honest w: by the oracle T itself at h98 (bond + its withdrawal).
    const wOk = n2("r7c-wok", wOp72, [tRel(999999900, 100)].concat(keep72));
    await submitAt(98, wOk);
    await triggerBounce(challenger, xframe, xfNx(98, wOk, P9.pre, P9.wit, T), 20000, "no fraud");
    await live(98, "honest w: by the oracle with its bond returned at unit 0");
    console.log("72. R7b-N2: bond returned at unit 0 under c: / p: / w: → 'no fraud' (P-xframe; P-frame refuses acct: leaves); PERP past the bond, op-account PERP under w: → frozen");

    // ===================== ROUND 8 (fix/47-r8) =============================
    // Pool occupancy (ls - lf < 50): finalize what we can first.
    {
      await network.timetravel({ shift: "3600s" });
      let s0 = await vars(rollup);
      for (let fh = Number(s0.last_finalized) + 1; fh <= 98; fh++) {
        await trigger(operator, rollup, { finalize: 1, height: fh }, 20000);
        s0 = await vars(rollup);
        if (Number(s0.last_finalized) !== fh) break;
      }
      console.log(`r8 prep: ls=${s0.last_submitted} lf=${s0.last_finalized}`);
    }
    const leHex = (v, bytes) => {
      let x = BigInt(v);
      if (x < 0n) x += 1n << BigInt(8 * bytes);
      let o = "";
      for (let i = 0; i < bytes; i++) { o += Number(x & 255n).toString(16).padStart(2, "0"); x >>= 8n; }
      return o;
    };
    const xTextA = (tag, acct, rest) => "mnu3|" + "4f44583101" + "ab".repeat(32) + tag + acct + rest + "|";
    const xUnitP = (P, tag, acct, rest, name, post) => {
      const uPre = xTextA(tag, acct, rest);
      const id = sha256Hex(uPre + "x");
      const units = pad2([id], name + "-units");
      return Object.assign(oneUnit(name, "x:" + id, post), { id, uPre, units, unitsRoot: merkle.getMerkleRoot(units), witRoot: P.wit });
    };
    const xfB = (pred, h, P, u, noText) => Object.assign({
      pred, height: h, rollup: ROLLUP_ADDR, k: 0, trace_root: u.traceRoot, ops_root: u.opsRoot, units_root: u.unitsRoot,
      op: u.op, ops_proof: merkle.getMerkleProof(u.ops, 0), pre_wit: P.wit, post_wit: u.wit, post_proof: merkle.getMerkleProof(u.trace, 0),
    }, noText ? {} : { unit: u.id, units_proof: merkle.getMerkleProof(u.units, 0), u_pre: u.uPre });
    const xfA8 = (h, P, u, a, extra) => {
      const post = u.post.find((l) => l.startsWith(`acct:${a}:`));
      const pre = P.pre.find((l) => l.startsWith(`acct:${a}:`));
      const d = Object.assign(xfB("xframe", h, P, u), { post_acct: post, post_acct_proof: u.leafProof(post) });
      if (pre) Object.assign(d, { pre_acct: pre, pre_acct_proof: P.proof(pre) });
      else Object.assign(d, absentIn(P.pre, `acct:${a}:`));
      return Object.assign(d, extra || {});
    };
    // Prefix absence [lo, hi) in a sorted tree, renamed to l / r.
    const gap = (tree, lo, hi, l, r) => {
      const i = tree.findIndex((x) => x >= lo);
      if (i < 0 || tree[i] < hi) throw new Error("fixture: prefix present " + lo);
      const o = {};
      if (i === 0) { o[l] = tree[0]; o[l + "_proof"] = merkle.getMerkleProof(tree, 0); return o; }
      o[l] = tree[i - 1]; o[l + "_proof"] = merkle.getMerkleProof(tree, i - 1);
      o[r] = tree[i]; o[r + "_proof"] = merkle.getMerkleProof(tree, i);
      return o;
    };
    const metaP = (h, P, u, m0, m1, noText) => Object.assign(xfB("mframe", h, P, u, noText), {
      pre_meta: m0, pre_meta_proof: P.proof(m0), post_meta: m1, post_meta_proof: u.leafProof(m1),
    });
    const OBT = `obond:${T}:0`;
    const P10 = await clawSetup(99, "r8-p10", [tA(1000000000, 60000), mA(2000000000), META1, BAND1, posM9, OBT, END]);
    const keep10 = [mA(2000000000), BAND1, posM9, OBT, END];
    const rp = (mkt, px) => leHex(mkt, 4) + leHex(px, 8);

    // ---- 73. R8-C1: P-mframe requires the unit text of an x: op ----------
    const META1r = "meta:1:1:1000:500:5:100:0:105:0:0";
    const rpOk = xUnitP(P10, "06", T, rp(1, 105), "r8-rpok", [tA(1000000000, 60000), META1r].concat(keep10));
    await submitAt(100, rpOk);
    await triggerBounce(challenger, mframe, metaP(100, P10, rpOk, META1, META1r, true), 20000, "bad unit");
    await triggerBounce(challenger, mframe, metaP(100, P10, rpOk, META1, META1r), 20000, "no fraud");
    await live(100, "honest ReportPrice with u_pre omitted");
    const META1k = "meta:1:1:1000:500:5:200:0:100:0:0";
    const fpOk = xUnitP(P10, "0d", T, leHex(7, 8), "r8-fpok", [tA(1000000000, 60000), META1k].concat(keep10));
    await submitAt(101, fpOk);
    await triggerBounce(challenger, mframe, metaP(101, P10, fpOk, META1, META1k, true), 20000, "bad unit");
    await triggerBounce(challenger, mframe, metaP(101, P10, fpOk, META1, META1k), 20000, "no fraud");
    await live(101, "honest FinalizeProposal with u_pre omitted");
    console.log("73. R8-C1: honest ReportPrice / FinalizeProposal judged without their unit text → 'bad unit'; with it → 'no fraud'");

    // ---- 74. R8-C5 (interim): FinalizeProposal changes one legal key ----
    const META1x = "meta:1:1:1000:500:5:10000:0:100:0:0";
    const fpLie = xUnitP(P10, "0d", T, leHex(999, 8), "r8-fplie", [tA(1000000000, 60000), META1x].concat(keep10));
    await submitAt(102, fpLie);
    await triggerVerdict(challenger, mframe, metaP(102, P10, fpLie, META1, META1x), 20000, "R8-C5: keeper 100 -> 10000 under a (rejected) FinalizeProposal");
    await frozen(102, "illegal keeper via FinalizeProposal");
    const META1t = "meta:1:1:1000:600:6:100:0:100:0:0";
    const fpTwo = xUnitP(P10, "0d", T, leHex(998, 8), "r8-fptwo", [tA(1000000000, 60000), META1t].concat(keep10));
    await submitAt(102, fpTwo);
    await triggerVerdict(challenger, mframe, metaP(102, P10, fpTwo, META1, META1t), 20000, "R8-C5: two keys under one FinalizeProposal");
    await frozen(102, "two keys via FinalizeProposal");
    await submitAt(102, fpOk);
    await live(102, "honest resubmit");
    console.log("74. R8-C5: keeper 10000 / two keys under a FinalizeProposal → frozen (P-mframe)");

    // ---- 75. R8-C6: funding only for holders of the reported market ------
    const mCredit = (tag, acct, rest, name) => xUnitP(P10, tag, acct, rest, name,
      [tA(1000000000, 60000), mA(1000000002000000000), META1].concat(keep10.filter((l) => !l.startsWith(`acct:${M}:`))));
    const rejRp = mCredit("06", K, rp(1, 100), "r8-rejrp");
    await submitAt(103, rejRp);
    await triggerBounce(challenger, xframe, xfA8(103, P10, rejRp, M), 20000, "no fraud");
    await triggerVerdict(challenger, xframe, xfA8(103, P10, rejRp, M, gap(P10.pre, `obond:${K}:`, `obond:${K};`, "bleft", "bright")), 20000, "R8-C6: credit under a ReportPrice of an unbonded oracle");
    await frozen(103, "credit under a rejected ReportPrice");
    const m2Rp = mCredit("06", T, rp(2, 100), "r8-m2rp");
    await submitAt(103, m2Rp);
    await triggerVerdict(challenger, xframe, xfA8(103, P10, m2Rp, M, Object.assign({ fmkt: 2 }, gap(P10.pre, `pos:${M}:2:`, `pos:${M}:2;`, "pleft", "pright"))), 20000, "R8-C6: credit to a holder of another market");
    await frozen(103, "credit to a holder of another market");
    const xpReg = mCredit("11", T, rp(1, 100) + "01", "r8-xpreg");
    await submitAt(103, xpReg);
    await triggerVerdict(challenger, xframe, xfA8(103, P10, xpReg, M, { fmkt: 1, fmeta: META1, fmeta_proof: P10.proof(META1) }), 20000, "R8-C6: UpdateExternalPrice on a regular market moved collateral");
    await frozen(103, "external price on a regular market");
    const fundOk8 = xUnitP(P10, "06", T, rp(1, 100), "r8-fundok", [tA(1000000000, 60000), mA(1999000000), META1].concat(keep10.filter((l) => !l.startsWith(`acct:${M}:`))));
    await submitAt(103, fundOk8);
    await triggerBounce(challenger, xframe, xfA8(103, P10, fundOk8, M, Object.assign({ fmkt: 1 }, { fmeta: META1, fmeta_proof: P10.proof(META1) })), 20000, "no fraud");
    await live(103, "honest funding to a holder of the reported market");
    console.log("75. R8-C6: credit under an unbonded oracle's ReportPrice / to another market's holder / under an 11 on a regular market → frozen; honest funding → 'no fraud'");

    // ---- 76. R8-H1: the mark moves only in its op's market, bounded ------
    const META1far = "meta:1:1:1000:500:5:100:0:120:0:0";
    const rpFar = xUnitP(P10, "06", T, rp(1, 120), "r8-rpfar", [tA(1000000000, 60000), META1far].concat(keep10));
    await submitAt(104, rpFar);
    await triggerVerdict(challenger, mframe, metaP(104, P10, rpFar, META1, META1far), 20000, "R8-H1: ReportPrice moved the mark 20 %");
    await frozen(104, "mark +20 %");
    const rpM2 = xUnitP(P10, "06", T, rp(2, 105), "r8-rpm2", [tA(1000000000, 60000), META1r].concat(keep10));
    await submitAt(104, rpM2);
    await triggerVerdict(challenger, mframe, metaP(104, P10, rpM2, META1, META1r), 20000, "R8-H1: ReportPrice of market 2 moved market 1");
    await frozen(104, "another market's mark");
    const xpMark = xUnitP(P10, "11", T, rp(1, 105) + "01", "r8-xpmark", [tA(1000000000, 60000), META1r].concat(keep10));
    await submitAt(104, xpMark);
    await triggerVerdict(challenger, mframe, metaP(104, P10, xpMark, META1, META1r), 20000, "R8-H1: UpdateExternalPrice moved the mark");
    await frozen(104, "mark under an 11");
    const rpK = xUnitP(P10, "06", K, rp(1, 105), "r8-rpk", [tA(1000000000, 60000), META1r].concat(keep10));
    await submitAt(104, rpK);
    await triggerVerdict(challenger, mframe, Object.assign(metaP(104, P10, rpK, META1, META1r), gap(P10.pre, `obond:${K}:`, `obond:${K};`, "bleft", "bright")), 20000, "R8-H1: unbonded oracle moved the mark");
    await frozen(104, "unbonded oracle's mark");
    await submitAt(104, rpOk);
    await live(104, "honest resubmit");
    console.log("76. R8-H1: ReportPrice +20 % / of another market / by an unbonded oracle, UpdateExternalPrice → frozen (P-mframe)");

    // ---- 77. R8-C4: an x: op moves its own PERP only by its exact amount --
    const commitMint = xUnitP(P10, "12", T, "cd".repeat(32) + leHex(5, 8), "r8-mint", [tA(1000000000, 1000000000000), META1].concat(keep10));
    await submitAt(105, commitMint);
    await triggerVerdict(challenger, xframe, xfA8(105, P10, commitMint, T), 20000, "R8-C4: operator Commit minted its own PERP");
    await frozen(105, "PERP minted by a Commit");
    const slashOk = xUnitP(P10, "10", M, T + leHex(1, 4), "r8-slash", [tA(1000000000, 60000), `acct:${M}:2000000000:25000:0`, META1, BAND1, posM9, END]);
    await submitAt(105, slashOk);
    await triggerBounce(challenger, xframe, xfA8(105, P10, slashOk, M), 20000, "no fraud");
    await triggerBounce(challenger, mframe, Object.assign(xfB("mframe", 105, P10, slashOk), {
      leaf: OBT, ins: false, leaf_proof: P10.proof(OBT),
    }, absentIn(slashOk.post, OBT)), 20000, "no fraud");
    await live(105, "honest SlashOracle");
    console.log("77. R8-C4: Commit minting the op account's PERP → frozen (P-xframe); honest Slash (+25000, bond leaf removed) → 'no fraud'");

    // ---- 78. R8-H2: the k == 0 bond allowance needs an expiring bond ------
    // T unstaked earlier: obond:T:100 (unlock 100 <= h - 1 at h107).
    const OBU = `obond:${T}:100`;
    const P11 = await clawSetup(106, "r8-p11", [tA(1000000000, 60000), mA(2000000000), META1, BAND1, posM9, OBU, END]);
    const keep11 = [META1, BAND1, posM9, END];
    const vote = (name, post) => xUnitP(P11, "0c", M, leHex(1, 8) + "01", name, post);
    const relOk = vote("r8-relok", [tA(1000000000, 110000), mA(2000000000)].concat(keep11));
    await submitAt(107, relOk);
    await triggerBounce(challenger, xframe, xfA8(107, P11, relOk, T, { obond: OBU, obond_proof: P11.proof(OBU) }), 20000, "no fraud");
    await triggerBounce(challenger, mframe, Object.assign(xfB("mframe", 107, P11, relOk), {
      leaf: OBU, ins: false, leaf_proof: P11.proof(OBU),
    }, absentIn(relOk.post, OBU)), 20000, "no fraud");
    await live(107, "honest bond release at unit 0");
    const relM = vote("r8-relm", [tA(1000000000, 110000), `acct:${M}:2000000000:50000:0`].concat(keep11));
    await submitAt(108, relM);
    await triggerBounce(challenger, xframe, xfA8(108, P11, relM, M), 20000, "no fraud");
    await triggerVerdict(challenger, xframe, xfA8(108, P11, relM, M, gap(P11.pre, `obond:${M}:`, `obond:${M};`, "oleft", "oright")), 20000, "R8-H2: +50000 at k == 0 to an account without a bond");
    await frozen(108, "bond allowance without a bond");
    const relKeep = vote("r8-relkeep", [tA(1000000000, 110000), mA(2000000000), OBU].concat(keep11));
    await submitAt(108, relKeep);
    await triggerVerdict(challenger, mframe, Object.assign(xfB("mframe", 108, P11, relKeep), {
      leaf: OBU, keep: true, leaf_proof: P11.proof(OBU), keep_proof: relKeep.leafProof(OBU),
    }), 20000, "R8-H2: expired bond kept after its release");
    await frozen(108, "expired bond kept");
    const OBM = `obond:${M}:0`;
    const voteBond = vote("r8-votebond", [tA(1000000000, 110000), mA(2000000000), OBM].concat(keep11));
    await submitAt(108, voteBond);
    await triggerVerdict(challenger, mframe, Object.assign(xfB("mframe", 108, P11, voteBond), {
      leaf: OBM, ins: true, leaf_proof: voteBond.leafProof(OBM),
    }, absentIn(P11.pre, OBM)), 20000, "R8-H2: a Vote created a bond");
    await frozen(108, "bond created by a Vote");
    await submitAt(108, relOk);
    await live(108, "honest resubmit");
    console.log("78. R8-H2: +50000 without a bond, expired bond kept, bond created by a Vote → frozen; honest release → 'no fraud'");

    // ---- 79. R8-C2: units-tree index aliasing can no longer hide a fill ---
    // Two single-fill Places (units 0 and 1) and a w: (unit 2); unit 1's
    // maker M1 is exempt; a fright from unit 0 posed at index 0 + 4 > k.
    {
      const T0 = "71".repeat(32), M0 = "72".repeat(32), T1 = "73".repeat(32), M1 = "74".repeat(32);
      const ac = (a, c) => `acct:${a}:${c}:0:0`;
      const pz = (a, q) => `pos:${a}:1:${q}:100:0:0`;
      const base = [META1, BAND1, END];
      const w0 = [...base, ac(T0, 1000), ac(M0, 1000), ac(T1, 1000), ac(M1, 1000), pz(M1, -5)].sort();
      const w1 = [...base, ac(T0, 990), ac(M0, 1010), ac(T1, 1000), ac(M1, 1000), pz(M1, -5), pz(T0, 1), pz(M0, -1)].sort();
      const w2 = [...base, ac(T0, 990), ac(M0, 1010), ac(T1, 980), ac(M1, 1020), pz(M1, -6), pz(T0, 1), pz(M0, -1), pz(T1, 1)].sort();
      const ops = [`p:${T0}:1:0:100:1:0:0:1:1`, `p:${T1}:1:0:100:1:0:0:1:1`, `w:${"79".repeat(32)}:0:1`];
      const U = ops.map((o, i) => sha256Hex("r8-alias-unit" + i));
      const fl = (u, t, m) => `f:${u}:0:${t}:${m}:${"7a".repeat(32)}:${"7b".repeat(32)}:1:100:1:1:0:0:0`;
      const fills = [fl(U[0], T0, M0), fl(U[1], T1, M1), "n:2"];
      const roots = [w0, w1, w2, w2].map((w) => merkle.getMerkleRoot(w));
      const trace = roots.slice(1);
      const A = { opsRoot: merkle.getMerkleRoot(ops), traceRoot: merkle.getMerkleRoot(trace), unitsRoot: merkle.getMerkleRoot(U),
        fillsRoot: merkle.getMerkleRoot(fills), fillCount: 2, unitCount: 3, witRoot: roots[3] };
      await submitAt(109, Object.assign(oneUnit("r8-alias-pre", "x:" + sha256Hex("r8-alias-pre"), [DEP_PRE]), { witRoot: roots[0] }));
      await submitAt(110, A);
      const pf = (w, l) => merkle.getMerkleProof(w, w.indexOf(l));
      const fu = merkle.getMerkleProof(U, 0);
      const common = { height: 110, rollup: ROLLUP_ADDR, k: 1, trace_root: A.traceRoot, ops_root: A.opsRoot, units_root: A.unitsRoot,
        fills_root: A.fillsRoot, op: ops[1], ops_proof: merkle.getMerkleProof(ops, 1), post_wit: roots[2], post_proof: merkle.getMerkleProof(trace, 1),
        pre_wit: roots[1], pre_proof: merkle.getMerkleProof(trace, 0), unit: U[1], units_proof: merkle.getMerkleProof(U, 1),
        pre_meta: META1, pre_meta_proof: pf(w1, META1), fright: fills[0], fright_proof: merkle.getMerkleProof(fills, 0) };
      const xa = Object.assign({ pred: "xframe" }, common, { post_acct: ac(M1, 1020), post_acct_proof: pf(w2, ac(M1, 1020)),
        pre_acct: ac(M1, 1000), pre_acct_proof: pf(w1, ac(M1, 1000)) });
      await triggerBounce(challenger, xframe, Object.assign({}, xa, { fright_up: Object.assign({}, fu, { index: fu.index + 4 }) }), 20000, "no fraud");
      await triggerBounce(challenger, xframe, Object.assign({}, xa, { fright_up: fu }), 20000, "no fraud");
      const L = pz(M1, -5);
      const fa = Object.assign({ pred: "frame" }, common, { leaf: L, leaf_proof: pf(w1, L), ins: false }, absentIn(w2, L));
      await triggerBounce(challenger, bindAa, Object.assign({}, fa, { fright_up: Object.assign({}, fu, { index: fu.index + 4 }) }), 20000, "no fraud");
      await live(110, "honest two-fill batch vs aliased fills evidence");
    }
    console.log("79. R8-C2: fright_up index aliased past k (P-xframe / P-frame) on an honest two-fill batch → 'no fraud'");

    // ---- 80. R8-C3: a PERP-only holder's acct: leaf (credited D:) --------
    {
      const FR = "cc".repeat(32);
      const chalAddr = await challenger.getAddress();
      const dUnit = (await trigger(challenger, vault, { deposit_perp: 1, account: FR }, 20000)).unit;
      const dOp = `D:${FR}:20000:${chalAddr}:${dUnit}`;
      const okLeaf = `acct:${FR}:0:20000:0`;
      const dPost = [okLeaf, "dep:" + dUnit, `adr:${chalAddr}:${FR}`, `adrx:${FR}:${chalAddr}`];
      await submitAt(111, oneUnit("r8-c3-pre", "x:" + sha256Hex("r8-c3-pre"), [DEP_PRE]));
      const li = GENESIS_LEAVES.findIndex((l) => l > `acct:${FR}:`);
      const preAbs = { pre_absent: true, left: GENESIS_LEAVES[li - 1], left_proof: genProof(GENESIS_LEAVES[li - 1]),
        right: GENESIS_LEAVES[li], right_proof: genProof(GENESIS_LEAVES[li]) };
      const lieLeaf = `acct:${FR}:0:20001:0`;
      const lie = oneUnit("r8-c3-lie", dOp, [lieLeaf].concat(dPost.slice(1)));
      await submitAt(112, lie);
      await triggerVerdict(challenger, dispute, Object.assign({ pred: "deposit", height: 112 }, depositPayload(lie, lieLeaf), preAbs), 20000, "R8-C3: fresh PERP holder credited past the deposit");
      await frozen(112, "fresh PERP credit past the deposit");
      const ok = oneUnit("r8-c3-ok", dOp, dPost);
      await submitAt(112, ok);
      await triggerBounce(challenger, dispute, Object.assign({ pred: "deposit", height: 112 }, depositPayload(ok, okLeaf), preAbs), 20000, "no fraud");
      await live(112, "honest D: creating a PERP-only holder's leaf");
    }
    console.log("80. R8-C3: credited D: on a fresh account (acct:X:0:amount:0) → 'no fraud'; credited past the deposit → frozen (P-deposit)");
  }

  // Scenario 23 (vault W-watermark drill, #37-11) lives in the standalone
  // test_vault_withdraw_aa.js: its own short chain (h1..h3 with REAL
  // forests) keeps this suite inside the 20-minute CI job.


  process.exit(failures === 0 ? 0 : 1);
}

// Oscript is_valid_merkle_proof accepts object proofs {root, siblings, index}.
function mkProof(element, index, root) {
  return { root, index, siblings: [] };
}

main().catch(async (e) => {
  console.error("E2E FAILED:", e && e.stack ? e.stack : e);
  try { if (network) await network.stop(); } catch (_) {}
  process.exit(1);
});
