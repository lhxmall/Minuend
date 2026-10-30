"use strict";

// Round 4 (#47 R4-E-1/2/4, R4-R-1/2/3/5, R4-A-2/7): deposit evidence for
// post_batch.js, dependency-free so it is unit-testable
// (test_deposit_evidence.js).
//
// * Evidence is built ONLY for the deposit units the producer APPLIED
//   (batch.json `applied_deposits: [{index, aa_unit, is_perp}]`, exported by
//   `Batch::applied_deposit_list`) and stamped on exactly that frame index
//   (frame_stamp.js). Rejected deposit units get none, so nobody can inflate
//   the batch's evidence with free rejected units, and two frames citing one
//   anchor can never both carry it.
// * The evidence content is what the vault AA records for the joint
//   (`dep_<unit>` / `depp_<unit>` = '{payer}:{amount}:{account}'), derived
//   exactly like ocore aa_composer.getTrigger + the vault's cases — mirror of
//   minuend-settle `deposit_verify::vault_deposit_of` (first data message,
//   SUM of outputs to the vault per asset, Oscript truthiness of
//   `deposit`/`deposit_perp` in case order, amount > 0, PERP asset id,
//   10000-byte bounce fee, account string rule).
// * Any failure for an APPLIED deposit (joint not found, hub/transport
//   error after retries, joint not a vault deposit of that kind, amount or
//   account disagreeing with the op or with the vault record, size caps)
//   THROWS: the poster must never post an applied deposit without evidence
//   (every watcher would reject the height). Retry later or re-cut the batch.

const VAULT_BOUNCE_FEE = 10000n;
const MAX_AA_STRING_LENGTH = 4096;
// R5-E-1 / R5-R-1: ONE set of size limits, mirrored from minuend-settle
// deposit_verify (the Rust test r5_limits_are_strictly_ordered_and_mirrored_in_js
// reads these lines, so keep the `const NAME = a * b;` form). Three tiers:
//   admit  (producer, admit_deposit / DepositEvidenceBudget, BEFORE apply)
//   < post (this file: the poster refuses only above these)
//   < verify (watchers' validate_against)
// The gaps absorb any JSON.stringify / serde_json byte difference, so an
// evidence the producer admitted is always postable and always accepted.
const DEPOSIT_EVIDENCE_UNIT_MAX_BYTES = 256 * 1024;
const DEPOSIT_EVIDENCE_BATCH_MAX_BYTES = 1048576;
const DEPOSIT_EVIDENCE_ADMIT_UNIT_MAX_BYTES = 240 * 1024;
const DEPOSIT_EVIDENCE_ADMIT_BATCH_MAX_BYTES = 960 * 1024;
const DEPOSIT_EVIDENCE_POST_UNIT_MAX_BYTES = 248 * 1024;
const DEPOSIT_EVIDENCE_POST_BATCH_MAX_BYTES = 992 * 1024;

// ocore string_utils.toNumber (post-aa2): number or null.
function oscriptToNumber(s) {
  const m = /^[+-]?(\d+(\.\d+)?)([eE][+-]?(\d+))?$/.exec(s);
  if (!m) return null;
  const f = parseFloat(s);
  if (!isFinite(f)) return null;
  const mantissa = m[1];
  const absExp = m[4];
  if (f === 0 && Number(mantissa) > 0 && absExp !== undefined && Number(absExp) > 0) return null;
  return f === 0 ? 0 : f;
}

// Oscript truthiness of `trigger.data.<key>` in a case `if`:
// true / false, or "error" where ocore raises (the AA bounces).
function oscriptTruthy(obj, key) {
  if (!Object.prototype.hasOwnProperty.call(obj, key)) return false;
  const v = obj[key];
  if (v === null || v === undefined) return "error";
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v !== 0;
  if (typeof v === "string") {
    if (v.length > MAX_AA_STRING_LENGTH) return "error";
    const f = oscriptToNumber(v);
    return f === null ? v.length > 0 : f !== 0;
  }
  return true; // object / array
}

function vaultAccount(v) {
  if (typeof v !== "string" || !/^[0-9a-f]{64}$/.test(v)) return null;
  if (oscriptToNumber(v) !== null) return null; // Oscript reads a number
  return v;
}

function hexToB64(h) { return Buffer.from(h, "hex").toString("base64"); }

function assetMatches(asset, perpAsset) {
  if (!perpAsset || asset === "base") return false;
  if (asset === perpAsset) return true;
  if (/^[0-9a-f]{64}$/.test(perpAsset) && asset === hexToB64(perpAsset)) return true;
  if (/^[0-9a-f]{64}$/.test(asset) && hexToB64(asset) === perpAsset) return true;
  return false;
}

// What the vault records for `unit` (joint.unit): {isPerp, amount (string),
// payer, account} or null when it records no deposit.
function vaultDepositOf(unit, vault, perpAsset) {
  if (!vault) throw new Error("vault address required");
  if (!unit || !Array.isArray(unit.messages) || !Array.isArray(unit.authors)) return null;
  const payer = unit.authors[0] && unit.authors[0].address;
  if (typeof payer !== "string") return null;
  if (unit.max_aa_responses === 0) return null;
  let data;
  const outputs = new Map();
  for (const m of unit.messages) {
    if (m.app === "data" && data === undefined) data = m.payload;
    else if (m.app === "payment" && m.payload) {
      const asset = m.payload.asset || "base";
      for (const o of m.payload.outputs || []) {
        if (o.address !== vault) continue;
        outputs.set(asset, (outputs.get(asset) || 0n) + BigInt(o.amount));
      }
    }
  }
  if (outputs.size === 0) return null;
  const baseSum = outputs.get("base") || 0n;
  if (baseSum < VAULT_BOUNCE_FEE) return null;
  if (!data || typeof data !== "object" || Array.isArray(data) || Object.keys(data).length === 0) return null;
  let isPerp;
  const t = oscriptTruthy(data, "deposit");
  if (t === "error") return null;
  if (t === true) isPerp = false;
  else if (oscriptTruthy(data, "deposit_perp") === true) isPerp = true;
  else return null;
  const account = vaultAccount(data.account);
  if (!account) return null;
  let amount;
  if (isPerp) {
    amount = 0n;
    for (const [a, v] of outputs) if (assetMatches(a, perpAsset)) amount += v;
    if (amount <= 0n) return null;
  } else {
    amount = baseSum - VAULT_BOUNCE_FEE;
    if (amount <= 0n) return null;
  }
  return { isPerp, amount: amount.toString(), payer, account };
}

function evidenceBytes(ev) { return Buffer.byteLength(JSON.stringify(ev)); }

function anchorHex(raw) {
  if (Array.isArray(raw)) return Buffer.from(raw).toString("hex");
  return String(raw || "").toLowerCase();
}

// The deposit op of a frame string (inspection only): {kind, aaUnit, op}.
function frameDeposit(frame) {
  let o;
  try { o = JSON.parse(frame); } catch (_) { return null; }
  const op = o && o.u && o.u.op;
  if (!op) return null;
  // Amounts can exceed 2^53: read the exact digits from the raw bytes.
  const m = /"(?:Deposit|GovDeposit)":\{[^{}]*?"amount":(-?\d+)/.exec(frame);
  const amount = m ? m[1] : null;
  if (op.Deposit) return { isPerp: false, aaUnit: anchorHex(op.Deposit.aa_unit), op: op.Deposit, amount };
  if (op.GovDeposit) return { isPerp: true, aaUnit: anchorHex(op.GovDeposit.aa_unit), op: op.GovDeposit, amount };
  return null;
}

// R5-E-1: what to do when a size limit refuses a cut batch. A producer that
// admits through deposit_verify::DepositEvidenceBudget never gets here.
const RECOVERY = "The producer admitted this deposit outside deposit_verify::admit_deposit / " +
  "DepositEvidenceBudget (whose limits are below these). This height cannot be posted as cut: " +
  "restore the producer to the snapshot of the previous height, re-ingest its units through " +
  "deposit_verify::ingest_within_budget (the oversize deposit is then refused or deferred) and cut again.";

// Build evidence for every applied deposit. Throws on ANY problem.
//   applied     batch.json applied_deposits [{index, aa_unit, is_perp}]
//   frames      batch.json frames (strings)
//   fetchJoint  async (aaUnitHex) => joint unit object | null (NOT FOUND);
//               must THROW on transport/hub errors (retried here)
//   readRecord  optional async (aaUnitHex, isPerp) => vault record string
//               '{payer}:{amount}:{account}' or null (producer rule: the
//               vault must hold the record the evidence reproduces)
// Returns Map(frameIndex -> evidence).
async function buildAppliedEvidences(applied, frames, opts) {
  const { vault, perpAsset, fetchJoint, readRecord } = opts;
  const tries = opts.tries || 4;
  const sleep = opts.sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
  if (!Array.isArray(applied)) throw new Error("batch.json has no applied_deposits list (re-run export_batch)");
  if (!vault) throw new Error("vault address required for deposit evidence");
  const out = new Map();
  const seen = new Set();
  let total = 0;
  for (const a of applied) {
    const idx = a.index;
    if (!Number.isInteger(idx) || idx < 0 || idx >= frames.length) throw new Error(`applied deposit index ${idx} out of range`);
    const fd = frameDeposit(frames[idx]);
    const aaUnit = anchorHex(a.aa_unit);
    if (!fd || fd.aaUnit !== aaUnit || fd.isPerp !== !!a.is_perp)
      throw new Error(`applied deposit ${idx} does not match its frame`);
    const key = aaUnit + ":" + (fd.isPerp ? "p" : "b");
    if (seen.has(key)) throw new Error(`anchor ${aaUnit} applied twice`);
    seen.add(key);
    let joint;
    let lastErr;
    for (let i = 0; i < tries; i++) {
      try {
        joint = await fetchJoint(aaUnit);
        lastErr = undefined;
        break;
      } catch (e) {
        lastErr = e;
        if (i + 1 < tries) await sleep(1000 * 2 ** i);
      }
    }
    if (lastErr) throw new Error(`deposit anchor ${aaUnit}: joint fetch failed (${lastErr && lastErr.message || lastErr}); not posting`);
    if (!joint) throw new Error(`APPLIED deposit anchor ${aaUnit} not found on Obyte; not posting`);
    const unit = joint.unit && typeof joint.unit === "object" ? joint.unit : joint;
    const rec = vaultDepositOf(unit, vault, perpAsset);
    if (!rec) throw new Error(`anchor ${aaUnit} is not a vault deposit; the producer must not have applied it`);
    if (rec.isPerp !== fd.isPerp) throw new Error(`anchor ${aaUnit}: joint kind ${rec.isPerp ? "PERP" : "base"} != applied op kind`);
    if (fd.amount !== rec.amount)
      throw new Error(`anchor ${aaUnit}: op amount != vault amount ${rec.amount}`);
    if (fd.op.addr !== undefined && fd.op.addr !== rec.payer) throw new Error(`anchor ${aaUnit}: op addr != payer ${rec.payer}`);
    if (fd.op.account !== undefined && anchorHex(fd.op.account) !== rec.account)
      throw new Error(`anchor ${aaUnit}: op account != designated account`);
    if (readRecord) {
      const r = await readRecord(aaUnit, rec.isPerp);
      const want = `${rec.payer}:${rec.amount}:${rec.account}`;
      if (r !== want) throw new Error(`anchor ${aaUnit}: vault record ${r} != evidence ${want}`);
    }
    const ev = {
      aa_unit: aaUnit,
      is_perp: rec.isPerp,
      amount: rec.amount,
      vault_address: vault,
      payer: rec.payer,
      account: rec.account,
      joint: unit,
    };
    const n = evidenceBytes(ev);
    if (n > DEPOSIT_EVIDENCE_POST_UNIT_MAX_BYTES)
      throw new Error(`anchor ${aaUnit}: evidence ${n} bytes exceeds the posting limit ${DEPOSIT_EVIDENCE_POST_UNIT_MAX_BYTES} ` +
        `(admission limit ${DEPOSIT_EVIDENCE_ADMIT_UNIT_MAX_BYTES}). ${RECOVERY}`);
    total += n;
    if (total > DEPOSIT_EVIDENCE_POST_BATCH_MAX_BYTES)
      throw new Error(`deposit evidence of this batch is ${total} bytes, above the posting limit ${DEPOSIT_EVIDENCE_POST_BATCH_MAX_BYTES} ` +
        `(admission budget ${DEPOSIT_EVIDENCE_ADMIT_BATCH_MAX_BYTES}). ${RECOVERY}`);
    out.set(idx, ev);
  }
  return out;
}

module.exports = {
  VAULT_BOUNCE_FEE,
  DEPOSIT_EVIDENCE_UNIT_MAX_BYTES,
  DEPOSIT_EVIDENCE_BATCH_MAX_BYTES,
  DEPOSIT_EVIDENCE_ADMIT_UNIT_MAX_BYTES,
  DEPOSIT_EVIDENCE_ADMIT_BATCH_MAX_BYTES,
  DEPOSIT_EVIDENCE_POST_UNIT_MAX_BYTES,
  DEPOSIT_EVIDENCE_POST_BATCH_MAX_BYTES,
  evidenceBytes,
  oscriptToNumber,
  oscriptTruthy,
  vaultAccount,
  vaultDepositOf,
  frameDeposit,
  buildAppliedEvidences,
};
