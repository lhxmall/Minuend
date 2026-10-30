"use strict";

// R2-R-4 (round 2 of #47): embed deposit evidence into export_batch frames
// WITHOUT re-serialising them. post_batch.js used to JSON.parse and
// JSON.stringify every frame; any integer above 2^53 (a Place margin/qty/
// client_seq, a Deposit amount, ...) was rounded, the unit bytes changed,
// its id and signature no longer matched and every watcher stalled on that
// height forever. Frames are now passed through byte-for-byte; a Deposit/
// GovDeposit frame that needs evidence gets `,"e":<evidence>` spliced in
// before its closing brace (the only bytes added). The frame is parsed only
// to INSPECT it (op kind and aa_unit), never to rebuild it.
//
// R4-E-1 / R4-R-1: evidence is keyed by FRAME INDEX, not by anchor. Only the
// deposit frame the producer APPLIED is stamped (batch.json
// `applied_deposits`), so a front-run / duplicate / cross-kind unit citing
// the same anchor never carries a copy (watchers used to see two evidences
// for one anchor and reject the whole height).

function anchorHex(raw) {
  if (Array.isArray(raw)) return Buffer.from(raw).toString("hex");
  return String(raw || "").toLowerCase();
}

// frames: array of frame strings; evByIndex: Map(frameIndex -> evidence).
function stampDepositEvidence(frames, evByIndex) {
  if (!(evByIndex instanceof Map)) throw new Error("evByIndex must be a Map");
  for (const k of evByIndex.keys())
    if (!Number.isInteger(k) || k < 0 || k >= frames.length) throw new Error(`evidence index ${k} out of range`);
  return frames.map((f, i) => {
    if (typeof f !== "string") throw new Error(`frame ${i} is not a string`);
    const ev = evByIndex.get(i);
    if (!ev) return f;
    let o;
    try { o = JSON.parse(f); } catch (_) { throw new Error(`frame ${i} is not JSON`); }
    const op = o && o.u && o.u.op;
    const dep = op && (op.Deposit || op.GovDeposit);
    if (!dep) throw new Error(`frame ${i} is not a deposit frame`);
    const isPerp = !op.Deposit;
    if (anchorHex(dep.aa_unit) !== String(ev.aa_unit).toLowerCase() || !!ev.is_perp !== isPerp)
      throw new Error(`frame ${i}: evidence does not match the deposit's anchor/kind`);
    if (Object.prototype.hasOwnProperty.call(o, "e")) throw new Error(`frame ${i} already carries evidence`);
    if (!f.endsWith("}")) throw new Error(`frame ${i} does not end with '}'`);
    return f.slice(0, -1) + ',"e":' + JSON.stringify(ev) + "}";
  });
}

module.exports = { stampDepositEvidence };
