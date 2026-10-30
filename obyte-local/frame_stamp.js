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

function anchorHex(raw) {
  if (Array.isArray(raw)) return Buffer.from(raw).toString("hex");
  return String(raw || "");
}

function stampDepositEvidence(frames, evByAnchor) {
  return frames.map((f, i) => {
    if (typeof f !== "string") throw new Error(`frame ${i} is not a string`);
    let o;
    try { o = JSON.parse(f); } catch (_) { return f; }
    if (!o || typeof o !== "object" || Array.isArray(o)) return f;
    const op = o.u && o.u.op;
    const dep = (op && (op.Deposit || op.GovDeposit)) || null;
    if (!dep) return f;
    // Evidence already embedded by the Rust exporter: keep its bytes.
    if (Object.prototype.hasOwnProperty.call(o, "e")) return f;
    const ev = evByAnchor.get(anchorHex(dep.aa_unit).toLowerCase());
    if (!ev) return f;
    if (!f.endsWith("}")) throw new Error(`frame ${i} does not end with '}'`);
    return f.slice(0, -1) + ',"e":' + JSON.stringify(ev) + "}";
  });
}

module.exports = { stampDepositEvidence };
