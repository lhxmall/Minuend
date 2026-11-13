"use strict";

const zlib = require("zlib");

const DEFAULT_PACKAGE_SOURCE_CAP = 4_000_000;
// R3-R-1: raw (decompressed) caps every watcher enforces. Must equal
// minuend_settle::MAX_PACKAGE_RAW_BYTES / MAX_COMMITTED_RAW_BYTES: packages
// are cut on raw size too, and a batch above the per-height cap is refused
// before posting (watchers would reject it and stall on the height).
const MAX_PACKAGE_RAW_BYTES = 64 * 1024 * 1024;
const MAX_COMMITTED_RAW_BYTES = 1024 * 1024 * 1024;

function packFrames(frames, options = {}) {
  const cap = options.cap ?? DEFAULT_PACKAGE_SOURCE_CAP;
  const rawCap = options.rawCap ?? MAX_PACKAGE_RAW_BYTES;
  const getJsonSourceString = options.getJsonSourceString ?? JSON.stringify;
  if (!Array.isArray(frames) || frames.some((frame) => typeof frame !== "string")) {
    throw new TypeError("frames must be an array of strings");
  }
  if (!Number.isSafeInteger(cap) || cap < 0) {
    throw new RangeError("package source cap must be a non-negative safe integer");
  }
  if (typeof getJsonSourceString !== "function") {
    throw new TypeError("getJsonSourceString must be a function");
  }

  const encode = (items, packageIndex) => {
    if (items.length === 0) return "";
    const prefix = packageIndex > 0 ? "\n" : "";
    const raw = `${prefix}${items.join("\n")}`;
    return zlib.gzipSync(Buffer.from(raw, "utf8")).toString("base64");
  };
  const sourceLength = (blob) =>
    Buffer.byteLength(getJsonSourceString({ package_blob: blob }), "utf8");

  const packages = [];
  let current = [];
  let currentRaw = 0;
  const flush = () => {
    if (current.length === 0) return;
    packages.push(encode(current, packages.length));
    current = [];
    currentRaw = 0;
  };

  for (const frame of frames) {
    // R3-R-1: raw bytes of the package if `frame` joins it (leading LF on
    // later packages, one LF between frames). Cut on raw size first.
    const frameRaw = Buffer.byteLength(frame, "utf8");
    const trialRaw =
      (packages.length > 0 ? 1 : 0) + currentRaw + (current.length > 0 ? 1 : 0) + frameRaw;
    if (current.length > 0 && trialRaw > rawCap) flush();
    else if (current.length > 0) {
      const trial = encode([...current, frame], packages.length);
      if (sourceLength(trial) > cap) flush();
    }
    currentRaw += (current.length > 0 ? 1 : 0) + frameRaw;
    current.push(frame);
  }
  flush();
  return packages;
}

function assertPackageSourceCap(packages, options = {}) {
  const cap = options.cap ?? DEFAULT_PACKAGE_SOURCE_CAP;
  const getJsonSourceString = options.getJsonSourceString ?? JSON.stringify;
  for (const blob of packages) {
    const sourceLength = Buffer.byteLength(
      getJsonSourceString({ package_blob: blob }),
      "utf8",
    );
    if (sourceLength > cap) {
      throw new RangeError(`package source length ${sourceLength} exceeds cap ${cap}`);
    }
  }
}

// R3-R-1: refuse (before anything is posted) packages a watcher would
// reject: any package above the raw cap, or all of them above the
// per-height raw cap.
function assertPackageRawCaps(packages, options = {}) {
  const rawCap = options.rawCap ?? MAX_PACKAGE_RAW_BYTES;
  const totalCap = options.totalRawCap ?? MAX_COMMITTED_RAW_BYTES;
  let total = 0;
  for (const blob of packages) {
    const n = zlib.gunzipSync(Buffer.from(blob, "base64")).length;
    if (n > rawCap) {
      throw new RangeError(`package raw length ${n} exceeds watcher cap ${rawCap}`);
    }
    total += n;
  }
  if (total > totalCap) {
    throw new RangeError(
      `batch raw length ${total} exceeds watcher per-height cap ${totalCap}: cut a smaller batch`,
    );
  }
  return total;
}

module.exports = {
  DEFAULT_PACKAGE_SOURCE_CAP,
  MAX_PACKAGE_RAW_BYTES,
  MAX_COMMITTED_RAW_BYTES,
  assertPackageRawCaps,
  assertPackageSourceCap,
  packFrames,
};
