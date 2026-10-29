"use strict";

// Small pure helpers shared by the operator scripts (no testkit / ocore
// imports, so they are unit-tested by test_script_helpers.js in CI).

const LEGACY_ENV_PREFIX = "OPERP_";
const ENV_PREFIX = "MINUEND_";
const warned = new Set();

// B9 (#47): #44 renamed every OPERP_* operator variable to MINUEND_* with no
// fallback, so an old configuration was silently ignored. Read the new name
// first; fall back to the legacy OPERP_* spelling with a deprecation warning
// (printed once per variable). Empty strings count as unset.
function envCompat(name, env = process.env, warn = console.warn) {
  if (!name.startsWith(ENV_PREFIX)) throw new Error(`envCompat: ${name} is not a ${ENV_PREFIX}* variable`);
  const legacy = LEGACY_ENV_PREFIX + name.slice(ENV_PREFIX.length);
  const nv = env[name] ? env[name] : undefined;
  const lv = env[legacy] ? env[legacy] : undefined;
  const once = (msg) => {
    if (warned.has(name)) return;
    warned.add(name);
    warn(msg);
  };
  if (nv !== undefined) {
    if (lv !== undefined) once(`warning: both ${name} and deprecated ${legacy} are set; using ${name} and ignoring ${legacy}`);
    return nv;
  }
  if (lv !== undefined) {
    once(`warning: ${legacy} is deprecated (renamed in #44); using its value, please rename it to ${name}`);
    return lv;
  }
  return undefined;
}

// L6 (#47): finalize succeeded when last_finalized reached OR PASSED our
// height — another poster may have finalized later heights concurrently,
// which made the old `===` check report a false failure.
function finalizeReached(lastFinalized, height) {
  const lf = Number(lastFinalized);
  const h = Number(height);
  return Number.isFinite(lf) && Number.isFinite(h) && lf >= h;
}

module.exports = { envCompat, finalizeReached, LEGACY_ENV_PREFIX, ENV_PREFIX };
