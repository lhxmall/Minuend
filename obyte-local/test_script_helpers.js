"use strict";

const assert = require("assert");
const { envCompat, finalizeReached } = require("./script_helpers");

// B9: new name wins; legacy falls back with one deprecation warning.
{
  const logs = [];
  const warn = (m) => logs.push(m);
  assert.strictEqual(envCompat("MINUEND_ROLLUP_AA", { MINUEND_ROLLUP_AA: "NEW" }, warn), "NEW");
  assert.strictEqual(logs.length, 0);
  assert.strictEqual(envCompat("MINUEND_DISPUTE_AA", { OPERP_DISPUTE_AA: "OLD" }, warn), "OLD");
  assert.ok(/deprecated/.test(logs[0]));
  // warned once per variable
  envCompat("MINUEND_DISPUTE_AA", { OPERP_DISPUTE_AA: "OLD" }, warn);
  assert.strictEqual(logs.length, 1);
  assert.strictEqual(
    envCompat("MINUEND_WATCH_MNEMONIC", { MINUEND_WATCH_MNEMONIC: "n", OPERP_WATCH_MNEMONIC: "o" }, warn),
    "n",
  );
  assert.ok(/ignoring OPERP_WATCH_MNEMONIC/.test(logs[1]));
  assert.strictEqual(envCompat("MINUEND_VAULT_AA", { MINUEND_VAULT_AA: "", OPERP_VAULT_AA: "" }, warn), undefined);
  assert.strictEqual(envCompat("MINUEND_DEPLOY_MNEMONIC", { MINUEND_DEPLOY_MNEMONIC: "", OPERP_DEPLOY_MNEMONIC: "x" }, warn), "x");
  assert.throws(() => envCompat("PATH", {}, warn));
}

// L6: finalize check is >=, not ===.
assert.strictEqual(finalizeReached(5, 5), true);
assert.strictEqual(finalizeReached("7", 5), true, "concurrent finalize past our height is success");
assert.strictEqual(finalizeReached(4, 5), false);
assert.strictEqual(finalizeReached(undefined, 5), false);
assert.strictEqual(finalizeReached("NaN", 5), false);

console.log("script helper checks passed");
