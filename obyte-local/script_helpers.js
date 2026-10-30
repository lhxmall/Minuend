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

// L5 (#47): live challenge posting gate. The dispute AAs compare the
// challenge unit's own timestamp against submitted_at + 3600, so a
// challenge is only worth broadcasting while `now + margin` is still before
// the deadline (B10: 600 s margin covers composing, broadcasting and the
// unit becoming stable). Evaluate with a FRESH clock right before sending.
const CHALLENGE_WINDOW_SECS = 3600;
const CHALLENGE_SAFETY_MARGIN_SECS = 600;
function challengeGate({ now, submittedAt, frozen, windowSecs = CHALLENGE_WINDOW_SECS, marginSecs = CHALLENGE_SAFETY_MARGIN_SECS }) {
  const sa = Number(submittedAt);
  const t = Number(now);
  if (!Number.isFinite(sa) || sa <= 0) return { ok: false, reason: "height not submitted" };
  if (Number(frozen || 0) !== 0) return { ok: false, reason: "height already frozen" };
  if (!Number.isFinite(t)) return { ok: false, reason: "bad clock" };
  const deadline = sa + windowSecs;
  if (t >= deadline) return { ok: false, reason: "challenge window closed" };
  if (t + marginSecs >= deadline)
    return { ok: false, reason: `less than ${marginSecs}s left in the challenge window` };
  return { ok: true, reason: `${deadline - t}s left`, deadline };
}

// Which dispute AA a proof goes to: main (deposit/withdraw/escrow/omit),
// book (ghost/skip, split out in round 2; mbind round 4; fsane round 5), fill (fill_math)
// or bind (#47 A2 + round 2: wpin/adr/tip/keep/mirror; frame round 4).
const TARGETS = {
  book: { deployKey: "dispute_book_aa_address", env: "MINUEND_DISPUTE_BOOK_AA", bind: { bind_book: 1 }, rollupVar: "dispute_book_aa" },
  main: { deployKey: "dispute_aa_address", env: "MINUEND_DISPUTE_AA", bind: { bind: 1 }, rollupVar: "dispute_aa" },
  fill: { deployKey: "dispute_fill_aa_address", env: "MINUEND_DISPUTE_FILL_AA", bind: { bind_fill: 1 }, rollupVar: "dispute_fill_aa" },
  bind: { deployKey: "dispute_bind_aa_address", env: "MINUEND_DISPUTE_BIND_AA", bind: { bind_bind: 1 }, rollupVar: "dispute_bind_aa" },
  // Round 6: P-claw (both legs of one fill) on the claw dispute AA.
  claw: { deployKey: "dispute_claw_aa_address", env: "MINUEND_DISPUTE_CLAW_AA", bind: { bind_claw: 1 }, rollupVar: "dispute_claw_aa" },
  // Round 7b: P-xframe / P-mframe / P-noband / P-tsize on the x-frame AA.
  xframe: { deployKey: "dispute_xframe_aa_address", env: "MINUEND_DISPUTE_XFRAME_AA", bind: { bind_xframe: 1 }, rollupVar: "dispute_xframe_aa" },
};
function disputeTarget(target, deploy, env = process.env, warn = console.warn) {
  const t = TARGETS[target];
  if (!t) throw new Error(`unknown dispute target '${target}' (main|book|fill|bind|claw|xframe)`);
  const address = (deploy && deploy[t.deployKey]) || envCompat(t.env, env, warn);
  return Object.assign({ address: address || null }, t);
}

// R2-R-8 (round 2 of #47): the live poster must challenge the rollup the
// WATCHER is watching. Precedence: --rollup (the watcher always passes it)
// > MINUEND_ROLLUP_AA > deployment.json — and deployment.json is only used
// when its `network` matches the network we are posting to (deploy scripts
// rewrite the same file, so it may describe another network/deployment).
function resolveLiveRollup({ cli, deploy, network, env = process.env, warn = console.warn }) {
  if (cli) return cli;
  const fromEnv = envCompat("MINUEND_ROLLUP_AA", env, warn);
  if (fromEnv) return fromEnv;
  const d = deploy && deploy.rollup_aa_address;
  if (!d) throw new Error("rollup address missing: pass --rollup (or MINUEND_ROLLUP_AA)");
  if (!deploy.network || deploy.network !== network)
    throw new Error(`deployment.json describes network ${JSON.stringify(deploy.network)}, not ${network}: pass --rollup`);
  return d;
}

// R2-R-8: the dispute AA a challenge goes to is the one the rollup itself
// has bound (`dispute_aa` / `dispute_fill_aa` / `dispute_bind_aa` state var)
// — the only AA whose verdicts the rollup accepts. An explicit
// --dispute-address must agree with it.
function pickDisputeAddress({ cli, bound, rollupVar }) {
  const b = typeof bound === "string" ? bound : "";
  if (!/^[0-9A-Z]{32}$/.test(b)) throw new Error(`rollup has no ${rollupVar} bound (${JSON.stringify(bound)})`);
  if (cli && cli !== b) throw new Error(`--dispute-address ${cli} is not the rollup's ${rollupVar} (${b})`);
  return b;
}

// Challenge trigger data: the proof file's fields plus height/pred/rollup.
// The proof must not override those three (a stale or foreign proof file
// would otherwise redirect the challenge).
function buildChallengeData({ height, pred, rollup, proof }) {
  if (!Number.isInteger(height) || height < 1) throw new Error("bad height");
  if (typeof pred !== "string" || !pred) throw new Error("bad pred");
  if (typeof rollup !== "string" || rollup.length !== 32) throw new Error("bad rollup address");
  if (!proof || typeof proof !== "object" || Array.isArray(proof)) throw new Error("proof must be a JSON object");
  for (const k of ["height", "pred", "rollup"])
    if (k in proof && proof[k] !== { height, pred, rollup }[k]) throw new Error(`proof overrides '${k}'`);
  return Object.assign({}, proof, { height, pred, rollup });
}

// R2-R-1: DA <-> submitted-roots binding hash (format: work/r2-da-binding.md,
// Rust minuend_settle::da_bind_hash). The rollup AA recomputes it from the
// submit trigger data; the temp_data header carries the same value.
const DA_BIND_FIELDS = [
  "chain_id", "height", "prev_state_hash", "state_root", "aa_root", "wit_root",
  "trace_root", "units_root", "units_set_root", "ops_root", "fills_root",
  "counts_root", "unit_count", "wit_count", "fill_count", "assertion_version", "data_root",
];
function daBindHash(f) {
  const parts = ["minuend-da-v1"];
  for (const k of DA_BIND_FIELDS) {
    const v = f[k];
    if (v === undefined || v === null || v === "") throw new Error(`daBindHash: missing ${k}`);
    parts.push(String(v));
  }
  return require("crypto").createHash("sha256").update(parts.join("|"), "utf8").digest("hex");
}

// Proof-target routing by predicate name (round 2 split).
function targetForPred(pred) {
  if (pred === "fill_math") return "fill";
  // Round 6: P-claw on the claw AA.
  if (pred === "claw") return "claw";
  // Round 7b: bystander frame of `x:` units, band:/meta: frame, missing
  // band leaf, committed tree size on the x-frame AA.
  if (["xframe", "mframe", "noband", "tsize"].includes(pred)) return "xframe";
  // R4-A-1: P-mbind on the book AA; R4-A-3: P-frame on the bind AA;
  // R5-A-2: P-fsane on the book AA.
  if (pred === "ghost" || pred === "skip" || pred === "mbind" || pred === "fsane") return "book";
  if (["wpin", "adr", "tip", "keep", "mirror", "frame"].includes(pred)) return "bind";
  // Round 7: P-opbind (ops leaf vs unit text) lives on the main dispute AA,
  // with deposit / withdraw / escrow.
  return "main";
}

// Default light hubs per network (override with MINUEND_WATCH_HUB).
function hubFor(network, override) {
  if (override) return override;
  if (network === "mainnet") return "obyte.org/bb";
  if (network === "testnet") return "obyte.org/bb-test";
  throw new Error(`unknown network '${network}' (mainnet|testnet)`);
}

module.exports = {
  envCompat,
  finalizeReached,
  challengeGate,
  disputeTarget,
  resolveLiveRollup,
  pickDisputeAddress,
  buildChallengeData,
  hubFor,
  daBindHash,
  targetForPred,
  DA_BIND_FIELDS,
  CHALLENGE_WINDOW_SECS,
  CHALLENGE_SAFETY_MARGIN_SECS,
  LEGACY_ENV_PREFIX,
  ENV_PREFIX,
};
