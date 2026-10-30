"use strict";

// Shared headless-bootstrap for the operator scripts (issue_perp.js,
// deploy_mainnet.js, and — #47 L5 — the watcher's live challenge poster
// post_challenge_live.js).
//
// Boots a light headless wallet from a mnemonic env var (default
// MINUEND_DEPLOY_MNEMONIC) against the network's hub, waits for
// `headless_wallet_ready`, and returns the wallet handle plus
// lazily-required ocore modules. boot() with no options keeps the original
// mainnet/deploy behaviour.
//
// DO NOT require("headless-obyte") for side effects: its package main
// (start.js) boots on require; requiring twice double-boots. This module
// requires it exactly once and caches the handle.

const path = require("path");
const { envCompat } = require("./script_helpers");

const nm = path.join(__dirname, "..", "vendor", "aa-testkit", "node_modules");
process.env.NODE_PATH = [nm, process.env.NODE_PATH].filter(Boolean).join(path.delimiter);
require("module").Module._initPaths();

let cached = null;

function readFirstAddress(headlessWallet) {
  return new Promise((resolve, reject) => {
    let done = false;
    try {
      headlessWallet.readFirstAddress((address) => {
        if (!done) {
          done = true;
          resolve(address);
        }
      });
    } catch (e) {
      if (!done) {
        done = true;
        reject(e);
      }
    }
    setTimeout(() => {
      if (!done) {
        done = true;
        reject(new Error("readFirstAddress timeout"));
      }
    }, 60000);
  });
}

async function boot(opts = {}) {
  if (cached) return cached;
  const mnemonicEnv = opts.mnemonicEnv || "MINUEND_DEPLOY_MNEMONIC";
  const net = opts.network || "mainnet";
  if (net !== "mainnet" && net !== "testnet") throw new Error(`unknown network '${net}'`);
  // B9 (#47): legacy OPERP_* mnemonic names accepted with a deprecation warning.
  const MNEMONIC = envCompat(mnemonicEnv);
  if (!MNEMONIC || MNEMONIC.trim().split(/\s+/).length < 12)
    throw new Error(`${mnemonicEnv} (12+ words) required`);
  delete process.env.devnet;
  delete process.env.testnet;
  delete process.env.mainnet;
  process.env[net] = "1";
  process.env.mnemonic = MNEMONIC.trim();

  // conf.js merges app-root/user confs then applies defaults: set ours
  // BEFORE headless-obyte boots (require order matters).
  const conf = require("ocore/conf.js");
  conf.bLight = true;
  conf.bSingleAddress = true;
  conf.bNoPassphrase = true;
  conf.hub = opts.hub || (net === "testnet" ? "obyte.org/bb-test" : "obyte.org/bb");

  const eventBus = require("ocore/event_bus.js");
  const headlessWallet = require("headless-obyte");
  await new Promise((resolve, reject) => {
    eventBus.once("headless_wallet_ready", resolve);
    setTimeout(() => reject(new Error("headless wallet start timeout (180s)")), 180000);
  });

  const address = await readFirstAddress(headlessWallet);
  cached = {
    wallet: headlessWallet,
    address,
    composer: require("ocore/composer.js"),
    network: require("ocore/network.js"),
    objectHash: require("ocore/object_hash.js"),
    eventBus,
  };
  return cached;
}

module.exports = { boot };
