#!/bin/sh
# Extract the real engine (fix/47-all @ 20326c0, read-only) into ../engine-src for the host harness.
set -e
cd "$(dirname "$0")/.."
rm -rf engine-src && mkdir engine-src
git -C "$(git rev-parse --show-toplevel)" archive 20326c0ff9472886521e32b3c5b04fe91269e848 Cargo.toml Cargo.lock crates | tar -x -C engine-src
echo "engine-src @ 20326c0 ready"
