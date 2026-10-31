#!/bin/bash
# Mutation sanity for the diff harness: each mutant of the PORT must be caught by `engine-diff fuzz`.
. /data/hark/spike-rv/env.sh
P=/data/hark/spike-rv/pilot; M=$P/mut; LOG=/data/hark/logs/rv/pilot-mut.log; : > $LOG
muts=(
 "src/types.rs@pub const TAKER_FEE_BPS: u64 = 5;@pub const TAKER_FEE_BPS: u64 = 4;"
 "src/book.rs@OrderType::Limit => maker_price <= order.price,@OrderType::Limit => maker_price < order.price,"
 "src/account.rs@    (num / den) as Price@    ((num + den / 2) / den) as Price"
 "src/engine.rs@                    bid_im.max(ask_im)@                    bid_im.saturating_add(ask_im)"
 "src/state.rs@                        if dev <= (old as i128).abs() / 10 {@                        if dev < (old as i128).abs() / 10 {"
 "src/engine.rs@        if live_count >= MAX_LIVE_ORDERS_PER_ACCOUNT {@        if live_count > MAX_LIVE_ORDERS_PER_ACCOUNT {"
 "src/book.rs@(u128::from(margin_left) * u128::from(fill_qty) / u128::from(remaining_before)) as u64@(u128::from(margin_left) * u128::from(fill_qty) / u128::from(remaining_before) + 1) as u64"
 "src/account.rs@        let liquidatable = mm > 0 && equity * 10_000 <= mm * i128::from(LIQ_RATIO_BPS);@        let liquidatable = mm > 0 && equity * 10_000 < mm * i128::from(LIQ_RATIO_BPS);"
 "src/engine.rs@if snap.equity - i128::from(margin) < snap.im + resting {@if snap.equity - i128::from(margin) <= snap.im + resting {"
 "src/state.rs@(-p.collateral).min(cp.collateral.max(0))@(-p.collateral).min(cp.collateral)"
 "src/account.rs@let release = *bucket * i128::from(close) / i128::from(old_abs);@let release = (*bucket * i128::from(close) + i128::from(old_abs) - 1) / i128::from(old_abs);"
 "src/engine.rs@if snap.equity < snap.im + resting + extra_im {@if snap.equity < snap.im + extra_im {"
 "src/engine.rs@!((pre >= 0 && post < 0) || (pre_eq >= 0 && pre_eq < fee))@!(pre >= 0 && post < 0)"
)
i=0
for m in "${muts[@]}"; do
  i=$((i+1)); IFS='@' read -r f from to <<< "$m"
  rm -rf $M; mkdir -p $M; cp -r $P/guest-engine $P/engine-diff $M/; ln -s $P/engine-src $M/engine-src
  python3 - "$M/guest-engine/$f" "$from" "$to" <<'PY'
import sys
p,a,b=sys.argv[1:]; s=open(p).read(); 
assert s.count(a)>=1, "pattern not found: "+a
open(p,'w').write(s.replace(a,b,1))
PY
  [ $? -ne 0 ] && { echo "mut $i: PATTERN MISSING" >> $LOG; continue; }
  (cd $M/engine-diff && CARGO_TARGET_DIR=/data/hark/target-pilot-mut cargo build --release -q 2>>$LOG) || { echo "mut $i build fail" >> $LOG; continue; }
  r=$(/data/hark/target-pilot-mut/release/engine-diff fuzz 100 300 | tail -1)
  echo "mut $i [$f: $to] -> $r" >> $LOG
done
echo DONE >> $LOG
