#!/bin/bash
# Mutation test of the harness (rerun with the upstream-scenario replay and MNWIT1 checks).
# Each mutant of the PORT (guest-engine) must make at least one check disagree with the real engine:
#   fuzz 100 300 (hash + events), scen upstream.scn (hash + events + per-unit roots),
#   witfuzz 30 300 (per-unit roots real-scratch / port-incremental / port-scratch).
. /data/hark/spike-rv/env.sh
P=${P:-/data/hark/spike-rv/wit}; M=$P/mut; LOG=${LOG:-/data/hark/logs/rv/wit-mut.log}; : > $LOG
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
 # MNWIT1 mutants (witness only: engine hash/events unchanged, roots must disagree)
 "src/engine.rs@        self.state.note_journal(&journal); // PILOT (MNWIT1)@"
 "src/state.rs@        self.wit_dirty.accounts.insert(id); // PILOT (MNWIT1)@"
 "src/engine.rs@        self.state.wit_dirty.orders.insert((market, order_id)); // PILOT (MNWIT1)@"
 "src/wit.rs@if o.isolated { 1 } else { 0 }, o.margin_left);@if o.isolated { 1 } else { 0 }, o.margin_left / 2);"
 "src/wit.rs@                    [R::L(x), R::E] | [R::E, R::L(x)] => {@                    [R::L(x), R::E] => {"
 "src/wit.rs@                        self.smt.remove(&key_of(&b.b[..b.kid]));\n                    }\n                    if !cur.is_empty() {@                    }\n                    if !cur.is_empty() {"
)
i=0
for m in "${muts[@]}"; do
  [[ "$m" == \#* ]] && continue
  i=$((i+1)); IFS='@' read -r f from to <<< "$m"
  rm -rf $M; mkdir -p $M; cp -r $P/guest-engine $P/engine-diff $M/; ln -s $P/engine-src $M/engine-src
  python3 - "$M/guest-engine/$f" "$from" "$to" <<'PY'
import sys
p,a,b=sys.argv[1:]; a=a.replace('\\n','\n'); b=b.replace('\\n','\n'); s=open(p).read()
assert s.count(a)>=1, "pattern not found: "+a
open(p,'w').write(s.replace(a,b,1))
PY
  [ $? -ne 0 ] && { echo "mut $i: PATTERN MISSING" >> $LOG; continue; }
  (cd $M/engine-diff && CARGO_TARGET_DIR=/data/hark/target-wit-mut cargo build --release -q 2>>$LOG) || { echo "mut $i build fail" >> $LOG; continue; }
  B=/data/hark/target-wit-mut/release/engine-diff
  fz=$($B fuzz 100 300 | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/')
  sc=$($B scen $P/engine-diff/scenarios/upstream.scn | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/')
  wf=$($B witfuzz 30 300 20 | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/')
  k=no; { [ "$fz" != 100 ] || [ "$sc" != 47 ] || [ "$wf" != 30 ]; } && k=KILLED
  echo "mut $i [$f: ${to:0:70}] fuzz $fz/100 scen $sc/47 witfuzz $wf/30 -> $k" >> $LOG
done
echo DONE >> $LOG
