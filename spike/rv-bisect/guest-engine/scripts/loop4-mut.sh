#!/bin/bash
# Loop round 4 mutation test: loop-4 mutants first (Accounts guard / holders index, liquidate / ADL / keeper /
# withdraw / report ports, SetHeight prune, session account cap, import lock), then the loop-3 survivors and the
# loop-3 list (patterns updated for round 4). Checks per mutant: loop3-mut.sh's set plus
#   liqfuzz 30 300 (port vs real engine on liquidate / ADL / withdraw / reports / ext prices / heights),
#   snaptest 20 200 (export / import / import lock / digest), capcheck 10 100 8 (account cap rule).
# MUTS="1 5 7" runs only those mutant numbers.
. /data/hark/spike-rv/env.sh
P=${P:-/data/hark/spike-rv/loop4}; M=$P/mut; LOG=${LOG:-/data/hark/logs/rv/l4-mut.log}; : > $LOG
muts=(
 # loop round 4: OI read path (R3-O1 survivor "OI = 0") and the guarded account map
 "src/engine.rs@        let mut oi: u128 = self.state.accounts.oi_long.get(&market).copied().unwrap_or(0);@        let mut oi: u128 = 0;"
 "src/state.rs@        if after != self.before {@        if false {"
 "src/state.rs@            h.remove(&id);\n            if h.is_empty() {@            if h.is_empty() {"
 # loop round 4: withdraw
 "src/engine.rs@        if pending >= MAX_PENDING_WITHDRAWALS_PER_ACCOUNT {@        if pending > MAX_PENDING_WITHDRAWALS_PER_ACCOUNT {"
 "src/engine.rs@        if amount > 0 && amount < MIN_WITHDRAW_AMOUNT && amount != acct.collateral {@        if amount > 0 && amount <= MIN_WITHDRAW_AMOUNT && amount != acct.collateral {"
 "src/engine.rs@acct.snapshot(&self.state.marks, &self.state.markets).equity < resting {@acct.snapshot(&self.state.marks, &self.state.markets).equity <= resting {"
 # loop round 4: liquidate / keeper / ADL haircut
 "src/engine.rs@        if caller == target {\n            return Err(RejectReason::BadAccount);@        if false {\n            return Err(RejectReason::BadAccount);"
 "src/engine.rs@            let pay = keeper_paid.min(bal.max(0));@            let pay = keeper_paid.min(bal.max(0)) / 2;"
 "src/engine.rs@adl_haircut_share(hole, *delta, total, Some(*id) == last);@adl_haircut_share(hole, *delta, total, false);"
 # loop round 4: funding / reports
 "src/state.rs@            .find(|s| s.height + FUNDING_EXTERNAL_MAX_STALENESS > self.height && s.price != 0)@            .find(|s| s.height + FUNDING_EXTERNAL_MAX_STALENESS >= self.height && s.price != 0)"
 "src/state.rs@        if q.len() < FUNDING_TWAP_MIN_SAMPLES {@        if q.len() + 1 < FUNDING_TWAP_MIN_SAMPLES {"
 "src/state.rs@            Some(last) if height < last + minuend_types::FUNDING_PEG_INTERVAL_HEIGHTS => {@            Some(last) if height <= last + minuend_types::FUNDING_PEG_INTERVAL_HEIGHTS => {"
 # loop round 4: SetHeight batch-commit hook (withdrawal prune), session account cap, import lock
 "src/lib.rs@            eng.state.withdrawals.retain(|_, w| w.height + REPLAY_WINDOW > height);@            eng.state.withdrawals.retain(|_, w| w.height + REPLAY_WINDOW >= height);"
 "src/lib.rs@s.accounts.contains_key(&author) || s.accounts.len() < cap,@s.accounts.contains_key(&author) || s.accounts.len() <= cap,"
 "src/lib.rs@        BatchOp::Deposit { .. } | BatchOp::Liquidate { .. } =>@        BatchOp::Deposit { .. } =>"
 "src/lib.rs@    if d != *digest {@    if false {"
 "src/lib.rs@        Ok(mut s) if r.i == *words => {@        Ok(mut s) => {"
 "src/snapshot.rs@    if s.accounts.len() > crate::MAX_STATE_ACCOUNTS {@    if false {"

 # loop round 3 list (survivors of round 3 included)
 # loop round 3: S1b arrival-ordered level + arr index
 "src/book.rs@                        l.remove(&a);\n                        true@                        true"
 "src/book.rs@                Self::lvl_put(&mut dq, &mut self.arr, a, id);@                Self::lvl_put(&mut dq, &mut self.arr, a + 1_000_000, id);"
 "src/book.rs@        if let Some(n) = j.next_arr0 {\n            self.next_arr = n;\n        }@"
 "src/book.rs@        let (a, id) = self.lvl_mut(side, price)?.pop_first()?;@        let (a, id) = self.lvl_mut(side, price)?.pop_last()?;"
 # loop round 3: running long OI
 "src/state.rs@                    self.put_account(id, a); // PILOT (S1b)@                    self.accounts.insert(id, a);"
 "src/state.rs@            self.put_account(fill.taker, taker); // PILOT (S1b)\n            self.put_account(fill.maker, maker);@            self.put_account(fill.taker, taker); // PILOT (S1b)\n            self.accounts.insert(fill.maker, maker);"
 # loop round 3: segments
 "src/lib.rs@    } else if rd(3) != 0 && (resumed || cfg!(feature = \"prod\")) {@    } else if rd(3) != 0 && cfg!(feature = \"prod\") {"
 "src/lib.rs@        wo.start_root = wo.root;\n@\n"
 "src/lib.rs@    if let Some(s) = sess.as_mut() {\n        s.segs += 1;\n    }@"
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
 "src/state.rs@        dirty.insert(*id);\n        let before = pos_of(a);@        let before = pos_of(a);"
 "src/engine.rs@        self.state.wit_dirty.orders.insert((market, order_id)); // PILOT (MNWIT1)@"
 "src/wit.rs@if o.isolated { 1 } else { 0 }, o.margin_left);@if o.isolated { 1 } else { 0 }, o.margin_left / 2);"
 "src/wit.rs@                    [R::L(x), R::E] | [R::E, R::L(x)] => {@                    [R::L(x), R::E] => {"
 "src/wit.rs@                        self.smt.remove(&key_of(&b.b[..b.kid]));\n                    }\n                    if !cur.is_empty() {@                    }\n                    if !cur.is_empty() {"
 # loop round 1 guards (shared host/guest code: only explicit expectations can see them)
 "src/lib.rs@    } else if rd(2) > MAX_UNITS {@    } else if rd(2) > MAX_UNITS + 1 {"
 "src/lib.rs@    } else if rd(1) > MAX_ACCOUNTS {@    } else if rd(1) > MAX_ACCOUNTS + 1 {"
 "src/lib.rs@accts.get(a as usize).copied().filter(|id| *id != INSURANCE_ACCOUNT);@accts.get(a as usize).copied();"
 # proof verifier (host reference = the AA rule set)
 "ed:src/smt_ref.rs@            if k2 == *k || (0..sib.len())@            if (0..sib.len())"
 "ed:src/smt_ref.rs@        Term::Empty => [0u8; 32],@        Term::Empty => return true,"
 "ed:src/smt_ref.rs@            if k2 == *k || (0..sib.len()).any(|d| bit(&k2, d) != bit(k, d)) {@            if k2 == *k {"
 # loop round 2: per-account order index (S1), journal deque-op undo (W4), depth rule (W2)
 "src/book.rs@        self.idx_del(o.account, *id);\n        Some(o)@        Some(o)"
 "src/book.rs@        self.by_acct.entry(a).or_default().insert(id);@"
 "src/book.rs@            for (a, id) in popped.into_iter().rev() {@            for (a, id) in popped.into_iter() {"
 "src/book.rs@            for _ in 0..pushed {@            for _ in 0..0 {"
 "src/book.rs@                    let x = self.lvl_pop_front(Side::Ask, price);\n                    if let Some(x) = x {\n                        self.jlevel(j, Side::Ask, price).popped.push(x);\n                    }\n                    self.drop_empty_level(Side::Ask, price);@                    let x = self.lvl_pop_front(Side::Ask, price);\n                    if let Some(x) = x {\n                        let _ = x;\n                    }\n                    self.drop_empty_level(Side::Ask, price);"
 "src/lib.rs@.map(|d| d <= wit::MAX_WIT_DEPTH)@.map(|d| d < wit::MAX_WIT_DEPTH)"
 "src/lib.rs@                && (has_pos || ok(&wit::pos_key(&author, m)))@"
 "src/lib.rs@        BatchOp::Deposit { .. } => !new_acct || ok(&wit::acct_key(&author)),@        BatchOp::Deposit { .. } => true,"
 "src/wit.rs@                    return Some(c + 1);@                    return Some(c);"
)
i=0
for m in "${muts[@]}"; do
  [[ "$m" == \#* ]] && continue
  i=$((i+1)); IFS='@' read -r f from to <<< "$m"
  [ -n "$MUTS" ] && ! [[ " $MUTS " == *" $i "* ]] && continue
  rm -rf $M; mkdir -p $M; cp -r $P/guest-engine $P/engine-diff $M/; ln -s $P/engine-src $M/engine-src
  case "$f" in ed:*) fp="$M/engine-diff/${f#ed:}";; *) fp="$M/guest-engine/$f";; esac
  python3 - "$fp" "$from" "$to" <<'PY'
import sys
p,a,b=sys.argv[1:]; a=a.replace('\\n','\n'); b=b.replace('\\n','\n'); s=open(p).read()
assert s.count(a)>=1, "pattern not found: "+a
open(p,'w').write(s.replace(a,b,1))
PY
  [ $? -ne 0 ] && { echo "mut $i: PATTERN MISSING" >> $LOG; continue; }
  (cd $M/engine-diff && CARGO_TARGET_DIR=/data/hark/target-l4-mut cargo build --release -q 2>>$LOG) || { echo "mut $i build fail" >> $LOG; continue; }
  (cd $M/engine-diff && CARGO_TARGET_DIR=/data/hark/target-l4-mut-d8 cargo build --release -q --features depth8 2>>$LOG) || { echo "mut $i d8 build fail" >> $LOG; continue; }
  B=/data/hark/target-l4-mut/release/engine-diff
  d8=$(/data/hark/target-l4-mut-d8/release/engine-diff depth8 5 2>/dev/null | tail -1 | sed 's/.*"ok":\([0-9]*\).*/\1/')
  fz=$($B fuzz 100 300 | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/')
  sc=$($B scen $P/engine-diff/scenarios/upstream.scn | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/')
  wf=$($B witfuzz 30 300 20 | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/')
  af=$($B advfuzz 30 300 | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/')
  stf=$($B selftest $P/poc/robust | tail -1)
  pf=$($B proofs 10 25 | tail -1)
  sf=$($B segfuzz 30 300 2>/dev/null | tail -1 | sed 's/.*"ok":\([0-9]*\).*/\1/')
  lq=$($B liqfuzz 30 300 2>/dev/null | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/')
  sn=$($B snaptest 20 200 2>/dev/null | tail -1 | sed 's/.*"ok":\([0-9]*\).*/\1/')
  cc=$($B capcheck 10 100 8 2>/dev/null | tail -1 | sed 's/.*"ok":\([0-9]*\).*/\1/')
  pk=ok; echo "$pf" | grep -q '"membership_bad":0,.*"absence_bad":0,.*"forged":0,' || pk=BAD
  k=no; { [ "$fz" != 100 ] || [ "$sc" != 47 ] || [ "$wf" != 30 ] || [ "$af" != 30 ] || [ "$stf" != '{"selftest_fail":[]}' ] || [ "$pk" != ok ] || [ "$d8" != 5 ] || [ "$sf" != 30 ] || [ "$lq" != 30 ] || [ "$sn" != 20 ] || [ "$cc" != 10 ]; } && k=KILLED
  echo "mut $i [$f: ${to:0:70}] fuzz $fz/100 scen $sc/47 witfuzz $wf/30 advfuzz $af/30 selftest $stf proofs $pk depth8 $d8/5 segfuzz $sf/30 liqfuzz $lq/30 snaptest $sn/20 capcheck $cc/10 -> $k" >> $LOG
done
echo DONE >> $LOG
