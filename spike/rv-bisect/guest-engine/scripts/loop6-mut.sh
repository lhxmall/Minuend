#!/bin/bash
# Loop round 6 mutation test (= loop5-mut.sh on loop6 sources + round-6 mutants 80.. (governance / commit-reveal
# port, review caps) + checks govfuzz 20 300 and govedge (7 cases); liqedge now includes liq_eq / liq_eq_plus1 (survivor 35)).
# Loop round 5 mutation test (= loop4-mut.sh, patterns updated for round 5, + round-5 mutants 59.., + checks orafuzz 20 300,
# hbind 20 300, snapcap, liqedge; liqfuzz also runs every batch as MNP2). Original round-4 header:
# Loop round 4 mutation test: loop-4 mutants first (Accounts guard / holders index, liquidate / ADL / keeper /
# withdraw / report ports, SetHeight prune, session account cap, import lock), then the loop-3 survivors and the
# loop-3 list (patterns updated for round 4). Checks per mutant: loop3-mut.sh's set plus
#   liqfuzz 30 300 (port vs real engine on liquidate / ADL / withdraw / reports / ext prices / heights),
#   snaptest 20 200 (export / import / import lock / digest), capcheck 10 100 8 (account cap rule).
# MUTS="1 5 7" runs only those mutant numbers. liqedge (deterministic boundary batches) added after the first
# full run; the first run's survivors were re-run with it (LOG=l4-mut2.log).
. /data/hark/spike-rv/env.sh
P=${P:-/data/hark/spike-rv/loop6}; M=$P/mut; LOG=${LOG:-/data/hark/logs/rv/l6-mut.log}; : > $LOG
muts=(
 # loop round 4: OI read path (R3-O1 survivor "OI = 0") and the guarded account map
 "src/engine.rs@        let mut oi: u128 = self.state.accounts.oi_long_of(market);@        let mut oi: u128 = 0;"
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
 "src/lib.rs@    s.withdrawals.retain(|_, w| w.height + REPLAY_WINDOW > height);@    s.withdrawals.retain(|_, w| w.height + REPLAY_WINDOW >= height);"
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
 "src/lib.rs@        s.segs = opt.run_no.unwrap_or(s.segs + 1);@        s.segs = opt.run_no.unwrap_or(s.segs);"
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
 # loop round 5 (59..): MNP2 unit ids (R4-M2), height binding (R4-M4), import run count, oracle stake / unstake / slash
 # port (R4-M3), PERP acct: leaves, hook commit (R5-L4)
 "src/lib.rs@                    ev(if (f.kind == 2 || f.kind == 3) && !v2 {@                    ev(if f.kind == 2 || f.kind == 3 {"
 "src/lib.rs@rd(uid_base + i * 8 + k as u32)@rd(uid_base + k as u32)"
 "src/lib.rs@    if bind_height && (*segs as Height) > eng.state.height {@    if false {"
 "src/lib.rs@                let ok_h = !bind_height && !cfg!(feature = \"prod\") && height >= eng.state.height;@                let ok_h = !cfg!(feature = \"prod\") && height >= eng.state.height;"
 "src/lib.rs@        s.segs = opt.run_no.unwrap_or(s.segs + 1);@        s.segs += 1;"
 "src/lib.rs@        s.segs = opt.run_no.unwrap_or(1);@        s.segs = 1;"
 "src/lib.rs@            s.segs += 1;\n            s.bind_height@            s.bind_height"
 "src/lib.rs@    s.prune_oracle_unbonding(height);@"
 "src/state.rs@        if bal < crate::types::ORACLE_BOND_PERP {@        if bal <= crate::types::ORACLE_BOND_PERP {"
 "src/state.rs@            if dev < deviation_bps {@            if dev <= deviation_bps {"
 "src/state.rs@                if sample.height != prev.height + 1 {@                if false {"
 "src/state.rs@        let burn = bond * (crate::types::SLASH_REWARD_BPS as u128) / 10_000;@        let burn = bond / 3;"
 "src/state.rs@            if *unlock <= current_height {@            if *unlock < current_height {"
 "src/state.rs@        self.perp_balances.insert(id, v);\n        self.accounts.mark_dirty(id);@        self.perp_balances.insert(id, v);"
 "src/wit.rs@                None if s.perp_balances.contains_key(id) || s.withdrawn_total.contains_key(id) => {@                None if false => {"
 "src/lib.rs@            wo.root = w.commit(&mut eng.state);@            let _ = &w;"
 "src/state.rs@        if self.height.saturating_sub(latest_height) > 256 {@        if self.height.saturating_sub(latest_height) > 257 {"
 "src/state.rs@        self.oracle_unbonding.remove(&target);\n        self.oracle_reports.remove(&(market, target));@        self.oracle_reports.remove(&(market, target));"

 # loop round 6 (80..): governance + commit-reveal port (R4-M3 rest), review caps R6-H1/H2/H3/M1
 "src/engine.rs@        if nonce <= self.state.seen_gov_nonces.get(&account).copied().unwrap_or(0) {@        if nonce < self.state.seen_gov_nonces.get(&account).copied().unwrap_or(0) {"
 "src/engine.rs@        if bal < amount {\n            return Err(RejectReason::Insufficient);\n        }\n        self.state.set_perp(account, bal - amount); // PILOT (MNWIT1)@        if bal <= amount {\n            return Err(RejectReason::Insufficient);\n        }\n        self.state.set_perp(account, bal - amount); // PILOT (MNWIT1)"
 "src/engine.rs@            .filter(|s| *s <= minuend_types::PERP_SUPPLY_MAX)@            .filter(|s| *s < minuend_types::PERP_SUPPLY_MAX)"
 "src/engine.rs@        if bal < minuend_types::CREATE_MARKET_FEE_PERP {@        if bal <= minuend_types::CREATE_MARKET_FEE_PERP {"
 "src/engine.rs@        self.state.perp_burned += minuend_types::CREATE_MARKET_FEE_PERP;@"
 "src/engine.rs@        self.state.wit_dirty.markets.insert(id); // PILOT (MNWIT1): band: + meta: leaves@"
 "src/engine.rs@        if funding_rate {\n            self.state.external_sources.insert(creator);@        if false {\n            self.state.external_sources.insert(creator);"
 "src/engine.rs@        if self.state.proposals.len() >= 64 {@        if self.state.proposals.len() > 64 {"
 "src/engine.rs@        if bal < minuend_types::PROPOSAL_MIN_STAKE_PERP {@        if bal <= minuend_types::PROPOSAL_MIN_STAKE_PERP {"
 "src/engine.rs@        if seq >= p.deadline_seq {@        if seq > p.deadline_seq {"
 "src/engine.rs@            if seq < p.deadline_seq {@            if seq <= p.deadline_seq {"
 "src/engine.rs@                && p.yes * minuend_types::PROPOSAL_QUORUM_DEN >= p.supply_at_create@                && p.yes * minuend_types::PROPOSAL_QUORUM_DEN > p.supply_at_create"
 "src/engine.rs@            let pass = p.yes > p.no@            let pass = p.yes >= p.no"
 "src/engine.rs@                    self.state.wit_dirty.markets.insert(market); // PILOT (MNWIT1): meta: leaf@"
 "src/engine.rs@.filter(|(_, &b)| b != 0)@.filter(|(_, &_b)| true)"
 "src/engine.rs@        if ttl_height <= commit_height || ttl_height > commit_height + minuend_types::COMMIT_TTL_HEIGHTS {@        if ttl_height < commit_height || ttl_height > commit_height + minuend_types::COMMIT_TTL_HEIGHTS {"
 "src/engine.rs@        if ttl_height <= commit_height || ttl_height > commit_height + minuend_types::COMMIT_TTL_HEIGHTS {@        if ttl_height <= commit_height || ttl_height >= commit_height + minuend_types::COMMIT_TTL_HEIGHTS {"
 "src/engine.rs@        if pending >= minuend_types::MAX_PENDING_COMMITS_PER_ACCOUNT {@        if pending > minuend_types::MAX_PENDING_COMMITS_PER_ACCOUNT {"
 "src/engine.rs@self.state.height > entry.ttl_height@self.state.height >= entry.ttl_height"
 "src/engine.rs@        if !parents.contains(&entry.commit_unit) {@        if false {"
 "src/lib.rs@            if out.is_err() {\n                eng.reveal_undo(commit_ref);\n            }@"
 "src/state.rs@        self.commits.retain(|_, e| e.ttl_height >= min_height);@        self.commits.retain(|_, e| e.ttl_height > min_height);"
 "src/lib.rs@            b.push(11);\n            b.extend_from_slice(&id(acct)?.0);\n            b.extend_from_slice(&market.to_le_bytes());\n            b.push(key);@            b.push(11);\n            b.extend_from_slice(&id(acct)?.0);\n            b.extend_from_slice(&market.to_le_bytes());\n            b.push(key ^ 1);"
 "src/lib.rs@p.voted.len() < p.weight_snapshot.len() + MAX_ZERO_VOTERS@p.voted.len() <= p.weight_snapshot.len() + MAX_ZERO_VOTERS"
 "src/lib.rs@        BatchOp::Commit { .. } => s.commits.len() < MAX_STATE_COMMITS,@        BatchOp::Commit { .. } => s.commits.len() <= MAX_STATE_COMMITS,"
 "src/lib.rs@        BatchOp::GovDeposit { .. } | BatchOp::GovWithdraw { .. } | BatchOp::Slash { .. } => {@        BatchOp::GovDeposit { .. } | BatchOp::Slash { .. } => {"
 "src/snapshot.rs@        w.b(e.revealed);@        w.b(false);"
 "src/lib.rs@    s.prune_commits(height);@"
 "src/lib.rs@            let signer_ok = inner.signer().and_then(acct_of) == Some(a);@            let signer_ok = inner.signer().and_then(acct_of).is_some();"
 "src/lib.rs@        if self.n > MAX_EXT || off.checked_add(len)? > self.n {@        if self.n > MAX_EXT || off.checked_add(len)? >= self.n {"
 "src/lib.rs@        BatchOp::CreateMarket { .. } => s.markets.len() < MAX_STATE_MARKETS,@        BatchOp::CreateMarket { .. } => s.markets.len() <= MAX_STATE_MARKETS,"
 "src/lib.rs@        BatchOp::CreateMarket { .. } => wit::market_keys(MarketId(s.next_market_id)).iter().all(|k| ok(k)),@        BatchOp::CreateMarket { .. } => true,"

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
  (cd $M/engine-diff && CARGO_TARGET_DIR=/data/hark/target-l6-mut cargo build --release -q 2>>$LOG) || { echo "mut $i build fail" >> $LOG; continue; }
  (cd $M/engine-diff && CARGO_TARGET_DIR=/data/hark/target-l6-mut-d8 cargo build --release -q --features depth8 2>>$LOG) || { echo "mut $i d8 build fail" >> $LOG; continue; }
  B=/data/hark/target-l6-mut/release/engine-diff
  d8=$(/data/hark/target-l6-mut-d8/release/engine-diff depth8 5 2>/dev/null | tail -1 | sed 's/.*"ok":\([0-9]*\).*/\1/')
  fz=$($B fuzz 100 300 | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/')
  sc=$($B scen $P/engine-diff/scenarios/upstream.scn | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/')
  wf=$($B witfuzz 30 300 20 | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/')
  af=$($B advfuzz 30 300 | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/')
  stf=$($B selftest ${ROBUST:-/data/hark/spike-rv/loop3/poc/robust} | tail -1)
  pf=$($B proofs 10 25 | tail -1)
  sf=$($B segfuzz 30 300 2>/dev/null | tail -1 | sed 's/.*"ok":\([0-9]*\).*/\1/')
  lq=$($B liqfuzz 30 300 2>/dev/null | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/')
  sn=$($B snaptest 20 200 2>/dev/null | tail -1 | sed 's/.*"ok":\([0-9]*\).*/\1/')
  cc=$($B capcheck 10 100 8 2>/dev/null | tail -1 | sed 's/.*"ok":\([0-9]*\).*/\1/')
  of=$($B orafuzz 20 300 2>/dev/null | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/')
  hb=$($B hbind 20 300 2>/dev/null | tail -1 | sed 's/.*"ok":\([0-9]*\).*/\1/')
  sk=$($B snapcap 2>/dev/null | tail -1 | sed 's/.*"ok":\([a-z]*\).*/\1/')
  le=$($B liqedge 2>/dev/null | grep -c '"ok":true')
  gv=$($B govfuzz 20 300 2>/dev/null | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/')
  ge=$($B govedge 2>/dev/null | tail -1 | sed 's/.*"ok":\([0-9]*\).*/\1/')
  pk=ok; echo "$pf" | grep -q '"membership_bad":0,.*"absence_bad":0,.*"forged":0,' || pk=BAD
  k=no; { [ "$fz" != 100 ] || [ "$sc" != 47 ] || [ "$wf" != 30 ] || [ "$af" != 30 ] || [ "$stf" != '{"selftest_fail":[]}' ] || [ "$pk" != ok ] || [ "$d8" != 5 ] || [ "$sf" != 30 ] || [ "$lq" != 30 ] || [ "$sn" != 20 ] || [ "$cc" != 10 ] || [ "$le" != 1 ] || [ "$of" != 20 ] || [ "$hb" != 20 ] || [ "$sk" != true ] || [ "$gv" != 20 ] || [ "$ge" != 7 ]; } && k=KILLED
  echo "mut $i [$f: ${to:0:70}] fuzz $fz/100 scen $sc/47 witfuzz $wf/30 advfuzz $af/30 selftest $stf proofs $pk depth8 $d8/5 segfuzz $sf/30 liqfuzz $lq/30 snaptest $sn/20 capcheck $cc/10 liqedge $le/1 orafuzz $of/20 hbind $hb/20 snapcap $sk govfuzz $gv/20 govedge $ge/7 -> $k" >> $LOG
done
echo DONE >> $LOG
