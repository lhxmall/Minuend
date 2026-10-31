#!/bin/bash
# Loop round 8 mutation subset (R7-M2 commit bond), from loop7-mut.sh.
# FAIL-FAST variant (loop round 7, generated from loop7-mut.sh by mkff): same mutants and checks, targeted checks first,
# stops at the first killing check (the box ran 4 mutation jobs + 3 suites at load ~25: ~20 min per full mutant).
# Loop round 7 mutation subset (R7 mutants; fail-fast; checks + xfuzz 20 300; govedge has 8 cases). Loop round 6 mutation test (= loop5-mut.sh on loop8 sources + round-6 mutants 80.. (governance / commit-reveal
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
P=${P:-/data/hark/spike-rv/loop8}; M=$P/mut; LOG=${LOG:-/data/hark/logs/rv/l8-mut.log}; [ -n "$KEEP" ] || : > $LOG
muts=(
 # loop round 8: R7-M2 commit bond (lib.rs commit_bond_ok / state_cap_ok); the harness mirror shares the predicate,
 # so only govedge's absolute expectations (case 8 r8:*, case 4/7) can kill these
 "src/lib.rs@    if !commit_bond_ok(@    if false && !commit_bond_ok("
 "src/lib.rs@None => balance >= reserved + COMMIT_BOND_PERP,@None => balance >= reserved,"
 "src/lib.rs@None => balance >= reserved + COMMIT_BOND_PERP,@None => balance > reserved + COMMIT_BOND_PERP,"
 "src/lib.rs@.is_none_or(|rest| rest >= reserved)@.is_none_or(|rest| rest > reserved)"
 "src/lib.rs@.is_none_or(|rest| rest >= reserved)@.is_some_and(|rest| rest >= reserved)"
 "src/lib.rs@        BatchOp::Stake { .. } => Some(types::ORACLE_BOND_PERP),\n@"
 "src/lib.rs@        BatchOp::CreateMarket { .. } => Some(types::CREATE_MARKET_FEE_PERP),\n@"
 "src/lib.rs@        BatchOp::GovWithdraw { amount, .. } => Some(amount as u128),\n@"
 "src/lib.rs@s.commits.values().filter(|e| e.account == author).count()@s.commits.values().filter(|e| e.account == author && !e.revealed).count()"
 "src/lib.rs@live() as u128 * COMMIT_BOND_PERP@live().saturating_sub(1) as u128 * COMMIT_BOND_PERP"
 "src/lib.rs@ || inner.is_some_and(|x| !state_cap_ok(&eng.state, &x, a, state_cap))@"
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
  (cd $M/engine-diff && CARGO_TARGET_DIR=/data/hark/target-l8-mut cargo build --release -q 2>>$LOG) || { echo "mut $i build fail" >> $LOG; continue; }
  B=/data/hark/target-l8-mut/release/engine-diff
  # fail-fast (loop round 7): targeted checks first, stop at the first mismatch; a survivor runs every check
  res=""; k=no
  if [ "$k" = no ]; then v=$($B govedge 2>/dev/null | tail -1 | sed 's/.*"ok":\([0-9]*\).*/\1/'); res="$res govedge $v"; [ "$v" != '8' ] && k="KILLED by govedge"; fi
  if [ "$k" = no ]; then v=$($B govfuzz 20 300 2>/dev/null | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/'); res="$res govfuzz $v"; [ "$v" != '20' ] && k="KILLED by govfuzz"; fi
  if [ "$k" = no ]; then v=$($B xfuzz 20 300 2>/dev/null | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/'); res="$res xfuzz $v"; [ "$v" != '20' ] && k="KILLED by xfuzz"; fi
  if [ "$k" = no ]; then v=$($B liqedge 2>/dev/null | grep -c '"ok":true'); res="$res liqedge $v"; [ "$v" != '1' ] && k="KILLED by liqedge"; fi
  if [ "$k" = no ]; then v=$($B capcheck 10 100 8 2>/dev/null | tail -1 | sed 's/.*"ok":\([0-9]*\).*/\1/'); res="$res capcheck $v"; [ "$v" != '10' ] && k="KILLED by capcheck"; fi
  if [ "$k" = no ]; then v=$($B snapcap 2>/dev/null | tail -1 | sed 's/.*"ok":\([a-z]*\).*/\1/'); res="$res snapcap $v"; [ "$v" != 'true' ] && k="KILLED by snapcap"; fi
  if [ "$k" = no ]; then v=$($B snaptest 20 200 2>/dev/null | tail -1 | sed 's/.*"ok":\([0-9]*\).*/\1/'); res="$res snaptest $v"; [ "$v" != '20' ] && k="KILLED by snaptest"; fi
  if [ "$k" = no ]; then v=$($B hbind 20 300 2>/dev/null | tail -1 | sed 's/.*"ok":\([0-9]*\).*/\1/'); res="$res hbind $v"; [ "$v" != '20' ] && k="KILLED by hbind"; fi
  if [ "$k" = no ]; then v=$($B orafuzz 20 300 2>/dev/null | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/'); res="$res orafuzz $v"; [ "$v" != '20' ] && k="KILLED by orafuzz"; fi
  if [ "$k" = no ]; then v=$($B liqfuzz 30 300 2>/dev/null | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/'); res="$res liqfuzz $v"; [ "$v" != '30' ] && k="KILLED by liqfuzz"; fi
  if [ "$k" = no ]; then v=$($B segfuzz 30 300 2>/dev/null | tail -1 | sed 's/.*"ok":\([0-9]*\).*/\1/'); res="$res segfuzz $v"; [ "$v" != '30' ] && k="KILLED by segfuzz"; fi
  if [ "$k" = no ]; then v=$($B fuzz 100 300 | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/'); res="$res fuzz $v"; [ "$v" != '100' ] && k="KILLED by fuzz"; fi
  if [ "$k" = no ]; then v=$($B scen $P/engine-diff/scenarios/upstream.scn | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/'); res="$res scen $v"; [ "$v" != '47' ] && k="KILLED by scen"; fi
  if [ "$k" = no ]; then v=$($B witfuzz 30 300 20 | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/'); res="$res witfuzz $v"; [ "$v" != '30' ] && k="KILLED by witfuzz"; fi
  if [ "$k" = no ]; then v=$($B advfuzz 30 300 | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/'); res="$res advfuzz $v"; [ "$v" != '30' ] && k="KILLED by advfuzz"; fi
  if [ "$k" = no ]; then v=$($B selftest ${ROBUST:-/data/hark/spike-rv/loop3/poc/robust} | tail -1); res="$res selftest $v"; [ "$v" != '{"selftest_fail":[]}' ] && k="KILLED by selftest"; fi
  if [ "$k" = no ]; then v=$($B proofs 10 25 | tail -1 | grep -q '"membership_bad":0,.*"absence_bad":0,.*"forged":0,' && echo ok || echo BAD); res="$res proofs $v"; [ "$v" != 'ok' ] && k="KILLED by proofs"; fi
  if [ "$k" = no ]; then v=$( (cd $M/engine-diff && CARGO_TARGET_DIR=/data/hark/target-l8-mut-d8 cargo build --release -q --features depth8 2>>$LOG) && /data/hark/target-l8-mut-d8/release/engine-diff depth8 5 2>/dev/null | tail -1 | sed 's/.*"ok":\([0-9]*\).*/\1/'); res="$res depth8 $v"; [ "$v" != '5' ] && k="KILLED by depth8"; fi
  echo "mut $i [$f: ${to:0:70}]$res -> $k" >> $LOG
done
echo DONE >> $LOG
