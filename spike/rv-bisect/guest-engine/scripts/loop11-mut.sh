#!/bin/bash
# Loop round 11 mutation subset: the R10-H1 caps (lib.rs state_cap_ok: MAX_STATE_MARKETS 16, MAX_STATE_ORACLES 32).
# Fail-fast like loop8-mut.sh. govedge has 9 cases (case 9 r10:* incl. r10:cap_values; case 7 cap:markets). The harness
# mirror (gov.rs pilot_gov_refused `caps`) is independent code over the real engine's state, so govfuzz / xfuzz also see
# predicate mutations in lib.rs once a run reaches a cap. MUTS="1 3" runs only those.
. /data/hark/spike-rv/env.sh
P=${P:-/data/hark/spike-rv/loop11}; M=$P/mut; LOG=${LOG:-/data/hark/logs/rv/l11-mut.log}; T=/data/hark/target-l11-mut; [ -n "$KEEP" ] || : > $LOG
muts=(
 "src/lib.rs@BatchOp::CreateMarket { .. } => s.markets.len() < MAX_STATE_MARKETS,@BatchOp::CreateMarket { .. } => true,"
 "src/lib.rs@BatchOp::CreateMarket { .. } => s.markets.len() < MAX_STATE_MARKETS,@BatchOp::CreateMarket { .. } => s.markets.len() <= MAX_STATE_MARKETS,"
 "src/lib.rs@BatchOp::Stake { .. } => s.oracle_bonds.contains_key(&author) || s.oracle_bonds.len() < MAX_STATE_ORACLES,@BatchOp::Stake { .. } => true,"
 "src/lib.rs@BatchOp::Stake { .. } => s.oracle_bonds.contains_key(&author) || s.oracle_bonds.len() < MAX_STATE_ORACLES,@BatchOp::Stake { .. } => s.oracle_bonds.len() < MAX_STATE_ORACLES,"
 "src/lib.rs@BatchOp::Stake { .. } => s.oracle_bonds.contains_key(&author) || s.oracle_bonds.len() < MAX_STATE_ORACLES,@BatchOp::Stake { .. } => s.oracle_bonds.contains_key(&author) || s.oracle_bonds.len() <= MAX_STATE_ORACLES,"
 "src/lib.rs@pub const MAX_STATE_MARKETS: usize = 16;@pub const MAX_STATE_MARKETS: usize = 32;"
 "src/lib.rs@pub const MAX_STATE_ORACLES: usize = 32;@pub const MAX_STATE_ORACLES: usize = 64;"
)
i=0
for m in "${muts[@]}"; do
  i=$((i+1)); IFS='@' read -r f from to <<< "$m"
  [ -n "$MUTS" ] && ! [[ " $MUTS " == *" $i "* ]] && continue
  rm -rf $M; mkdir -p $M; cp -r $P/guest-engine $P/engine-diff $M/; ln -s $P/engine-src $M/engine-src
  fp="$M/guest-engine/$f"
  python3 - "$fp" "$from" "$to" <<'PY'
import sys
p,a,b=sys.argv[1:]; a=a.replace('\\n','\n'); b=b.replace('\\n','\n'); s=open(p).read()
assert s.count(a)>=1, "pattern not found: "+a
open(p,'w').write(s.replace(a,b,1))
PY
  [ $? -ne 0 ] && { echo "mut $i: PATTERN MISSING" >> $LOG; continue; }
  (cd $M/engine-diff && CARGO_TARGET_DIR=$T cargo build --release -q 2>>$LOG) || { echo "mut $i build fail" >> $LOG; continue; }
  B=$T/release/engine-diff; res=""; k=no
  if [ "$k" = no ]; then v=$($B govedge 2>/dev/null | tail -1); res="$res govedge ${v:0:160}"; echo "$v" | grep -q '"ok":9,' || k="KILLED by govedge"; fi
  if [ "$k" = no ]; then v=$($B govfuzz 20 300 2>/dev/null | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/'); res="$res govfuzz $v"; [ "$v" != '20' ] && k="KILLED by govfuzz"; fi
  if [ "$k" = no ]; then v=$($B xfuzz 20 300 2>/dev/null | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/'); res="$res xfuzz $v"; [ "$v" != '20' ] && k="KILLED by xfuzz"; fi
  if [ "$k" = no ]; then v=$($B capcheck 10 100 8 2>/dev/null | tail -1 | sed 's/.*"ok":\([0-9]*\).*/\1/'); res="$res capcheck $v"; [ "$v" != '10' ] && k="KILLED by capcheck"; fi
  if [ "$k" = no ]; then v=$($B orafuzz 20 300 2>/dev/null | tail -1 | sed 's/.*"match":\([0-9]*\).*/\1/'); res="$res orafuzz $v"; [ "$v" != '20' ] && k="KILLED by orafuzz"; fi
  echo "mut $i [${to:0:90}]$res -> $k" >> $LOG
done
echo MUTDONE >> $LOG
