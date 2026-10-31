#!/bin/bash
# Harness self-test: inject known bugs into a copy of js/ref.js and check that the sail comparison alone
# (RVSTEP=0, so rv_step is not involved) catches every one.   usage: XTMP=dir ./mutants.sh [N]
cd "$(dirname "$0")"; N=${1:-1500}; D=${XTMP:-$PWD/tmp}/mut; mkdir -p $D
R=../js/ref.js
mk(){ sed "$2" $R > $D/$1.js; if cmp -s $R $D/$1.js; then echo "MUTANT $1 did not apply"; fi; }
mk sltiu_signed   's/case 3: wr(a < B2 ? 1 : 0)/case 3: wr(s32(a) < s32(B2) ? 1 : 0)/'
mk lh_zeroext     's/if (f3 < 3 \&\& size < 4) v = sx/if (f3 < 1 \&\& size < 4) v = sx/'
mk remu_div0      's/case 7: r = b === 0 ? A : A % B/case 7: r = b === 0 ? 0n : A % B/'
mk div_ovf        's/(s32(a) === -M32 \/ 2 \&\& s32(b) === -1) ? As : As \/ Bs/(s32(a) === -M32 \/ 2 \&\& s32(b) === -1) ? 0n : As \/ Bs/'
# (B2 & 63 instead of & 31 is an EQUIVALENT mutant in JS: <<, >>, >>> already use the low 5 bits of the count)
mk sra_logical    's/wr(alt ? s32(a) >> sh : a >>> sh)/wr(a >>> sh)/'
mk sll_reg_noshift_mask 's/case 1: wr(a << sh)/case 1: wr(Number(BigInt.asUintN(32, BigInt(a) << BigInt(B2 % 64))))/'
mk jalr_nolsb     's/jumpTo((a + immI) \& ~1)/jumpTo(a + immI)/'
mk sb_mask        's/(2 \*\* (8 \* size) - 1) \* 2 \*\* (8 \* off)/(2 ** (8 * size) - 1)/'
mk bge_unsigned   's/case 5: c = s32(a) >= s32(b)/case 5: c = a >= b/'
mk mulhsu_swap    's/case 2: r = (As \* B) >> 32n/case 2: r = (A * Bs) >> 32n/'
mk auipc_noadd    's/wr(st.pc + immU)/wr(immU)/'
rm -f $D/shamt6.js
for m in $D/${ONLY:-*}.js; do n=$(basename $m .js)
  r=$(XREF=$m RVSTEP=0 N=$N SEED=99 node xfuzz.js 2>/dev/null | tail -1 | node -e 'const s=JSON.parse(require("fs").readFileSync(0)).summary; console.log(s.bugs)')
  t=$(XREF=$m RVSTEP=0 node xtests.js ${RVT:-/data/hark/spike-rv/rvt/out}/*.elf 2>/dev/null | tail -1 | node -e 'const s=JSON.parse(require("fs").readFileSync(0)).summary; console.log(s.bugs)')
  echo "{\"mutant\":\"$n\",\"fuzzBugCases\":$r,\"riscvTestsBug\":$t}"
done
