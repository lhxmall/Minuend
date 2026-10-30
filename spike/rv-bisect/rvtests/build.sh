#!/bin/bash
# build every rv32ui/rv32um test into an ELF via cpp + rustc global_asm (no gcc cross toolchain needed)
. /data/hark/spike-rv/env.sh
K=/data/hark/spike-rv/rvt; cd $K; mkdir -p out tmp
for f in src/isa/rv32ui/*.S src/isa/rv32um/*.S; do
  n=$(basename $(dirname $f))-$(basename $f .S)
  cpp -P -x assembler-with-cpp -D__riscv_xlen=32 -D__riscv -I kit -I src/isa/macros/scalar -I src/isa/rv64ui -I $(dirname $f) $f > tmp/$n.s 2>tmp/$n.cpp.err || { echo "CPPFAIL $n"; continue; }
  printf '#![no_std]\n#![no_main]\ncore::arch::global_asm!(include_str!("%s"), options(raw));\n#[panic_handler] fn p(_: &core::panic::PanicInfo) -> ! { loop {} }\n' "$K/tmp/$n.s" > tmp/$n.rs
  rustc --edition 2021 --target riscv32im-unknown-none-elf -C panic=abort -C opt-level=0 -C link-arg=-T$K/kit/link.ld -o out/$n.elf tmp/$n.rs > tmp/$n.rustc.err 2>&1 && echo "OK $n" || echo "BUILDFAIL $n"
done
