// Minimal bare env for running riscv-tests on the spike rv32im machine:
// pass/fail via ecall a7=93 (HALT) with a0 = 0 (pass) or (testnum<<1)|1 (fail). No CSRs.
#ifndef _ENV_SPIKE_H
#define _ENV_SPIKE_H
#define RVTEST_RV32U .macro init; .endm
#define RVTEST_RV64U .macro init; .endm
#define RVTEST_RV32M .macro init; .endm
#define TESTNUM gp
#define RVTEST_CODE_BEGIN .section .text.init,"ax",@progbits; .align 2; .globl _start; _start: init;
#define RVTEST_CODE_END unimp
#define RVTEST_PASS li a0, 0; li a7, 93; ecall
#define RVTEST_FAIL sll a0, TESTNUM, 1; or a0, a0, 1; li a7, 93; ecall
#define EXTRA_DATA
#define RVTEST_DATA_BEGIN EXTRA_DATA .align 4; .global begin_signature; begin_signature:
#define RVTEST_DATA_END .align 4; .global end_signature; end_signature:
#endif
