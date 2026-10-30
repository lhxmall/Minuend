ENTRY(_start)
SECTIONS {
  . = 0x1000;
  .text : { *(.text.init) *(.text .text.*) }
  . = ALIGN(0x1000);
  .data : { *(.rodata .rodata.* .data .data.* .sdata .sdata.* .tohost) }
  .bss : { *(.bss .bss.* .sbss .sbss.* COMMON) }
  /DISCARD/ : { *(.eh_frame*) *(.comment) }
}
