ENTRY(_start)
MEMORY { RAM : ORIGIN = 0x1000, LENGTH = 0x3EFF000 }
SECTIONS {
  .text : { *(.text._start) *(.text .text.*) } > RAM
  .rodata : { *(.rodata .rodata.* .srodata .srodata.*) } > RAM
  .data : { *(.data .data.* .sdata .sdata.*) } > RAM
  .bss (NOLOAD) : { . = ALIGN(4); _bss_start = .; *(.bss .bss.* .sbss .sbss.* COMMON) . = ALIGN(4); _bss_end = .; } > RAM
  _heap_start = ALIGN(16);
  /DISCARD/ : { *(.eh_frame*) *(.comment) }
}
