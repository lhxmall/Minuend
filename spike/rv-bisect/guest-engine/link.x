ENTRY(_start)
MEMORY { RAM : ORIGIN = 0x1000, LENGTH = 0x3EFF000 }
SECTIONS {
  .text : { *(.text._start) *(.text .text.*) } > RAM
  .rodata : { *(.rodata .rodata.* .srodata .srodata.*) } > RAM
  .data : { *(.data .data.* .sdata .sdata.*) } > RAM
  .bss (NOLOAD) : { _bss_start = .; *(.bss .bss.* .sbss .sbss.* COMMON) _bss_end = .; } > RAM
  _heap_start = ALIGN(16);
  /DISCARD/ : { *(.eh_frame*) *(.comment) }
}
