ENTRY(_start)

PHDRS {
  stuff PT_LOAD FLAGS(7);
}

SECTIONS {
    /* here we place `.entry` as the first section */
    .entry  : { *(.entry) }
    . = .;
    .text   : { *(.text.*) }
    .rodata : { *(.rodata.*) }
    .data   : { *(.data.*) }
    .bss    : { *(.bss.*) }
}