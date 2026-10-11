ENTRY(_start)
PHDRS
{
  text PT_LOAD FLAGS(5);
  rodata PT_LOAD FLAGS(4);
  data PT_LOAD FLAGS(6);
}
SECTIONS
{
  . = 0x0;
  .text : { *(.text*) } :text
  . = ALIGN(0x10000);
  .rodata : { *(.rodata*) } :rodata
  . = ALIGN(0x10000);
  .data : { *(.data*) } :data
  .bss : { *(.bss*) *(COMMON) } :data
  /DISCARD/ : { *(.note*) *(.comment*) *(.eh_frame*) *(.dynamic) *(.dynsym) *(.dynstr) *(.gnu.hash) }
}
