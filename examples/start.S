.text
.global _start
.type _start, %function
_start:
    mov x0, sp
    bl guest_main
    mov x8, #94
    svc #0
    brk #0
.size _start, .-_start
.section .note.GNU-stack,"",%progbits
