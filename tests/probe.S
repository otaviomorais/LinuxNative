// Freestanding guest: no libc, no runtime imports, direct Linux syscalls.
.text
.global _start
.type _start, %function
_start:
    // Full integer/NEON preservation, flags and floating-point control.
    .irp n,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
    mov x\n, #\n
    .endr
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    movi v\n\().16b, #0x5a
    .endr
    mov x0, #(1 << 22)
    msr fpcr, x0
    mov x0, #0x10
    msr fpsr, x0
    adr x0, saved_sp
    mov x8, sp
    str x8, [x0]
    mov x8, #0x7fff
    cmp xzr, xzr
    svc #0
    b.ne fail_registers
    cmn x0, #38
    b.ne fail_registers
    adr x0, saved_registers
    stp x1, x2, [x0, #0]
    stp x3, x4, [x0, #16]
    stp x5, x6, [x0, #32]
    stp x7, x8, [x0, #48]
    stp x9, x10, [x0, #64]
    stp x11, x12, [x0, #80]
    stp x13, x14, [x0, #96]
    stp x15, x16, [x0, #112]
    stp x17, x18, [x0, #128]
    stp x19, x20, [x0, #144]
    stp x21, x22, [x0, #160]
    stp x23, x24, [x0, #176]
    stp x25, x26, [x0, #192]
    stp x27, x28, [x0, #208]
    stp x29, x30, [x0, #224]
    mov x9, #1
1:
    ldr x10, [x0], #8
    mov x11, x9
    cmp x9, #8
    b.ne 2f
    mov x11, #0x7fff
2:
    cmp x10, x11
    b.ne fail_registers
    add x9, x9, #1
    cmp x9, #31
    b.ne 1b
    adr x0, saved_sp
    ldr x0, [x0]
    mov x1, sp
    cmp x0, x1
    b.ne fail_registers
    mrs x0, fpcr
    mov x1, #(1 << 22)
    cmp x0, x1
    b.ne fail_registers
    mrs x0, fpsr
    cmp x0, #0x10
    b.ne fail_registers
    adr x0, saved_vectors
    .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    str q\n, [x0], #16
    .endr
    adr x0, saved_vectors
    mov x1, #512
3:
    ldrb w2, [x0], #1
    cmp w2, #0x5a
    b.ne fail_registers
    subs x1, x1, #1
    b.ne 3b
    // This literal looks exactly like SVC. Mapping symbols must keep it data.
    adr x0, svc_literal
    ldr w0, [x0]
    mov w1, #1
    movk w1, #0xd400, lsl #16
    cmp w0, w1
    b.ne fail_registers

    // Missing files must return Linux's negative errno, not libc's -1.
    mov x0, #-100
    adr x1, missing_path
    mov x2, #0
    mov x8, #56
    svc #0
    cmn x0, #2
    b.ne fail_errno
    // Out-of-scope paths and write modes must be explicit refusals.
    mov x0, #-100
    adr x1, relative_path
    mov x2, #0
    svc #0
    cmn x0, #95
    b.ne fail_errno
    mov x0, #-100
    adr x1, parent_path
    svc #0
    cmn x0, #13
    b.ne fail_errno
    mov x0, #-100
    adr x1, input_path
    mov x2, #1
    svc #0
    cmn x0, #95
    b.ne fail_errno
    // Exercise open/read/close/write on a mapped /etc path.
    mov x0, #-100
    adr x1, input_path
    mov x2, #0
    svc #0
    tbnz x0, #63, fail_open
    mov x19, x0
    adr x1, buffer
    mov x2, #4096
    mov x8, #63
    svc #0
    cmp x0, #0
    b.le fail_read
    mov x20, x0
    mov x0, x19
    mov x8, #57
    svc #0
    cbnz x0, fail_read
    mov x0, #1
    adr x1, buffer
    mov x2, x20
    mov x8, #64
    svc #0
    cmp x0, x20
    b.ne fail_read
    mov x0, #0
    b finish
fail_registers: mov x0, #21; b finish
fail_errno:     mov x0, #22; b finish
fail_open:      mov x0, #23; b finish
fail_read:      mov x0, #24
finish:
    mov x8, #94
    svc #0
    brk #0
    b after_literal
svc_literal:
    .word 0xd4000001
after_literal:
    nop
.size _start, .-_start

.section .rodata
input_path: .asciz "/etc/linuxnative-probe.txt"
missing_path: .asciz "/etc/linuxnative-missing.txt"
relative_path: .asciz "etc/linuxnative-probe.txt"
parent_path: .asciz "/../linuxnative-probe.txt"
.bss
.p2align 4
saved_registers: .skip 240
saved_sp: .skip 8
.p2align 4
saved_vectors: .skip 512
buffer: .skip 4096
.section .note.GNU-stack,"",%progbits
