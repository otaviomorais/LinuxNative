// Direct-call gateway. No signal traps and no tracing process.
.text
.p2align 2
.global ln_gateway
.hidden ln_gateway
.type ln_gateway, %function
ln_gateway:
    sub sp, sp, #800
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    mrs x16, nzcv
    str x16, [sp, #248]
    mrs x16, fpcr
    str x16, [sp, #256]
    mrs x16, fpsr
    str x16, [sp, #264]
    stp q0, q1, [sp, #272]
    stp q2, q3, [sp, #304]
    stp q4, q5, [sp, #336]
    stp q6, q7, [sp, #368]
    stp q8, q9, [sp, #400]
    stp q10, q11, [sp, #432]
    stp q12, q13, [sp, #464]
    stp q14, q15, [sp, #496]
    stp q16, q17, [sp, #528]
    stp q18, q19, [sp, #560]
    stp q20, q21, [sp, #592]
    stp q22, q23, [sp, #624]
    stp q24, q25, [sp, #656]
    stp q26, q27, [sp, #688]
    stp q28, q29, [sp, #720]
    stp q30, q31, [sp, #752]
    mrs x16, tpidr_el0
    str x16, [sp, #784]
    // Restore host environment: x18 and tpidr_el0
    adrp x16, ln_host_x18
    ldr x18, [x16, :lo12:ln_host_x18]
    adrp x16, ln_host_tpidr
    ldr x16, [x16, :lo12:ln_host_tpidr]
    msr tpidr_el0, x16
    mov x0, sp
    bl ln_dispatch
    str x0, [sp, #0]
    ldp q0, q1, [sp, #272]
    ldp q2, q3, [sp, #304]
    ldp q4, q5, [sp, #336]
    ldp q6, q7, [sp, #368]
    ldp q8, q9, [sp, #400]
    ldp q10, q11, [sp, #432]
    ldp q12, q13, [sp, #464]
    ldp q14, q15, [sp, #496]
    ldp q16, q17, [sp, #528]
    ldp q18, q19, [sp, #560]
    ldp q20, q21, [sp, #592]
    ldp q22, q23, [sp, #624]
    ldp q24, q25, [sp, #656]
    ldp q26, q27, [sp, #688]
    ldp q28, q29, [sp, #720]
    ldp q30, q31, [sp, #752]
    ldr x16, [sp, #248]
    msr nzcv, x16
    ldr x16, [sp, #256]
    msr fpcr, x16
    ldr x16, [sp, #264]
    msr fpsr, x16
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x16, [sp, #784]
    msr tpidr_el0, x16
    ldr x30, [sp, #240]
    add sp, sp, #800
    ret
.size ln_gateway, .-ln_gateway

.global ln_enter
.type ln_enter, %function
ln_enter:
    adrp x9, ln_host_x18
    str x18, [x9, :lo12:ln_host_x18]
    mrs x10, tpidr_el0
    adrp x9, ln_host_tpidr
    str x10, [x9, :lo12:ln_host_tpidr]
    mov x9, x0
    mov sp, x1
    mov x0, #0
    mov x30, #0
    br x9
.size ln_enter, .-ln_enter

.bss
.p2align 3
ln_host_x18: .skip 8
ln_host_tpidr: .skip 8
.section .note.GNU-stack,"",%progbits
