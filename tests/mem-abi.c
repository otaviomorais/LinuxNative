#include "../examples/guest.h"

int guest_main(const uint64_t *stack)
{
    if (stack[0] > 1) {
        const char *arg = (const char *)(uintptr_t)stack[2];
        if (arg && arg[0] == '-' && arg[1] == '-' && arg[2] == 's') {
            /* Test W^X policy on mmap -> -EACCES */
            if (call6(LN_MMAP, 0, 4096, LN_PROT_READ | LN_PROT_WRITE | LN_PROT_EXEC,
                      LN_MAP_PRIVATE | LN_MAP_ANONYMOUS, -1, 0) != -13)
                return 70;
            /* Test MAP_FIXED rejection -> -EOPNOTSUPP */
            if (call6(LN_MMAP, 0x10000000, 4096, LN_PROT_READ | LN_PROT_WRITE,
                      LN_MAP_PRIVATE | LN_MAP_ANONYMOUS | LN_MAP_FIXED, -1, 0) != -95)
                return 71;
            /* Test W^X policy on mprotect -> -EACCES */
            long p = call6(LN_MMAP, 0, 4096, LN_PROT_READ | LN_PROT_WRITE,
                           LN_MAP_PRIVATE | LN_MAP_ANONYMOUS, -1, 0);
            if (p <= 0) return 72;
            if (call3(LN_MPROTECT, p, 4096, LN_PROT_READ | LN_PROT_WRITE | LN_PROT_EXEC) != -13)
                return 73;
            call2(LN_MUNMAP, p, 4096);
            return write_all(1, "security policy ok\n", sizeof("security policy ok\n") - 1) ? 74 : 0;
        }
    }

    /* 1. Test uname */
    struct ln_utsname u;
    if (call1(LN_UNAME, 0) != -14) /* NULL pointer -> -EFAULT */
        return 10;
    if (call1(LN_UNAME, (long)&u) != 0)
        return 11;
    if (u.sysname[0] != 'L' || u.machine[0] != 'a')
        return 12;

    /* 2. Test brk */
    long b0 = call1(LN_BRK, 0);
    if (b0 <= 0)
        return 20;
    long b1 = call1(LN_BRK, b0 + 4096);
    if (b1 != b0 + 4096)
        return 21;
    *(volatile int *)(uintptr_t)b0 = 0x12345678;
    if (*(volatile int *)(uintptr_t)b0 != 0x12345678)
        return 22;
    long b2 = call1(LN_BRK, b0);
    if (b2 != b0)
        return 23;

    /* 3. Test mmap */
    /* Invalid length 0 -> -EINVAL */
    if (call6(LN_MMAP, 0, 0, LN_PROT_READ | LN_PROT_WRITE, LN_MAP_PRIVATE | LN_MAP_ANONYMOUS, -1, 0) != -22)
        return 30;

    /* Valid anonymous mmap */
    long p = call6(LN_MMAP, 0, 65536, LN_PROT_READ | LN_PROT_WRITE, LN_MAP_PRIVATE | LN_MAP_ANONYMOUS, -1, 0);
    if (p <= 0 || p == -1)
        return 31;

    unsigned char *mem = (unsigned char *)(uintptr_t)p;
    mem[0] = 0xaa;
    mem[65535] = 0x55;
    if (mem[0] != 0xaa || mem[65535] != 0x55)
        return 32;

    /* 4. Test mprotect */
    if (call3(LN_MPROTECT, p, 65536, LN_PROT_READ) != 0)
        return 40;

    /* 5. Test munmap */
    /* Unaligned address -> -EINVAL */
    if (call2(LN_MUNMAP, 1, 65536) != -22)
        return 50;
    /* Length 0 -> -EINVAL */
    if (call2(LN_MUNMAP, p, 0) != -22)
        return 51;
    /* Valid munmap */
    if (call2(LN_MUNMAP, p, 65536) != 0)
        return 52;

    return write_all(1, "memory ABI ok\n", sizeof("memory ABI ok\n") - 1) ? 60 : 0;
}
