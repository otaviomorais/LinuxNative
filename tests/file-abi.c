#include "../examples/guest.h"

static struct ln_stat status;

int guest_main(const uint64_t *stack)
{
    if (stack[0] != 2) return 30;
    long fd = call3(LN_OPENAT, -100, (long)stack[2], 0);
    if (fd < 0) return 31;
    if (call3(LN_FSTAT, -1, (long)&status, 0) != -9) return 32;
    if (call3(LN_FSTAT, fd, 0, 0) != -14) return 33;
    if (call3(LN_LSEEK, -1, 0, 0) != -9) return 34;
    if (call3(LN_LSEEK, fd, -1, 0) != -22) return 35;
    if (call3(LN_LSEEK, fd, 0, 99) != -22) return 36;
    if (call3(LN_FSTAT, fd, (long)&status, 0) || status.size < 0) return 37;
    if (call3(LN_LSEEK, fd, 0, 2) != status.size) return 38;
    if (call3(LN_LSEEK, fd, 0, 1) != status.size) return 39;
    if (call3(LN_LSEEK, fd, -status.size, 1) != 0) return 40;
    /* Verify 64-bit offsets without creating a multi-gigabyte file. */
    if (call3(LN_LSEEK, fd, (1L << 33) + 17, 0) != (1L << 33) + 17) return 41;
    char byte;
    if (call3(LN_READ, fd, (long)&byte, 1) != 0) return 42;
    if (call3(LN_CLOSE, fd, 0, 0)) return 43;
    return write_all(1, "file ABI ok\n", sizeof("file ABI ok\n") - 1) ? 44 : 0;
}
