#include "../examples/micro-libc.h"

static const char message[] = "static PIE ABI ok\n";
static uint64_t counter = 100;

int guest_main(const uint64_t *stack)
{
    (void)stack;

    /* Verify PC-relative read and write to data segment */
    counter += 42;
    if (counter != 142) return 1;

    /* Verify syscall routing */
    if (sys_getpid() <= 0 || sys_getuid() < 0) return 2;

    /* Verify dynamic memory allocation under relocated base */
    char *buf = mini_malloc(128);
    if (!buf) return 3;
    for (int i = 0; i < 128; ++i) buf[i] = (char)i;
    if (buf[64] != 64) {
        mini_free(buf);
        return 4;
    }
    mini_free(buf);

    mini_puts(message);
    return 0;
}
