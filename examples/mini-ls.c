#include "micro-libc.h"

int guest_main(const uint64_t *stack)
{
    const char *path = "/etc";
    if (stack[0] > 1) {
        path = (const char *)(uintptr_t)stack[2];
    }

    /* Check process identity syscalls */
    if (sys_getpid() <= 0 || sys_getppid() <= 0 || sys_gettid() <= 0) {
        mini_puts("mini-ls: invalid pid/ppid/tid\n");
        return 10;
    }
    if (sys_getuid() < 0 || sys_geteuid() < 0 || sys_getgid() < 0 || sys_getegid() < 0) {
        mini_puts("mini-ls: invalid uid/gid\n");
        return 11;
    }

    /* Print process identity */
    mini_puts("pid: ");
    mini_print_u64(sys_getpid());
    mini_puts(" uid: ");
    mini_print_u64(sys_getuid());
    mini_puts("\n");

    /* Open directory */
    long fd = call3(LN_OPENAT, -100, (long)path, O_DIRECTORY);
    if (fd < 0) {
        mini_puts("mini-ls: open failed\n");
        return 1;
    }

    /* Allocate buffer with dynamic heap memory */
    size_t bufsz = 4096;
    char *buf = mini_malloc(bufsz);
    if (!buf) {
        mini_puts("mini-ls: malloc failed\n");
        call3(LN_CLOSE, fd, 0, 0);
        return 2;
    }

    int entries = 0;
    for (;;) {
        long nbytes = call3(LN_GETDENTS64, fd, (long)buf, bufsz);
        if (nbytes < 0) {
            mini_puts("mini-ls: getdents64 failed\n");
            mini_free(buf);
            call3(LN_CLOSE, fd, 0, 0);
            return 3;
        }
        if (!nbytes) break;

        size_t bpos = 0;
        while (bpos < (size_t)nbytes) {
            struct ln_dirent64 *d = (struct ln_dirent64 *)(buf + bpos);
            mini_puts("entry: ");
            mini_puts(d->d_name);
            mini_puts(" type: ");
            mini_print_u64(d->d_type);
            mini_puts("\n");
            entries++;
            bpos += d->d_reclen;
        }
    }

    mini_free(buf);
    call3(LN_CLOSE, fd, 0, 0);

    mini_puts("entries counted: ");
    mini_print_u64(entries);
    mini_puts("\n");
    return 0;
}
