#ifndef LN_MICRO_LIBC_H
#define LN_MICRO_LIBC_H

#include "guest.h"

/* Minimal freestanding runtime layer backed by LinuxNative syscall ABI. */

#ifndef O_DIRECTORY
#define O_DIRECTORY 040000
#endif

/* Simple bump/mmap allocator with header tracking allocation size */
static inline void *mini_malloc(size_t size)
{
    if (!size) return 0;
    size_t total = size + 16;
    /* Round up to 16-byte alignment */
    total = (total + 15) & ~(size_t)15;
    long p = call6(LN_MMAP, 0, total, LN_PROT_READ | LN_PROT_WRITE,
                   LN_MAP_PRIVATE | LN_MAP_ANONYMOUS, -1, 0);
    if (p <= 0 || p == -1) return 0;
    uint64_t *hdr = (uint64_t *)(uintptr_t)p;
    hdr[0] = total;
    hdr[1] = 0xbeefcafe;
    return (void *)(hdr + 2);
}

static inline void mini_free(void *ptr)
{
    if (!ptr) return;
    uint64_t *hdr = ((uint64_t *)ptr) - 2;
    if (hdr[1] != 0xbeefcafe) return;
    size_t total = (size_t)hdr[0];
    call2(LN_MUNMAP, (long)hdr, total);
}

/* Process identity */
static inline long sys_getpid(void)  { return call1(LN_GETPID, 0); }
static inline long sys_getppid(void) { return call1(LN_GETPPID, 0); }
static inline long sys_getuid(void)  { return call1(LN_GETUID, 0); }
static inline long sys_geteuid(void) { return call1(LN_GETEUID, 0); }
static inline long sys_getgid(void)  { return call1(LN_GETGID, 0); }
static inline long sys_getegid(void) { return call1(LN_GETEGID, 0); }
static inline long sys_gettid(void)  { return call1(LN_GETTID, 0); }

/* File and directory I/O */
static inline long sys_open(const char *path, int flags, int mode)
{
    return call4(LN_OPENAT, LN_AT_FDCWD, (long)path, flags, mode);
}

static inline long sys_creat(const char *path, int mode)
{
    return call4(LN_OPENAT, LN_AT_FDCWD, (long)path, LN_O_WRONLY | LN_O_CREAT | LN_O_TRUNC, mode);
}

static inline long sys_mkdir(const char *path, int mode)
{
    return call3(LN_MKDIRAT, LN_AT_FDCWD, (long)path, mode);
}

static inline long sys_unlink(const char *path)
{
    return call3(LN_UNLINKAT, LN_AT_FDCWD, (long)path, 0);
}

static inline long sys_rmdir(const char *path)
{
    return call3(LN_UNLINKAT, LN_AT_FDCWD, (long)path, LN_AT_REMOVEDIR);
}

static inline long sys_close(long fd)
{
    return call3(LN_CLOSE, fd, 0, 0);
}

static inline long sys_read(long fd, void *buf, size_t count)
{
    return call3(LN_READ, fd, (long)buf, count);
}

static inline long sys_write(long fd, const void *buf, size_t count)
{
    return call3(LN_WRITE, fd, (long)buf, count);
}

/* Output helpers */
static inline void mini_puts(const char *s)
{
    size_t len = 0;
    while (s[len]) ++len;
    write_all(1, s, len);
}

static inline void mini_putc(char c)
{
    write_all(1, &c, 1);
}

static inline void mini_print_u64(uint64_t n)
{
    char buf[24];
    size_t i = 0;
    do {
        buf[i++] = '0' + (n % 10);
        n /= 10;
    } while (n);
    for (size_t j = 0; j < i / 2; ++j) {
        char tmp = buf[j];
        buf[j] = buf[i - 1 - j];
        buf[i - 1 - j] = tmp;
    }
    write_all(1, buf, i);
}

#endif
