/* Freestanding C file inspector. The same ELF runs directly on Linux ARM64
 * and through LinuxNative, without linking against the runtime. */
#include "guest.h"

static unsigned char buffer[4096];
static char output[512];
static size_t used;

static void text(const char *s)
{
    while (*s) output[used++] = *s++;
}

static void number(uint64_t n)
{
    char digits[20];
    size_t count = 0;
    do { digits[count++] = '0' + n % 10; n /= 10; } while (n);
    while (count) output[used++] = digits[--count];
}

static void field(const char *name, uint64_t value)
{
    text(name);
    number(value);
}

static int fail(const char *message, size_t size, int code)
{
    write_all(2, message, size);
    return code;
}

#define FAIL(message, code) fail(message "\n", sizeof(message), code)

int guest_main(const uint64_t *stack)
{
    if (stack[0] != 2)
        return FAIL("usage: file-scan ABSOLUTE_PATH", 2);
    const char *path = (const char *)(uintptr_t)stack[2];
    long fd = call3(LN_OPENAT, -100, (long)path, 0);
    if (fd < 0) return FAIL("file-scan: open failed", 3);
    struct ln_stat status;
    if (call3(LN_FSTAT, fd, (long)&status, 0) < 0 || status.size < 0)
        return FAIL("file-scan: fstat failed", 4);
    if ((status.mode & 0170000) != 0100000)
        return FAIL("file-scan: regular file required", 4);
    if (call3(LN_LSEEK, fd, 0, 2) != status.size || call3(LN_LSEEK, fd, 0, 0) != 0)
        return FAIL("file-scan: seek failed", 5);
    uint64_t hash = UINT64_C(14695981039346656037), bytes = 0;
    unsigned char last = 0;
    for (;;) {
        long count = call3(LN_READ, fd, (long)buffer, sizeof(buffer));
        if (count == -4) continue;
        if (count < 0) return FAIL("file-scan: read failed", 6);
        if (!count) break;
        for (long i = 0; i < count; ++i) {
            hash ^= buffer[i];
            hash *= UINT64_C(1099511628211);
        }
        last = buffer[count - 1];
        bytes += (uint64_t)count;
    }
    if (bytes != (uint64_t)status.size)
        return FAIL("file-scan: file changed while reading", 6);
    if (bytes && (call3(LN_LSEEK, fd, -1, 2) != status.size - 1 ||
                  call3(LN_READ, fd, (long)buffer, 1) != 1 || buffer[0] != last))
        return FAIL("file-scan: backward seek failed", 5);
    if (call3(LN_CLOSE, fd, 0, 0)) return FAIL("file-scan: close failed", 6);
    field("{\"size\":", bytes);
    field(",\"mode\":", status.mode);
    field(",\"uid\":", status.uid);
    field(",\"gid\":", status.gid);
    field(",\"nlink\":", status.nlink);
    field(",\"ino\":", status.ino);
    field(",\"dev\":", status.dev);
    field(",\"blksize\":", status.blksize);
    field(",\"blocks\":", status.blocks);
    text(",\"mtime_sec\":");
    if (status.mtime_sec < 0) {
        text("-");
        number(-(uint64_t)status.mtime_sec);
    } else {
        number((uint64_t)status.mtime_sec);
    }
    field(",\"mtime_nsec\":", status.mtime_nsec);
    text(",\"fnv1a64\":\"");
    for (int shift = 60; shift >= 0; shift -= 4)
        output[used++] = "0123456789abcdef"[(hash >> shift) & 15];
    text("\"}\n");
    return write_all(1, output, used) ? 7 : 0;
}
