#define _GNU_SOURCE
#include "lnative.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int root_fd = -1;
static int trace_calls;

int ln_runtime_init(const char *root, int verbose)
{
    root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0) {
        perror("lnative: root directory");
        return -1;
    }
    trace_calls = verbose;
    return 0;
}

static long guest_open(const uint64_t *r)
{
    /* Guest pointers must be valid in this trusted-code prototype. */
    const char *path = (const char *)(uintptr_t)r[1];
    if (!path)
        return -EFAULT;
    if (strnlen(path, PATH_MAX) == PATH_MAX)
        return -ENAMETOOLONG;
    if (path[0] != '/')
        return -EOPNOTSUPP;
    if (r[2] & ~(uint64_t)O_CLOEXEC)
        return -EOPNOTSUPP; /* read-only files in milestone 0 */
    for (const char *p = path; *p;) {
        while (*p == '/') ++p;
        const char *end = p;
        while (*end && *end != '/') ++end;
        if (end - p == 2 && p[0] == '.' && p[1] == '.')
            return -EACCES;
        p = end;
    }
    while (*path == '/') ++path;
    /* This is path mapping, not confinement: symlinks can leave the root. */
    int fd = openat(root_fd, *path ? path : ".", (int)r[2]);
    return fd < 0 ? -errno : fd;
}

uint64_t ln_dispatch(uint64_t *r)
{
    long result;
    switch (r[8]) {
    case 56: /* AArch64 openat; an absolute path ignores dirfd. */
        result = guest_open(r);
        break;
    case 57:
        result = close((int)r[0]);
        if (result < 0) result = -errno;
        break;
    case 63:
        result = read((int)r[0], (void *)(uintptr_t)r[1], (size_t)r[2]);
        if (result < 0) result = -errno;
        break;
    case 64:
        result = write((int)r[0], (const void *)(uintptr_t)r[1], (size_t)r[2]);
        if (result < 0) result = -errno;
        break;
    case 93:
    case 94:
        if (trace_calls)
            fprintf(stderr, "lnative: syscall %llu exit=%u\n",
                    (unsigned long long)r[8], (unsigned)(r[0] & 255));
        _exit((int)r[0]);
    default:
        result = -ENOSYS;
        break;
    }
    if (trace_calls)
        fprintf(stderr, "lnative: syscall %llu -> %ld\n",
                (unsigned long long)r[8], result);
    return (uint64_t)result;
}
