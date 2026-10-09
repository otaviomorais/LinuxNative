#define _GNU_SOURCE
#include "lnative.h"
#include "../include/linux_aarch64.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int root_fd = -1;
static int trace_calls;

_Static_assert(sizeof(off_t) == 8, "64-bit host file offsets required");

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
        return -EOPNOTSUPP; /* read-only files in the current prototype */
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

static long guest_fstat(const uint64_t *r)
{
    if (!r[1]) return -EFAULT;
    struct stat host;
    if (fstat((int)r[0], &host)) return -errno;
    uint64_t links = host.st_nlink;
    int64_t block_size = host.st_blksize;
    if (links > UINT32_MAX || block_size > INT32_MAX || block_size < 0)
        return -EOVERFLOW;
    /* Do not memcpy host struct stat: Bionic/glibc layout is not our ABI. */
    struct ln_stat guest = {
        .dev = host.st_dev, .ino = host.st_ino, .mode = host.st_mode,
        .nlink = host.st_nlink, .uid = host.st_uid, .gid = host.st_gid,
        .rdev = host.st_rdev, .size = host.st_size, .blksize = host.st_blksize,
        .blocks = host.st_blocks,
        .atime_sec = host.st_atim.tv_sec, .atime_nsec = host.st_atim.tv_nsec,
        .mtime_sec = host.st_mtim.tv_sec, .mtime_nsec = host.st_mtim.tv_nsec,
        .ctime_sec = host.st_ctim.tv_sec, .ctime_nsec = host.st_ctim.tv_nsec
    };
    memcpy((void *)(uintptr_t)r[1], &guest, sizeof(guest));
    return 0;
}

uint64_t ln_dispatch(uint64_t *r)
{
    long result;
    switch (r[8]) {
    case LN_OPENAT: /* An absolute path ignores dirfd. */
        result = guest_open(r);
        break;
    case LN_CLOSE:
        result = close((int)r[0]);
        if (result < 0) result = -errno;
        break;
    case LN_LSEEK:
        result = lseek((int)r[0], (off_t)(int64_t)r[1], (int)r[2]);
        if (result < 0) result = -errno;
        break;
    case LN_FSTAT:
        result = guest_fstat(r);
        break;
    case LN_READ:
        result = read((int)r[0], (void *)(uintptr_t)r[1], (size_t)r[2]);
        if (result < 0) result = -errno;
        break;
    case LN_WRITE:
        result = write((int)r[0], (const void *)(uintptr_t)r[1], (size_t)r[2]);
        if (result < 0) result = -errno;
        break;
    case LN_EXIT:
    case LN_EXIT_GROUP:
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
