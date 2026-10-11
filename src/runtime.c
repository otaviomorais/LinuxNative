#define _GNU_SOURCE
#include "lnative.h"
#include "../include/linux_aarch64.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

static int root_fd = -1;
static int trace_calls;
static uintptr_t guest_brk_initial;
static uintptr_t guest_brk_current;

void ln_runtime_set_bounds(uintptr_t base, size_t size)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t top = base + size;
    guest_brk_initial = (top + page - 1) & ~(page - 1);
    guest_brk_current = guest_brk_initial;
}

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

static long guest_resolve_path(const char *path, const char **rel_path)
{
    /* Guest pointers must be valid in this trusted-code prototype. */
    if (!path)
        return -EFAULT;
    if (strnlen(path, PATH_MAX) == PATH_MAX)
        return -ENAMETOOLONG;
    if (path[0] != '/')
        return -EOPNOTSUPP;
    for (const char *p = path; *p;) {
        while (*p == '/') ++p;
        const char *end = p;
        while (*end && *end != '/') ++end;
        if (end - p == 2 && p[0] == '.' && p[1] == '.')
            return -EACCES;
        p = end;
    }
    while (*path == '/') ++path;
    *rel_path = *path ? path : ".";
    return 0;
}

static long guest_open(const uint64_t *r)
{
    const char *rel_path = NULL;
    long err = guest_resolve_path((const char *)(uintptr_t)r[1], &rel_path);
    if (err) return err;

#ifndef O_LARGEFILE
#define O_LARGEFILE 0x8000
#endif

    uint64_t allowed = O_ACCMODE | O_CLOEXEC | O_DIRECTORY | O_CREAT | O_EXCL | O_TRUNC | O_APPEND |
                       O_NONBLOCK | O_NOCTTY | O_LARGEFILE;
    if (r[2] & ~allowed)
        return -EOPNOTSUPP;

    int fd = openat(root_fd, rel_path, (int)r[2], (mode_t)r[3]);
    return fd < 0 ? -errno : fd;
}

static long guest_mkdirat(const uint64_t *r)
{
    const char *rel_path = NULL;
    long err = guest_resolve_path((const char *)(uintptr_t)r[1], &rel_path);
    if (err) return err;

    if (mkdirat(root_fd, rel_path, (mode_t)r[2]))
        return -errno;
    return 0;
}

static long guest_unlinkat(const uint64_t *r)
{
    const char *rel_path = NULL;
    long err = guest_resolve_path((const char *)(uintptr_t)r[1], &rel_path);
    if (err) return err;

    int flags = (int)r[2];
    if (flags & ~AT_REMOVEDIR)
        return -EINVAL;

    if (unlinkat(root_fd, rel_path, flags))
        return -errno;
    return 0;
}

static int marshal_stat(const struct stat *host, void *guest_statbuf)
{
    uint64_t links = host->st_nlink;
    int64_t block_size = host->st_blksize;
    if (links > UINT32_MAX || block_size > INT32_MAX || block_size < 0)
        return -EOVERFLOW;
    /* Do not memcpy host struct stat: Bionic/glibc layout is not our ABI. */
    struct ln_stat guest = {
        .dev = host->st_dev, .ino = host->st_ino, .mode = host->st_mode,
        .nlink = host->st_nlink, .uid = host->st_uid, .gid = host->st_gid,
        .rdev = host->st_rdev, .size = host->st_size, .blksize = host->st_blksize,
        .blocks = host->st_blocks,
        .atime_sec = host->st_atim.tv_sec, .atime_nsec = host->st_atim.tv_nsec,
        .mtime_sec = host->st_mtim.tv_sec, .mtime_nsec = host->st_mtim.tv_nsec,
        .ctime_sec = host->st_ctim.tv_sec, .ctime_nsec = host->st_ctim.tv_nsec
    };
    memcpy(guest_statbuf, &guest, sizeof(guest));
    return 0;
}

static long guest_fstat(const uint64_t *r)
{
    if (!r[1]) return -EFAULT;
    struct stat host;
    if (fstat((int)r[0], &host)) return -errno;
    return marshal_stat(&host, (void *)(uintptr_t)r[1]);
}

static long guest_newfstatat(const uint64_t *r)
{
    int dirfd = (int)(int64_t)r[0];
    const char *path = (const char *)(uintptr_t)r[1];
    void *statbuf = (void *)(uintptr_t)r[2];
    int flags = (int)r[3];

    if (!statbuf) return -EFAULT;

    struct stat host;
    int ret;
    if ((flags & 0x1000 /* AT_EMPTY_PATH */) && path && path[0] == '\0') {
        ret = fstat(dirfd, &host);
    } else {
        const char *rel_path = NULL;
        long err = guest_resolve_path(path, &rel_path);
        if (err) return err;
        ret = fstatat(root_fd, rel_path, &host, flags & ~0x1000);
    }
    if (ret < 0) return -errno;
    return marshal_stat(&host, statbuf);
}

static long guest_faccessat(const uint64_t *r)
{
    const char *path = (const char *)(uintptr_t)r[1];
    int mode = (int)r[2];

    const char *rel_path = NULL;
    long err = guest_resolve_path(path, &rel_path);
    if (err) return err;

    if (faccessat(root_fd, rel_path, mode, 0))
        return -errno;
    return 0;
}

static long guest_readlinkat(const uint64_t *r)
{
    const char *path = (const char *)(uintptr_t)r[1];
    char *buf = (char *)(uintptr_t)r[2];
    size_t bufsiz = (size_t)r[3];

    if (!path || !buf) return -EFAULT;

    ssize_t ret;
    if (!strncmp(path, "/proc/", 6)) {
        ret = readlinkat(AT_FDCWD, path, buf, bufsiz);
    } else {
        const char *rel_path = NULL;
        long err = guest_resolve_path(path, &rel_path);
        if (err) return err;
        ret = readlinkat(root_fd, rel_path, buf, bufsiz);
    }
    if (ret < 0) return -errno;
    return ret;
}

static long guest_uname(const uint64_t *r)
{
    if (!r[0]) return -EFAULT;
    struct utsname host;
    if (uname(&host)) return -errno;
    struct ln_utsname guest;
    memset(&guest, 0, sizeof(guest));
    strncpy(guest.sysname, host.sysname, sizeof(guest.sysname) - 1);
    strncpy(guest.nodename, host.nodename, sizeof(guest.nodename) - 1);
    strncpy(guest.release, host.release, sizeof(guest.release) - 1);
    strncpy(guest.version, host.version, sizeof(guest.version) - 1);
    strncpy(guest.machine, host.machine, sizeof(guest.machine) - 1);
#ifdef _GNU_SOURCE
    strncpy(guest.domainname, host.domainname, sizeof(guest.domainname) - 1);
#endif
    memcpy((void *)(uintptr_t)r[0], &guest, sizeof(guest));
    return 0;
}

static long guest_brk(const uint64_t *r)
{
    uintptr_t req = (uintptr_t)r[0];
    if (!req || req < guest_brk_initial)
        return (long)guest_brk_current;

    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t cur_page = (guest_brk_current + page - 1) & ~(page - 1);
    uintptr_t req_page = (req + page - 1) & ~(page - 1);

    if (req_page > cur_page) {
        size_t add_size = req_page - cur_page;
        void *p = mmap((void *)cur_page, add_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (p == MAP_FAILED)
            return (long)guest_brk_current;
    } else if (cur_page > req_page) {
        munmap((void *)req_page, cur_page - req_page);
    }
    guest_brk_current = req;
    return (long)guest_brk_current;
}

static long guest_mmap(const uint64_t *r)
{
    void *addr = (void *)(uintptr_t)r[0];
    size_t length = (size_t)r[1];
    int prot = (int)r[2];
    int flags = (int)r[3];
    int fd = (int)(int64_t)r[4];
    off_t offset = (off_t)(int64_t)r[5];

    if (!length)
        return -EINVAL;

    if ((prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC))
        return -EACCES;

    if (flags & MAP_FIXED) {
        if ((uintptr_t)addr < (1ULL << 32))
            return -EOPNOTSUPP;
    }

    flags &= ~0x800; /* MAP_DENYWRITE */

    if (flags & MAP_ANONYMOUS) {
        fd = -1;
        offset = 0;
    }

    void *result = mmap(addr, length, prot, flags, fd, offset);
    if (result == MAP_FAILED)
        return -errno;

    return (long)(uintptr_t)result;
}

static long guest_munmap(const uint64_t *r)
{
    void *addr = (void *)(uintptr_t)r[0];
    size_t length = (size_t)r[1];
    size_t page = (size_t)sysconf(_SC_PAGESIZE);

    if (!length || ((uintptr_t)addr & (page - 1)))
        return -EINVAL;

    if (munmap(addr, length))
        return -errno;

    return 0;
}

static long guest_mprotect(const uint64_t *r)
{
    void *addr = (void *)(uintptr_t)r[0];
    size_t length = (size_t)r[1];
    int prot = (int)r[2];
    size_t page = (size_t)sysconf(_SC_PAGESIZE);

    if (!length || ((uintptr_t)addr & (page - 1)))
        return -EINVAL;

    if ((prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC))
        return -EACCES;

    if (mprotect(addr, length, prot))
        return -errno;

    return 0;
}

static long guest_getdents64(const uint64_t *r)
{
    int fd = (int)r[0];
    void *dirp = (void *)(uintptr_t)r[1];
    size_t count = (size_t)r[2];

    if (!dirp)
        return -EFAULT;
    if (!count)
        return -EINVAL;

    long n = syscall(SYS_getdents64, fd, dirp, count);
    if (n < 0)
        return -errno;

    return n;
}

static long guest_prlimit64(const uint64_t *r)
{
    pid_t pid = (pid_t)(int64_t)r[0];
    int resource = (int)r[1];
    const struct rlimit *new_limit = (const void *)(uintptr_t)r[2];
    struct rlimit *old_limit = (void *)(uintptr_t)r[3];

    int ret = syscall(SYS_prlimit64, pid, resource, new_limit, old_limit);
    if (ret < 0) return -errno;
    return 0;
}

static long guest_getrandom(const uint64_t *r)
{
    void *buf = (void *)(uintptr_t)r[0];
    size_t buflen = (size_t)r[1];
    unsigned int flags = (unsigned int)r[2];

    long ret = syscall(SYS_getrandom, buf, buflen, flags);
    if (ret < 0) return -errno;
    return ret;
}

static long guest_ioctl(const uint64_t *r)
{
    int fd = (int)r[0];
    unsigned long request = (unsigned long)r[1];
    void *arg = (void *)(uintptr_t)r[2];

    int ret = ioctl(fd, request, arg);
    if (ret < 0) return -errno;
    return ret;
}

static long guest_fcntl(const uint64_t *r)
{
    int fd = (int)r[0];
    int cmd = (int)r[1];
    void *arg = (void *)(uintptr_t)r[2];

    int ret = fcntl(fd, cmd, arg);
    if (ret < 0) return -errno;
    return ret;
}

static long guest_readv(const uint64_t *r)
{
    int fd = (int)r[0];
    const struct iovec *iov = (const void *)(uintptr_t)r[1];
    int vlen = (int)r[2];

    ssize_t ret = readv(fd, iov, vlen);
    if (ret < 0) return -errno;
    return ret;
}

static long guest_writev(const uint64_t *r)
{
    int fd = (int)r[0];
    const struct iovec *iov = (const void *)(uintptr_t)r[1];
    int vlen = (int)r[2];

    ssize_t ret = writev(fd, iov, vlen);
    if (ret < 0) return -errno;
    return ret;
}

static long guest_clock_gettime(const uint64_t *r)
{
    clockid_t clk_id = (clockid_t)r[0];
    struct timespec *tp = (void *)(uintptr_t)r[1];

    if (!tp) return -EFAULT;
    if (clock_gettime(clk_id, tp)) return -errno;
    return 0;
}

static long guest_rt_sigaction(const uint64_t *r)
{
    int signum = (int)r[0];
    const void *act = (const void *)(uintptr_t)r[1];
    void *oldact = (void *)(uintptr_t)r[2];
    size_t sigsetsize = (size_t)r[3];

    long ret = syscall(SYS_rt_sigaction, signum, act, oldact, sigsetsize);
    if (ret < 0) return -errno;
    return 0;
}

static long guest_rt_sigprocmask(const uint64_t *r)
{
    int how = (int)r[0];
    const void *set = (const void *)(uintptr_t)r[1];
    void *oset = (void *)(uintptr_t)r[2];
    size_t sigsetsize = (size_t)r[3];

    long ret = syscall(SYS_rt_sigprocmask, how, set, oset, sigsetsize);
    if (ret < 0) return -errno;
    return 0;
}

static long guest_madvise(const uint64_t *r)
{
    void *addr = (void *)(uintptr_t)r[0];
    size_t length = (size_t)r[1];
    int advice = (int)r[2];

    if (madvise(addr, length, advice)) return -errno;
    return 0;
}

static long guest_nanosleep(const uint64_t *r)
{
    const struct timespec *req = (const void *)(uintptr_t)r[0];
    struct timespec *rem = (void *)(uintptr_t)r[1];

    if (!req) return -EFAULT;
    if (nanosleep(req, rem)) return -errno;
    return 0;
}

uint64_t ln_dispatch(uint64_t *r)
{
    long result;
    switch (r[8]) {
    case LN_FCNTL:
        result = guest_fcntl(r);
        break;
    case LN_IOCTL:
        result = guest_ioctl(r);
        break;
    case LN_FACCESSAT:
        result = guest_faccessat(r);
        break;
    case LN_READV:
        result = guest_readv(r);
        break;
    case LN_WRITEV:
        result = guest_writev(r);
        break;
    case LN_READLINKAT:
        result = guest_readlinkat(r);
        break;
    case LN_NEWFSTATAT:
        result = guest_newfstatat(r);
        break;
    case LN_SET_TID_ADDRESS:
        result = getpid();
        break;
    case LN_SET_ROBUST_LIST:
        result = 0;
        break;
    case LN_NANOSLEEP:
        result = guest_nanosleep(r);
        break;
    case LN_CLOCK_GETTIME:
        result = guest_clock_gettime(r);
        break;
    case LN_RT_SIGACTION:
        result = guest_rt_sigaction(r);
        break;
    case LN_RT_SIGPROCMASK:
        result = guest_rt_sigprocmask(r);
        break;
    case LN_UNAME:
        result = guest_uname(r);
        break;
    case LN_GETPID:
        result = getpid();
        break;
    case LN_GETPPID:
        result = getppid();
        break;
    case LN_GETUID:
        result = getuid();
        break;
    case LN_GETEUID:
        result = geteuid();
        break;
    case LN_GETGID:
        result = getgid();
        break;
    case LN_GETEGID:
        result = getegid();
        break;
    case LN_GETTID:
        result = syscall(SYS_gettid);
        break;
    case LN_GETDENTS64:
        result = guest_getdents64(r);
        break;
    case LN_BRK:
        result = guest_brk(r);
        break;
    case LN_MUNMAP:
        result = guest_munmap(r);
        break;
    case LN_MMAP:
        result = guest_mmap(r);
        break;
    case LN_MPROTECT:
        result = guest_mprotect(r);
        break;
    case LN_MADVISE:
        result = guest_madvise(r);
        break;
    case LN_PRLIMIT64:
        result = guest_prlimit64(r);
        break;
    case LN_GETRANDOM:
        result = guest_getrandom(r);
        break;
    case LN_MKDIRAT:
        result = guest_mkdirat(r);
        break;
    case LN_UNLINKAT:
        result = guest_unlinkat(r);
        break;
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
