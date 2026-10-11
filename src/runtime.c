#define _GNU_SOURCE
#include "lnative.h"
#include "../include/linux_aarch64.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

static int root_fd = -1;
static char root_prefix[PATH_MAX];
static size_t root_prefix_len;
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
    if (realpath(root, root_prefix)) {
        root_prefix_len = strlen(root_prefix);
        while (root_prefix_len > 1 && root_prefix[root_prefix_len - 1] == '/') {
            root_prefix[--root_prefix_len] = '\0';
        }
    } else {
        strncpy(root_prefix, root, sizeof(root_prefix) - 1);
        root_prefix[sizeof(root_prefix) - 1] = '\0';
        root_prefix_len = strlen(root_prefix);
    }
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

    /* If the path begins with root_prefix, strip it */
    if (root_prefix_len > 0 && !strncmp(path, root_prefix, root_prefix_len)) {
        if (path[root_prefix_len] == '/' || path[root_prefix_len] == '\0') {
            path += root_prefix_len;
            if (!*path)
                path = "/";
        }
    }

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
    const char *path = (const char *)(uintptr_t)r[1];
    const char *rel_path = NULL;
    long err = guest_resolve_path(path, &rel_path);
    if (err) return err;

#ifndef O_LARGEFILE
#define O_LARGEFILE 0x8000
#endif

    uint64_t allowed = O_ACCMODE | O_CLOEXEC | O_DIRECTORY | O_CREAT | O_EXCL | O_TRUNC | O_APPEND |
                       O_NONBLOCK | O_NOCTTY | O_LARGEFILE;
    if (r[2] & ~allowed)
        return -EOPNOTSUPP;

    int fd = openat(root_fd, rel_path, (int)r[2], (mode_t)r[3]);
    if (fd < 0 && errno == ENOENT && (!strncmp(path, "/dev/", 5) || !strncmp(path, "/proc/", 6))) {
        fd = open(path, (int)r[2], (mode_t)r[3]);
    }
    if (trace_calls) {
        fprintf(stderr, "lnative: open '%s' (rel '%s') -> %d\n", path, rel_path, fd);
    }
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
        if (ret < 0 && errno == ENOENT && (!strncmp(path, "/dev/", 5) || !strncmp(path, "/proc/", 6))) {
            ret = fstatat(AT_FDCWD, path, &host, flags & ~0x1000);
        }
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

    if (faccessat(root_fd, rel_path, mode, 0)) {
        if (errno == ENOENT && (!strncmp(path, "/dev/", 5) || !strncmp(path, "/proc/", 6))) {
            if (faccessat(AT_FDCWD, path, mode, 0))
                return -errno;
            return 0;
        }
        return -errno;
    }
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

static long guest_statx(const uint64_t *r)
{
    int dirfd = (int)r[0];
    const char *path = (const char *)(uintptr_t)r[1];
    int flags = (int)r[2];
    unsigned int mask = (unsigned int)r[3];
    void *statxbuf = (void *)(uintptr_t)r[4];

    if (!path || !*path) {
        long res = syscall(SYS_statx, dirfd, "", flags, mask, statxbuf);
        return res < 0 ? -errno : res;
    }

    if (!strncmp(path, "/dev/", 5) || !strncmp(path, "/proc/", 6) || !strncmp(path, "/sys/", 6)) {
        long res = syscall(SYS_statx, AT_FDCWD, path, flags, mask, statxbuf);
        if (res >= 0 || errno != ENOENT)
            return res < 0 ? -errno : res;
    }

    const char *rel_path = NULL;
    long err = guest_resolve_path(path, &rel_path);
    if (err) return err;

    long res = syscall(SYS_statx, root_fd, rel_path, flags, mask, statxbuf);
    if (res < 0 && errno == ENOENT && (!strncmp(path, "/dev/", 5) || !strncmp(path, "/proc/", 6) || !strncmp(path, "/sys/", 6))) {
        res = syscall(SYS_statx, AT_FDCWD, path, flags, mask, statxbuf);
    }
    return res < 0 ? -errno : res;
}

static long guest_pipe2(const uint64_t *r)
{
    int *pipefd = (int *)(uintptr_t)r[0];
    int flags = (int)r[1];
    if (pipe2(pipefd, flags))
        return -errno;
    return 0;
}

static long guest_dup(const uint64_t *r)
{
    int res = dup((int)r[0]);
    return res < 0 ? -errno : res;
}

static long guest_dup3(const uint64_t *r)
{
    int res = dup3((int)r[0], (int)r[1], (int)r[2]);
    return res < 0 ? -errno : res;
}

static long guest_futex(const uint64_t *r)
{
    long res = syscall(SYS_futex, (void *)(uintptr_t)r[0], (int)r[1], (uint32_t)r[2],
                       (const struct timespec *)(uintptr_t)r[3], (void *)(uintptr_t)r[4], (uint32_t)r[5]);
    return res < 0 ? -errno : res;
}

static long guest_prctl(const uint64_t *r)
{
    long res = syscall(SYS_prctl, (int)r[0], (unsigned long)r[1], (unsigned long)r[2],
                       (unsigned long)r[3], (unsigned long)r[4]);
    return res < 0 ? -errno : res;
}

static long guest_sysinfo(const uint64_t *r)
{
    long res = syscall(SYS_sysinfo, (void *)(uintptr_t)r[0]);
    return res < 0 ? -errno : res;
}

static long guest_gettimeofday(const uint64_t *r)
{
    long res = gettimeofday((struct timeval *)(uintptr_t)r[0], (struct timezone *)(uintptr_t)r[1]);
    return res < 0 ? -errno : res;
}

static long guest_wait4(const uint64_t *r)
{
    long res = wait4((pid_t)(int64_t)r[0], (int *)(uintptr_t)r[1], (int)r[2], (struct rusage *)(uintptr_t)r[3]);
    return res < 0 ? -errno : res;
}

static long guest_tgkill(const uint64_t *r)
{
    long res = syscall(SYS_tgkill, (pid_t)(int64_t)r[0], (pid_t)(int64_t)r[1], (int)r[2]);
    return res < 0 ? -errno : res;
}

static long guest_chdir(const uint64_t *r)
{
    const char *path = (const char *)(uintptr_t)r[0];
    if (!path) return -EFAULT;
    const char *rel_path = NULL;
    long err = guest_resolve_path(path, &rel_path);
    if (err) return err;

    char full_host_path[PATH_MAX];
    int n = snprintf(full_host_path, sizeof(full_host_path), "%s/%s", root_prefix, rel_path);
    if (n < 0 || (size_t)n >= sizeof(full_host_path)) return -ENAMETOOLONG;

    if (chdir(full_host_path))
        return -errno;
    return 0;
}

static long guest_getcwd(const uint64_t *r)
{
    char *buf = (char *)(uintptr_t)r[0];
    size_t size = (size_t)r[1];
    if (!buf || !size) return -EINVAL;

    char host_cwd[PATH_MAX];
    if (!getcwd(host_cwd, sizeof(host_cwd)))
        return -errno;

    const char *guest_path = "/";
    if (strncmp(host_cwd, root_prefix, root_prefix_len) == 0) {
        guest_path = host_cwd + root_prefix_len;
        if (*guest_path == '\0') guest_path = "/";
    }
    size_t len = strlen(guest_path) + 1;
    if (len > size) return -ERANGE;
    memcpy(buf, guest_path, len);
    return (long)len;
}

static long guest_clone(const uint64_t *r)
{
    unsigned long flags = (unsigned long)r[0];
    void *child_stack = (void *)(uintptr_t)r[1];
    int *ptid = (int *)(uintptr_t)r[2];
    unsigned long tls = (unsigned long)r[3];
    int *ctid = (int *)(uintptr_t)r[4];

    long res = syscall(SYS_clone, flags, child_stack, ptid, tls, ctid);
    return res < 0 ? -errno : res;
}

static long guest_execve(const uint64_t *r)
{
    const char *filename = (const char *)(uintptr_t)r[0];
    char *const *argv = (char *const *)(uintptr_t)r[1];
    char *const *envp = (char *const *)(uintptr_t)r[2];

    if (!filename) return -EFAULT;

    size_t argc = 0;
    if (argv) {
        while (argv[argc]) argc++;
    }

    char self_path[PATH_MAX];
    ssize_t s = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (s <= 0) return -errno;
    self_path[s] = '\0';

    char **new_argv = malloc((argc + 4) * sizeof(char *));
    if (!new_argv) return -ENOMEM;
    new_argv[0] = self_path;
    new_argv[1] = "--root";
    new_argv[2] = root_prefix;
    new_argv[3] = (char *)filename;
    for (size_t i = 1; i < argc; ++i) {
        new_argv[3 + i] = argv[i];
    }
    new_argv[3 + (argc > 0 ? argc : 1)] = NULL;

    execve(self_path, new_argv, envp);
    free(new_argv);
    return -errno;
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

static int branch_offset(uintptr_t from, uintptr_t to, uint32_t *word)
{
    int64_t delta = (int64_t)to - (int64_t)from;
    if ((delta & 3) || delta < -(1LL << 27) || delta >= (1LL << 27))
        return -1;
    *word = 0x14000000u | ((uint32_t)(delta / 4) & 0x03ffffffu);
    return 0;
}

static sigjmp_buf g_patch_jmp;
static volatile sig_atomic_t g_patch_handling = 0;

static void patch_sig_handler(int sig, siginfo_t *info, void *ucontext)
{
    (void)sig; (void)info; (void)ucontext;
    if (g_patch_handling) {
        siglongjmp(g_patch_jmp, 1);
    }
    _exit(128 + sig);
}

static void *alloc_stub_near(uintptr_t near_addr, size_t size)
{
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size = (size + page - 1) & ~(page - 1);

    for (size_t step = 0x10000; step <= 64 * 1024 * 1024; step += 0x10000) {
        if (near_addr > step + 0x10000000) {
            uintptr_t try_addr = (near_addr - step) & ~(page - 1);
            void *p = mmap((void *)try_addr, size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
            if (p != MAP_FAILED) return p;
        }
        uintptr_t try_addr = (near_addr + step) & ~(page - 1);
        void *p = mmap((void *)try_addr, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (p != MAP_FAILED) return p;
    }
    return NULL;
}

static void patch_executable_region(void *addr, size_t length)
{
    if (!addr || !length) return;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + length;

    size_t count = 0;
    const uint32_t *ptr = (const uint32_t *)start;
    size_t num_words = length / 4;

    struct sigaction sa, old_bus, old_segv;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = patch_sig_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGBUS, &sa, &old_bus);
    sigaction(SIGSEGV, &sa, &old_segv);

    g_patch_handling = 1;
    if (sigsetjmp(g_patch_jmp, 1) == 0) {
        for (size_t i = 0; i < num_words; ++i) {
            if (ptr[i] == 0xd4000001u) {
                count++;
            }
        }
    }
    g_patch_handling = 0;
    sigaction(SIGBUS, &old_bus, NULL);
    sigaction(SIGSEGV, &old_segv, NULL);

    if (!count) return;

    size_t stub_bytes = (count * 48 + page - 1) & ~(page - 1);
    void *stub_base = alloc_stub_near(start, stub_bytes);
    if (!stub_base) return;

    uintptr_t page_start = start & ~(page - 1);
    size_t page_len = ((start + length + page - 1) & ~(page - 1)) - page_start;

    if (mprotect((void *)page_start, page_len, PROT_READ | PROT_WRITE)) {
        munmap(stub_base, stub_bytes);
        return;
    }

    uint32_t *write_ptr = (uint32_t *)start;
    size_t stub_idx = 0;
    for (size_t i = 0; i < num_words && stub_idx < count; ++i) {
        if (write_ptr[i] == 0xd4000001u) {
            uintptr_t site = start + i * 4;
            uintptr_t stub = (uintptr_t)stub_base + stub_idx * 48;
            uint32_t words[12] = {
                0xa9be47f0, /* stp x16,x17,[sp,#-32]! */
                0xf9000bfe, /* str x30,[sp,#16] */
                0x580000d0, /* ldr x16, literal at +32 */
                0xd63f0200, /* blr x16 */
                0xf9400bfe, /* ldr x30,[sp,#16] */
                0xa8c247f0, /* ldp x16,x17,[sp],#32 */
                0, 0xd503201f, 0, 0, 0xd503201f, 0xd503201f
            };
            uint32_t jump;
            if (branch_offset(site, stub, &jump) == 0 &&
                branch_offset(stub + 24, site + 4, &words[6]) == 0) {
                uint64_t target = (uintptr_t)ln_gateway;
                memcpy(&words[8], &target, sizeof(target));
                memcpy((void *)stub, words, sizeof(words));
                write_ptr[i] = jump;
                stub_idx++;
            }
        }
    }

    __builtin___clear_cache((char *)start, (char *)start + length);
    __builtin___clear_cache((char *)stub_base, (char *)stub_base + stub_bytes);
    mprotect((void *)page_start, page_len, PROT_READ | PROT_EXEC);
    mprotect(stub_base, stub_bytes, PROT_READ | PROT_EXEC);

    if (trace_calls) {
        fprintf(stderr, "lnative: runtime patched %zu SVC sites in [%p, %p]\n",
                stub_idx, addr, (void *)end);
    }
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

    if (trace_calls) {
        fprintf(stderr, "lnative: mmap addr=%p len=%zu prot=0x%x flags=0x%x fd=%d off=%ld\n",
                addr, length, prot, flags, fd, (long)offset);
    }

    void *result = mmap(addr, length, prot, flags, fd, offset);
    if (result == MAP_FAILED)
        return -errno;

    if (prot & PROT_EXEC) {
        size_t scan_len = length;
        if (fd >= 0) {
            struct stat st;
            if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
                if (offset >= st.st_size) {
                    scan_len = 0;
                } else if ((off_t)(offset + length) > st.st_size) {
                    scan_len = (size_t)(st.st_size - offset);
                }
            }
        }
        if (scan_len > 0) {
            patch_executable_region(result, scan_len);
        }
    }

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

    if (prot & PROT_EXEC) {
        patch_executable_region(addr, length);
    }

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
    case LN_GETCWD:
        result = guest_getcwd(r);
        break;
    case LN_DUP:
        result = guest_dup(r);
        break;
    case LN_DUP3:
        result = guest_dup3(r);
        break;
    case LN_FCNTL:
        result = guest_fcntl(r);
        break;
    case LN_IOCTL:
        result = guest_ioctl(r);
        break;
    case LN_CHDIR:
        result = guest_chdir(r);
        break;
    case LN_FACCESSAT:
        result = guest_faccessat(r);
        break;
    case LN_PIPE2:
        result = guest_pipe2(r);
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
    case LN_FUTEX:
        result = guest_futex(r);
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
    case LN_TGKILL:
        result = guest_tgkill(r);
        break;
    case LN_RT_SIGACTION:
        result = guest_rt_sigaction(r);
        break;
    case LN_RT_SIGPROCMASK:
        result = guest_rt_sigprocmask(r);
        break;
    case LN_SETPGID:
        result = setpgid((pid_t)(int64_t)r[0], (pid_t)(int64_t)r[1]);
        if (result < 0) result = -errno;
        break;
    case LN_GETPGID:
        result = getpgid((pid_t)(int64_t)r[0]);
        if (result < 0) result = -errno;
        break;
    case LN_SETSID:
        result = setsid();
        if (result < 0) result = -errno;
        break;
    case LN_GETSID:
        result = getsid((pid_t)(int64_t)r[0]);
        if (result < 0) result = -errno;
        break;
    case LN_UNAME:
        result = guest_uname(r);
        break;
    case LN_UMASK:
        result = umask((mode_t)r[0]);
        break;
    case LN_PRCTL:
        result = guest_prctl(r);
        break;
    case LN_GETTIMEOFDAY:
        result = guest_gettimeofday(r);
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
    case LN_SYSINFO:
        result = guest_sysinfo(r);
        break;
    case LN_CLONE:
        result = guest_clone(r);
        break;
    case LN_EXECVE:
        result = guest_execve(r);
        break;
    case LN_WAIT4:
        result = guest_wait4(r);
        break;
    case LN_STATX:
        result = guest_statx(r);
        break;
    case LN_RSEQ:
        result = -ENOSYS;
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
