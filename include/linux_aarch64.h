#ifndef LN_LINUX_AARCH64_H
#define LN_LINUX_AARCH64_H

#include <stddef.h>
#include <stdint.h>

/* Linux AArch64 asm-generic syscall numbers and UAPI stat layout.
 * Guest ABI definitions, independent of the runtime's host libc. */
enum {
    LN_MKDIRAT = 34,
    LN_UNLINKAT = 35,
    LN_OPENAT = 56, LN_CLOSE = 57, LN_GETDENTS64 = 61, LN_LSEEK = 62,
    LN_READ = 63, LN_WRITE = 64, LN_FSTAT = 80,
    LN_EXIT = 93, LN_EXIT_GROUP = 94,
    LN_UNAME = 160,
    LN_GETPID = 172, LN_GETPPID = 173,
    LN_GETUID = 174, LN_GETEUID = 175,
    LN_GETGID = 176, LN_GETEGID = 177,
    LN_GETTID = 178,
    LN_BRK = 214, LN_MUNMAP = 215, LN_MMAP = 222, LN_MPROTECT = 226
};

enum {
    LN_O_RDONLY = 00,
    LN_O_WRONLY = 01,
    LN_O_RDWR   = 02,
    LN_O_CREAT  = 0100,
    LN_O_EXCL   = 0200,
    LN_O_TRUNC  = 01000,
    LN_O_APPEND = 02000,
    LN_O_DIRECTORY = 040000,
    LN_O_CLOEXEC = 02000000
};

enum {
    LN_AT_FDCWD = -100,
    LN_AT_REMOVEDIR = 0x200
};

struct ln_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];
};

enum {
    LN_DT_UNKNOWN = 0,
    LN_DT_FIFO = 1,
    LN_DT_CHR = 2,
    LN_DT_DIR = 4,
    LN_DT_BLK = 6,
    LN_DT_REG = 8,
    LN_DT_LNK = 10,
    LN_DT_SOCK = 12
};

enum {
    LN_PROT_NONE = 0,
    LN_PROT_READ = 1,
    LN_PROT_WRITE = 2,
    LN_PROT_EXEC = 4
};

enum {
    LN_MAP_SHARED = 0x01,
    LN_MAP_PRIVATE = 0x02,
    LN_MAP_FIXED = 0x10,
    LN_MAP_ANONYMOUS = 0x20
};

struct ln_utsname {
    char sysname[65];
    char nodename[65];
    char release[65];
    char version[65];
    char machine[65];
    char domainname[65];
};

_Static_assert(sizeof(struct ln_utsname) == 390, "AArch64 utsname size");

struct ln_stat {
    uint64_t dev, ino;
    uint32_t mode, nlink, uid, gid;
    uint64_t rdev, pad1;
    int64_t size;
    int32_t blksize, pad2;
    int64_t blocks, atime_sec;
    uint64_t atime_nsec;
    int64_t mtime_sec;
    uint64_t mtime_nsec;
    int64_t ctime_sec;
    uint64_t ctime_nsec;
    uint32_t unused[2];
};

_Static_assert(sizeof(struct ln_stat) == 128, "AArch64 stat size");
_Static_assert(offsetof(struct ln_stat, size) == 48, "AArch64 stat size field");
_Static_assert(offsetof(struct ln_stat, blocks) == 64, "AArch64 stat blocks field");
_Static_assert(offsetof(struct ln_stat, mtime_sec) == 88, "AArch64 stat timestamps");
_Static_assert(offsetof(struct ln_stat, unused) == 120, "AArch64 stat padding");

#endif
