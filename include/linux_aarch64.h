#ifndef LN_LINUX_AARCH64_H
#define LN_LINUX_AARCH64_H

#include <stddef.h>
#include <stdint.h>

/* Linux AArch64 asm-generic syscall numbers and UAPI stat layout.
 * Guest ABI definitions, independent of the runtime's host libc. */
enum {
    LN_OPENAT = 56, LN_CLOSE = 57, LN_LSEEK = 62,
    LN_READ = 63, LN_WRITE = 64, LN_FSTAT = 80,
    LN_EXIT = 93, LN_EXIT_GROUP = 94
};

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
