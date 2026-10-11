#include "../examples/micro-libc.h"

static void join_path(char *out, const char *a, const char *b)
{
    size_t i = 0;
    while (a && *a) out[i++] = *a++;
    while (b && *b) out[i++] = *b++;
    out[i] = '\0';
}

int guest_main(const uint64_t *stack)
{
    const char *base = "/testdir";
    if (stack[0] > 1) {
        const char *arg = (const char *)(uintptr_t)stack[2];
        if (arg && arg[0] == '-' && arg[1] == '-' && arg[2] == 's') {
            /* Security test: path traversal with .. must return -EACCES (-13) */
            if (sys_mkdir("/testdir/../../escape", 0755) != -13) return 70;
            if (sys_creat("/testdir/../escape.txt", 0644) != -13) return 71;
            if (sys_unlink("/testdir/../escape.txt") != -13) return 72;

            /* Relative paths must return -EOPNOTSUPP (-95) */
            if (sys_open("relative.txt", LN_O_RDONLY, 0) != -95) return 73;
            if (sys_mkdir("relative_dir", 0755) != -95) return 74;
            if (sys_unlink("relative_file") != -95) return 75;

            /* Unsupported open flags must return -EOPNOTSUPP (-95) */
            if (sys_open("/testfile", 0x10000000, 0) != -95) return 76;

            mini_puts("fs security policy ok\n");
            return 0;
        }
        base = arg;
    }

    struct ln_stat st;
    char path_file[256];
    join_path(path_file, base, "/hello.txt");
    char buf[64];

    /* 1. Create a directory */
    if (sys_mkdir(base, 0755) != 0)
        return 1;

    /* 2. Verify directory exists and is a directory */
    long dfd = sys_open(base, LN_O_DIRECTORY, 0);
    if (dfd < 0) return 2;
    if (call3(LN_FSTAT, dfd, (long)&st, 0) != 0) return 3;
    if ((st.mode & 0170000) != 0040000) return 4;
    sys_close(dfd);

    /* 3. Create a file in that directory */
    long fd = sys_creat(path_file, 0644);
    if (fd < 0) return 5;

    /* 4. Write data */
    if (sys_write(fd, "hello world!\n", 13) != 13) return 6;
    sys_close(fd);

    /* 5. Read back and verify */
    fd = sys_open(path_file, LN_O_RDONLY, 0);
    if (fd < 0) return 7;
    long n = sys_read(fd, buf, sizeof(buf));
    if (n != 13) return 8;
    buf[13] = '\0';
    if (buf[0] != 'h' || buf[11] != '!' || buf[12] != '\n') return 9;
    sys_close(fd);

    /* 6. Append to file */
    fd = sys_open(path_file, LN_O_WRONLY | LN_O_APPEND, 0);
    if (fd < 0) return 10;
    if (sys_write(fd, "appended\n", 9) != 9) return 11;
    sys_close(fd);

    /* 7. Verify appended content */
    fd = sys_open(path_file, LN_O_RDONLY, 0);
    if (fd < 0) return 12;
    n = sys_read(fd, buf, sizeof(buf));
    if (n != 22) return 13;
    sys_close(fd);

    /* 8. Exclusive create on existing file must fail with -EEXIST (-17) */
    long excl = sys_open(path_file, LN_O_WRONLY | LN_O_CREAT | LN_O_EXCL, 0644);
    if (excl != -17) return 14;

    /* 9. Rmdir non-empty directory must fail with -ENOTEMPTY (-39) */
    long rmdir_fail = sys_rmdir(base);
    if (rmdir_fail != -39) return 15;

    /* 10. Unlink the file */
    if (sys_unlink(path_file) != 0) return 16;

    /* 11. Now rmdir the empty directory must succeed */
    if (sys_rmdir(base) != 0) return 17;

    mini_puts("fs mutation ok\n");
    return 0;
}
