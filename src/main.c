#define _GNU_SOURCE
#include "lnative.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <ucontext.h>
#include <unistd.h>

static int resolve_binary(const char *root, const char *arg, char *out, size_t out_sz)
{
    const char *rel = arg;
    while (*rel == '/') rel++;
    snprintf(out, out_sz, "%s/%s", root, rel);
    if (access(out, R_OK) == 0) return 0;

    if (!strchr(arg, '/')) {
        snprintf(out, out_sz, "%s/bin/%s", root, arg);
        if (access(out, R_OK) == 0) return 0;
        snprintf(out, out_sz, "%s/usr/bin/%s", root, arg);
        if (access(out, R_OK) == 0) return 0;
    }

    if (access(arg, R_OK) == 0) {
        snprintf(out, out_sz, "%s", arg);
        return 0;
    }
    snprintf(out, out_sz, "%s", arg);
    return 0;
}

static int resolve_interp(const char *root, const char *interp, char *out, size_t out_sz)
{
    const char *rel = interp;
    while (*rel == '/') rel++;
    snprintf(out, out_sz, "%s/%s", root, rel);
    if (access(out, R_OK) == 0) return 0;

    snprintf(out, out_sz, "%s/lib/ld-linux-aarch64.so.1", root);
    if (access(out, R_OK) == 0) return 0;

    snprintf(out, out_sz, "%s/usr/lib/ld-linux-aarch64.so.1", root);
    if (access(out, R_OK) == 0) return 0;

    snprintf(out, out_sz, "%s/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1", root);
    if (access(out, R_OK) == 0) return 0;

    if (access(interp, R_OK) == 0) {
        snprintf(out, out_sz, "%s", interp);
        return 0;
    }

    snprintf(out, out_sz, "%s", interp);
    return -1;
}

static void crash_handler(int sig, siginfo_t *info, void *uctx)
{
    ucontext_t *uc = (ucontext_t *)uctx;
    fprintf(stderr, "lnative: CRASH signal %d at addr %p, pc=%p\n",
            sig, info->si_addr, (void *)uc->uc_mcontext.pc);
    _exit(128 + sig);
}

static int is_x86_64_elf(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    unsigned char header[64];
    ssize_t n = read(fd, header, sizeof(header));
    close(fd);
    if (n < 64) return 0;
    if (header[0] != 0x7f || header[1] != 'E' || header[2] != 'L' || header[3] != 'F')
        return 0;
    if (header[4] != 2) /* ELFCLASS64 */
        return 0;
    if (header[5] != 1) /* ELFDATA2LSB */
        return 0;
    uint16_t machine = (uint16_t)header[18] | ((uint16_t)header[19] << 8);
    return (machine == 0x3e); /* EM_X86_64 = 62 */
}

static int find_transpiler(char *out, size_t sz)
{
    const char *env = getenv("LNATIVE_TRANSPILE_PY");
    if (env && access(env, R_OK) == 0) {
        snprintf(out, sz, "%s", env);
        return 0;
    }

    char exe[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len > 0) {
        exe[len] = '\0';
        char *last_slash = strrchr(exe, '/');
        if (last_slash) {
            *last_slash = '\0';
            snprintf(out, sz, "%s/../tools/x86_transpile.py", exe);
            if (access(out, R_OK) == 0) return 0;
            snprintf(out, sz, "%s/tools/x86_transpile.py", exe);
            if (access(out, R_OK) == 0) return 0;
        }
    }

    const char *home = getenv("HOME");
    if (home) {
        snprintf(out, sz, "%s/LinuxNative/tools/x86_transpile.py", home);
        if (access(out, R_OK) == 0) return 0;
    }

    return -1;
}

static int compute_file_fingerprint(const char *path, char *hex_out, size_t hex_sz)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }

    uint64_t h1 = 14695981039346656037ULL;
    uint64_t h2 = 0xcbf29ce484222325ULL;
    unsigned char buf[16384];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; i++) {
            h1 = (h1 ^ buf[i]) * 1099511628211ULL;
            h2 = (h2 ^ buf[i]) * 0x100000001b3ULL;
        }
    }
    close(fd);
    snprintf(hex_out, hex_sz, "%016llx%016llx_%llx",
             (unsigned long long)h1, (unsigned long long)h2, (unsigned long long)st.st_size);
    return 0;
}

static int ensure_x86_transpiled(const char *src_path, char *out_path, size_t out_sz, int verbose)
{
    char transpiler[PATH_MAX];
    if (find_transpiler(transpiler, sizeof(transpiler)) != 0) {
        if (verbose)
            fprintf(stderr, "lnative: x86_transpile.py tool not found\n");
        return -1;
    }

    char fingerprint[64];
    if (compute_file_fingerprint(src_path, fingerprint, sizeof(fingerprint)) != 0) {
        return -1;
    }

    const char *home = getenv("HOME");
    if (!home || !*home) home = "/tmp";
    char cache_dir[PATH_MAX];
    snprintf(cache_dir, sizeof(cache_dir), "%s/.cache/lnative/aot", home);

    char mkdir_cmd[PATH_MAX + 32];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p \"%s\"", cache_dir);
    (void)system(mkdir_cmd);

    char cached_elf[PATH_MAX];
    snprintf(cached_elf, sizeof(cached_elf), "%s/aot_%s.elf", cache_dir, fingerprint);

    /* Check if cache already exists and is executable */
    if (access(cached_elf, X_OK) == 0) {
        if (verbose)
            fprintf(stderr, "lnative: AOT cache hit: %s\n", cached_elf);
        snprintf(out_path, out_sz, "%s", cached_elf);
        return 0;
    }

    if (verbose)
        fprintf(stderr, "lnative: transpiling x86_64 binary to native AArch64: %s -> %s\n",
                src_path, cached_elf);

    char cmd[PATH_MAX * 3 + 128];
    if (verbose) {
        snprintf(cmd, sizeof(cmd), "python3 \"%s\" \"%s\" -o \"%s\"",
                 transpiler, src_path, cached_elf);
    } else {
        snprintf(cmd, sizeof(cmd), "python3 \"%s\" \"%s\" -o \"%s\" >/dev/null 2>&1",
                 transpiler, src_path, cached_elf);
    }

    int ret = system(cmd);
    if (ret != 0 || access(cached_elf, X_OK) != 0) {
        if (verbose)
            fprintf(stderr, "lnative: transpilation failed (exit %d)\n", ret);
        unlink(cached_elf);
        return -1;
    }

    snprintf(out_path, out_sz, "%s", cached_elf);
    return 0;
}

int main(int argc, char **argv)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);

    int verbose = 0;
    const char *root = NULL;
    int arg_idx = 1;

    while (arg_idx < argc) {
        if (!strcmp(argv[arg_idx], "--verbose")) {
            verbose = 1;
            arg_idx++;
        } else if (!strcmp(argv[arg_idx], "--root")) {
            if (arg_idx + 1 >= argc) {
                fprintf(stderr, "usage: lnative [--verbose] --root DIRECTORY STATIC_ELF [ARG...]\n"
                                "Experimental: trusted AArch64 probes only; not a sandbox.\n");
                return 2;
            }
            root = argv[arg_idx + 1];
            arg_idx += 2;
        } else {
            break;
        }
    }

    if (arg_idx >= argc) {
        fprintf(stderr, "usage: lnative [--verbose] --root DIRECTORY STATIC_ELF [ARG...]\n"
                        "Experimental: trusted AArch64 probes only; not a sandbox.\n");
        return 2;
    }

    if (!root) {
        root = ".";
    }

    if (ln_runtime_init(root, verbose))
        return 1;
    char target_path[PATH_MAX];
    resolve_binary(root, argv[arg_idx], target_path, sizeof(target_path));

    if (is_x86_64_elf(target_path)) {
        if (verbose)
            fprintf(stderr, "lnative: detected x86_64 ELF '%s'\n", target_path);
        char cached_path[PATH_MAX];
        if (ensure_x86_transpiled(target_path, cached_path, sizeof(cached_path), verbose) == 0) {
            snprintf(target_path, sizeof(target_path), "%s", cached_path);
        }
    }

    struct ln_image image = {0};
    if (ln_load(target_path, &image))
        return 1;

    struct ln_image interp_image = {0};
    uintptr_t entry_point = image.entry;
    uint64_t at_base = 0;

    if (image.interp[0] != '\0') {
        char interp_path[PATH_MAX];
        if (resolve_interp(root, image.interp, interp_path, sizeof(interp_path))) {
            fprintf(stderr, "lnative: cannot find interpreter '%s'\n", image.interp);
            return 1;
        }
        if (ln_load(interp_path, &interp_image)) {
            fprintf(stderr, "lnative: failed to load interpreter '%s'\n", interp_path);
            return 1;
        }
        entry_point = interp_image.entry;
        at_base = (uint64_t)interp_image.base;
    }

    uintptr_t max_top = (uintptr_t)image.base + image.size;
    if (interp_image.base) {
        uintptr_t interp_top = (uintptr_t)interp_image.base + interp_image.size;
        if (interp_top > max_top)
            max_top = interp_top;
    }
    if (verbose)
        fprintf(stderr, "lnative: target base=%p, interp base=%p\n", image.base, interp_image.base);
    ln_runtime_set_bounds((uintptr_t)image.base, max_top - (uintptr_t)image.base);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t stack_size = 1024 * 1024;
    size_t guest_argc = (size_t)(argc - arg_idx);

    /* Setup standard guest environment variables */
    char env_user[128], env_home[PATH_MAX], env_term[128];
    const char *u = getenv("USER");
    snprintf(env_user, sizeof(env_user), "USER=%s", u ? u : "root");
    const char *h = getenv("HOME");
    snprintf(env_home, sizeof(env_home), "HOME=%s", h ? h : "/root");
    const char *t = getenv("TERM");
    snprintf(env_term, sizeof(env_term), "TERM=%s", t ? t : "xterm-256color");

    const char *guest_env[] = {
        "PATH=/bin:/usr/bin:/sbin:/usr/sbin",
        "SHELL=/bin/bash",
        env_term,
        "LANG=C.UTF-8",
        "PS1=\\[\\033[01;32m\\]\\u@debian\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ ",
        env_user,
        env_home
    };
    size_t guest_envc = sizeof(guest_env) / sizeof(guest_env[0]);

    /* Reserve at least half of the stack for execution, including the gateway. */
    size_t argument_size = (guest_argc + guest_envc + 40) * sizeof(uint64_t) + 31;
    for (size_t i = 0; i < guest_argc; ++i) {
        size_t length = strlen(argv[arg_idx + i]) + 1;
        if (argument_size > stack_size / 2 || length > stack_size / 2 - argument_size) {
            fprintf(stderr, "lnative: guest arguments exceed stack budget\n");
            return 1;
        }
        argument_size += length;
    }
    for (size_t i = 0; i < guest_envc; ++i) {
        size_t length = strlen(guest_env[i]) + 1;
        if (argument_size > stack_size / 2 || length > stack_size / 2 - argument_size) {
            fprintf(stderr, "lnative: guest arguments exceed stack budget\n");
            return 1;
        }
        argument_size += length;
    }
    void *stack = mmap(NULL, stack_size + 2 * page, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED ||
        mprotect((char *)stack + page, stack_size, PROT_READ | PROT_WRITE)) {
        perror("lnative: stack");
        return 1;
    }
    uintptr_t top = (uintptr_t)stack + page + stack_size;
    /* 16 bytes random seed for AT_RANDOM */
    top -= 16;
    for (int i = 0; i < 16; i += 4) {
        uint32_t r = (uint32_t)rand();
        memcpy((void *)(top + i), &r, sizeof(r));
    }
    uint64_t random_ptr = top;

    /* Linux process stack and auxiliary vector ABI. */
    struct {
        uint64_t type;
        uint64_t val;
    } aux_entries[] = {
        { AT_PHDR, (uint64_t)image.phdr },
        { AT_PHENT, (uint64_t)image.phent },
        { AT_PHNUM, (uint64_t)image.phnum },
        { AT_PAGESZ, (uint64_t)page },
        { AT_BASE, at_base },
        { AT_FLAGS, 0 },
        { AT_ENTRY, (uint64_t)image.entry },
        { AT_UID, (uint64_t)getuid() },
        { AT_EUID, (uint64_t)geteuid() },
        { AT_GID, (uint64_t)getgid() },
        { AT_EGID, (uint64_t)getegid() },
        { AT_SECURE, 0 },
        { AT_RANDOM, random_ptr },
        { AT_CLKTCK, 100 },
        { AT_NULL, 0 }
    };
    size_t num_aux = sizeof(aux_entries) / sizeof(aux_entries[0]);
    size_t words = 1 + guest_argc + 1 + guest_envc + 1 + num_aux * 2;
    uint64_t *initial = calloc(words, sizeof(*initial));
    if (!initial) { perror("lnative: arguments"); return 1; }

    uint64_t env_ptrs[16];
    for (size_t i = 0; i < guest_envc; ++i) {
        size_t length = strlen(guest_env[i]) + 1;
        top -= length;
        memcpy((void *)top, guest_env[i], length);
        env_ptrs[i] = top;
    }

    initial[0] = guest_argc;
    for (size_t i = 0; i < guest_argc; ++i) {
        size_t length = strlen(argv[arg_idx + i]) + 1;
        top -= length;
        memcpy((void *)top, argv[arg_idx + i], length);
        initial[i + 1] = top;
    }
    initial[1 + guest_argc] = 0;
    for (size_t i = 0; i < guest_envc; ++i) {
        initial[2 + guest_argc + i] = env_ptrs[i];
    }
    initial[2 + guest_argc + guest_envc] = 0;
    for (size_t i = 0; i < num_aux; ++i) {
        initial[3 + guest_argc + guest_envc + 2 * i] = aux_entries[i].type;
        initial[3 + guest_argc + guest_envc + 2 * i + 1] = aux_entries[i].val;
    }
    top = (top - words * sizeof(*initial)) & ~(uintptr_t)15;
    memcpy((void *)top, initial, words * sizeof(*initial));
    free(initial);
    if (verbose)
        fprintf(stderr, "lnative: patched %zu SVC sites; entering guest\n",
                image.sites + interp_image.sites);
    ln_enter(entry_point, top);
}
