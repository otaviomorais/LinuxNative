#define _GNU_SOURCE
#include "lnative.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
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

int main(int argc, char **argv)
{

    int verbose = 0;
    if (argc > 1 && !strcmp(argv[1], "--verbose")) {
        verbose = 1;
        ++argv;
        --argc;
    }
    if (argc < 4 || strcmp(argv[1], "--root")) {
        fprintf(stderr, "usage: lnative [--verbose] --root DIRECTORY STATIC_ELF [ARG...]\n"
                        "Experimental: trusted AArch64 probes only; not a sandbox.\n");
        return 2;
    }
    if (ln_runtime_init(argv[2], verbose))
        return 1;
    char target_path[PATH_MAX];
    resolve_binary(argv[2], argv[3], target_path, sizeof(target_path));
    struct ln_image image = {0};
    if (ln_load(target_path, &image))
        return 1;

    struct ln_image interp_image = {0};
    uintptr_t entry_point = image.entry;
    uint64_t at_base = 0;

    if (image.interp[0] != '\0') {
        char interp_path[PATH_MAX];
        if (resolve_interp(argv[2], image.interp, interp_path, sizeof(interp_path))) {
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
    ln_runtime_set_bounds((uintptr_t)image.base, max_top - (uintptr_t)image.base);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t stack_size = 1024 * 1024;
    size_t guest_argc = (size_t)argc - 3;

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
        size_t length = strlen(argv[3 + i]) + 1;
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
        size_t length = strlen(argv[3 + i]) + 1;
        top -= length;
        memcpy((void *)top, argv[3 + i], length);
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
