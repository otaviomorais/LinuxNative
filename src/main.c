#define _GNU_SOURCE
#include "lnative.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <unistd.h>

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
    struct ln_image image = {0};
    if (ln_load(argv[3], &image))
        return 1;
    ln_runtime_set_bounds((uintptr_t)image.base, image.size);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t stack_size = 1024 * 1024;
    size_t guest_argc = (size_t)argc - 3;
    /* Reserve at least half of the stack for execution, including the gateway. */
    size_t argument_size = (guest_argc + 7) * sizeof(uint64_t) + 15;
    for (size_t i = 0; i < guest_argc; ++i) {
        size_t length = strlen(argv[3 + i]) + 1;
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
    /* Minimal process stack, not the complete Linux process ABI. */
    size_t words = guest_argc + 7;
    uint64_t *initial = calloc(words, sizeof(*initial));
    if (!initial) { perror("lnative: arguments"); return 1; }
    initial[0] = guest_argc;
    for (size_t i = 0; i < guest_argc; ++i) {
        size_t length = strlen(argv[3 + i]) + 1;
        top -= length;
        memcpy((void *)top, argv[3 + i], length);
        initial[i + 1] = top;
    }
    initial[guest_argc + 3] = AT_PAGESZ;
    initial[guest_argc + 4] = page;
    initial[guest_argc + 5] = AT_NULL;
    top = (top - words * sizeof(*initial)) & ~(uintptr_t)15;
    memcpy((void *)top, initial, words * sizeof(*initial));
    free(initial);
    if (verbose)
        fprintf(stderr, "lnative: patched %zu SVC sites; entering guest\n", image.sites);
    ln_enter(image.entry, top);
}
