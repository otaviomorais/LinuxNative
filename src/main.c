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
    if (argc != 4 || strcmp(argv[1], "--root")) {
        fprintf(stderr, "usage: lnative [--verbose] --root DIRECTORY STATIC_ELF\n"
                        "Experimental: trusted AArch64 probes only; not a sandbox.\n");
        return 2;
    }
    if (ln_runtime_init(argv[2], verbose))
        return 1;
    struct ln_image image = {0};
    if (ln_load(argv[3], &image))
        return 1;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size_t stack_size = 1024 * 1024;
    void *stack = mmap(NULL, stack_size + 2 * page, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED ||
        mprotect((char *)stack + page, stack_size, PROT_READ | PROT_WRITE)) {
        perror("lnative: stack");
        return 1;
    }
    uintptr_t top = (uintptr_t)stack + page + stack_size;
    size_t name_len = strlen(argv[3]) + 1;
    top -= name_len;
    memcpy((void *)top, argv[3], name_len);
    uintptr_t name = top;
    top &= ~(uintptr_t)15;
    /* Minimal process stack, not the complete Linux process ABI. */
    uint64_t initial[] = {1, name, 0, 0, AT_PAGESZ, page, AT_NULL, 0};
    top -= sizeof(initial);
    memcpy((void *)top, initial, sizeof(initial));
    if (verbose)
        fprintf(stderr, "lnative: patched %zu SVC sites; entering guest\n", image.sites);
    ln_enter(image.entry, top);
}
