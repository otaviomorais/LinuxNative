#ifndef LNATIVE_H
#define LNATIVE_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

struct ln_image {
    void *base;
    size_t size;
    uintptr_t entry;
    size_t sites;
    uintptr_t phdr;
    size_t phent;
    size_t phnum;
    char interp[PATH_MAX];
};

int ln_load(const char *path, struct ln_image *image);
int ln_runtime_init(const char *root, int verbose);
void ln_runtime_set_bounds(uintptr_t base, size_t size);
uint64_t ln_dispatch(uint64_t *registers);
void ln_gateway(void);
_Noreturn void ln_enter(uintptr_t entry, uintptr_t stack);

#endif
