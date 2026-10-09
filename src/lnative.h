#ifndef LNATIVE_H
#define LNATIVE_H

#include <stddef.h>
#include <stdint.h>

struct ln_image {
    void *base;
    size_t size;
    uintptr_t entry;
    size_t sites;
};

int ln_load(const char *path, struct ln_image *image);
int ln_runtime_init(const char *root, int verbose);
uint64_t ln_dispatch(uint64_t *registers);
void ln_gateway(void);
_Noreturn void ln_enter(uintptr_t entry, uintptr_t stack);

#endif
