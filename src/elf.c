#define _GNU_SOURCE
#include "lnative.h"
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#define MAX_FILE (64u * 1024u * 1024u)
#define MAX_SPAN (32u * 1024u * 1024u)
#define MAX_SITES 65536u
#define STUB_SIZE 48u

struct marker { uint64_t address; int code; };

static int reject(const char *why)
{
    fprintf(stderr, "lnative: rejected ELF: %s\n", why);
    return -1;
}

static int inside(uint64_t offset, uint64_t length, uint64_t total)
{
    return offset <= total && length <= total - offset;
}

static uintptr_t down(uintptr_t n, size_t page) { return n & ~(page - 1); }
static uintptr_t up(uintptr_t n, size_t page) { return (n + page - 1) & ~(page - 1); }

static int compare_marker(const void *a, const void *b)
{
    uint64_t x = ((const struct marker *)a)->address;
    uint64_t y = ((const struct marker *)b)->address;
    return (x > y) - (x < y);
}

static int branch(uintptr_t from, uintptr_t to, uint32_t *word)
{
    int64_t delta = (int64_t)to - (int64_t)from;
    if ((delta & 3) || delta < -(1LL << 27) || delta >= (1LL << 27))
        return -1;
    *word = 0x14000000u | ((uint32_t)(delta / 4) & 0x03ffffffu);
    return 0;
}

/* AAPCS64 mapping symbols distinguish instructions from embedded data.
 * Stripped or ambiguous code is deliberately unsupported in milestone 0. */
static int collect_sites(const unsigned char *file, size_t length,
                         const Elf64_Ehdr *eh, const Elf64_Phdr *ph,
                         uint64_t *sites, size_t *count)
{
    (void)ph;
    if (!eh->e_shnum || eh->e_shnum > 4096 ||
        eh->e_shentsize != sizeof(Elf64_Shdr) ||
        !inside(eh->e_shoff, (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr), length) ||
        eh->e_shoff % _Alignof(Elf64_Shdr))
        return reject("section table and AArch64 mapping symbols required");
    const Elf64_Shdr *sh = (const void *)(file + eh->e_shoff);
    const Elf64_Sym *symbols = NULL;
    const char *strings = NULL;
    size_t nsymbols = 0, string_size = 0;
    for (size_t i = 0; i < eh->e_shnum; ++i) {
        if (sh[i].sh_type != SHT_NOBITS &&
            !inside(sh[i].sh_offset, sh[i].sh_size, length))
            return reject("section outside file");
        if (sh[i].sh_type != SHT_SYMTAB) continue;
        if (symbols || sh[i].sh_entsize != sizeof(Elf64_Sym) ||
            sh[i].sh_size % sizeof(Elf64_Sym) ||
            sh[i].sh_offset % _Alignof(Elf64_Sym) || sh[i].sh_link >= eh->e_shnum)
            return reject("invalid or multiple symbol tables");
        const Elf64_Shdr *str = &sh[sh[i].sh_link];
        if (str->sh_type != SHT_STRTAB || !inside(str->sh_offset, str->sh_size, length))
            return reject("invalid symbol strings");
        symbols = (const void *)(file + sh[i].sh_offset);
        nsymbols = sh[i].sh_size / sizeof(Elf64_Sym);
        strings = (const void *)(file + str->sh_offset);
        string_size = str->sh_size;
    }
    if (nsymbols > 1000000)
        return reject("symbol table too large");
    struct marker *markers = nsymbols ? calloc(nsymbols, sizeof(*markers)) : NULL;
    if (nsymbols && !markers) return reject("out of memory");
    int result = -1, entry_is_code = 0;
    for (size_t i = 0; i < eh->e_shnum; ++i) {
        if ((sh[i].sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) != (SHF_ALLOC | SHF_EXECINSTR) ||
            sh[i].sh_type != SHT_PROGBITS)
            continue;
        uint64_t begin = sh[i].sh_addr, end = begin + sh[i].sh_size;
        size_t n = 0;
        if (markers && symbols && nsymbols) {
            for (size_t s = 0; s < nsymbols; ++s) {
                if (symbols[s].st_shndx != i) continue;
                if (symbols[s].st_name >= string_size ||
                    !memchr(strings + symbols[s].st_name, 0, string_size - symbols[s].st_name)) {
                    reject("invalid symbol name"); goto done;
                }
                const char *name = strings + symbols[s].st_name;
                if (name[0] != '$' || (name[1] != 'x' && name[1] != 'd') ||
                    (name[2] != 0 && name[2] != '.')) continue;
                if (ELF64_ST_TYPE(symbols[s].st_info) != STT_NOTYPE ||
                    ELF64_ST_BIND(symbols[s].st_info) != STB_LOCAL ||
                    symbols[s].st_value < begin || symbols[s].st_value >= end) {
                    reject("invalid mapping symbol"); goto done;
                }
                markers[n++] = (struct marker){symbols[s].st_value, name[1] == 'x'};
            }
        }
        if (n > 0) {
            qsort(markers, n, sizeof(*markers), compare_marker);
            if (markers[0].address != begin) {
                reject("mapping symbols must cover the executable section"); goto done;
            }
            for (size_t k = 0; k < n; ++k) {
                uint64_t start = markers[k].address;
                uint64_t stop = k + 1 < n ? markers[k + 1].address : end;
                if (start == stop) {
                    reject("ambiguous duplicate mapping symbols"); goto done;
                }
                if (!markers[k].code) continue;
                if ((start | stop) & 3) {
                    reject("unaligned instruction region"); goto done;
                }
                if (eh->e_entry >= start && eh->e_entry < stop && !(eh->e_entry & 3))
                    entry_is_code = 1;
                for (uint64_t pc = start; pc < stop; pc += 4) {
                    uint32_t word;
                    memcpy(&word, file + sh[i].sh_offset + pc - begin, sizeof(word));
                    if ((word & 0xffe0001fu) != 0xd4000001u) continue;
                    if (word != 0xd4000001u || *count == MAX_SITES) {
                        reject("unsupported SVC immediate or too many syscall sites"); goto done;
                    }
                    sites[(*count)++] = pc;
                }
            }
        } else {
            if ((begin | end) & 3) {
                reject("unaligned instruction region"); goto done;
            }
            if (eh->e_entry >= begin && eh->e_entry < end && !(eh->e_entry & 3))
                entry_is_code = 1;
            for (uint64_t pc = begin; pc < end; pc += 4) {
                uint32_t word;
                memcpy(&word, file + sh[i].sh_offset + pc - begin, sizeof(word));
                if ((word & 0xffe0001fu) != 0xd4000001u) continue;
                if (word != 0xd4000001u || *count == MAX_SITES) {
                    reject("unsupported SVC immediate or too many syscall sites"); goto done;
                }
                sites[(*count)++] = pc;
            }
        }
    }
    if (!entry_is_code) { reject("entry point is not mapped code"); goto done; }
    result = 0;
done:
    free(markers);
    return result;
}

int ln_load(const char *path, struct ln_image *image)
{
    int fd = -1, result = -1;
    unsigned char *file = NULL;
    uint64_t *sites = NULL;
    void *mapping = MAP_FAILED;
    size_t reservation = 0;
    struct stat st;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st)) { perror("lnative: ELF file"); goto done; }
    if (!S_ISREG(st.st_mode) || st.st_size < (off_t)sizeof(Elf64_Ehdr) || st.st_size > MAX_FILE) {
        reject("invalid file size/type"); goto done;
    }
    size_t length = (size_t)st.st_size;
    file = malloc(length);
    sites = calloc(MAX_SITES, sizeof(*sites));
    if (!file || !sites) { reject("out of memory"); goto done; }
    size_t got = 0;
    while (got < length) {
        ssize_t n = read(fd, file + got, length - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { reject("incomplete file read"); goto done; }
        got += (size_t)n;
    }
    const Elf64_Ehdr *eh = (const void *)file;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) || eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_ident[EI_DATA] != ELFDATA2LSB || eh->e_ident[EI_VERSION] != EV_CURRENT ||
        eh->e_machine != EM_AARCH64 || (eh->e_type != ET_EXEC && eh->e_type != ET_DYN) ||
        eh->e_version != EV_CURRENT || eh->e_ehsize != sizeof(*eh)) {
        reject("requires little-endian AArch64 ET_EXEC"); goto done;
    }
    if (!eh->e_phnum || eh->e_phnum > 128 || eh->e_phentsize != sizeof(Elf64_Phdr) ||
        !inside(eh->e_phoff, (uint64_t)eh->e_phnum * sizeof(Elf64_Phdr), length) ||
        eh->e_phoff % _Alignof(Elf64_Phdr)) {
        reject("invalid program headers"); goto done;
    }
    const Elf64_Phdr *ph = (const void *)(file + eh->e_phoff);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t low = UINTPTR_MAX, high = 0;
    image->interp[0] = '\0';
    for (size_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type == PT_INTERP) {
            if (ph[i].p_filesz == 0 || ph[i].p_filesz >= sizeof(image->interp) ||
                !inside(ph[i].p_offset, ph[i].p_filesz, length)) {
                reject("invalid PT_INTERP segment"); goto done;
            }
            memcpy(image->interp, file + ph[i].p_offset, ph[i].p_filesz);
            image->interp[ph[i].p_filesz] = '\0';
            size_t slen = strlen(image->interp);
            while (slen > 0 && (image->interp[slen - 1] == '\0' || image->interp[slen - 1] == '\n')) {
                image->interp[--slen] = '\0';
            }
            continue;
        }
        if (eh->e_type == ET_EXEC && ph[i].p_type == PT_DYNAMIC) {
            reject("dynamic linking unsupported on ET_EXEC"); goto done;
        }
        if (eh->e_type == ET_EXEC && ph[i].p_type == PT_TLS) {
            reject("TLS unsupported on ET_EXEC"); goto done;
        }
        if (ph[i].p_type == PT_GNU_STACK && (ph[i].p_flags & PF_X)) {
            reject("executable stacks unsupported"); goto done;
        }
        if (ph[i].p_type != PT_LOAD) continue;
        if (eh->e_type == ET_EXEC && ph[i].p_vaddr < 65536) {
            reject("invalid, unreadable, or writable-executable segment"); goto done;
        }
        if (!ph[i].p_memsz || ph[i].p_memsz > MAX_SPAN ||
            !inside(ph[i].p_vaddr, ph[i].p_memsz, 1ULL << 47) ||
            !inside(ph[i].p_offset, ph[i].p_filesz, length) || ph[i].p_filesz > ph[i].p_memsz ||
            !(ph[i].p_flags & PF_R) || ((ph[i].p_flags & (PF_W | PF_X)) == (PF_W | PF_X))) {
            reject("invalid, unreadable, or writable-executable segment"); goto done;
        }
        uintptr_t begin = down(ph[i].p_vaddr, page);
        uintptr_t end = up(ph[i].p_vaddr + ph[i].p_memsz, page);
        for (size_t j = 0; j < i; ++j) {
            if (ph[j].p_type == PT_LOAD && begin < up(ph[j].p_vaddr + ph[j].p_memsz, page) &&
                down(ph[j].p_vaddr, page) < end) {
                reject("overlapping segment pages unsupported"); goto done;
            }
        }
        if (begin < low) low = begin;
        if (end > high) high = end;
    }
    if (eh->e_type == ET_DYN) {
        if (low != 0) {
            reject("ET_DYN requires relocatable base 0; got fixed AArch64 ET_EXEC address");
            goto done;
        }
    }
    if (low == UINTPTR_MAX || high - low > MAX_SPAN) { reject("invalid image span"); goto done; }
    size_t count = 0;
    if (collect_sites(file, length, eh, ph, sites, &count)) goto done;
    size_t stub_bytes = count > 0 ? up(count * STUB_SIZE, page) : 0;
    reservation = high - low + stub_bytes;
    uintptr_t load_bias = 0;
    if (eh->e_type == ET_DYN) {
        mapping = mmap(NULL, reservation, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED) { perror("lnative: reserve guest address space"); goto done; }
        load_bias = (uintptr_t)mapping;
    } else {
        mapping = mmap((void *)low, reservation, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (mapping == MAP_FAILED) { perror("lnative: reserve guest address space"); goto done; }
        if ((uintptr_t)mapping != low) { reject("MAP_FIXED_NOREPLACE unavailable"); goto done; }
        load_bias = 0;
    }
    for (size_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != PT_LOAD) continue;
        uintptr_t seg_vaddr = ph[i].p_vaddr + load_bias;
        uintptr_t begin = down(seg_vaddr, page);
        size_t size = up(seg_vaddr + ph[i].p_memsz, page) - begin;
        if (mprotect((void *)begin, size, PROT_READ | PROT_WRITE)) {
            perror("lnative: populate segment"); goto done;
        }
        memcpy((void *)seg_vaddr, file + ph[i].p_offset, ph[i].p_filesz);
        if (ph[i].p_memsz > ph[i].p_filesz) {
            memset((void *)(seg_vaddr + ph[i].p_filesz), 0, ph[i].p_memsz - ph[i].p_filesz);
        }
    }
    if (stub_bytes > 0) {
        uintptr_t stub_base = high + load_bias;
        if (mprotect((void *)stub_base, stub_bytes, PROT_READ | PROT_WRITE)) {
            perror("lnative: populate gateways"); goto done;
        }
        for (size_t i = 0; i < count; ++i) {
            uintptr_t stub = stub_base + i * STUB_SIZE;
            uint32_t words[12] = {
                0xa9be47f0, /* stp x16,x17,[sp,#-32]! */
                0xf9000bfe, /* str x30,[sp,#16] */
                0x580000d0, /* ldr x16, literal at +32 */
                0xd63f0200, /* blr x16 */
                0xf9400bfe, /* ldr x30,[sp,#16] */
                0xa8c247f0, /* ldp x16,x17,[sp],#32 */
                0, 0xd503201f, 0, 0, 0xd503201f, 0xd503201f
            };
            uintptr_t site = sites[i] + load_bias;
            uint32_t jump;
            if (branch(site, stub, &jump) || branch(stub + 24, site + 4, &words[6])) {
                reject("gateway outside direct-branch range"); goto done;
            }
            uint64_t target = (uintptr_t)ln_gateway;
            memcpy(&words[8], &target, sizeof(target));
            memcpy((void *)stub, words, sizeof(words));
            memcpy((void *)site, &jump, sizeof(jump));
        }
    }
    for (size_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != PT_LOAD) continue;
        uintptr_t seg_vaddr = ph[i].p_vaddr + load_bias;
        uintptr_t begin = down(seg_vaddr, page);
        size_t size = up(seg_vaddr + ph[i].p_memsz, page) - begin;
        int protection = PROT_READ | ((ph[i].p_flags & PF_W) ? PROT_WRITE : 0) |
                         ((ph[i].p_flags & PF_X) ? PROT_EXEC : 0);
        if (ph[i].p_flags & PF_X)
            __builtin___clear_cache((char *)begin, (char *)(begin + size));
        if (mprotect((void *)begin, size, protection)) {
            perror("lnative: finalize segment permissions"); goto done;
        }
    }
    if (stub_bytes > 0) {
        uintptr_t stub_base = high + load_bias;
        __builtin___clear_cache((char *)stub_base, (char *)(stub_base + stub_bytes));
        if (mprotect((void *)stub_base, stub_bytes, PROT_READ | PROT_EXEC)) {
            perror("lnative: finalize gateways"); goto done;
        }
    }
    uintptr_t phdr_addr = 0;
    for (size_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type == PT_PHDR) {
            phdr_addr = ph[i].p_vaddr + load_bias;
            break;
        }
    }
    if (!phdr_addr) {
        for (size_t i = 0; i < eh->e_phnum; ++i) {
            if (ph[i].p_type == PT_LOAD &&
                eh->e_phoff >= ph[i].p_offset &&
                eh->e_phoff + (uint64_t)eh->e_phnum * sizeof(Elf64_Phdr) <= ph[i].p_offset + ph[i].p_filesz) {
                phdr_addr = ph[i].p_vaddr + load_bias + (eh->e_phoff - ph[i].p_offset);
                break;
            }
        }
    }
    image->base = mapping;
    image->size = reservation;
    image->entry = eh->e_entry + load_bias;
    image->sites = count;
    image->phdr = phdr_addr;
    image->phent = eh->e_phentsize;
    image->phnum = eh->e_phnum;
    result = 0;
done:
    if (result && mapping != MAP_FAILED) munmap(mapping, reservation);
    if (fd >= 0) close(fd);
    free(file);
    free(sites);
    return result;
}
