#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

static size_t page_size(void) {
    long value = sysconf(_SC_PAGESIZE);
    if (value <= 0) {
        return 4096;
    }
    return (size_t)value;
}

static uint64_t align_down_u64(uint64_t value, uint64_t align) {
    return value & ~(align - 1U);
}

static uint64_t align_up_u64(uint64_t value, uint64_t align) {
    return (value + align - 1U) & ~(align - 1U);
}

static int prot_from_flags(uint32_t flags) {
    int prot = 0;
    if ((flags & PF_R) != 0) {
        prot |= PROT_READ;
    }
    if ((flags & PF_W) != 0) {
        prot |= PROT_WRITE;
    }
    if ((flags & PF_X) != 0) {
        prot |= PROT_EXEC;
    }
    return prot;
}

static void fail(const char *message) {
    perror(message);
    exit(1);
}

static void reject(const char *message) {
    fprintf(stderr, "manual_elf_loader: %s\n", message);
    exit(1);
}

static void validate_header(const Elf64_Ehdr *ehdr, size_t file_size) {
    if (file_size < sizeof(*ehdr)) {
        reject("file is too small for an ELF64 header");
    }
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        reject("not an ELF file");
    }
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
        ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        ehdr->e_ident[EI_VERSION] != EV_CURRENT) {
        reject("expected a 64-bit little-endian current-version ELF");
    }
    if (ehdr->e_type != ET_EXEC) {
        reject("this teaching loader requires an ET_EXEC non-PIE payload");
    }
    if (ehdr->e_machine != EM_X86_64 || ehdr->e_version != EV_CURRENT) {
        reject("expected an x86_64 ELF executable");
    }
    if (ehdr->e_phentsize != sizeof(Elf64_Phdr)) {
        reject("unexpected program header entry size");
    }
    if (ehdr->e_phnum == 0) {
        reject("ELF has no program headers");
    }
    if (ehdr->e_phoff > file_size ||
        (uint64_t)ehdr->e_phnum > (UINT64_MAX - ehdr->e_phoff) / sizeof(Elf64_Phdr) ||
        ehdr->e_phoff + (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr) > file_size) {
        reject("program header table extends past end of file");
    }
}

static void validate_segment(const Elf64_Phdr *phdr, size_t file_size, size_t pagesz) {
    if (phdr->p_filesz > phdr->p_memsz) {
        reject("PT_LOAD has p_filesz greater than p_memsz");
    }
    if (phdr->p_offset > file_size || phdr->p_filesz > file_size - phdr->p_offset) {
        reject("PT_LOAD file range extends past end of file");
    }
    if ((phdr->p_offset & (pagesz - 1U)) != (phdr->p_vaddr & (pagesz - 1U))) {
        reject("PT_LOAD offset and virtual address are not page-congruent");
    }
    if (phdr->p_memsz != 0 && phdr->p_vaddr > UINT64_MAX - phdr->p_memsz) {
        reject("PT_LOAD virtual address range overflows");
    }
}

static void map_load_segment(const unsigned char *image, const Elf64_Phdr *phdr, size_t file_size, size_t pagesz) {
    const uint64_t page_mask = (uint64_t)pagesz - 1U;
    uint64_t map_start = align_down_u64(phdr->p_vaddr, pagesz);
    uint64_t map_end = align_up_u64(phdr->p_vaddr + phdr->p_memsz, pagesz);
    uint64_t page_delta = phdr->p_vaddr & page_mask;
    size_t map_size;
    void *mapped;

    validate_segment(phdr, file_size, pagesz);
    if (map_end <= map_start) {
        return;
    }
    if (map_end - map_start > SIZE_MAX) {
        reject("PT_LOAD mapping is too large for this host");
    }
    map_size = (size_t)(map_end - map_start);

    mapped = mmap((void *)(uintptr_t)map_start, map_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (mapped == MAP_FAILED) {
        fail("mmap PT_LOAD");
    }
    if ((uint64_t)(uintptr_t)mapped != map_start) {
        reject("kernel did not map the requested ET_EXEC address");
    }

    memcpy((unsigned char *)mapped + page_delta, image + phdr->p_offset, (size_t)phdr->p_filesz);

    if (mprotect(mapped, map_size, prot_from_flags(phdr->p_flags)) != 0) {
        fail("mprotect PT_LOAD");
    }
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "./build/fixtures/manual_payload";
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    unsigned char *image;
    const Elf64_Ehdr *ehdr;
    const Elf64_Phdr *phdrs;
    uintptr_t entry;
    size_t pagesz = page_size();

    if (fd < 0) {
        fail("open payload");
    }
    if (fstat(fd, &st) != 0) {
        fail("fstat payload");
    }
    if (st.st_size <= 0) {
        reject("payload is empty");
    }
    image = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (image == MAP_FAILED) {
        fail("mmap payload file");
    }
    close(fd);

    ehdr = (const Elf64_Ehdr *)image;
    validate_header(ehdr, (size_t)st.st_size);
    phdrs = (const Elf64_Phdr *)(const void *)(image + ehdr->e_phoff);
    entry = (uintptr_t)ehdr->e_entry;

    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        if (phdrs[i].p_type == PT_INTERP) {
            reject("PT_INTERP payloads need the kernel/dynamic loader, not this demo loader");
        }
        if (phdrs[i].p_type == PT_DYNAMIC) {
            reject("PT_DYNAMIC payloads need relocation handling, which this demo omits");
        }
    }

    for (uint16_t i = 0; i < ehdr->e_phnum; ++i) {
        if (phdrs[i].p_type == PT_LOAD) {
            map_load_segment(image, &phdrs[i], (size_t)st.st_size, pagesz);
        }
    }

    if (munmap(image, (size_t)st.st_size) != 0) {
        fail("munmap payload file");
    }

    ((void (*)(void))entry)();
    __builtin_unreachable();
}
