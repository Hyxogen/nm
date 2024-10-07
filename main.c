#include "elf.h"
#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string.h> // TODO use libft functions

// TODO endiannes?
enum elf_type {
	ELF32,
	ELF64,
};

struct gelf {
	enum elf_type type;
	union {
		const Elf32_Ehdr *hdr32;
		const Elf64_Ehdr *hdr64;
		const void *addr;
	};
	size_t size;
};

struct symbol {
	Elf64_Addr value;
	const char *name;
	unsigned char info;
};

static bool check_ptr(const void *start, size_t nbytes, const void *addr)
{
	return addr >= start && addr <= (void *)((char *)start + nbytes);
}

static bool gelf_checkptr(const struct gelf *gelf, const void *addr)
{
	return check_ptr(gelf->addr, gelf->size, addr);
}

static void *gelf_shdr_get_addr(const struct gelf *gelf, const Elf32_Shdr *shdr)
{
	if (shdr->sh_addr)
		return (void *)(uintptr_t)shdr->sh_addr;
	return (char *)gelf->addr + shdr->sh_offset;
}

static Elf32_Shdr *Elf32_find_shdr(const struct gelf *gelf, const char *name)
{
	Elf32_Off off = gelf->hdr32->e_shoff;
	if (off == 0)
		return NULL;

	void *shdr_start = (char *)gelf->addr + gelf->hdr32->e_shoff;
	if (!gelf_checkptr(gelf, shdr_start)) {
		printf("invalid shdr_start\n");
		return NULL;
	}

	Elf32_Shdr *strsection =
	    (void *)((char *)shdr_start +
		     gelf->hdr32->e_shstrndx * gelf->hdr32->e_shentsize);
	if (!gelf_checkptr(gelf, strsection)) {
		printf("invalid strsection\n");
		return NULL;
	}

	char *strtab = gelf_shdr_get_addr(gelf, strsection);
	if (!gelf_checkptr(gelf, strsection)) {
		printf("invalid strsection addr\n");
		return NULL;
	}

	for (Elf32_Half i = 0; i < gelf->hdr32->e_shnum; i++) {
		Elf32_Shdr *shdr = (Elf32_Shdr *)((char *)shdr_start +
						  i * gelf->hdr32->e_shentsize);
		if (!strcmp(&strtab[shdr->sh_name], name))
			return shdr;
	}
	return NULL;
}

static struct symbol *read_symbols32(const struct gelf *gelf, size_t *nsyms)
{
	const Elf32_Shdr *symtab_shdr = Elf32_find_shdr(gelf, ".symtab");
	if (!symtab_shdr)
		return NULL;

	const void *symtab = gelf_shdr_get_addr(gelf, symtab_shdr);
	if (!gelf_checkptr(gelf, symtab))
		return NULL; // invalid address

	const Elf32_Shdr *strtab_shdr = Elf32_find_shdr(gelf, ".strtab");
	if (!strtab_shdr)
		return NULL;

	const char *strtab = gelf_shdr_get_addr(gelf, strtab_shdr);
	if (!gelf_checkptr(gelf, symtab))
		return NULL; // invalid address

	struct symbol *symbols = NULL;
	size_t cap = 0;
	size_t count = 0;

	// TODO check if section size is including the header
	for (Elf32_Off off = 0; off < symtab_shdr->sh_size;
	     off += symtab_shdr->sh_entsize) {
		if (cap == count) {
			cap = cap ? cap * 2 : 1;
			symbols = realloc(symbols, cap * sizeof(*symbols));
			if (!symbols) {
				perror("realloc");
				exit(1);
			}
		}

		const Elf32_Sym *sym = (void *)((char *)symtab + off);

		if (sym->st_name >= symtab_shdr->sh_size)
			continue; // invalid name, TODO what to do?

		// TODO check if st_value is valid?
		symbols[count].value = sym->st_value;
		symbols[count].info = sym->st_info;
		symbols[count].name = &strtab[sym->st_name];

		count += 1;
	}

	*nsyms = count;
	return symbols;
}

static struct symbol *read_symbols(const struct gelf *gelf, size_t *nsyms)
{
	switch (gelf->type) {
	case ELF32:
		return read_symbols32(gelf, nsyms);
	default:
		assert(0 && "todo");
	}
}

static void *read_file(const char *path, size_t *size)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return NULL;
	}

	struct stat statbuf;
	if (fstat(fd, &statbuf)) {
		perror("stat");
		return NULL;
	}

	*size = statbuf.st_size;
	void *file = mmap(NULL, *size, PROT_READ, MAP_PRIVATE, fd, 0);

	if (close(fd))
		perror("close");

	if (file == MAP_FAILED) {
		perror("mmap");
		return NULL;
	}
	// TODO in theory, mmap could return a valid nullptr, it probably
	// doesn't
	return file;
}

static int read_gelf(struct gelf *gelf, const char *path)
{
	gelf->addr = read_file(path, &gelf->size);
	if (!gelf->addr)
		return -1;
	// TODO check magic

	gelf->type = ELF32;
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		// TODO default to a.out
		// TODO argv[0] could not exist
		printf("usage: %s <file>\n", argv[0]);
		return 0;
	}

	struct gelf gelf;
	if (read_gelf(&gelf, argv[1])) {
		printf("failed to read elf\n");
		return -1;
	}

	size_t nsyms = 0;
	struct symbol *symbols = read_symbols(&gelf, &nsyms);

	for (size_t i = 0; i < nsyms; i++) {
		printf("%s\n", symbols[i].name);
	}
	return 0;
}
