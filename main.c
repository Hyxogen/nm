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

typedef Elf64_Off Gelf_Off;
typedef Elf64_Xword Gelf_Xword;
typedef Elf64_Addr Gelf_Addr;
typedef Elf64_Word Gelf_Word;

// TODO endiannes?
typedef enum {
	ELF32,
	ELF64,
} Gelf_Type;

typedef struct {
	Gelf_Type type;
	Gelf_Word sh_type;
	Gelf_Xword sh_size;
	Gelf_Xword sh_entsize;
	union {
		const Elf32_Shdr *shdr32;
		const Elf64_Shdr *shdr64;
		const void *addr;
	};
} Gelf_Shdr;

typedef struct {
	Gelf_Type type;
	Gelf_Addr st_value;
	Gelf_Word st_name;
} Gelf_Sym;

struct gelf {
	Gelf_Type type;
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

static void *Elf32_shdr_get_addr(const struct gelf *gelf, const Elf32_Shdr *shdr)
{
	if (shdr->sh_addr)
		return (void *)(uintptr_t)shdr->sh_addr;
	return (char *)gelf->addr + shdr->sh_offset;
}

static void *Elf64_shdr_get_addr(const struct gelf *gelf, const Elf64_Shdr *shdr)
{
	if (shdr->sh_addr)
		return (void *)(uintptr_t)shdr->sh_addr;
	return (char *)gelf->addr + shdr->sh_offset;
}

static void *gelf_shdr_get_addr(const struct gelf *gelf, const Gelf_Shdr *shdr)
{
	switch (gelf->type) {
	case ELF32:
		return Elf32_shdr_get_addr(gelf, shdr->shdr32);
	case ELF64:
		return Elf64_shdr_get_addr(gelf, shdr->shdr64);
	default:
		assert(0 && "not implemented");
	}
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

	char *strtab = Elf32_shdr_get_addr(gelf, strsection);
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

static Elf64_Shdr *Elf64_find_shdr(const struct gelf *gelf, const char *name)
{
	Elf64_Off off = gelf->hdr64->e_shoff;
	if (off == 0)
		return NULL;

	void *shdr_start = (char *)gelf->addr + gelf->hdr64->e_shoff;
	if (!gelf_checkptr(gelf, shdr_start)) {
		printf("invalid shdr_start\n");
		return NULL;
	}

	Elf64_Shdr *strsection =
	    (void *)((char *)shdr_start +
		     gelf->hdr64->e_shstrndx * gelf->hdr64->e_shentsize);
	if (!gelf_checkptr(gelf, strsection)) {
		printf("invalid strsection\n");
		return NULL;
	}

	char *strtab = Elf64_shdr_get_addr(gelf, strsection);
	if (!gelf_checkptr(gelf, strsection)) {
		printf("invalid strsection addr\n");
		return NULL;
	}

	for (Elf64_Half i = 0; i < gelf->hdr64->e_shnum; i++) {
		Elf64_Shdr *shdr = (Elf64_Shdr *)((char *)shdr_start +
						  i * gelf->hdr64->e_shentsize);
		if (!strcmp(&strtab[shdr->sh_name], name))
			return shdr;
	}
	return NULL;
}

static int gelf_find_shdr(const struct gelf *gelf, Gelf_Shdr *dest, const char *name)
{
	dest->type = gelf->type;
	if (gelf->type == ELF32) {
		dest->shdr32 = Elf32_find_shdr(gelf, name);
		dest->sh_type = dest->shdr32->sh_type;
		dest->sh_size = dest->shdr32->sh_size;
		dest->sh_entsize = dest->shdr32->sh_entsize;
	} else {
		assert(gelf->type == ELF64);
		dest->shdr64 = Elf64_find_shdr(gelf, name);
		dest->sh_type = dest->shdr64->sh_type;
		dest->sh_size = dest->shdr64->sh_size;
		dest->sh_entsize = dest->shdr64->sh_entsize;
	}
	return dest->addr == NULL;
}

static int Gelf_read_sym(const Gelf_Shdr *symtab, Gelf_Sym *dest, const void *addr)
{
	assert(symtab->sh_type == SHT_SYMTAB);

	dest->type = symtab->type;

	if (symtab->type == ELF32) {
		const Elf32_Sym *sym = addr;
		dest->st_value = sym->st_value;
		dest->st_name = sym->st_name;
	} else {
		assert(symtab->type == symtab->type);
		const Elf64_Sym *sym = addr;
		dest->st_value = sym->st_value;
		dest->st_name = sym->st_name;
	}
	return 0;
}

static struct symbol *read_symbols(const struct gelf *gelf, size_t *nsyms)
{
	Gelf_Shdr symtab_shdr, strtab_shdr;

	if (gelf_find_shdr(gelf, &symtab_shdr, ".symtab"))
		return NULL;

	if (gelf_find_shdr(gelf, &strtab_shdr, ".strtab"))
		return NULL;

	const void *symtab = gelf_shdr_get_addr(gelf, &symtab_shdr);
	if (!gelf_checkptr(gelf, symtab))
		return NULL; // invalid address

	const char *strtab = gelf_shdr_get_addr(gelf, &strtab_shdr);
	if (!gelf_checkptr(gelf, symtab))
		return NULL; // invalid address

	struct symbol *symbols = NULL;
	size_t cap = 0;
	size_t count = 0;

	// TODO check if section size is including the header
	for (Gelf_Off off = 0; off < symtab_shdr.sh_size;
	     off += symtab_shdr.sh_entsize) {
		if (cap == count) {
			cap = cap ? cap * 2 : 1;
			symbols = realloc(symbols, cap * sizeof(*symbols));
			if (!symbols) {
				perror("realloc");
				exit(1);
			}
		}

		Gelf_Sym sym;
		if (Gelf_read_sym(&symtab_shdr, &sym, (char*)symtab + off))
			continue;

		if (sym.st_name >= symtab_shdr.sh_size)
			continue; // invalid name, TODO what to do?

		// TODO check if st_value is valid?
		symbols[count].value = sym.st_value;
		//symbols[count].info = sym.st_info;
		symbols[count].name = &strtab[sym.st_name];

		count += 1;
	}

	*nsyms = count;
	return symbols;
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

	if (memcmp(gelf->hdr64->e_ident, "\x7f""ELF", 4))
		return -1; //TODO free resources
	switch (gelf->hdr64->e_ident[EI_CLASS]) {
	case ELFCLASS32:
		gelf->type = ELF32;
		break;
	case ELFCLASS64:
		gelf->type = ELF64;
		break;
	default:
		printf("unsupported elf class: 0x%02hhx\n", gelf->hdr64->e_ident[EI_CLASS]);
		return -1;
	}

	if (gelf->hdr64->e_ident[EI_DATA] != ELFDATA2LSB) {
		printf("unsupported data encoding 0x%02hhx\n", gelf->hdr64->e_ident[EI_CLASS]);
		return -1;
	}

	return 0;
}

static void print_symbol(struct gelf *gelf, const struct symbol *sym)
{
	int width = gelf->type == ELF32 ? 8 : 16;

	printf("%0*llx ", width, (unsigned long long) sym->value);
	printf("? ");
	printf("%s\n", sym->name);
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
		print_symbol(&gelf, &symbols[i]);
	}
	return 0;
}
