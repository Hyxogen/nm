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
#include <ctype.h>
#include <locale.h>

#include <string.h> // TODO use libft functions

typedef Elf64_Off Gelf_Off;
typedef Elf64_Xword Gelf_Xword;
typedef Elf64_Addr Gelf_Addr;
typedef Elf64_Word Gelf_Word;
typedef Elf64_Half Gelf_Half;

#define GELF_ST_BIND(info) ELF64_ST_BIND(info)
#define GELF_ST_TYPE(info) ELF64_ST_TYPE(info)
#define GELF_ST_VISIBILITY(info) ELF64_ST_VISIBILITY(info)

// TODO endiannes?
typedef enum {
	ELF32,
	ELF64,
} Gelf_Type;

typedef struct {
	Gelf_Type type;
	Gelf_Word sh_name;
	Gelf_Word sh_type;
	Gelf_Xword sh_size;
	Gelf_Xword sh_entsize;
	Gelf_Xword sh_flags;
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
	unsigned char st_info;
	unsigned char st_other;
	Gelf_Half st_shndx;
} Gelf_Sym;

typedef struct {
	Gelf_Type type;
	Gelf_Xword e_shentsize;
	Gelf_Half e_shnum;
	Gelf_Half e_shstrndx;
	union {
		const Elf32_Ehdr *hdr32;
		const Elf64_Ehdr *hdr64;
		const void *addr;
	};
	size_t size;
} Gelf_Ehdr;

struct symbol {
	Elf64_Addr value;
	const char *name;
	char ch;
};

static bool check_ptr(const void *start, size_t nbytes, const void *addr)
{
	return addr >= start && addr <= (void *)((char *)start + nbytes);
}

static bool gelf_checkptr(const Gelf_Ehdr *gelf, const void *addr)
{
	return check_ptr(gelf->addr, gelf->size, addr);
}

static void *Elf32_shdr_get_addr(const Gelf_Ehdr *gelf, const Elf32_Shdr *shdr)
{
	if (shdr->sh_addr)
		return (void *)(uintptr_t)shdr->sh_addr;
	return (char *)gelf->addr + shdr->sh_offset;
}

static void *Elf64_shdr_get_addr(const Gelf_Ehdr *gelf, const Elf64_Shdr *shdr)
{
	if (shdr->sh_addr)
		return (void *)(uintptr_t)shdr->sh_addr;
	return (char *)gelf->addr + shdr->sh_offset;
}

static void *gelf_shdr_get_addr(const Gelf_Ehdr *gelf, const Gelf_Shdr *shdr)
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

static int gelf_get_shdr(const Gelf_Ehdr *gelf, Gelf_Shdr *dest, size_t idx)
{
	if (idx >= gelf->e_shnum)
		return -1;

	dest->type = gelf->type;
	if (gelf->type == ELF32) {
		const Elf32_Shdr *shdr =
		    (void *)((char *)gelf->addr + gelf->hdr32->e_shoff +
			     gelf->e_shentsize * idx);

		dest->shdr32 = shdr;
		dest->sh_type = dest->shdr32->sh_type;
		dest->sh_size = dest->shdr32->sh_size;
		dest->sh_entsize = dest->shdr32->sh_entsize;
		dest->sh_name = dest->shdr32->sh_name;
		dest->sh_flags = dest->shdr32->sh_flags;
	} else {
		assert(gelf->type == ELF64);

		const Elf64_Shdr *shdr =
		    (void *)((char *)gelf->addr + gelf->hdr64->e_shoff +
			     gelf->e_shentsize * idx);

		dest->shdr64 = shdr;
		dest->sh_type = dest->shdr64->sh_type;
		dest->sh_size = dest->shdr64->sh_size;
		dest->sh_entsize = dest->shdr64->sh_entsize;
		dest->sh_name = dest->shdr64->sh_name;
		dest->sh_flags = dest->shdr64->sh_flags;
	}
	return 0;
}

static const char *gelf_shdr_get_name(const Gelf_Ehdr *gelf, const Gelf_Shdr *shdr)
{
	Gelf_Shdr shstrtab;
	if (gelf_get_shdr(gelf, &shstrtab, gelf->e_shstrndx))
		return NULL;

	if (shdr->sh_name >= shstrtab.sh_size)
		return NULL;

	//TODO make sure that string is null terminated!
	const char *data = gelf_shdr_get_addr(gelf, &shstrtab);
	if (!gelf_checkptr(gelf, data))
		return NULL;
	return &data[shdr->sh_name];
}

static int gelf_find_shdr(const Gelf_Ehdr *gelf, Gelf_Shdr *dest, const char *name)
{
	for (size_t i = 0; i < gelf->e_shnum; i++) {
		if (gelf_get_shdr(gelf, dest, i))
			return -1;

		const char *sname = gelf_shdr_get_name(gelf, dest);
		if (!sname)
			continue;
		if (!strcmp(sname, name))
			return 0;
	}
	return -1;
}

static int Gelf_read_sym(const Gelf_Shdr *symtab, Gelf_Sym *dest, const void *addr)
{
	assert(symtab->sh_type == SHT_SYMTAB);

	dest->type = symtab->type;

	if (symtab->type == ELF32) {
		const Elf32_Sym *sym = addr;
		dest->st_value = sym->st_value;
		dest->st_name = sym->st_name;
		dest->st_info = sym->st_info;
		dest->st_other = sym->st_other;
		dest->st_shndx = sym->st_shndx;
	} else {
		assert(symtab->type == symtab->type);
		const Elf64_Sym *sym = addr;
		dest->st_value = sym->st_value;
		dest->st_name = sym->st_name;
		dest->st_info = sym->st_info;
		dest->st_other = sym->st_other;
		dest->st_shndx = sym->st_shndx;
	}
	return 0;
}

static char get_nm_sym(const Gelf_Ehdr *gelf, const Gelf_Sym *sym)
{
	int bind = GELF_ST_BIND(sym->st_info);
	int type = GELF_ST_TYPE(sym->st_info);

	bool uppercase = bind != STB_LOCAL;

	char res = '?';

	Gelf_Shdr section;
	if (sym->st_shndx == SHN_ABS) {
		uppercase = type != STT_FILE;
		res = 'a';
	} else if (sym->st_shndx == SHN_COMMON) {
		uppercase = true;
		res = 'c';
	} else if (bind == STB_GNU_UNIQUE) {
		uppercase = false;
		res = 'u';
	} else if (bind == STB_WEAK) {
		uppercase = sym->st_shndx != SHN_UNDEF;
		res = 'w';
		if (type == STT_OBJECT)
			res = 'v';
	} else if (sym->st_shndx == SHN_UNDEF) {
		uppercase = true;
		res = 'U';
	} else if (!gelf_get_shdr(gelf, &section, sym->st_shndx)) {
		if (section.sh_flags & SHF_ALLOC) {
			if (section.sh_type == SHT_NOBITS)
				res = 'b';
			else if (section.sh_flags & SHF_EXECINSTR)
				res = 't';
			else if (section.sh_flags & SHF_WRITE)
				res = 'd';
			else
				res = 'r';
		} else {
			uppercase = true;
			res = 'N';
		}
	}

	if (uppercase)
		res = toupper(res);
	return res;
}

static const char *gelf_get_sym_name(const Gelf_Ehdr *gelf, const Gelf_Sym *sym)
{
	//TODO differentiate between no name and invalid name in return
	int type = GELF_ST_TYPE(sym->st_info);

	if (type == STT_SECTION) {
		Gelf_Shdr section;

		if (gelf_get_shdr(gelf, &section, sym->st_shndx))
			return NULL;
		return gelf_shdr_get_name(gelf, &section);
	}

	Gelf_Shdr strtab_shdr;
	if (gelf_find_shdr(gelf, &strtab_shdr, ".strtab")) {
		return NULL;
	}

	const char *strtab = gelf_shdr_get_addr(gelf, &strtab_shdr);
	if (!gelf_checkptr(gelf, strtab)) {
		return NULL; /* invalid address */
	}

	if (sym->st_name >= strtab_shdr.sh_size) {
		return NULL; /* invalid name, TODO what to do? */
	}
	return &strtab[sym->st_name];
}

static struct symbol *read_symbols(const Gelf_Ehdr *gelf, size_t *nsyms)
{
	Gelf_Shdr symtab_shdr;

	if (gelf_find_shdr(gelf, &symtab_shdr, ".symtab"))
		return NULL;

	const void *symtab = gelf_shdr_get_addr(gelf, &symtab_shdr);
	if (!gelf_checkptr(gelf, symtab))
		return NULL; // invalid address

	struct symbol *symbols = NULL;
	size_t cap = 0;
	size_t count = 0;

	// TODO check if section size is including the header
	// It seems like it doens't include the header
	Gelf_Off off = symtab_shdr.sh_entsize;
	for (; off < symtab_shdr.sh_size;
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


		// TODO check if st_value is valid?
		symbols[count].value = sym.st_value;
		symbols[count].ch = get_nm_sym(gelf, &sym);
		//symbols[count].info = sym.st_info;
		symbols[count].name = gelf_get_sym_name(gelf, &sym);

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

static int read_gelf(Gelf_Ehdr *gelf, const char *path)
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
		gelf->e_shentsize = gelf->hdr32->e_shentsize;
		gelf->e_shnum = gelf->hdr32->e_shnum;
		gelf->e_shstrndx = gelf->hdr32->e_shstrndx;
		break;
	case ELFCLASS64:
		gelf->type = ELF64;
		gelf->e_shentsize = gelf->hdr64->e_shentsize;
		gelf->e_shnum = gelf->hdr64->e_shnum;
		gelf->e_shstrndx = gelf->hdr64->e_shstrndx;
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

static void print_symbol(Gelf_Ehdr *gelf, const struct symbol *sym)
{
	int width = gelf->type == ELF32 ? 8 : 16;

	if (sym->ch == 'U' || sym->ch == 'w' || sym->ch == 'v') {
		for (int i = 0; i <= width; i++) {
			printf(" ");
		}
	} else {
		printf("%0*llx ", width, (unsigned long long) sym->value);
	}
	printf("%c ", sym->ch);
	printf("%s\n", sym->name);
}

static int cmp_sym(const void *a, const void *b)
{
	const struct symbol *sa = (struct symbol*)a;
	const struct symbol *sb = (struct symbol*)b;

	if (!sb)
		return !sa;
	if (!sa)
		return -1;

	return strcmp(sa->name, sb->name);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		// TODO default to a.out
		// TODO argv[0] could not exist
		printf("usage: %s <file>\n", argv[0]);
		return 0;
	}

	//setlocale(LC_CTYPE, "");
	//setlocale(LC_COLLATE, "");

	Gelf_Ehdr gelf;
	if (read_gelf(&gelf, argv[1])) {
		printf("failed to read elf\n");
		return -1;
	}

	size_t nsyms = 0;
	struct symbol *symbols = read_symbols(&gelf, &nsyms);

	qsort(symbols, nsyms, sizeof(*symbols), cmp_sym);

	for (size_t i = 0; i < nsyms; i++) {
		print_symbol(&gelf, &symbols[i]);
	}

	//TODO destroy gelf
	return 0;
}
