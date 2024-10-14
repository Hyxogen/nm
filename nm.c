#include "elf.h"
#include <assert.h>
#include <fcntl.h>
#include <ft/getopt.h>
#include <ft/stdio.h>
#include <ft/stdlib.h>
#include <ft/string.h>
#include <ft/ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

//TODO remove
#include <string.h>
#include <stdlib.h>

#ifndef __BYTE_ORDER__
# error "__BYTE_ORDER__ must be defined to compile this"
#endif

#if (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__) && \
	(__BYTE_ORDER__ != __ORDER_BIG_ENDIAN)
# error "unsupported endiannes"
#endif

#define eprintf(...) ft_dprintf(STDERR_FILENO, __VA_ARGS__)

typedef Elf64_Off Gelf_Off;
typedef Elf64_Xword Gelf_Xword;
typedef Elf64_Addr Gelf_Addr;
typedef Elf64_Word Gelf_Word;
typedef Elf64_Half Gelf_Half;

#define GELF_ST_BIND(info) ELF64_ST_BIND(info)
#define GELF_ST_TYPE(info) ELF64_ST_TYPE(info)
#define GELF_ST_VISIBILITY(info) ELF64_ST_VISIBILITY(info)

typedef struct {
	bool is_elf32;
	Gelf_Xword e_shentsize;
	Gelf_Half e_shnum;
	Gelf_Half e_shstrndx;
	Gelf_Off e_shoff;
	union {
		Elf32_Ehdr *elf32;
		Elf64_Ehdr *elf64;
		void *addr;
	};

	size_t size;
} Gelf_Ehdr;

typedef struct {
	bool is_elf32;
	Gelf_Word sh_name;
	Gelf_Word sh_type;
	Gelf_Xword sh_size;
	Gelf_Xword sh_entsize;
	Gelf_Xword sh_flags;
	Gelf_Off sh_offset;
	union {
		const Elf32_Shdr *shdr32;
		const Elf64_Shdr *shdr64;
		const void *addr;
	};
} Gelf_Shdr;

typedef struct {
	bool is_elf32;
	Gelf_Addr st_value;
	Gelf_Xword st_size;
	Gelf_Word st_name;
	unsigned char st_info;
	unsigned char st_other;
	Gelf_Half st_shndx;
} Gelf_Sym;

enum error {
	NM_OK = 0,
	NM_ENOSYM,
	NM_EBADELF,
	NM_EFILE,
	NM_EUNSUP,
	NM_ENOMEM,
	NM_ENOTFOUND,
	//TODO add something like NM_ESYS which indicates that you have to read
	//errno for more information
};

struct nm_state {
	const char *file;

	Gelf_Ehdr elf;

	Gelf_Shdr shstrtab;
	Gelf_Shdr strtab;
	Gelf_Shdr symtab;
};

struct symbol {
	Elf64_Addr value;
	const char *name;
	bool is_debug;
	char ch;
};

static struct opts {
	bool print_debug;
	bool extern_only;
	bool undefined_only;
	bool reverse_sort;
	bool no_sort;
} prog_opts;

const char *prog_name = "nm";

static int compare_symbol(const void *a, const void *b, void *dummy);
static int compare_symbol_rev(const void *a, const void *b, void *opaque);
static int (*const sorters[2])(const void *, const void *, void*) = {
	compare_symbol,
	compare_symbol_rev,
};

static void merge(void *p, void *tmp, size_t begin, size_t end, size_t size,
		  int (*cmp)(const void *, const void *, void *), void *context)
{
	size_t middle = (begin + end) / 2;

	size_t i = begin, j = middle;

	size_t insert = begin;
	for (; i < middle && j < end; insert++) {
		void *a = (char *)p + i * size;
		void *b = (char *)p + j * size;

		int order = cmp(a, b, context);

		if (order <= 0) {
			memcpy((char *)tmp + insert * size, a, size);
			i++;
		} else {
			memcpy((char *)tmp + insert * size, b, size);
			j++;
		}
	}

	while (i < middle) {
		memcpy((char *)tmp + insert * size, (char *)p + i * size, size);
		i++;
		insert++;
	}
	while (j < end) {
		memcpy((char *)tmp + insert * size, (char *)p + j * size, size);
		j++;
		insert++;
	}
}

/* sort [begin, end) */
static void sort(void *p, void *dest, size_t begin, size_t end, size_t size,
		 int (*cmp)(const void *, const void *, void *), void *context)
{
	size_t count = end - begin;

	if (count <= 1)
		return;

	size_t half = count / 2;

	sort(dest, p, begin, begin + half, size, cmp, context);
	sort(dest, p, begin + half, end, size, cmp, context);
	merge(p, dest, begin, end, size, cmp, context);
}

int mergesort(void *p, size_t count, size_t size,
	      int (*cmp)(const void *, const void *, void *), void *context)
{
	if (count <= 2)
		return 0;

	void *tmp = calloc(count, size);
	if (!tmp)
		return -1;
	memcpy(tmp, p, count * size);

	sort(tmp, p, 0, count, size, cmp, context);

	free(tmp);
	return 0;
}

/* this function assumes that the "large" range is sanitized */
static bool check_bounds(const void *large_start, size_t large_size,
			 const void *small_start, size_t small_size)
{
	const char *clarge_start = large_start;
	const char *csmall_start = small_start;

	const char *clarge_end = clarge_start + large_size;
	const char *csmall_end = csmall_start + small_size;

	return clarge_start <= csmall_start && clarge_start <= csmall_end &&
	       csmall_end <= clarge_end;
}

static bool check_ptr(const void *start, size_t len, const void *ptr)
{
	return ptr >= start && ptr < (void *)((char *)start + len);
}

static void error(const char *fmt, ...)
{
	if (prog_name)
		eprintf("%s: ", prog_name);

	va_list args;
	va_start(args, fmt);

	ft_vdprintf(STDERR_FILENO, fmt, args);
	va_end(args);

	eprintf("\n");
}

static int read_file(void **dest, size_t *size, const char *path)
{
	int res = -1;

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("open");
		goto finish;
	}

	struct stat statbuf;
	if (fstat(fd, &statbuf)) {
		perror("fstat");
		goto finish;
	}

	*size = statbuf.st_size;
	*dest = mmap(NULL, *size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (*dest == MAP_FAILED) {
		perror("mmap");
		goto finish;
	}

	res = 0;
finish:
	if (fd >= 0) {
		if (close(fd))
			perror("close");
	}
	return res;
}

static int free_elf(Gelf_Ehdr *elf)
{
	if (munmap(elf->addr, elf->size)) {
		perror("mmap");
		return -1;
	}
	return 0;
}

static enum error Gelf_shdr_at(const Gelf_Ehdr *gelf, Gelf_Shdr *dest,
			       size_t idx)
{
	assert(idx < gelf->e_shnum);

	if (gelf->e_shentsize == 0)
		return NM_EBADELF;

	const void *addr =
		(char *)gelf->addr + +gelf->e_shoff + gelf->e_shentsize * idx;
	if (!check_ptr(gelf->addr, gelf->size, addr))
		return NM_EBADELF;

	dest->is_elf32 = gelf->is_elf32;
	if (gelf->is_elf32) {
		const Elf32_Shdr *shdr = addr;

		dest->shdr32 = shdr;
		dest->sh_type = dest->shdr32->sh_type;
		dest->sh_size = dest->shdr32->sh_size;
		dest->sh_entsize = dest->shdr32->sh_entsize;
		dest->sh_name = dest->shdr32->sh_name;
		dest->sh_flags = dest->shdr32->sh_flags;
		dest->sh_offset = dest->shdr32->sh_offset;
	} else {
		const Elf64_Shdr *shdr = addr;

		dest->shdr64 = shdr;
		dest->sh_type = dest->shdr64->sh_type;
		dest->sh_size = dest->shdr64->sh_size;
		dest->sh_entsize = dest->shdr64->sh_entsize;
		dest->sh_name = dest->shdr64->sh_name;
		dest->sh_flags = dest->shdr64->sh_flags;
		dest->sh_offset = dest->shdr64->sh_offset;
	}
	return NM_OK;
}

static const void *Gelf_shdr_get_addr(const Gelf_Ehdr *gelf,
				      const Gelf_Shdr *shdr)
{
	return (char *)gelf->addr + shdr->sh_offset;
}

static const char *Gelf_strtab_get_name(const Gelf_Ehdr *gelf,
					const Gelf_Shdr *strtab, size_t idx)
{
	assert(strtab->sh_type == SHT_STRTAB);
	if (idx == 0)
		return "";
	if (idx >= strtab->sh_size)
		return NULL;

	const char *arr = Gelf_shdr_get_addr(gelf, strtab);
	return &arr[idx];
}

static const char *Gelf_shdr_get_name(const Gelf_Ehdr *gelf,
				      const Gelf_Shdr *shstrtab,
				      const Gelf_Shdr *shdr)
{
	return Gelf_strtab_get_name(gelf, shstrtab, shdr->sh_name);
}

static enum error Gelf_shdr_find(const Gelf_Ehdr *gelf,
				 const Gelf_Shdr *shstrtab, Gelf_Shdr *dest,
				 const char *name)
{
	for (Gelf_Half i = 0; i < gelf->e_shnum; i++) {
		enum error err = Gelf_shdr_at(gelf, dest, i);
		if (err != NM_OK)
			continue;

		const char *shdr_name =
			Gelf_shdr_get_name(gelf, shstrtab, dest);
		if (!name || ft_strcmp(shdr_name, name))
			continue;

		return NM_OK;
	}
	return NM_ENOTFOUND;
}

static bool Gelf_shdr_check(const Gelf_Ehdr *gelf, const Gelf_Shdr *shdr)
{
	const void *addr = (char *)gelf->addr + shdr->sh_offset;

	if (!check_bounds(gelf->addr, gelf->size, addr, shdr->sh_size))
		return false;

	if (shdr->sh_type == SHT_STRTAB) {
		const unsigned char *c = addr;

		if (shdr->sh_size && (c[0] || c[shdr->sh_size - 1]))
			return false; /* first and last byte must be zero */
	} else if (shdr->sh_type == SHT_SYMTAB) {
		if (shdr->sh_entsize == 0)
			return false;
	}

	return true;
}

static enum error Gelf_shdr_find_checked(const Gelf_Ehdr *gelf,
					 const Gelf_Shdr *shstrtab,
					 Gelf_Shdr *dest, const char *name)
{
	enum error res = Gelf_shdr_find(gelf, shstrtab, dest, name);
	if (res == NM_OK) {
		if (!Gelf_shdr_check(gelf, dest))
			res = NM_EBADELF;
	}
	return res;
}

static enum error Gelf_sym_at(const Gelf_Ehdr *gelf,
			      const Gelf_Shdr *symtab_shdr, Gelf_Sym *dest,
			      size_t idx)
{
	dest->is_elf32 = gelf->is_elf32;

	const void *addr = (char *)Gelf_shdr_get_addr(gelf, symtab_shdr) +
			   symtab_shdr->sh_entsize * idx;

	if (gelf->is_elf32) {
		const Elf32_Sym *sym = addr;
		dest->st_value = sym->st_value;
		dest->st_name = sym->st_name;
		dest->st_info = sym->st_info;
		dest->st_other = sym->st_other;
		dest->st_shndx = sym->st_shndx;
		dest->st_size = sym->st_size;
	} else {
		const Elf64_Sym *sym = addr;
		dest->st_value = sym->st_value;
		dest->st_name = sym->st_name;
		dest->st_info = sym->st_info;
		dest->st_other = sym->st_other;
		dest->st_shndx = sym->st_shndx;
		dest->st_size = sym->st_size;
	}
	return NM_OK;
}

static char get_symbol_char(const Gelf_Ehdr *gelf, const Gelf_Sym *sym, bool *is_debug)
{
	int bind = GELF_ST_BIND(sym->st_info);
	int type = GELF_ST_TYPE(sym->st_info);

	bool uppercase = bind != STB_LOCAL;

	char ch = '?';
	*is_debug = false;

	if (type == STT_SECTION || type == STT_FILE)
		*is_debug = true;

	Gelf_Shdr section;
	if (sym->st_shndx == SHN_COMMON) {
		uppercase = true;
		ch = 'c';
	} else if (bind == STB_WEAK) {
		uppercase = sym->st_shndx != SHN_UNDEF;
		if (bind == STB_WEAK) {
			ch = 'w';
			if (type == STT_OBJECT)
				ch = 'v';
		}
	} else if (sym->st_shndx == SHN_UNDEF) {
		uppercase = true;
		ch = 'u';
	} else if (type == STT_GNU_IFUNC) {
		uppercase = false;
		ch = 'i';
	} else if (bind == STB_GNU_UNIQUE) {
		uppercase = false;
		ch = 'u';
	} else if (sym->st_shndx == SHN_ABS) {
		uppercase = type != STT_FILE;
		ch = 'a';
	} else if (sym->st_shndx < gelf->e_shnum) {
		enum error res = Gelf_shdr_at(gelf, &section, sym->st_shndx);
		if (res != NM_OK) {
			assert(0 && "a");
			return '?';
		}

		if (section.sh_type == SHT_NOBITS) {
			ch = 'b';
		} else if (section.sh_flags & SHF_ALLOC) {
			if (section.sh_flags & SHF_EXECINSTR)
				ch = 't';
			else if (section.sh_flags & SHF_WRITE)
				ch = 'd';
			else
				ch = 'r';
		} else {
			/*uppercase = false;*/
			ch = 'n';
		}
	}

	if (uppercase)
		ch = ft_toupper(ch);
	return ch;
}

static enum error read_symbol_at(const struct nm_state *state,
				 struct symbol *dest, size_t idx)
{
	Gelf_Sym sym;
	enum error res = Gelf_sym_at(&state->elf, &state->symtab, &sym, idx);

	if (res != NM_OK)
		return res;

	int type = GELF_ST_TYPE(sym.st_info);

	if (type == STT_SECTION) {
		if (sym.st_shndx >= state->elf.e_shnum)
			return NM_EBADELF;

		Gelf_Shdr shdr;
		res = Gelf_shdr_at(&state->elf, &shdr, sym.st_shndx);
		if (res != NM_OK)
			return res;

		dest->name = Gelf_shdr_get_name(&state->elf, &state->shstrtab,
						&shdr);
	} else {
		dest->name = Gelf_strtab_get_name(&state->elf, &state->strtab,
						  sym.st_name);
	}

	dest->value = sym.st_value;
	dest->ch = get_symbol_char(&state->elf, &sym, &dest->is_debug);

	/* apparently, for common values, the size is used as the value */
	if (ft_tolower(dest->ch) == 'c')
		dest->value = sym.st_size;

	if (dest->name == NULL)
		return NM_EBADELF;
	return res;
}

static bool should_exclude(const struct symbol *sym)
{
	if (sym->is_debug && !prog_opts.print_debug)
		return true;
	return false;
}

static enum error read_symbols(const struct nm_state *state,
			       struct symbol **symbols, size_t *nsyms)
{
	*nsyms = state->symtab.sh_size / state->symtab.sh_entsize;
	if (*nsyms == 0)
		return NM_ENOSYM;
	*symbols = ft_calloc(*nsyms, sizeof(*(*symbols)));

	if (!*symbols)
		return NM_ENOMEM;

	size_t j = 0;
	/* we start at one to skip over the first undefined symbol */
	for (size_t i = 1; i < *nsyms; i++) {
		struct symbol *sym = &(*symbols)[j];

		enum error res = read_symbol_at(state, sym, i);

		if (res != NM_OK) {
			free(*symbols);
			return res;
		}

		if (should_exclude(sym))
			continue;

		j += 1;
	}
	*nsyms = j;
	return NM_OK;
}

static enum error check_elf(const Gelf_Ehdr *gelf)
{
	if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) {
		if (gelf->elf32->e_ident[EI_DATA] != ELFDATA2LSB)
			return NM_EUNSUP;
	}

	if (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) {
		if (gelf->elf32->e_ident[EI_DATA] != ELFDATA2MSB)
			return NM_EUNSUP;
	}

	if (gelf->e_shnum == 0 || gelf->e_shentsize == 0 || gelf->e_shoff == 0)
		return NM_ENOSYM;
	if (gelf->e_shnum >= SHN_LORESERVE)
		return NM_EBADELF;

	const void *shstart = (char *)gelf->addr + gelf->e_shoff;

	size_t size = gelf->e_shnum * gelf->e_shentsize;
	if ((size / gelf->e_shnum) != gelf->e_shentsize)
		return NM_EBADELF;

	if (!check_bounds(gelf->addr, gelf->size, shstart, size))
		return NM_EBADELF;

	return NM_OK;
}

static enum error read_elf(Gelf_Ehdr *dest, const char *path)
{
	enum error res = NM_OK;

	if (read_file(&dest->addr, &dest->size, path))
		return NM_ENOMEM;

	if (dest->size < EI_NIDENT) {
		res = NM_EFILE;
		goto done;
	}

	if (ft_memcmp(dest->elf32->e_ident,
		      "\x7f"
		      "ELF",
		      4)) {
		res = NM_EFILE;
		goto done;
	}

	switch (dest->elf32->e_ident[EI_CLASS]) {
	case ELFCLASS32:
		dest->is_elf32 = true;
		dest->e_shentsize = dest->elf32->e_shentsize;
		dest->e_shnum = dest->elf32->e_shnum;
		dest->e_shstrndx = dest->elf32->e_shstrndx;
		dest->e_shoff = dest->elf32->e_shoff;
		break;
	case ELFCLASS64:
		dest->is_elf32 = false;
		dest->e_shentsize = dest->elf64->e_shentsize;
		dest->e_shnum = dest->elf64->e_shnum;
		dest->e_shstrndx = dest->elf64->e_shstrndx;
		dest->e_shoff = dest->elf64->e_shoff;
		break;
	default:
		res = NM_EUNSUP;
		goto done;
	}

	if ((dest->is_elf32 && dest->size < sizeof(Elf32_Ehdr)) ||
	    (!dest->is_elf32 && dest->size < sizeof(Elf64_Ehdr))) {
		res = NM_EBADELF;
		goto done;
	}

	res = check_elf(dest);

done:
	if (res != NM_OK)
		free_elf(dest);
	return res;
}

static enum error init_state(struct nm_state *state, const char *file)
{
	state->file = file;

	enum error res = read_elf(&state->elf, state->file);
	if (res != NM_OK)
		goto done;

	if (state->elf.e_shstrndx >= state->elf.e_shnum) {
		res = NM_EBADELF;
		goto done;
	}

	res = Gelf_shdr_at(&state->elf, &state->shstrtab,
			   state->elf.e_shstrndx);
	if (res != NM_OK)
		goto done;

	if (state->shstrtab.sh_type != SHT_STRTAB ||
	    !Gelf_shdr_check(&state->elf, &state->shstrtab)) {
		res = NM_EBADELF;
		goto done;
	}

	res = Gelf_shdr_find_checked(&state->elf, &state->shstrtab,
				     &state->strtab, ".strtab");
	if (res == NM_ENOTFOUND) {
		res = NM_ENOSYM;
		goto done;
	}
	if (res != NM_OK || state->strtab.sh_type != SHT_STRTAB) {
		res = NM_EBADELF;
		goto done;
	}

	res = Gelf_shdr_find_checked(&state->elf, &state->shstrtab,
				     &state->symtab, ".symtab");
	if (res == NM_ENOTFOUND) {
		res = NM_ENOSYM;
		goto done;
	}
	if (res != NM_OK || state->symtab.sh_type != SHT_SYMTAB) {
		res = NM_EBADELF;
		goto done;
	}

done:
	if (res != NM_OK)
		free_elf(&state->elf);
	return res;
}

static void free_state(struct nm_state *state)
{
	free_elf(&state->elf);
}

static int compare_symbol(const void *a, const void *b, void *dummy)
{
	(void)dummy;
	const struct symbol *sa = (struct symbol*)a;
	const struct symbol *sb = (struct symbol*)b;

	if (!sb->name)
		return !sa;
	if (!sa->name)
		return -1;

	return ft_strcmp(sa->name, sb->name);
}

static int compare_symbol_rev(const void *a, const void *b, void *opaque)
{
	return -compare_symbol(a, b, opaque);
}

static void print_symbol(const struct nm_state *state, const struct symbol *sym)
{
	int width = state->elf.is_elf32 ? 8 : 16;

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

static void print_symbols(const char *path)
{
	struct nm_state state = {};

	enum error err = init_state(&state, path);
	if (err == NM_OK) {
		size_t nsyms;
		struct symbol *symbols;

		err = read_symbols(&state, &symbols, &nsyms);
		if (err == NM_OK) {
			if (!prog_opts.no_sort) {
				mergesort(symbols, nsyms, sizeof(*symbols),
					 sorters[prog_opts.reverse_sort], NULL);
			}

			for (size_t i = 0; i < nsyms; i++) {
				print_symbol(&state, &symbols[i]);
			}
			free(symbols);
		}
		free_state(&state);
	}
	if (err != NM_OK) {
		//TODO print err
		assert(0);
	}
}

static void print_help(void)
{
	ft_dprintf(STDERR_FILENO,
		   "Usage: %s [option(s)] [file(s)]\n"
		   "\n"
		   " Options:\n"
		   "  -a, --debug-syms        display debugger-only symbols\n"
		   "  -g, --extern-only       display only external symbols\n"
		   "  -u, --undefined-only    display only undefined symbols\n"
		   "  -r, --reverse-sort      reverse the output\n"
		   "  -p, --no-sort           do not sort the output\n",
		   prog_name);
}

static void parse_opts(struct opts *opts, int argc, char **argv)
{
	struct option longopts[] = {
		{"debug-syms", no_argument, NULL, 0},
		{"extern-only", no_argument, NULL, 1},
		{"undefined-only", no_argument, NULL, 2},
		{"reverse-sort", no_argument, NULL, 3},
		{"no-sort", no_argument, NULL, 4},
		{"help", no_argument, NULL, 5},
		{NULL, 0, NULL, 0},
	};

	ft_opterr = 1;
	int c;

	while ((c = ft_getopt_long(argc, argv, "agurph", longopts, NULL)) != -1) {
		switch (c) {
		case 0:
		case 'a':
			opts->print_debug = true;
			break;
		case 1:
		case 'g':
			opts->extern_only = true;
			break;
		case 2:
		case 'u':
			opts->undefined_only = true;
			break;
		case 3:
		case 'r':
			opts->reverse_sort = true;
			break;
		case 4:
		case 'p':
			opts->no_sort = true;
			break;
		default:
		case 5:
		case 'h':
		case '?':
			print_help();
			exit(EXIT_FAILURE);
			break;
		}
	}
}

int main(int argc, char **argv)
{
	if (argc)
		prog_name = argv[0];
	parse_opts(&prog_opts, argc, argv);

	if (ft_optind >= argc) {
		/* no file was specified, default to a.out */
		print_symbols("a.out");
	} else {
		for (; ft_optind < argc; ft_optind++) {
			print_symbols(argv[ft_optind]);
		}
	}
	return EXIT_SUCCESS;
}