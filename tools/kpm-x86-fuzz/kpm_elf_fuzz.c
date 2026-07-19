// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Userspace smoke fuzzer for x86_64 KPM ELF metadata.
 *
 * This intentionally mirrors the loader's public input contract instead of
 * linking kernel code. It is a fast CI guard for malformed ELF section tables,
 * string tables, symbol tables and RELA records.
 */

#include <elf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define KPM_MAX_FILE_SIZE (16U * 1024U * 1024U)
#define KPM_MAX_LOADED_SIZE (32U * 1024U * 1024U)
#define KPM_MAX_SECTIONS 4096U
#define KPM_PAGE_SIZE 4096U

#ifdef KPM_FUZZ_STANDALONE
#include <stdio.h>
#include <stdlib.h>
#endif

static bool range_ok(size_t size, uint64_t off, uint64_t len)
{
	if (off > size)
		return false;
	if (len > size - off)
		return false;
	return true;
}

static bool ranges_overlap(uint64_t first_off, uint64_t first_size, uint64_t second_off, uint64_t second_size)
{
	return first_size && second_size && first_off < second_off + second_size &&
	       second_off < first_off + first_size;
}

static bool read_shdr(const uint8_t *data, size_t size, uint64_t off, Elf64_Shdr *out)
{
	if (!range_ok(size, off, sizeof(*out)))
		return false;
	memcpy(out, data + off, sizeof(*out));
	return true;
}

static bool read_rela(const uint8_t *data, size_t size, uint64_t off, Elf64_Rela *out)
{
	if (!range_ok(size, off, sizeof(*out)))
		return false;
	memcpy(out, data + off, sizeof(*out));
	return true;
}

static bool read_sym(const uint8_t *data, size_t size, uint64_t off, Elf64_Sym *out)
{
	if (!range_ok(size, off, sizeof(*out)))
		return false;
	memcpy(out, data + off, sizeof(*out));
	return true;
}

static bool string_in_table(const uint8_t *strtab, uint64_t size, uint32_t off)
{
	uint64_t i;

	if (off >= size)
		return false;
	for (i = off; i < size; i++) {
		if (strtab[i] == '\0')
			return true;
	}
	return false;
}

static bool section_name_is(const uint8_t *strtab, uint64_t size, const Elf64_Shdr *shdr, const char *name)
{
	size_t len = strlen(name);

	if (!string_in_table(strtab, size, shdr->sh_name))
		return false;
	if (shdr->sh_name + len >= size)
		return false;
	return memcmp(strtab + shdr->sh_name, name, len + 1) == 0;
}

static uint64_t rela_write_width(uint32_t type)
{
	switch (type) {
	case R_X86_64_64:
	case R_X86_64_PC64:
		return 8;
	case R_X86_64_32:
	case R_X86_64_32S:
	case R_X86_64_PC32:
	case R_X86_64_PLT32:
	case R_X86_64_GOTPCREL:
	case R_X86_64_GOTPCRELX:
	case R_X86_64_REX_GOTPCRELX:
		return 4;
	case R_X86_64_NONE:
		return 0;
	default:
		return UINT64_MAX;
	}
}

static bool validate_rela_section(const uint8_t *data, size_t size, const Elf64_Shdr *rela,
				  const Elf64_Shdr *target, uint16_t shnum, uint16_t symtab_index,
				  uint64_t symbol_count)
{
	uint64_t count;
	uint64_t i;

	if (rela->sh_entsize != sizeof(Elf64_Rela))
		return false;
	if (rela->sh_size % sizeof(Elf64_Rela))
		return false;
	if (rela->sh_info >= shnum)
		return false;
	if (rela->sh_link != symtab_index)
		return false;
	if (!range_ok(size, rela->sh_offset, rela->sh_size))
		return false;

	count = rela->sh_size / sizeof(Elf64_Rela);
	for (i = 0; i < count; i++) {
		Elf64_Rela rel;
		uint32_t type;
		uint64_t width;

		if (!read_rela(data, size, rela->sh_offset + i * sizeof(rel), &rel))
			return false;
		if (ELF64_R_SYM(rel.r_info) >= symbol_count)
			return false;
		type = ELF64_R_TYPE(rel.r_info);
		width = rela_write_width(type);
		if (width == UINT64_MAX)
			return false;

		if (width && rel.r_offset > target->sh_size)
			return false;
		if (width && width > target->sh_size - rel.r_offset)
			return false;
	}

	return true;
}

static bool validate_kpm_elf(const uint8_t *data, size_t size)
{
	Elf64_Ehdr hdr;
	Elf64_Shdr nullsec;
	Elf64_Shdr shstr;
	Elf64_Shdr symtab = { 0 };
	Elf64_Shdr strtab = { 0 };
	const uint8_t *shstrtab;
	const uint8_t *symstrings = NULL;
	uint64_t shdr_bytes;
	uint64_t loaded_size = 0;
	uint64_t symbol_count = 0;
	uint64_t sym_i;
	unsigned int info_count = 0;
	unsigned int init_count = 0;
	unsigned int exit_count = 0;
	unsigned int ctl0_count = 0;
	unsigned int ctl1_count = 0;
	uint16_t symtab_index = SHN_UNDEF;
	uint16_t i;

	if (size < sizeof(hdr) || size > KPM_MAX_FILE_SIZE)
		return false;

	memcpy(&hdr, data, sizeof(hdr));
	if (memcmp(hdr.e_ident, ELFMAG, SELFMAG))
		return false;
	if (hdr.e_ident[EI_CLASS] != ELFCLASS64 || hdr.e_ident[EI_DATA] != ELFDATA2LSB ||
	    hdr.e_ident[EI_VERSION] != EV_CURRENT || hdr.e_version != EV_CURRENT)
		return false;
	if (hdr.e_type != ET_REL || hdr.e_machine != EM_X86_64)
		return false;
	if (hdr.e_ehsize != sizeof(hdr) || hdr.e_phnum != 0 || hdr.e_shentsize != sizeof(Elf64_Shdr) ||
	    hdr.e_shnum == 0 || hdr.e_shnum > KPM_MAX_SECTIONS)
		return false;
	if (hdr.e_shstrndx == SHN_UNDEF || hdr.e_shstrndx == SHN_XINDEX || hdr.e_shstrndx >= hdr.e_shnum)
		return false;

	shdr_bytes = (uint64_t)hdr.e_shnum * sizeof(Elf64_Shdr);
	if (hdr.e_shoff < sizeof(hdr) || !range_ok(size, hdr.e_shoff, shdr_bytes))
		return false;
	if (!read_shdr(data, size, hdr.e_shoff, &nullsec) || nullsec.sh_type != SHT_NULL || nullsec.sh_size ||
	    nullsec.sh_addr)
		return false;
	if (!read_shdr(data, size, hdr.e_shoff + (uint64_t)hdr.e_shstrndx * sizeof(Elf64_Shdr), &shstr))
		return false;
	if (shstr.sh_type != SHT_STRTAB || !shstr.sh_size || !range_ok(size, shstr.sh_offset, shstr.sh_size))
		return false;

	shstrtab = data + shstr.sh_offset;
	if (shstrtab[shstr.sh_size - 1] != '\0')
		return false;
	for (i = 1; i < hdr.e_shnum; i++) {
		Elf64_Shdr shdr;
		uint64_t align;
		uint16_t j;

		if (!read_shdr(data, size, hdr.e_shoff + (uint64_t)i * sizeof(Elf64_Shdr), &shdr))
			return false;
		if (!string_in_table(shstrtab, shstr.sh_size, shdr.sh_name))
			return false;
		if (shdr.sh_addralign > KPM_PAGE_SIZE ||
		    (shdr.sh_addralign && (shdr.sh_addralign & (shdr.sh_addralign - 1))))
			return false;
		if (shdr.sh_addralign > 1 && (shdr.sh_offset & (shdr.sh_addralign - 1)))
			return false;
		if ((shdr.sh_flags & (SHF_WRITE | SHF_EXECINSTR)) == (SHF_WRITE | SHF_EXECINSTR))
			return false;
		if ((shdr.sh_flags & SHF_ALLOC) && shdr.sh_type != SHT_PROGBITS && shdr.sh_type != SHT_NOBITS)
			return false;
		if (shdr.sh_type == SHT_NOBITS && (shdr.sh_flags & SHF_EXECINSTR))
			return false;
		if ((shdr.sh_flags & SHF_ALLOC) &&
		    ((shdr.sh_flags & (SHF_COMPRESSED | SHF_TLS)) || shdr.sh_size > KPM_MAX_LOADED_SIZE))
			return false;
		if (shdr.sh_type != SHT_NOBITS) {
			if (!range_ok(size, shdr.sh_offset, shdr.sh_size))
				return false;
			if (ranges_overlap(shdr.sh_offset, shdr.sh_size, 0, sizeof(hdr)) ||
			    ranges_overlap(shdr.sh_offset, shdr.sh_size, hdr.e_shoff, shdr_bytes))
				return false;
			for (j = 1; j < i; j++) {
				Elf64_Shdr previous;

				if (!read_shdr(data, size, hdr.e_shoff + (uint64_t)j * sizeof(previous), &previous))
					return false;
				if (previous.sh_type != SHT_NOBITS &&
				    ranges_overlap(shdr.sh_offset, shdr.sh_size, previous.sh_offset, previous.sh_size))
					return false;
			}
		}
		if (shdr.sh_type == SHT_NOBITS && shdr.sh_offset > size)
			return false;

		if (shdr.sh_flags & SHF_ALLOC) {
			align = shdr.sh_addralign ? shdr.sh_addralign : 1;
			if (loaded_size > UINT64_MAX - (align - 1))
				return false;
			loaded_size = (loaded_size + align - 1) & ~(align - 1);
			if (shdr.sh_size > KPM_MAX_LOADED_SIZE - loaded_size)
				return false;
			loaded_size += shdr.sh_size;
		}

		if ((shdr.sh_flags & SHF_ALLOC) && section_name_is(shstrtab, shstr.sh_size, &shdr, ".kpm.info")) {
			info_count++;
			if (shdr.sh_type != SHT_PROGBITS || !shdr.sh_size || shdr.sh_size > 4096 ||
			    data[shdr.sh_offset + shdr.sh_size - 1] != '\0')
				return false;
		}
		if ((shdr.sh_flags & SHF_ALLOC) && section_name_is(shstrtab, shstr.sh_size, &shdr, ".kpm.init")) {
			init_count++;
			if (shdr.sh_type != SHT_PROGBITS || shdr.sh_size != sizeof(uint64_t))
				return false;
		}
		if ((shdr.sh_flags & SHF_ALLOC) && section_name_is(shstrtab, shstr.sh_size, &shdr, ".kpm.exit")) {
			exit_count++;
			if (shdr.sh_type != SHT_PROGBITS || shdr.sh_size != sizeof(uint64_t))
				return false;
		}
		if ((shdr.sh_flags & SHF_ALLOC) && section_name_is(shstrtab, shstr.sh_size, &shdr, ".kpm.ctl0")) {
			ctl0_count++;
			if (shdr.sh_type != SHT_PROGBITS || shdr.sh_size != sizeof(uint64_t))
				return false;
		}
		if ((shdr.sh_flags & SHF_ALLOC) && section_name_is(shstrtab, shstr.sh_size, &shdr, ".kpm.ctl1")) {
			ctl1_count++;
			if (shdr.sh_type != SHT_PROGBITS || shdr.sh_size != sizeof(uint64_t))
				return false;
		}
		if (shdr.sh_type == SHT_SYMTAB && symtab_index == SHN_UNDEF) {
			symtab_index = i;
			symtab = shdr;
		}
	}

	if (info_count != 1 || init_count != 1 || exit_count != 1 || ctl0_count > 1 || ctl1_count > 1)
		return false;
	if (symtab_index == SHN_UNDEF || !symtab.sh_size || symtab.sh_entsize != sizeof(Elf64_Sym) ||
	    symtab.sh_size % sizeof(Elf64_Sym) || symtab.sh_link == SHN_UNDEF || symtab.sh_link >= hdr.e_shnum)
		return false;
	if (!read_shdr(data, size, hdr.e_shoff + (uint64_t)symtab.sh_link * sizeof(Elf64_Shdr), &strtab))
		return false;
	if (strtab.sh_type != SHT_STRTAB || !strtab.sh_size || !range_ok(size, strtab.sh_offset, strtab.sh_size))
		return false;
	symstrings = data + strtab.sh_offset;
	if (symstrings[strtab.sh_size - 1] != '\0')
		return false;
	symbol_count = symtab.sh_size / sizeof(Elf64_Sym);
	if (symtab.sh_info > symbol_count)
		return false;
	for (sym_i = 1; sym_i < symbol_count; sym_i++) {
		Elf64_Sym sym;
		Elf64_Shdr target;

		if (!read_sym(data, size, symtab.sh_offset + sym_i * sizeof(sym), &sym))
			return false;
		if (!string_in_table(symstrings, strtab.sh_size, sym.st_name))
			return false;
		if (sym.st_shndx == SHN_UNDEF || sym.st_shndx == SHN_ABS)
			continue;
		if (sym.st_shndx >= SHN_LORESERVE || sym.st_shndx >= hdr.e_shnum)
			return false;
		if (!read_shdr(data, size, hdr.e_shoff + (uint64_t)sym.st_shndx * sizeof(Elf64_Shdr), &target))
			return false;
		if (!(target.sh_flags & SHF_ALLOC) || sym.st_value > target.sh_size || sym.st_size > target.sh_size - sym.st_value)
			return false;
	}

	for (i = 1; i < hdr.e_shnum; i++) {
		Elf64_Shdr rela;
		Elf64_Shdr target;

		if (!read_shdr(data, size, hdr.e_shoff + (uint64_t)i * sizeof(Elf64_Shdr), &rela))
			return false;
		if (rela.sh_type != SHT_RELA)
			continue;
		if (rela.sh_info >= hdr.e_shnum)
			return false;
		if (!read_shdr(data, size, hdr.e_shoff + (uint64_t)rela.sh_info * sizeof(Elf64_Shdr), &target))
			return false;
		if (!validate_rela_section(data, size, &rela, &target, hdr.e_shnum, symtab_index, symbol_count))
			return false;
	}

	return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	(void)validate_kpm_elf(data, size);
	return 0;
}

#ifdef KPM_FUZZ_STANDALONE
int main(int argc, char **argv)
{
	bool expect_valid = false;
	bool check_expectation = false;
	int first = 1;
	int i;

	if (argc > 1 && !strcmp(argv[1], "--expect-valid")) {
		expect_valid = true;
		check_expectation = true;
		first = 2;
	} else if (argc > 1 && !strcmp(argv[1], "--expect-invalid")) {
		check_expectation = true;
		first = 2;
	}

	for (i = first; i < argc; i++) {
		FILE *fp = fopen(argv[i], "rb");
		long len;
		uint8_t *buf;

		if (!fp) {
			perror(argv[i]);
			return 1;
		}
		if (fseek(fp, 0, SEEK_END) != 0) {
			fclose(fp);
			return 1;
		}
		len = ftell(fp);
		if (len < 0) {
			fclose(fp);
			return 1;
		}
		if (fseek(fp, 0, SEEK_SET) != 0) {
			fclose(fp);
			return 1;
		}
		buf = malloc((size_t)len);
		if (!buf && len > 0) {
			fclose(fp);
			return 1;
		}
		if (len > 0 && fread(buf, 1, (size_t)len, fp) != (size_t)len) {
			free(buf);
			fclose(fp);
			return 1;
		}
		fclose(fp);
		if (check_expectation && validate_kpm_elf(buf, (size_t)len) != expect_valid) {
			fprintf(stderr, "%s: unexpected ELF validation result\n", argv[i]);
			free(buf);
			return 1;
		}
		LLVMFuzzerTestOneInput(buf, (size_t)len);
		free(buf);
	}

	return 0;
}
#endif
