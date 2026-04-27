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

static void validate_rela_section(const uint8_t *data, size_t size, const Elf64_Shdr *rela,
				  const Elf64_Shdr *target, uint16_t shnum)
{
	uint64_t count;
	uint64_t i;

	if (rela->sh_entsize && rela->sh_entsize != sizeof(Elf64_Rela))
		return;
	if (rela->sh_size % sizeof(Elf64_Rela))
		return;
	if (rela->sh_info >= shnum)
		return;
	if (!range_ok(size, rela->sh_offset, rela->sh_size))
		return;

	count = rela->sh_size / sizeof(Elf64_Rela);
	for (i = 0; i < count; i++) {
		Elf64_Rela rel;
		uint32_t type;
		uint64_t width;

		if (!read_rela(data, size, rela->sh_offset + i * sizeof(rel), &rel))
			return;
		type = ELF64_R_TYPE(rel.r_info);
		width = rela_write_width(type);
		if (width == UINT64_MAX)
			return;

		if (width && rel.r_offset > target->sh_size)
			return;
		if (width && width > target->sh_size - rel.r_offset)
			return;
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	Elf64_Ehdr hdr;
	Elf64_Shdr shstr;
	const uint8_t *shstrtab;
	uint64_t shdr_bytes;
	bool has_info = false;
	bool has_init = false;
	bool has_exit = false;
	uint16_t i;

	if (size < sizeof(hdr))
		return 0;

	memcpy(&hdr, data, sizeof(hdr));
	if (memcmp(hdr.e_ident, ELFMAG, SELFMAG))
		return 0;
	if (hdr.e_ident[EI_CLASS] != ELFCLASS64 || hdr.e_ident[EI_DATA] != ELFDATA2LSB)
		return 0;
	if (hdr.e_type != ET_REL || hdr.e_machine != EM_X86_64)
		return 0;
	if (hdr.e_shentsize != sizeof(Elf64_Shdr) || hdr.e_shnum == 0)
		return 0;
	if (hdr.e_shstrndx == SHN_UNDEF || hdr.e_shstrndx >= hdr.e_shnum)
		return 0;

	shdr_bytes = (uint64_t)hdr.e_shnum * sizeof(Elf64_Shdr);
	if (!range_ok(size, hdr.e_shoff, shdr_bytes))
		return 0;
	if (!read_shdr(data, size, hdr.e_shoff + (uint64_t)hdr.e_shstrndx * sizeof(Elf64_Shdr), &shstr))
		return 0;
	if (!range_ok(size, shstr.sh_offset, shstr.sh_size))
		return 0;

	shstrtab = data + shstr.sh_offset;
	for (i = 1; i < hdr.e_shnum; i++) {
		Elf64_Shdr shdr;

		if (!read_shdr(data, size, hdr.e_shoff + (uint64_t)i * sizeof(Elf64_Shdr), &shdr))
			return 0;
		if (!string_in_table(shstrtab, shstr.sh_size, shdr.sh_name))
			return 0;
		if (shdr.sh_type != SHT_NOBITS && !range_ok(size, shdr.sh_offset, shdr.sh_size))
			return 0;

		if ((shdr.sh_flags & SHF_ALLOC) && section_name_is(shstrtab, shstr.sh_size, &shdr, ".kpm.info")) {
			has_info = shdr.sh_size > 0 && data[shdr.sh_offset + shdr.sh_size - 1] == '\0';
		}
		if ((shdr.sh_flags & SHF_ALLOC) && section_name_is(shstrtab, shstr.sh_size, &shdr, ".kpm.init"))
			has_init = shdr.sh_size == sizeof(uint64_t);
		if ((shdr.sh_flags & SHF_ALLOC) && section_name_is(shstrtab, shstr.sh_size, &shdr, ".kpm.exit"))
			has_exit = shdr.sh_size == sizeof(uint64_t);
	}

	if (!has_info || !has_init || !has_exit)
		return 0;

	for (i = 1; i < hdr.e_shnum; i++) {
		Elf64_Shdr rela;
		Elf64_Shdr target;

		if (!read_shdr(data, size, hdr.e_shoff + (uint64_t)i * sizeof(Elf64_Shdr), &rela))
			return 0;
		if (rela.sh_type != SHT_RELA)
			continue;
		if (rela.sh_info >= hdr.e_shnum)
			return 0;
		if (!read_shdr(data, size, hdr.e_shoff + (uint64_t)rela.sh_info * sizeof(Elf64_Shdr), &target))
			return 0;
		validate_rela_section(data, size, &rela, &target, hdr.e_shnum);
	}

	return 0;
}

#ifdef KPM_FUZZ_STANDALONE
int main(int argc, char **argv)
{
	int i;

	for (i = 1; i < argc; i++) {
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
		LLVMFuzzerTestOneInput(buf, (size_t)len);
		free(buf);
	}

	return 0;
}
#endif
