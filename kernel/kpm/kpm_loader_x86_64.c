// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Experimental direct KPM ELF loader for ReSukiSU on WSA x86_64.
 *
 * This bypasses KernelPatch kpimg/kptools because that payload is ARM64-only.
 * It loads ET_REL x86_64 KPM objects using the standard .kpm.* metadata and
 * callback sections plus common non-PIC x86_64 relocations.
 */

#include <linux/cred.h>
#include <linux/elf.h>
#include <linux/err.h>
#include <linux/ftrace.h>
#include <linux/fs.h>
#include <linux/jump_label.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/memory.h>
#include <linux/mm.h>
#include <linux/moduleloader.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include <linux/static_call.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <asm/alternative.h>
#include <asm/cacheflush.h>
#include <asm/elf.h>
#include <asm/insn.h>
#include <asm/text-patching.h>
#include <asm/unistd.h>
#include <uapi/linux/elf-em.h>

#include "compact.h"
#include "arch.h"
#include "hook/patch_memory.h"
#include "kpm_loader_x86_64.h"

#define SUKISU_KPM_LOADER_VERSION "ReSukiSU-x86_64-KPM-loader/0.2"
#define SUKISU_KPM_MAX_MODULE_SIZE (16 * 1024 * 1024)
#define SUKISU_KPM_HOOK_NO_ERR 0
#define SUKISU_KPM_HOOK_BAD_ADDRESS 4095
#define SUKISU_KPM_HOOK_DUPLICATED 4094
#define SUKISU_KPM_HOOK_NO_MEM 4093
#define SUKISU_KPM_HOOK_BAD_RELO 4092
#define SUKISU_KPM_HOOK_TRANSIT_NO_MEM 4091
#define SUKISU_KPM_HOOK_CHAIN_FULL 4090
#define SUKISU_KPM_PATCH_FLAGS (KSU_PATCH_TEXT_FLUSH_DCACHE | KSU_PATCH_TEXT_FLUSH_ICACHE)
#define SUKISU_KPM_X86_JMP_ABS_SIZE 14
#define SUKISU_KPM_X86_MAX_STOLEN_SIZE 32
#define SUKISU_KPM_X86_WRAP_STUB_SIZE 256
#define SUKISU_KPM_HOOK_CHAIN_NUM 0x10
#define SUKISU_KPM_FP_HOOK_CHAIN_NUM 0x20
#define SUKISU_KPM_SYSCALL_HOOK_CHAIN_NUM 0x20
#define SUKISU_KPM_TRANSIT_INST_NUM 0x60
#define SUKISU_KPM_RELOCATE_INST_NUM (4 * 8 + 8 - 4)
#define SUKISU_KPM_CHAIN_ITEM_EMPTY 0
#define SUKISU_KPM_CHAIN_ITEM_READY 1
#define SUKISU_KPM_WRAP_ARG_MAX 12
#define SUKISU_KPM_WRAP_FRAME_CHAIN 0
#define SUKISU_KPM_WRAP_FRAME_SKIP 8
#define SUKISU_KPM_WRAP_FRAME_LOCAL 16
#define SUKISU_KPM_WRAP_FRAME_RET 80
#define SUKISU_KPM_WRAP_FRAME_ARGS 88
#define SUKISU_KPM_WRAP_FRAME_SIZE 184

#ifndef R_X86_64_PC64
#define R_X86_64_PC64 24
#endif
#ifndef R_X86_64_GOTPCREL
#define R_X86_64_GOTPCREL 9
#endif
#ifndef R_X86_64_GOTPCRELX
#define R_X86_64_GOTPCRELX 41
#endif
#ifndef R_X86_64_REX_GOTPCRELX
#define R_X86_64_REX_GOTPCRELX 42
#endif

#ifdef CONFIG_KPROBES
extern int __copy_instruction(u8 *dest, u8 *src, u8 *real, struct insn *insn);
#endif

typedef long (*sukisu_kpm_initcall_t)(const char *args, const char *event, void __user *reserved);
typedef long (*sukisu_kpm_ctl0call_t)(const char *args, char __user *out_msg, int outlen);
typedef long (*sukisu_kpm_ctl1call_t)(void *a1, void *a2, void *a3);
typedef long (*sukisu_kpm_exitcall_t)(void __user *reserved);
typedef void (*sukisu_kpm_chain_callback_t)(void *fargs, void *udata);

struct sukisu_kpm_module_info {
	const char *base;
	const char *name;
	const char *version;
	const char *license;
	const char *author;
	const char *description;
};

struct sukisu_kpm_module {
	struct list_head list;
	struct sukisu_kpm_module_info info;
	char *args;
	char *ctl_args;
	void *start;
	unsigned int size;
	unsigned int text_size;
	unsigned int ro_size;
	sukisu_kpm_initcall_t *init;
	sukisu_kpm_ctl0call_t *ctl0;
	sukisu_kpm_ctl1call_t *ctl1;
	sukisu_kpm_exitcall_t *exit;
};

struct sukisu_kpm_load_info {
	const Elf_Ehdr *hdr;
	unsigned long len;
	Elf_Shdr *sechdrs;
	char *secstrings;
	char *strtab;
	struct {
		unsigned int sym;
		unsigned int str;
		unsigned int info;
	} index;
	unsigned int got_entries;
	unsigned int got_next;
	unsigned int got_offset;
	struct {
		const char *base;
		unsigned long size;
		const char *name;
		const char *version;
		const char *license;
		const char *author;
		const char *description;
	} info;
};

struct sukisu_kpm_symbol_alias {
	const char *name;
	unsigned long addr;
};

struct sukisu_kpm_kp_hook {
	u64 func_addr;
	u64 origin_addr;
	u64 replace_addr;
	u64 relo_addr;
	s32 tramp_insts_num;
	s32 relo_insts_num;
	u32 origin_insts[6] __aligned(8);
	u32 tramp_insts[6] __aligned(8);
	u32 relo_insts[SUKISU_KPM_RELOCATE_INST_NUM] __aligned(8);
} __aligned(8);

struct sukisu_kpm_kp_fp_hook {
	unsigned long fp_addr;
	u64 replace_addr;
	u64 origin_fp;
} __aligned(8);

struct sukisu_kpm_hook_local {
	u64 data[8];
};

struct sukisu_kpm_hook_fargs12 {
	void *chain;
	int skip_origin;
	struct sukisu_kpm_hook_local local;
	u64 ret;
	union {
		struct {
			u64 arg0;
			u64 arg1;
			u64 arg2;
			u64 arg3;
			u64 arg4;
			u64 arg5;
			u64 arg6;
			u64 arg7;
			u64 arg8;
			u64 arg9;
			u64 arg10;
			u64 arg11;
		};
		u64 args[SUKISU_KPM_WRAP_ARG_MAX];
	};
} __aligned(8);

struct sukisu_kpm_inline_hook {
	struct list_head list;
	void *func;
	void *replace;
	void *trampoline;
	unsigned int stolen_size;
	unsigned int patch_size;
	bool uses_text_poke_bp;
	u8 original[SUKISU_KPM_X86_MAX_STOLEN_SIZE];
};

struct sukisu_kpm_wrap_chain {
	struct sukisu_kpm_kp_hook hook;
	s32 chain_items_max;
	s8 states[SUKISU_KPM_HOOK_CHAIN_NUM];
	void *udata[SUKISU_KPM_HOOK_CHAIN_NUM];
	void *befores[SUKISU_KPM_HOOK_CHAIN_NUM];
	void *afters[SUKISU_KPM_HOOK_CHAIN_NUM];
	u32 transit[SUKISU_KPM_TRANSIT_INST_NUM];
	struct list_head list;
	atomic_t active;
	int argno;
	bool disabled;
	void *stub;
};

struct sukisu_kpm_fp_wrap_chain {
	struct sukisu_kpm_kp_fp_hook hook;
	s32 chain_items_max;
	s8 states[SUKISU_KPM_FP_HOOK_CHAIN_NUM];
	void *udata[SUKISU_KPM_FP_HOOK_CHAIN_NUM];
	void *befores[SUKISU_KPM_FP_HOOK_CHAIN_NUM];
	void *afters[SUKISU_KPM_FP_HOOK_CHAIN_NUM];
	u32 transit[SUKISU_KPM_TRANSIT_INST_NUM];
	struct list_head list;
	atomic_t active;
	int argno;
	bool disabled;
	void *stub;
};

static LIST_HEAD(sukisu_kpm_modules);
static LIST_HEAD(sukisu_kpm_inline_hooks);
static LIST_HEAD(sukisu_kpm_wrap_chains);
static LIST_HEAD(sukisu_kpm_fp_wrap_chains);
static DEFINE_MUTEX(sukisu_kpm_module_lock);
static DEFINE_MUTEX(sukisu_kpm_hook_lock);

static u32 sukisu_kpm_kver = LINUX_VERSION_CODE;
static u32 sukisu_kpm_kpver = KERNEL_VERSION(0, 1, 0);
static int sukisu_kpm_endian;
static s64 sukisu_kpm_page_size = PAGE_SIZE;
static s64 sukisu_kpm_page_shift = PAGE_SHIFT;
static int sukisu_kpm_has_syscall_wrapper;
static int sukisu_kpm_has_config_compat;

static void *sukisu_kpm_malloc(size_t bytes)
{
	return vmalloc(bytes);
}

static void *sukisu_kpm_malloc_exec(size_t bytes)
{
	return module_alloc(bytes);
}

static void sukisu_kpm_free(void *ptr)
{
	vfree(ptr);
}

static void sukisu_kpm_free_exec(void *ptr)
{
	if (ptr)
		module_memfree(ptr);
}

static unsigned long sukisu_kpm_pages_for_size(size_t size)
{
	return PAGE_ALIGN(size) >> PAGE_SHIFT;
}

static int sukisu_kpm_set_exec_rox(void *ptr, size_t size)
{
	unsigned long start = (unsigned long)ptr;
	unsigned long pages = sukisu_kpm_pages_for_size(size);
	int rc;

	if (!ptr || !pages)
		return -EINVAL;

	rc = set_memory_nx(start, pages);
	if (rc)
		return rc;
	rc = set_memory_ro(start, pages);
	if (rc)
		return rc;
	rc = set_memory_x(start, pages);
	if (rc) {
		set_memory_rw(start, pages);
		set_memory_nx(start, pages);
		return rc;
	}
	flush_icache_range(start, start + size);
	return 0;
}

static void sukisu_kpm_set_exec_rw_nx(void *ptr, size_t size)
{
	unsigned long start = (unsigned long)ptr;
	unsigned long pages = sukisu_kpm_pages_for_size(size);

	if (!ptr || !pages)
		return;

	set_memory_rw(start, pages);
	set_memory_nx(start, pages);
}

static void sukisu_kpm_sync_before_exec_free(void)
{
	synchronize_rcu_tasks_rude();
	synchronize_rcu_tasks();
}

static void sukisu_kpm_free_generated_exec(void *ptr, size_t size, bool sync)
{
	if (!ptr)
		return;
	if (sync)
		sukisu_kpm_sync_before_exec_free();
	sukisu_kpm_set_exec_rw_nx(ptr, size);
	module_memfree(ptr);
}

static int __must_check sukisu_kpm_compat_copy_to_user(void __user *to, const void *from, int n)
{
	if (!to || !from || n <= 0)
		return 0;

	return copy_to_user(to, from, n) ? 0 : n;
}

static long sukisu_kpm_compat_strncpy_from_user(char *dest, const char __user *src, long count)
{
	long ret;

	if (!dest || !src || count <= 0)
		return -EINVAL;

	ret = strncpy_from_user(dest, src, count);
	if (ret >= count) {
		dest[count - 1] = '\0';
		return count - 1;
	}
	if (ret < 0)
		dest[0] = '\0';
	return ret;
}

static uid_t sukisu_kpm_current_uid(void)
{
	return from_kuid(&init_user_ns, current_uid());
}

static bool sukisu_kpm_bad_kernel_addr(unsigned long addr)
{
	return !addr || !(addr & 0x8000000000000000ULL);
}

static int sukisu_kpm_patch_bytes(void *addr, const void *bytes, size_t len)
{
	if (!addr || !bytes || !len)
		return -EINVAL;
	if (WARN_ON_ONCE(in_interrupt() || irqs_disabled()))
		return -EWOULDBLOCK;
	might_sleep();

	return ksu_patch_text(addr, (void *)bytes, len, SUKISU_KPM_PATCH_FLAGS);
}

static bool sukisu_kpm_rel32_fits(const void *addr, const void *target, size_t insn_len)
{
	s64 disp = (s64)(long)target - ((s64)(long)addr + insn_len);

	return disp == (s64)(s32)disp;
}

static void sukisu_kpm_make_rel32_jmp(u8 *buf, const void *addr, const void *target)
{
	s32 disp = (s32)((long)target - ((long)addr + JMP32_INSN_SIZE));

	buf[0] = JMP32_INSN_OPCODE;
	memcpy(buf + 1, &disp, sizeof(disp));
}

static int sukisu_kpm_patch_rel32_jmp_bp(void *addr, const void *target)
{
	u8 patch[JMP32_INSN_SIZE];

	if (!sukisu_kpm_rel32_fits(addr, target, JMP32_INSN_SIZE))
		return -ERANGE;
	if (WARN_ON_ONCE(in_interrupt() || irqs_disabled()))
		return -EWOULDBLOCK;
	might_sleep();

	sukisu_kpm_make_rel32_jmp(patch, addr, target);
	mutex_lock(&text_mutex);
	text_poke_bp(addr, patch, JMP32_INSN_SIZE, NULL);
	mutex_unlock(&text_mutex);
	return 0;
}

static int sukisu_kpm_restore_rel32_hook_bp(void *addr, const void *original,
					    const void *emulate_target)
{
	u8 emulate[JMP32_INSN_SIZE];
	u8 cur_bytes[JMP32_INSN_SIZE];
	int rc;

	if (!sukisu_kpm_rel32_fits(addr, emulate_target, JMP32_INSN_SIZE))
		return -ERANGE;
	if (in_interrupt() || irqs_disabled())
		return -EWOULDBLOCK;

	rc = copy_from_kernel_nofault(cur_bytes, addr, sizeof(cur_bytes));
	if (rc)
		return rc;

	sukisu_kpm_make_rel32_jmp(emulate, addr, emulate_target);
	if (memcmp(cur_bytes, emulate, sizeof(cur_bytes)))
		return -EBUSY;

	might_sleep();
	mutex_lock(&text_mutex);
	text_poke_bp(addr, original, JMP32_INSN_SIZE, emulate);
	mutex_unlock(&text_mutex);
	return 0;
}

static void sukisu_kpm_make_abs_jmp(u8 *buf, const void *target)
{
	buf[0] = 0xff;
	buf[1] = 0x25;
	memset(buf + 2, 0, 4);
	memcpy(buf + 6, &target, sizeof(target));
}

static bool sukisu_kpm_insn_is_unsafe_to_copy(struct insn *insn)
{
	u8 op0 = insn->opcode.bytes[0];
	u8 op1 = insn->opcode.bytes[1];

	if (op0 == 0xe8 || op0 == 0xe9 || op0 == 0xeb)
		return true;
	if (op0 >= 0x70 && op0 <= 0x7f)
		return true;
	if (op0 >= 0xe0 && op0 <= 0xe3)
		return true;
	if (op0 == 0x0f && op1 >= 0x80 && op1 <= 0x8f)
		return true;
	if (op0 == 0xc2 || op0 == 0xc3 || op0 == 0xca || op0 == 0xcb || op0 == 0xcf)
		return true;
	if (op0 == 0xcc)
		return true;

	if (op0 == 0xff) {
		insn_get_modrm(insn);
		switch (X86_MODRM_REG(insn->modrm.bytes[0])) {
		case 2:
		case 4:
			return true;
		default:
			break;
		}
	}

	return false;
}

static int sukisu_kpm_build_trampoline(void *func, void *trampoline, unsigned int min_stolen_size,
				       unsigned int *stolen_size)
{
#ifdef CONFIG_KPROBES
	unsigned int copied = 0;

	if (min_stolen_size < JMP32_INSN_SIZE || min_stolen_size > SUKISU_KPM_X86_MAX_STOLEN_SIZE)
		return -EINVAL;

	while (copied < min_stolen_size) {
		struct insn insn;
		int len;

		memset(&insn, 0, sizeof(insn));
		len = __copy_instruction((u8 *)trampoline + copied, (u8 *)func + copied,
					 (u8 *)trampoline + copied, &insn);
		if (len <= 0 || len > MAX_INSN_SIZE)
			return -EINVAL;
		if (sukisu_kpm_insn_is_unsafe_to_copy(&insn))
			return -EINVAL;

		copied += len;
		if (copied > SUKISU_KPM_X86_MAX_STOLEN_SIZE)
			return -EOVERFLOW;
	}

	if (sukisu_kpm_rel32_fits((u8 *)trampoline + copied, (u8 *)func + copied, JMP32_INSN_SIZE))
		sukisu_kpm_make_rel32_jmp((u8 *)trampoline + copied, (u8 *)trampoline + copied,
					  (u8 *)func + copied);
	else
		sukisu_kpm_make_abs_jmp((u8 *)trampoline + copied, (u8 *)func + copied);
	*stolen_size = copied;
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

static bool sukisu_kpm_text_range_reserved(void *start, unsigned int len)
{
	void *end;

	if (!len)
		return true;

	end = start + len - 1;
	if (ftrace_location((unsigned long)start))
		return true;
#ifdef CONFIG_KPROBES
	if (get_kprobe((kprobe_opcode_t *)start))
		return true;
#endif
	if (ftrace_text_reserved(start, end))
		return true;
	if (alternatives_text_reserved(start, end))
		return true;
	if (jump_label_text_reserved(start, end))
		return true;
	if (static_call_text_reserved(start, end))
		return true;

	return false;
}

static struct sukisu_kpm_inline_hook *sukisu_kpm_find_inline_hook_locked(void *func)
{
	struct sukisu_kpm_inline_hook *pos;

	list_for_each_entry(pos, &sukisu_kpm_inline_hooks, list) {
		if (pos->func == func)
			return pos;
	}

	return NULL;
}

static int sukisu_kpm_install_inline_hook_locked(void *func, void *replace, void **backup)
{
	struct sukisu_kpm_inline_hook *hook;
	u8 patch[SUKISU_KPM_X86_MAX_STOLEN_SIZE];
	unsigned int min_stolen_size;
	bool use_rel32;
	int rc;

	if (backup)
		*backup = NULL;
	if (sukisu_kpm_bad_kernel_addr((unsigned long)func) ||
	    sukisu_kpm_bad_kernel_addr((unsigned long)replace))
		return SUKISU_KPM_HOOK_BAD_ADDRESS;
	if (sukisu_kpm_find_inline_hook_locked(func))
		return SUKISU_KPM_HOOK_DUPLICATED;

	use_rel32 = sukisu_kpm_rel32_fits(func, replace, JMP32_INSN_SIZE);
	min_stolen_size = use_rel32 ? JMP32_INSN_SIZE : SUKISU_KPM_X86_JMP_ABS_SIZE;

	hook = kzalloc(sizeof(*hook), GFP_KERNEL);
	if (!hook)
		return SUKISU_KPM_HOOK_NO_MEM;

	hook->trampoline = module_alloc(SUKISU_KPM_X86_MAX_STOLEN_SIZE + SUKISU_KPM_X86_JMP_ABS_SIZE);
	if (!hook->trampoline) {
		kfree(hook);
		return SUKISU_KPM_HOOK_TRANSIT_NO_MEM;
	}
	sukisu_kpm_set_exec_rw_nx(hook->trampoline,
				  SUKISU_KPM_X86_MAX_STOLEN_SIZE + SUKISU_KPM_X86_JMP_ABS_SIZE);
	memset(hook->trampoline, 0xcc, SUKISU_KPM_X86_MAX_STOLEN_SIZE + SUKISU_KPM_X86_JMP_ABS_SIZE);

	rc = sukisu_kpm_build_trampoline(func, hook->trampoline, min_stolen_size, &hook->stolen_size);
	if (rc)
		goto err_free;

	if (sukisu_kpm_text_range_reserved(func, hook->stolen_size)) {
		rc = -EBUSY;
		goto err_free;
	}

	rc = copy_from_kernel_nofault(hook->original, func, hook->stolen_size);
	if (rc)
		goto err_free;

	rc = sukisu_kpm_set_exec_rox(hook->trampoline,
				     SUKISU_KPM_X86_MAX_STOLEN_SIZE + SUKISU_KPM_X86_JMP_ABS_SIZE);
	if (rc)
		goto err_free;

	if (use_rel32) {
		hook->patch_size = JMP32_INSN_SIZE;
		hook->uses_text_poke_bp = true;
		rc = sukisu_kpm_patch_rel32_jmp_bp(func, replace);
	} else {
		hook->patch_size = hook->stolen_size;
		memset(patch, 0x90, sizeof(patch));
		sukisu_kpm_make_abs_jmp(patch, replace);
		rc = sukisu_kpm_patch_bytes(func, patch, hook->patch_size);
	}
	if (rc)
		goto err_free;

	hook->func = func;
	hook->replace = replace;
	list_add(&hook->list, &sukisu_kpm_inline_hooks);
	if (backup)
		*backup = hook->trampoline;
	return SUKISU_KPM_HOOK_NO_ERR;

err_free:
	sukisu_kpm_free_generated_exec(hook->trampoline,
				       SUKISU_KPM_X86_MAX_STOLEN_SIZE + SUKISU_KPM_X86_JMP_ABS_SIZE,
				       false);
	kfree(hook);
	return SUKISU_KPM_HOOK_BAD_RELO;
}

static int sukisu_kpm_unhook_locked(void *func)
{
	struct sukisu_kpm_inline_hook *hook;
	int rc;

	hook = sukisu_kpm_find_inline_hook_locked(func);
	if (!hook)
		return -ENOENT;

	if (hook->uses_text_poke_bp)
		rc = sukisu_kpm_restore_rel32_hook_bp(func, hook->original, hook->replace);
	else
		rc = sukisu_kpm_patch_bytes(func, hook->original, hook->patch_size);
	if (rc)
		return rc;

	list_del(&hook->list);
	sukisu_kpm_free_generated_exec(hook->trampoline,
				       SUKISU_KPM_X86_MAX_STOLEN_SIZE + SUKISU_KPM_X86_JMP_ABS_SIZE,
				       true);
	kfree(hook);
	return 0;
}

static int sukisu_kpm_hotpatch_nosync(void *addr, u32 value)
{
	if (sukisu_kpm_bad_kernel_addr((unsigned long)addr))
		return -EINVAL;
	return sukisu_kpm_patch_bytes(addr, &value, sizeof(value));
}

static int sukisu_kpm_hotpatch(void *addrs[], u32 values[], int cnt)
{
	int i;

	if (!addrs || !values || cnt < 0 || cnt > 1024)
		return -EINVAL;

	for (i = 0; i < cnt; i++) {
		int rc = sukisu_kpm_hotpatch_nosync(addrs[i], values[i]);

		if (rc)
			return rc;
	}

	return 0;
}

static int sukisu_kpm_patch_function_pointer(unsigned long fp_addr, void *replace, void **backup)
{
	void *origin;
	int rc;

	if (backup)
		*backup = NULL;
	if (sukisu_kpm_bad_kernel_addr(fp_addr) || sukisu_kpm_bad_kernel_addr((unsigned long)replace))
		return -EINVAL;

	rc = copy_from_kernel_nofault(&origin, (void *)fp_addr, sizeof(origin));
	if (rc)
		return rc;
	if (backup)
		*backup = origin;

	return sukisu_kpm_patch_bytes((void *)fp_addr, &replace, sizeof(replace));
}

static u64 sukisu_kpm_call_origin(void *origin, int argno, u64 *args)
{
	if (!origin)
		return 0;

	switch (argno) {
	case 0:
		return ((u64(*)(void))origin)();
	case 1:
		return ((u64(*)(u64))origin)(args[0]);
	case 2:
		return ((u64(*)(u64, u64))origin)(args[0], args[1]);
	case 3:
		return ((u64(*)(u64, u64, u64))origin)(args[0], args[1], args[2]);
	case 4:
		return ((u64(*)(u64, u64, u64, u64))origin)(args[0], args[1], args[2], args[3]);
	case 5:
		return ((u64(*)(u64, u64, u64, u64, u64))origin)(args[0], args[1], args[2], args[3], args[4]);
	case 6:
		return ((u64(*)(u64, u64, u64, u64, u64, u64))origin)(args[0], args[1], args[2],
								       args[3], args[4], args[5]);
	case 7:
		return ((u64(*)(u64, u64, u64, u64, u64, u64, u64))origin)(args[0], args[1],
									   args[2], args[3],
									   args[4], args[5],
									   args[6]);
	case 8:
		return ((u64(*)(u64, u64, u64, u64, u64, u64, u64, u64))origin)(
			args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
	case 9:
		return ((u64(*)(u64, u64, u64, u64, u64, u64, u64, u64, u64))origin)(
			args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8]);
	case 10:
		return ((u64(*)(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64))origin)(
			args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8],
			args[9]);
	case 11:
		return ((u64(*)(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64))origin)(
			args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8],
			args[9], args[10]);
	default:
		return ((u64(*)(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64))origin)(
			args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8],
			args[9], args[10], args[11]);
	}
}

static u64 sukisu_kpm_wrap_dispatch_common(void *chain, atomic_t *active, bool *disabled, int argno,
					   int max_items, s8 *states, void **befores, void **afters,
					   void **udata, void *origin,
					   struct sukisu_kpm_hook_fargs12 *fargs)
{
	int i;
	u64 ret;

	if (argno < 0)
		argno = 0;
	if (argno > SUKISU_KPM_WRAP_ARG_MAX)
		argno = SUKISU_KPM_WRAP_ARG_MAX;

	atomic_inc(active);
	fargs->chain = chain;
	fargs->skip_origin = 0;
	memset(&fargs->local, 0, sizeof(fargs->local));
	fargs->ret = 0;

	if (!READ_ONCE(*disabled)) {
		for (i = 0; i < max_items; i++) {
			sukisu_kpm_chain_callback_t before;

			if (READ_ONCE(states[i]) != SUKISU_KPM_CHAIN_ITEM_READY)
				continue;
			before = READ_ONCE(befores[i]);
			if (before)
				before(fargs, READ_ONCE(udata[i]));
		}
	}

	if (!fargs->skip_origin)
		fargs->ret = sukisu_kpm_call_origin(origin, argno, fargs->args);

	if (!READ_ONCE(*disabled)) {
		for (i = 0; i < max_items; i++) {
			sukisu_kpm_chain_callback_t after;

			if (READ_ONCE(states[i]) != SUKISU_KPM_CHAIN_ITEM_READY)
				continue;
			after = READ_ONCE(afters[i]);
			if (after)
				after(fargs, READ_ONCE(udata[i]));
		}
	}

	ret = fargs->ret;
	atomic_dec(active);
	return ret;
}

static u64 sukisu_kpm_wrap_dispatch(struct sukisu_kpm_wrap_chain *chain,
				    struct sukisu_kpm_hook_fargs12 *fargs)
{
	return sukisu_kpm_wrap_dispatch_common(chain, &chain->active, &chain->disabled, chain->argno,
					       SUKISU_KPM_HOOK_CHAIN_NUM, chain->states, chain->befores,
					       chain->afters, chain->udata, (void *)chain->hook.relo_addr,
					       fargs);
}

static u64 sukisu_kpm_fp_wrap_dispatch(struct sukisu_kpm_fp_wrap_chain *chain,
				       struct sukisu_kpm_hook_fargs12 *fargs)
{
	return sukisu_kpm_wrap_dispatch_common(chain, &chain->active, &chain->disabled, chain->argno,
					       SUKISU_KPM_FP_HOOK_CHAIN_NUM, chain->states,
					       chain->befores, chain->afters, chain->udata,
					       (void *)chain->hook.origin_fp, fargs);
}

static void sukisu_kpm_emit1(u8 **p, u8 value)
{
	*(*p)++ = value;
}

static void sukisu_kpm_emit4(u8 **p, u32 value)
{
	memcpy(*p, &value, sizeof(value));
	*p += sizeof(value);
}

static void sukisu_kpm_emit8(u8 **p, u64 value)
{
	memcpy(*p, &value, sizeof(value));
	*p += sizeof(value);
}

static void sukisu_kpm_emit_sub_rsp(u8 **p, u32 value)
{
	sukisu_kpm_emit1(p, 0x48);
	sukisu_kpm_emit1(p, 0x81);
	sukisu_kpm_emit1(p, 0xec);
	sukisu_kpm_emit4(p, value);
}

static void sukisu_kpm_emit_add_rsp(u8 **p, u32 value)
{
	sukisu_kpm_emit1(p, 0x48);
	sukisu_kpm_emit1(p, 0x81);
	sukisu_kpm_emit1(p, 0xc4);
	sukisu_kpm_emit4(p, value);
}

static void sukisu_kpm_emit_mov_mrsp_reg(u8 **p, u32 disp, u8 reg)
{
	sukisu_kpm_emit1(p, 0x48 | ((reg & 8) ? 0x04 : 0));
	sukisu_kpm_emit1(p, 0x89);
	sukisu_kpm_emit1(p, 0x84 | ((reg & 7) << 3));
	sukisu_kpm_emit1(p, 0x24);
	sukisu_kpm_emit4(p, disp);
}

static void sukisu_kpm_emit_mov_rax_mrsp(u8 **p, u32 disp)
{
	sukisu_kpm_emit1(p, 0x48);
	sukisu_kpm_emit1(p, 0x8b);
	sukisu_kpm_emit1(p, 0x84);
	sukisu_kpm_emit1(p, 0x24);
	sukisu_kpm_emit4(p, disp);
}

static void sukisu_kpm_emit_mov_mrsp_rax(u8 **p, u32 disp)
{
	sukisu_kpm_emit1(p, 0x48);
	sukisu_kpm_emit1(p, 0x89);
	sukisu_kpm_emit1(p, 0x84);
	sukisu_kpm_emit1(p, 0x24);
	sukisu_kpm_emit4(p, disp);
}

static void sukisu_kpm_emit_movabs_rax(u8 **p, u64 value)
{
	sukisu_kpm_emit1(p, 0x48);
	sukisu_kpm_emit1(p, 0xb8);
	sukisu_kpm_emit8(p, value);
}

static void sukisu_kpm_emit_movabs_rdi(u8 **p, u64 value)
{
	sukisu_kpm_emit1(p, 0x48);
	sukisu_kpm_emit1(p, 0xbf);
	sukisu_kpm_emit8(p, value);
}

static void *sukisu_kpm_make_wrap_stub(void *chain, int argno, void *dispatcher)
{
	static const u8 arg_regs[6] = { 7, 6, 2, 1, 8, 9 };
	u8 *stub;
	u8 *p;
	int i;
	int capture;
	int rc;

	if (argno < 0 || argno > SUKISU_KPM_WRAP_ARG_MAX)
		return NULL;

	stub = module_alloc(SUKISU_KPM_X86_WRAP_STUB_SIZE);
	if (!stub)
		return NULL;

	sukisu_kpm_set_exec_rw_nx(stub, SUKISU_KPM_X86_WRAP_STUB_SIZE);
	memset(stub, 0xcc, SUKISU_KPM_X86_WRAP_STUB_SIZE);
	p = stub;

	sukisu_kpm_emit_sub_rsp(&p, SUKISU_KPM_WRAP_FRAME_SIZE);

	capture = min(argno, 6);
	for (i = 0; i < capture; i++)
		sukisu_kpm_emit_mov_mrsp_reg(&p, SUKISU_KPM_WRAP_FRAME_ARGS + i * sizeof(u64),
					      arg_regs[i]);

	for (i = 6; i < argno; i++) {
		sukisu_kpm_emit_mov_rax_mrsp(&p, SUKISU_KPM_WRAP_FRAME_SIZE + sizeof(u64) +
							    (i - 6) * sizeof(u64));
		sukisu_kpm_emit_mov_mrsp_rax(&p, SUKISU_KPM_WRAP_FRAME_ARGS + i * sizeof(u64));
	}

	sukisu_kpm_emit_movabs_rdi(&p, (u64)chain);
	sukisu_kpm_emit1(&p, 0x48);
	sukisu_kpm_emit1(&p, 0x89);
	sukisu_kpm_emit1(&p, 0xe6);
	sukisu_kpm_emit_movabs_rax(&p, (u64)dispatcher);
	sukisu_kpm_emit1(&p, 0xff);
	sukisu_kpm_emit1(&p, 0xd0);

	sukisu_kpm_emit_mov_rax_mrsp(&p, SUKISU_KPM_WRAP_FRAME_RET);
	sukisu_kpm_emit_add_rsp(&p, SUKISU_KPM_WRAP_FRAME_SIZE);
	sukisu_kpm_emit1(&p, 0xc3);

	if (p - stub > SUKISU_KPM_X86_WRAP_STUB_SIZE) {
		module_memfree(stub);
		return NULL;
	}

	rc = sukisu_kpm_set_exec_rox(stub, SUKISU_KPM_X86_WRAP_STUB_SIZE);
	if (rc) {
		sukisu_kpm_set_exec_rw_nx(stub, SUKISU_KPM_X86_WRAP_STUB_SIZE);
		module_memfree(stub);
		return NULL;
	}
	return stub;
}

static int sukisu_kpm_add_chain_item(s8 *states, int max_items, void **befores, void **afters, void **udata,
				     void *before, void *after, void *data)
{
	int i;
	int empty = -1;

	if (!before && !after)
		return SUKISU_KPM_HOOK_BAD_ADDRESS;

	for (i = 0; i < max_items; i++) {
		if (READ_ONCE(states[i]) == SUKISU_KPM_CHAIN_ITEM_READY &&
		    READ_ONCE(befores[i]) == before && READ_ONCE(afters[i]) == after)
			return SUKISU_KPM_HOOK_DUPLICATED;
		if (empty < 0 && READ_ONCE(states[i]) == SUKISU_KPM_CHAIN_ITEM_EMPTY)
			empty = i;
	}

	if (empty < 0)
		return SUKISU_KPM_HOOK_CHAIN_FULL;

	WRITE_ONCE(befores[empty], before);
	WRITE_ONCE(afters[empty], after);
	WRITE_ONCE(udata[empty], data);
	smp_wmb();
	WRITE_ONCE(states[empty], SUKISU_KPM_CHAIN_ITEM_READY);
	return SUKISU_KPM_HOOK_NO_ERR;
}

static bool sukisu_kpm_remove_chain_item(s8 *states, int max_items, void **befores, void **afters, void **udata,
					 void *before, void *after)
{
	bool removed = false;
	int i;

	for (i = 0; i < max_items; i++) {
		if (READ_ONCE(states[i]) != SUKISU_KPM_CHAIN_ITEM_READY)
			continue;
		if (READ_ONCE(befores[i]) != before || READ_ONCE(afters[i]) != after)
			continue;

		WRITE_ONCE(states[i], SUKISU_KPM_CHAIN_ITEM_EMPTY);
		smp_wmb();
		WRITE_ONCE(befores[i], NULL);
		WRITE_ONCE(afters[i], NULL);
		WRITE_ONCE(udata[i], NULL);
		removed = true;
	}

	return removed;
}

static bool sukisu_kpm_has_chain_items(s8 *states, int max_items)
{
	int i;

	for (i = 0; i < max_items; i++) {
		if (READ_ONCE(states[i]) == SUKISU_KPM_CHAIN_ITEM_READY)
			return true;
	}

	return false;
}

static void sukisu_kpm_wait_chain_idle(atomic_t *active)
{
	while (atomic_read(active))
		cpu_relax();
}

static struct sukisu_kpm_wrap_chain *sukisu_kpm_find_wrap_chain_locked(void *func)
{
	struct sukisu_kpm_wrap_chain *pos;

	list_for_each_entry(pos, &sukisu_kpm_wrap_chains, list) {
		if ((void *)pos->hook.func_addr == func)
			return pos;
	}

	return NULL;
}

static struct sukisu_kpm_wrap_chain *sukisu_kpm_find_wrap_chain_by_chain_locked(void *chain)
{
	struct sukisu_kpm_wrap_chain *pos;

	list_for_each_entry(pos, &sukisu_kpm_wrap_chains, list) {
		if ((void *)pos == chain)
			return pos;
	}

	return NULL;
}

static struct sukisu_kpm_fp_wrap_chain *sukisu_kpm_find_fp_wrap_chain_locked(unsigned long fp_addr)
{
	struct sukisu_kpm_fp_wrap_chain *pos;

	list_for_each_entry(pos, &sukisu_kpm_fp_wrap_chains, list) {
		if (pos->hook.fp_addr == fp_addr)
			return pos;
	}

	return NULL;
}

static int sukisu_kpm_syscall_wrap(int nr, int narg, int is_compat, void *before, void *after, void *udata)
{
	(void)nr;
	(void)narg;
	if (is_compat)
		return -EOPNOTSUPP;
	(void)before;
	(void)after;
	(void)udata;
	return -EOPNOTSUPP;
}

static void sukisu_kpm_syscall_unwrap(int nr, int is_compat, void *before, void *after)
{
	(void)nr;
	(void)is_compat;
	(void)before;
	(void)after;
}

static unsigned long sukisu_kpm_syscalln_addr(int nr, int is_compat)
{
	unsigned long addr;
	unsigned long *table;

	if (is_compat || nr < 0 || nr >= __NR_syscalls)
		return 0;
	addr = sukisu_compact_find_symbol("sys_call_table");
	if (!addr)
		addr = kallsyms_lookup_name("sys_call_table");
	table = (unsigned long *)addr;
	if (!table)
		return 0;
	return READ_ONCE(table[nr]);
}

static unsigned long sukisu_kpm_syscalln_name_addr(int nr, int is_compat)
{
	return sukisu_kpm_syscalln_addr(nr, is_compat);
}

static int sukisu_kpm_hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
	return sukisu_kpm_syscall_wrap(nr, narg, 0, before, after, udata);
}

static void sukisu_kpm_unhook_syscalln(int nr, void *before, void *after)
{
	sukisu_kpm_syscall_unwrap(nr, 0, before, after);
}

static int sukisu_kpm_hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
	return sukisu_kpm_syscall_wrap(nr, narg, 1, before, after, udata);
}

static void sukisu_kpm_unhook_compat_syscalln(int nr, void *before, void *after)
{
	sukisu_kpm_syscall_unwrap(nr, 1, before, after);
}

static int sukisu_kpm_fp_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata)
{
	return sukisu_kpm_syscall_wrap(nr, narg, is_compat, before, after, udata);
}

static void sukisu_kpm_fp_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
	sukisu_kpm_syscall_unwrap(nr, is_compat, before, after);
}

static int sukisu_kpm_inline_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after,
					   void *udata)
{
	return sukisu_kpm_syscall_wrap(nr, narg, is_compat, before, after, udata);
}

static void sukisu_kpm_inline_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
	sukisu_kpm_syscall_unwrap(nr, is_compat, before, after);
}

static int sukisu_kpm_patch_verify_safety(void)
{
	return 0;
}

static int sukisu_kpm_hook_prepare(void *hook)
{
	struct sukisu_kpm_kp_hook *kp_hook = hook;

	if (!kp_hook || sukisu_kpm_bad_kernel_addr((unsigned long)kp_hook->func_addr) ||
	    sukisu_kpm_bad_kernel_addr((unsigned long)kp_hook->replace_addr))
		return SUKISU_KPM_HOOK_BAD_ADDRESS;

	kp_hook->origin_addr = kp_hook->func_addr;
	kp_hook->relo_addr = 0;
	kp_hook->tramp_insts_num = 0;
	kp_hook->relo_insts_num = 0;
	return SUKISU_KPM_HOOK_NO_ERR;
}

static void sukisu_kpm_hook_install(void *hook)
{
	struct sukisu_kpm_kp_hook *kp_hook = hook;
	void *backup = NULL;

	if (!kp_hook)
		return;

	mutex_lock(&sukisu_kpm_hook_lock);
	if (sukisu_kpm_install_inline_hook_locked((void *)kp_hook->func_addr, (void *)kp_hook->replace_addr,
						  &backup) == SUKISU_KPM_HOOK_NO_ERR)
		kp_hook->relo_addr = (u64)backup;
	mutex_unlock(&sukisu_kpm_hook_lock);
}

static void sukisu_kpm_hook_uninstall(void *hook)
{
	struct sukisu_kpm_kp_hook *kp_hook = hook;

	if (!kp_hook)
		return;

	mutex_lock(&sukisu_kpm_hook_lock);
	sukisu_kpm_unhook_locked((void *)kp_hook->func_addr);
	mutex_unlock(&sukisu_kpm_hook_lock);
}

static int sukisu_kpm_hook(void *func, void *replace, void **backup)
{
	int rc;

	mutex_lock(&sukisu_kpm_hook_lock);
	rc = sukisu_kpm_install_inline_hook_locked(func, replace, backup);
	mutex_unlock(&sukisu_kpm_hook_lock);
	return rc;
}

static void sukisu_kpm_unhook(void *func)
{
	int rc;

	mutex_lock(&sukisu_kpm_hook_lock);
	rc = sukisu_kpm_unhook_locked(func);
	mutex_unlock(&sukisu_kpm_hook_lock);

	if (rc)
		pr_warn("kpm: x86_64 unhook failed for %px: %d\n", func, rc);
}

static int sukisu_kpm_hook_chain_add(void *chain, void *before, void *after, void *udata)
{
	struct sukisu_kpm_wrap_chain *wrap;
	int rc;

	mutex_lock(&sukisu_kpm_hook_lock);
	wrap = sukisu_kpm_find_wrap_chain_by_chain_locked(chain);
	if (!wrap) {
		mutex_unlock(&sukisu_kpm_hook_lock);
		return SUKISU_KPM_HOOK_BAD_ADDRESS;
	}

	rc = sukisu_kpm_add_chain_item(wrap->states, SUKISU_KPM_HOOK_CHAIN_NUM, wrap->befores,
				       wrap->afters, wrap->udata, before, after, udata);
	mutex_unlock(&sukisu_kpm_hook_lock);
	return rc;
}

static void sukisu_kpm_hook_chain_remove(void *chain, void *before, void *after)
{
	struct sukisu_kpm_wrap_chain *wrap;
	bool removed;

	mutex_lock(&sukisu_kpm_hook_lock);
	wrap = sukisu_kpm_find_wrap_chain_by_chain_locked(chain);
	if (!wrap) {
		mutex_unlock(&sukisu_kpm_hook_lock);
		return;
	}

	removed = sukisu_kpm_remove_chain_item(wrap->states, SUKISU_KPM_HOOK_CHAIN_NUM, wrap->befores,
					       wrap->afters, wrap->udata, before, after);
	if (removed)
		sukisu_kpm_wait_chain_idle(&wrap->active);
	mutex_unlock(&sukisu_kpm_hook_lock);
}

static int sukisu_kpm_hook_wrap(void *func, int argno, void *before, void *after, void *udata)
{
	struct sukisu_kpm_wrap_chain *chain;
	bool created = false;
	void *backup = NULL;
	int rc;

	if (argno < 0 || argno > SUKISU_KPM_WRAP_ARG_MAX)
		return SUKISU_KPM_HOOK_BAD_ADDRESS;

	mutex_lock(&sukisu_kpm_hook_lock);
	chain = sukisu_kpm_find_wrap_chain_locked(func);
	if (chain) {
		if (chain->argno != argno) {
			mutex_unlock(&sukisu_kpm_hook_lock);
			return SUKISU_KPM_HOOK_BAD_ADDRESS;
		}
		goto add_item;
	}

	chain = kzalloc(sizeof(*chain), GFP_KERNEL);
	if (!chain) {
		mutex_unlock(&sukisu_kpm_hook_lock);
		return SUKISU_KPM_HOOK_NO_MEM;
	}

	chain->chain_items_max = SUKISU_KPM_HOOK_CHAIN_NUM;
	chain->argno = argno;
	atomic_set(&chain->active, 0);
	chain->stub = sukisu_kpm_make_wrap_stub(chain, argno, sukisu_kpm_wrap_dispatch);
	if (!chain->stub) {
		kfree(chain);
		mutex_unlock(&sukisu_kpm_hook_lock);
		return SUKISU_KPM_HOOK_TRANSIT_NO_MEM;
	}

	rc = sukisu_kpm_install_inline_hook_locked(func, chain->stub, &backup);
	if (rc) {
		sukisu_kpm_free_generated_exec(chain->stub, SUKISU_KPM_X86_WRAP_STUB_SIZE, false);
		kfree(chain);
		mutex_unlock(&sukisu_kpm_hook_lock);
		return rc;
	}

	chain->hook.func_addr = (u64)func;
	chain->hook.origin_addr = (u64)func;
	chain->hook.replace_addr = (u64)chain->stub;
	chain->hook.relo_addr = (u64)backup;
	list_add(&chain->list, &sukisu_kpm_wrap_chains);
	created = true;

add_item:
	rc = sukisu_kpm_add_chain_item(chain->states, SUKISU_KPM_HOOK_CHAIN_NUM, chain->befores,
				       chain->afters, chain->udata, before, after, udata);
	if (rc && created) {
		WRITE_ONCE(chain->disabled, true);
		sukisu_kpm_unhook_locked(func);
		list_del(&chain->list);
		sukisu_kpm_wait_chain_idle(&chain->active);
		sukisu_kpm_free_generated_exec(chain->stub, SUKISU_KPM_X86_WRAP_STUB_SIZE, false);
		kfree(chain);
	}
	mutex_unlock(&sukisu_kpm_hook_lock);
	return rc;
}

static void sukisu_kpm_hook_unwrap_remove(void *func, void *before, void *after, int remove)
{
	struct sukisu_kpm_wrap_chain *chain;
	bool removed;

	mutex_lock(&sukisu_kpm_hook_lock);
	chain = sukisu_kpm_find_wrap_chain_locked(func);
	if (!chain) {
		mutex_unlock(&sukisu_kpm_hook_lock);
		return;
	}

	removed = sukisu_kpm_remove_chain_item(chain->states, SUKISU_KPM_HOOK_CHAIN_NUM, chain->befores,
					       chain->afters, chain->udata, before, after);
	if (!removed) {
		mutex_unlock(&sukisu_kpm_hook_lock);
		return;
	}

	if (!remove || sukisu_kpm_has_chain_items(chain->states, SUKISU_KPM_HOOK_CHAIN_NUM)) {
		sukisu_kpm_wait_chain_idle(&chain->active);
		mutex_unlock(&sukisu_kpm_hook_lock);
		return;
	}

	WRITE_ONCE(chain->disabled, true);
	if (!sukisu_kpm_unhook_locked(func)) {
		list_del(&chain->list);
		sukisu_kpm_wait_chain_idle(&chain->active);
		sukisu_kpm_free_generated_exec(chain->stub, SUKISU_KPM_X86_WRAP_STUB_SIZE, false);
		kfree(chain);
	}
	mutex_unlock(&sukisu_kpm_hook_lock);
}

static void sukisu_kpm_fp_hook(unsigned long fp_addr, void *replace, void **backup)
{
	int rc = sukisu_kpm_patch_function_pointer(fp_addr, replace, backup);

	if (rc)
		pr_warn("kpm: x86_64 fp_hook failed for %px: %d\n", (void *)fp_addr, rc);
}

static void sukisu_kpm_fp_unhook(unsigned long fp_addr, void *backup)
{
	int rc;

	if (!backup || sukisu_kpm_bad_kernel_addr(fp_addr))
		return;

	rc = sukisu_kpm_patch_bytes((void *)fp_addr, &backup, sizeof(backup));
	if (rc)
		pr_warn("kpm: x86_64 fp_unhook failed for %px: %d\n", (void *)fp_addr, rc);
}

static int sukisu_kpm_fp_hook_wrap(unsigned long fp_addr, int argno, void *before, void *after, void *udata)
{
	struct sukisu_kpm_fp_wrap_chain *chain;
	bool created = false;
	void *backup = NULL;
	int rc;

	if (argno < 0 || argno > SUKISU_KPM_WRAP_ARG_MAX)
		return SUKISU_KPM_HOOK_BAD_ADDRESS;

	mutex_lock(&sukisu_kpm_hook_lock);
	chain = sukisu_kpm_find_fp_wrap_chain_locked(fp_addr);
	if (chain) {
		if (chain->argno != argno) {
			mutex_unlock(&sukisu_kpm_hook_lock);
			return SUKISU_KPM_HOOK_BAD_ADDRESS;
		}
		goto add_item;
	}

	chain = kzalloc(sizeof(*chain), GFP_KERNEL);
	if (!chain) {
		mutex_unlock(&sukisu_kpm_hook_lock);
		return SUKISU_KPM_HOOK_NO_MEM;
	}

	chain->chain_items_max = SUKISU_KPM_FP_HOOK_CHAIN_NUM;
	chain->argno = argno;
	atomic_set(&chain->active, 0);
	chain->stub = sukisu_kpm_make_wrap_stub(chain, argno, sukisu_kpm_fp_wrap_dispatch);
	if (!chain->stub) {
		kfree(chain);
		mutex_unlock(&sukisu_kpm_hook_lock);
		return SUKISU_KPM_HOOK_TRANSIT_NO_MEM;
	}

	rc = sukisu_kpm_patch_function_pointer(fp_addr, chain->stub, &backup);
	if (rc) {
		sukisu_kpm_free_generated_exec(chain->stub, SUKISU_KPM_X86_WRAP_STUB_SIZE, false);
		kfree(chain);
		mutex_unlock(&sukisu_kpm_hook_lock);
		return SUKISU_KPM_HOOK_BAD_ADDRESS;
	}

	chain->hook.fp_addr = fp_addr;
	chain->hook.replace_addr = (u64)chain->stub;
	chain->hook.origin_fp = (u64)backup;
	list_add(&chain->list, &sukisu_kpm_fp_wrap_chains);
	created = true;

add_item:
	rc = sukisu_kpm_add_chain_item(chain->states, SUKISU_KPM_FP_HOOK_CHAIN_NUM, chain->befores,
				       chain->afters, chain->udata, before, after, udata);
	if (rc && created) {
		WRITE_ONCE(chain->disabled, true);
		sukisu_kpm_patch_bytes((void *)fp_addr, &backup, sizeof(backup));
		list_del(&chain->list);
		sukisu_kpm_sync_before_exec_free();
		sukisu_kpm_wait_chain_idle(&chain->active);
		sukisu_kpm_free_generated_exec(chain->stub, SUKISU_KPM_X86_WRAP_STUB_SIZE, false);
		kfree(chain);
	}
	mutex_unlock(&sukisu_kpm_hook_lock);
	return rc;
}

static void sukisu_kpm_fp_hook_unwrap(unsigned long fp_addr, void *before, void *after)
{
	struct sukisu_kpm_fp_wrap_chain *chain;
	void *backup;
	bool removed;

	mutex_lock(&sukisu_kpm_hook_lock);
	chain = sukisu_kpm_find_fp_wrap_chain_locked(fp_addr);
	if (!chain) {
		mutex_unlock(&sukisu_kpm_hook_lock);
		return;
	}

	removed = sukisu_kpm_remove_chain_item(chain->states, SUKISU_KPM_FP_HOOK_CHAIN_NUM, chain->befores,
					       chain->afters, chain->udata, before, after);
	if (!removed) {
		mutex_unlock(&sukisu_kpm_hook_lock);
		return;
	}

	if (sukisu_kpm_has_chain_items(chain->states, SUKISU_KPM_FP_HOOK_CHAIN_NUM)) {
		sukisu_kpm_wait_chain_idle(&chain->active);
		mutex_unlock(&sukisu_kpm_hook_lock);
		return;
	}

	WRITE_ONCE(chain->disabled, true);
	backup = (void *)chain->hook.origin_fp;
	if (!sukisu_kpm_patch_bytes((void *)fp_addr, &backup, sizeof(backup))) {
		list_del(&chain->list);
		sukisu_kpm_sync_before_exec_free();
		sukisu_kpm_wait_chain_idle(&chain->active);
		sukisu_kpm_free_generated_exec(chain->stub, SUKISU_KPM_X86_WRAP_STUB_SIZE, false);
		kfree(chain);
	}
	mutex_unlock(&sukisu_kpm_hook_lock);
}

static int sukisu_kpm_branch_unsupported(void)
{
	pr_warn_once("kpm: x86_64 ARM64 branch helper requested\n");
	return -EOPNOTSUPP;
}

unsigned long sukisu_kpm_symbol_lookup_name(const char *name);

static const struct sukisu_kpm_symbol_alias sukisu_kpm_symbol_aliases[] = {
	{ "kver", (unsigned long)&sukisu_kpm_kver },
	{ "kpver", (unsigned long)&sukisu_kpm_kpver },
	{ "endian", (unsigned long)&sukisu_kpm_endian },
	{ "page_size", (unsigned long)&sukisu_kpm_page_size },
	{ "page_shift", (unsigned long)&sukisu_kpm_page_shift },
	{ "has_syscall_wrapper", (unsigned long)&sukisu_kpm_has_syscall_wrapper },
	{ "has_config_compat", (unsigned long)&sukisu_kpm_has_config_compat },
	{ "symbol_lookup_name", (unsigned long)&sukisu_kpm_symbol_lookup_name },
	{ "kallsyms_lookup_name", (unsigned long)&sukisu_kpm_symbol_lookup_name },
	{ "compact_find_symbol", (unsigned long)&sukisu_compact_find_symbol },
	{ "sukisu_compact_find_symbol", (unsigned long)&sukisu_compact_find_symbol },
	{ "syscalln_addr", (unsigned long)&sukisu_kpm_syscalln_addr },
	{ "syscalln_name_addr", (unsigned long)&sukisu_kpm_syscalln_name_addr },
	{ "hook_syscalln", (unsigned long)&sukisu_kpm_hook_syscalln },
	{ "unhook_syscalln", (unsigned long)&sukisu_kpm_unhook_syscalln },
	{ "hook_compat_syscalln", (unsigned long)&sukisu_kpm_hook_compat_syscalln },
	{ "unhook_compat_syscalln", (unsigned long)&sukisu_kpm_unhook_compat_syscalln },
	{ "fp_wrap_syscalln", (unsigned long)&sukisu_kpm_fp_wrap_syscalln },
	{ "fp_unwrap_syscalln", (unsigned long)&sukisu_kpm_fp_unwrap_syscalln },
	{ "fp_hook_syscalln", (unsigned long)&sukisu_kpm_hook_syscalln },
	{ "fp_unhook_syscalln", (unsigned long)&sukisu_kpm_unhook_syscalln },
	{ "fp_hook_compat_syscalln", (unsigned long)&sukisu_kpm_hook_compat_syscalln },
	{ "fp_unhook_compat_syscalln", (unsigned long)&sukisu_kpm_unhook_compat_syscalln },
	{ "inline_wrap_syscalln", (unsigned long)&sukisu_kpm_inline_wrap_syscalln },
	{ "inline_unwrap_syscalln", (unsigned long)&sukisu_kpm_inline_unwrap_syscalln },
	{ "inline_hook_syscalln", (unsigned long)&sukisu_kpm_hook_syscalln },
	{ "inline_unhook_syscalln", (unsigned long)&sukisu_kpm_unhook_syscalln },
	{ "inline_hook_compat_syscalln", (unsigned long)&sukisu_kpm_hook_compat_syscalln },
	{ "inline_unhook_compat_syscalln", (unsigned long)&sukisu_kpm_unhook_compat_syscalln },
	{ "kp_malloc", (unsigned long)&sukisu_kpm_malloc },
	{ "kp_free", (unsigned long)&sukisu_kpm_free },
	{ "kp_malloc_exec", (unsigned long)&sukisu_kpm_malloc_exec },
	{ "kp_free_exec", (unsigned long)&sukisu_kpm_free_exec },
	{ "compat_copy_to_user", (unsigned long)&sukisu_kpm_compat_copy_to_user },
	{ "compat_strncpy_from_user", (unsigned long)&sukisu_kpm_compat_strncpy_from_user },
	{ "current_uid", (unsigned long)&sukisu_kpm_current_uid },
	{ "patch_verify_safety", (unsigned long)&sukisu_kpm_patch_verify_safety },
	{ "hotpatch", (unsigned long)&sukisu_kpm_hotpatch },
	{ "hotpatch_nosync", (unsigned long)&sukisu_kpm_hotpatch_nosync },
	{ "hook_prepare", (unsigned long)&sukisu_kpm_hook_prepare },
	{ "hook_install", (unsigned long)&sukisu_kpm_hook_install },
	{ "hook_uninstall", (unsigned long)&sukisu_kpm_hook_uninstall },
	{ "hook", (unsigned long)&sukisu_kpm_hook },
	{ "unhook", (unsigned long)&sukisu_kpm_unhook },
	{ "hook_chain_add", (unsigned long)&sukisu_kpm_hook_chain_add },
	{ "hook_chain_remove", (unsigned long)&sukisu_kpm_hook_chain_remove },
	{ "hook_wrap", (unsigned long)&sukisu_kpm_hook_wrap },
	{ "hook_unwrap_remove", (unsigned long)&sukisu_kpm_hook_unwrap_remove },
	{ "fp_hook", (unsigned long)&sukisu_kpm_fp_hook },
	{ "fp_unhook", (unsigned long)&sukisu_kpm_fp_unhook },
	{ "fp_hook_wrap", (unsigned long)&sukisu_kpm_fp_hook_wrap },
	{ "fp_hook_unwrap", (unsigned long)&sukisu_kpm_fp_hook_unwrap },
	{ "branch_from_to", (unsigned long)&sukisu_kpm_branch_unsupported },
	{ "branch_relative", (unsigned long)&sukisu_kpm_branch_unsupported },
	{ "branch_absolute", (unsigned long)&sukisu_kpm_branch_unsupported },
	{ "ret_absolute", (unsigned long)&sukisu_kpm_branch_unsupported },
};

unsigned long sukisu_kpm_symbol_lookup_name(const char *name)
{
	size_t i;
	unsigned long addr;

	if (!name || !*name)
		return 0;

	for (i = 0; i < ARRAY_SIZE(sukisu_kpm_symbol_aliases); i++) {
		if (!strcmp(name, sukisu_kpm_symbol_aliases[i].name))
			return sukisu_kpm_symbol_aliases[i].addr;
	}

	addr = sukisu_compact_find_symbol(name);
	if (addr)
		return addr;

	return kallsyms_lookup_name(name);
}

static char *sukisu_kpm_next_string(char *string, unsigned long *secsize)
{
	while (*secsize > 0 && string[0]) {
		string++;
		(*secsize)--;
	}

	while (*secsize > 0 && !string[0]) {
		string++;
		(*secsize)--;
	}

	return *secsize ? string : NULL;
}

static char *sukisu_kpm_get_next_modinfo(const struct sukisu_kpm_load_info *info, const char *tag, char *prev)
{
	char *p;
	char *modinfo;
	unsigned long size;
	unsigned int taglen;
	Elf_Shdr *infosec;

	if (!info->index.info)
		return NULL;

	taglen = strlen(tag);
	infosec = &info->sechdrs[info->index.info];
	size = infosec->sh_size;
	modinfo = (char *)info->hdr + infosec->sh_offset;

	if (prev) {
		if (prev < modinfo || prev >= modinfo + size)
			return NULL;
		size -= prev - modinfo;
		modinfo = sukisu_kpm_next_string(prev, &size);
	}

	for (p = modinfo; p && size > 0; p = sukisu_kpm_next_string(p, &size)) {
		size_t len = strnlen(p, size);

		if (len == size)
			return NULL;
		if (len > taglen && !memcmp(p, tag, taglen) && p[taglen] == '=')
			return p + taglen + 1;
	}

	return NULL;
}

static char *sukisu_kpm_get_modinfo(const struct sukisu_kpm_load_info *info, const char *tag)
{
	return sukisu_kpm_get_next_modinfo(info, tag, NULL);
}

static int sukisu_kpm_find_sec(const struct sukisu_kpm_load_info *info, const char *name)
{
	int i;

	for (i = 1; i < info->hdr->e_shnum; i++) {
		Elf_Shdr *shdr = &info->sechdrs[i];

		if ((shdr->sh_flags & SHF_ALLOC) && !strcmp(info->secstrings + shdr->sh_name, name))
			return i;
	}

	return 0;
}

static long sukisu_kpm_get_offset(unsigned int *size, const Elf_Shdr *sechdr)
{
	unsigned int align;
	long ret;

	align = sechdr->sh_addralign ? sechdr->sh_addralign : 1;
	ret = ALIGN(*size, align);
	*size = ret + sechdr->sh_size;
	return ret;
}

static bool sukisu_kpm_reloc_uses_got(unsigned int type)
{
	return type == R_X86_64_GOTPCREL ||
	       type == R_X86_64_GOTPCRELX ||
	       type == R_X86_64_REX_GOTPCRELX;
}

static int sukisu_kpm_count_got_relocations(struct sukisu_kpm_load_info *info)
{
	unsigned int count = 0;
	int i;

	for (i = 1; i < info->hdr->e_shnum; i++) {
		Elf_Rela *rel;
		unsigned int target = info->sechdrs[i].sh_info;
		unsigned int nrels;
		unsigned int j;

		if (info->sechdrs[i].sh_type != SHT_RELA)
			continue;
		if (target >= info->hdr->e_shnum)
			continue;
		if (!(info->sechdrs[target].sh_flags & SHF_ALLOC))
			continue;
		if (info->sechdrs[i].sh_size % sizeof(*rel))
			return -ENOEXEC;

		rel = (void *)info->sechdrs[i].sh_addr;
		nrels = info->sechdrs[i].sh_size / sizeof(*rel);
		for (j = 0; j < nrels; j++) {
			if (sukisu_kpm_reloc_uses_got(ELF64_R_TYPE(rel[j].r_info)))
				count++;
		}
	}

	info->got_entries = count;
	return 0;
}

static void sukisu_kpm_layout_sections(struct sukisu_kpm_module *mod, struct sukisu_kpm_load_info *info)
{
	static const unsigned long masks[][2] = {
		{ SHF_EXECINSTR | SHF_ALLOC, 0 },
		{ SHF_ALLOC, SHF_WRITE },
		{ SHF_WRITE | SHF_ALLOC, 0 },
	};
	int i;
	int m;

	for (i = 0; i < info->hdr->e_shnum; i++)
		info->sechdrs[i].sh_entsize = ~0UL;

	for (m = 0; m < ARRAY_SIZE(masks); m++) {
		for (i = 0; i < info->hdr->e_shnum; i++) {
			Elf_Shdr *s = &info->sechdrs[i];

			if ((s->sh_flags & masks[m][0]) != masks[m][0] || (s->sh_flags & masks[m][1]) ||
			    s->sh_entsize != ~0UL)
				continue;

			s->sh_entsize = sukisu_kpm_get_offset(&mod->size, s);
		}

		if (m == 0) {
			mod->size = ALIGN(mod->size, PAGE_SIZE);
			mod->text_size = mod->size;
		} else if (m == 1) {
			mod->size = ALIGN(mod->size, PAGE_SIZE);
			mod->ro_size = mod->size;
		} else {
			mod->size = ALIGN(mod->size, PAGE_SIZE);
		}
	}

	if (info->got_entries) {
		mod->size = ALIGN(mod->size, sizeof(u64));
		info->got_offset = mod->size;
		mod->size += info->got_entries * sizeof(u64);
		mod->size = ALIGN(mod->size, PAGE_SIZE);
	}
}

static int sukisu_kpm_rewrite_section_headers(struct sukisu_kpm_load_info *info)
{
	int i;

	info->sechdrs[0].sh_addr = 0;
	for (i = 1; i < info->hdr->e_shnum; i++) {
		Elf_Shdr *shdr = &info->sechdrs[i];

		if (shdr->sh_name >= info->sechdrs[info->hdr->e_shstrndx].sh_size)
			return -ENOEXEC;

		if (shdr->sh_type != SHT_NOBITS) {
			if (shdr->sh_offset > info->len || shdr->sh_size > info->len - shdr->sh_offset)
				return -ENOEXEC;
			shdr->sh_addr = (unsigned long)info->hdr + shdr->sh_offset;
		}
	}

	return 0;
}

static int sukisu_kpm_setup_load_info(struct sukisu_kpm_load_info *info)
{
	int i;
	int rc;
	Elf_Shdr *info_sec;

	info->sechdrs = (void *)info->hdr + info->hdr->e_shoff;
	info->secstrings = (void *)info->hdr + info->sechdrs[info->hdr->e_shstrndx].sh_offset;

	rc = sukisu_kpm_rewrite_section_headers(info);
	if (rc)
		return rc;

	if (!sukisu_kpm_find_sec(info, ".kpm.init") || !sukisu_kpm_find_sec(info, ".kpm.exit")) {
		pr_err("kpm: no .kpm.init or .kpm.exit section\n");
		return -ENOEXEC;
	}

	info->index.info = sukisu_kpm_find_sec(info, ".kpm.info");
	if (!info->index.info) {
		pr_err("kpm: no .kpm.info section\n");
		return -ENOEXEC;
	}

	info_sec = &info->sechdrs[info->index.info];
	if (!info_sec->sh_size || ((char *)info->hdr + info_sec->sh_offset)[info_sec->sh_size - 1]) {
		pr_err("kpm: .kpm.info is not NUL-terminated\n");
		return -ENOEXEC;
	}

	info->info.base = (char *)info->hdr + info_sec->sh_offset;
	info->info.size = info_sec->sh_size;
	info->info.name = sukisu_kpm_get_modinfo(info, "name");
	info->info.version = sukisu_kpm_get_modinfo(info, "version");
	info->info.license = sukisu_kpm_get_modinfo(info, "license");
	info->info.author = sukisu_kpm_get_modinfo(info, "author");
	info->info.description = sukisu_kpm_get_modinfo(info, "description");

	if (!info->info.name || !info->info.version) {
		pr_err("kpm: module name/version not found\n");
		return -ENOEXEC;
	}

	for (i = 1; i < info->hdr->e_shnum; i++) {
		if (info->sechdrs[i].sh_type == SHT_SYMTAB) {
			info->index.sym = i;
			info->index.str = info->sechdrs[i].sh_link;
			break;
		}
	}

	if (!info->index.sym || !info->index.str || info->index.str >= info->hdr->e_shnum) {
		pr_err("kpm: module has no usable symbol table\n");
		return -ENOEXEC;
	}
	if (info->sechdrs[info->index.sym].sh_size % sizeof(Elf_Sym)) {
		pr_err("kpm: malformed symbol table size\n");
		return -ENOEXEC;
	}
	if (info->sechdrs[info->index.str].sh_type != SHT_STRTAB ||
	    !info->sechdrs[info->index.str].sh_size) {
		pr_err("kpm: module has no usable string table\n");
		return -ENOEXEC;
	}

	info->strtab = (char *)info->hdr + info->sechdrs[info->index.str].sh_offset;
	return 0;
}

static int sukisu_kpm_elf_header_check(struct sukisu_kpm_load_info *info)
{
	const Elf_Ehdr *hdr = info->hdr;
	unsigned long shdr_size;

	if (info->len <= sizeof(*hdr))
		return -ENOEXEC;
	if (memcmp(hdr->e_ident, ELFMAG, SELFMAG))
		return -ENOEXEC;
	if (hdr->e_ident[EI_CLASS] != ELFCLASS64 || hdr->e_ident[EI_DATA] != ELFDATA2LSB)
		return -ENOEXEC;
	if (hdr->e_type != ET_REL || hdr->e_machine != EM_X86_64)
		return -ENOEXEC;
	if (hdr->e_shentsize != sizeof(Elf_Shdr) || !hdr->e_shnum)
		return -ENOEXEC;
	if (hdr->e_shstrndx == SHN_UNDEF || hdr->e_shstrndx >= hdr->e_shnum)
		return -ENOEXEC;

	shdr_size = hdr->e_shnum * sizeof(Elf_Shdr);
	if (hdr->e_shoff > info->len || shdr_size > info->len - hdr->e_shoff)
		return -ENOEXEC;

	return 0;
}

static int sukisu_kpm_move_module(struct sukisu_kpm_module *mod, struct sukisu_kpm_load_info *info)
{
	int i;

	mod->start = module_alloc(mod->size);
	if (!mod->start)
		return -ENOMEM;

	sukisu_kpm_set_exec_rw_nx(mod->start, mod->size);
	memset(mod->start, 0, mod->size);

	for (i = 1; i < info->hdr->e_shnum; i++) {
		const char *sname;
		void *dest;
		Elf_Shdr *shdr = &info->sechdrs[i];

		if (!(shdr->sh_flags & SHF_ALLOC))
			continue;

		dest = mod->start + shdr->sh_entsize;
		sname = info->secstrings + shdr->sh_name;

		if (shdr->sh_type != SHT_NOBITS)
			memcpy(dest, (void *)shdr->sh_addr, shdr->sh_size);

		shdr->sh_addr = (unsigned long)dest;

		if (!mod->init && !strcmp(".kpm.init", sname)) {
			if (shdr->sh_size != sizeof(*mod->init))
				return -ENOEXEC;
			mod->init = (sukisu_kpm_initcall_t *)dest;
		}
		if (!mod->ctl0 && !strcmp(".kpm.ctl0", sname)) {
			if (shdr->sh_size != sizeof(*mod->ctl0))
				return -ENOEXEC;
			mod->ctl0 = (sukisu_kpm_ctl0call_t *)dest;
		}
		if (!mod->ctl1 && !strcmp(".kpm.ctl1", sname)) {
			if (shdr->sh_size != sizeof(*mod->ctl1))
				return -ENOEXEC;
			mod->ctl1 = (sukisu_kpm_ctl1call_t *)dest;
		}
		if (!mod->exit && !strcmp(".kpm.exit", sname)) {
			if (shdr->sh_size != sizeof(*mod->exit))
				return -ENOEXEC;
			mod->exit = (sukisu_kpm_exitcall_t *)dest;
		}
		if (!mod->info.base && !strcmp(".kpm.info", sname))
			mod->info.base = (const char *)dest;
	}

	if (!mod->init || !mod->exit || !mod->info.base)
		return -ENOEXEC;

	mod->info.name = info->info.name - info->info.base + mod->info.base;
	mod->info.version = info->info.version - info->info.base + mod->info.base;
	if (info->info.license)
		mod->info.license = info->info.license - info->info.base + mod->info.base;
	if (info->info.author)
		mod->info.author = info->info.author - info->info.base + mod->info.base;
	if (info->info.description)
		mod->info.description = info->info.description - info->info.base + mod->info.base;

	return 0;
}

static int sukisu_kpm_simplify_symbols(struct sukisu_kpm_module *mod, struct sukisu_kpm_load_info *info)
{
	Elf_Shdr *symsec = &info->sechdrs[info->index.sym];
	Elf_Sym *sym = (void *)symsec->sh_addr;
	unsigned int i;
	unsigned int nsyms;
	int ret = 0;

	nsyms = symsec->sh_size / sizeof(Elf_Sym);
	for (i = 1; i < nsyms; i++) {
		const char *name;
		unsigned long secbase;
		unsigned long addr;

		if (sym[i].st_name >= info->sechdrs[info->index.str].sh_size)
			return -ENOEXEC;
		name = info->strtab + sym[i].st_name;

		switch (sym[i].st_shndx) {
		case SHN_COMMON:
			pr_err("kpm: common symbol %s; build with -fno-common\n", name);
			ret = -ENOEXEC;
			break;
		case SHN_ABS:
			break;
		case SHN_UNDEF:
			addr = sukisu_kpm_symbol_lookup_name(name);
			if (!addr) {
				pr_err("kpm: unknown symbol %s in %s\n", name, mod->info.name);
				ret = -ENOENT;
				break;
			}
			sym[i].st_value = addr;
			break;
		default:
			if (sym[i].st_shndx >= info->hdr->e_shnum)
				return -ENOEXEC;
			secbase = info->sechdrs[sym[i].st_shndx].sh_addr;
			sym[i].st_value += secbase;
			break;
		}
	}

	return ret;
}

static int sukisu_kpm_check_reloc_range(const Elf_Shdr *target, const Elf_Rela *rel, size_t width)
{
	if (rel->r_offset > target->sh_size || width > target->sh_size - rel->r_offset)
		return -ENOEXEC;
	return 0;
}

static bool sukisu_kpm_addr_in_text(const struct sukisu_kpm_module *mod, unsigned long addr)
{
	return addr >= (unsigned long)mod->start &&
	       addr < (unsigned long)mod->start + mod->text_size;
}

static int sukisu_kpm_validate_entrypoints(const struct sukisu_kpm_module *mod)
{
	if (!mod->init || !*mod->init || !sukisu_kpm_addr_in_text(mod, (unsigned long)*mod->init))
		return -ENOEXEC;
	if (!mod->exit || !*mod->exit || !sukisu_kpm_addr_in_text(mod, (unsigned long)*mod->exit))
		return -ENOEXEC;
	if (mod->ctl0 && *mod->ctl0 && !sukisu_kpm_addr_in_text(mod, (unsigned long)*mod->ctl0))
		return -ENOEXEC;
	if (mod->ctl1 && *mod->ctl1 && !sukisu_kpm_addr_in_text(mod, (unsigned long)*mod->ctl1))
		return -ENOEXEC;
	return 0;
}

static int sukisu_kpm_apply_relocate_add(struct sukisu_kpm_module *mod, struct sukisu_kpm_load_info *info,
					 unsigned int relsec)
{
	Elf_Rela *rel = (void *)info->sechdrs[relsec].sh_addr;
	Elf_Shdr *target = &info->sechdrs[info->sechdrs[relsec].sh_info];
	Elf_Shdr *symsec = &info->sechdrs[info->index.sym];
	Elf_Sym *symtab = (void *)symsec->sh_addr;
	unsigned int nrels;
	unsigned int nsyms;
	unsigned int i;

	nrels = info->sechdrs[relsec].sh_size / sizeof(Elf_Rela);
	nsyms = symsec->sh_size / sizeof(Elf_Sym);

	if (info->sechdrs[relsec].sh_size % sizeof(Elf_Rela))
		return -ENOEXEC;

	for (i = 0; i < nrels; i++) {
		unsigned int type = ELF64_R_TYPE(rel[i].r_info);
		unsigned int sym_index = ELF64_R_SYM(rel[i].r_info);
		void *loc;
		void *got;
		s64 sval;
		u64 symval;
		u64 val;

		if (sym_index >= nsyms)
			return -ENOEXEC;

		loc = (void *)target->sh_addr + rel[i].r_offset;
		symval = symtab[sym_index].st_value;
		val = symval + rel[i].r_addend;

		switch (type) {
		case R_X86_64_NONE:
			break;
		case R_X86_64_64:
			if (sukisu_kpm_check_reloc_range(target, &rel[i], sizeof(u64)))
				return -ENOEXEC;
			*(u64 *)loc = val;
			break;
		case R_X86_64_32:
			if (sukisu_kpm_check_reloc_range(target, &rel[i], sizeof(u32)))
				return -ENOEXEC;
			if (val != (u32)val)
				return -ERANGE;
			*(u32 *)loc = val;
			break;
		case R_X86_64_32S:
			if (sukisu_kpm_check_reloc_range(target, &rel[i], sizeof(s32)))
				return -ENOEXEC;
			if ((s64)val != (s32)val)
				return -ERANGE;
			*(s32 *)loc = val;
			break;
		case R_X86_64_PC32:
		case R_X86_64_PLT32:
			if (sukisu_kpm_check_reloc_range(target, &rel[i], sizeof(s32)))
				return -ENOEXEC;
			sval = (s64)val - (s64)(unsigned long)loc;
			if (sval != (s32)sval) {
				pr_err("kpm: PC-relative relocation overflow for %s; use -mcmodel=kernel -fno-pic\n",
				       mod->info.name);
				return -ERANGE;
			}
			*(s32 *)loc = (s32)sval;
			break;
		case R_X86_64_PC64:
			if (sukisu_kpm_check_reloc_range(target, &rel[i], sizeof(s64)))
				return -ENOEXEC;
			*(s64 *)loc = (s64)val - (s64)(unsigned long)loc;
			break;
		case R_X86_64_GOTPCREL:
		case R_X86_64_GOTPCRELX:
		case R_X86_64_REX_GOTPCRELX:
			if (sukisu_kpm_check_reloc_range(target, &rel[i], sizeof(s32)))
				return -ENOEXEC;
			if (!info->got_entries || info->got_next >= info->got_entries)
				return -ENOEXEC;
			got = mod->start + info->got_offset + info->got_next * sizeof(u64);
			info->got_next++;
			*(u64 *)got = symval;
			sval = (s64)((unsigned long)got + rel[i].r_addend) - (s64)(unsigned long)loc;
			if (sval != (s32)sval) {
				pr_err("kpm: GOTPCREL relocation overflow for %s\n", mod->info.name);
				return -ERANGE;
			}
			*(s32 *)loc = (s32)sval;
			break;
		default:
			pr_err("kpm: unsupported x86_64 RELA relocation %u in %s\n", type, mod->info.name);
			return -ENOEXEC;
		}
	}

	return 0;
}

static int sukisu_kpm_apply_relocations(struct sukisu_kpm_module *mod, struct sukisu_kpm_load_info *info)
{
	int i;

	for (i = 1; i < info->hdr->e_shnum; i++) {
		unsigned int target = info->sechdrs[i].sh_info;
		int rc;

		if (target >= info->hdr->e_shnum)
			continue;
		if (!(info->sechdrs[target].sh_flags & SHF_ALLOC))
			continue;

		if (info->sechdrs[i].sh_type == SHT_REL) {
			pr_err("kpm: x86_64 REL relocations are unsupported; build with RELA\n");
			return -ENOEXEC;
		}
		if (info->sechdrs[i].sh_type != SHT_RELA)
			continue;

		rc = sukisu_kpm_apply_relocate_add(mod, info, i);
		if (rc)
			return rc;
	}

	return 0;
}

static int sukisu_kpm_enable_text_exec(struct sukisu_kpm_module *mod)
{
	unsigned long start;
	unsigned long total_pages;
	unsigned long text_pages;
	unsigned long ro_pages;
	int rc;

	if (!mod->start || !mod->size)
		return -EINVAL;

	start = (unsigned long)mod->start;
	total_pages = mod->size >> PAGE_SHIFT;
	text_pages = mod->text_size >> PAGE_SHIFT;
	ro_pages = (mod->ro_size - mod->text_size) >> PAGE_SHIFT;

	rc = set_memory_nx(start, total_pages);
	if (rc)
		return rc;

	if (text_pages) {
		rc = set_memory_ro(start, text_pages);
		if (rc)
			return rc;
		rc = set_memory_x(start, text_pages);
		if (rc)
			return rc;
		flush_icache_range(start, start + mod->text_size);
	}

	if (ro_pages) {
		rc = set_memory_ro(start + mod->text_size, ro_pages);
		if (rc)
			return rc;
	}

	return 0;
}

static void sukisu_kpm_disable_text_exec(struct sukisu_kpm_module *mod)
{
	if (mod->start && mod->size) {
		set_memory_rw((unsigned long)mod->start, mod->size >> PAGE_SHIFT);
		set_memory_nx((unsigned long)mod->start, mod->size >> PAGE_SHIFT);
	}
}

static void sukisu_kpm_free_module(struct sukisu_kpm_module *mod)
{
	if (!mod)
		return;

	kfree(mod->args);
	kfree(mod->ctl_args);
	if (mod->start) {
		sukisu_kpm_disable_text_exec(mod);
		module_memfree(mod->start);
	}
	kfree(mod);
}

static struct sukisu_kpm_module *sukisu_kpm_find_module_locked(const char *name)
{
	struct sukisu_kpm_module *pos;

	list_for_each_entry(pos, &sukisu_kpm_modules, list) {
		if (!strcmp(name, pos->info.name))
			return pos;
	}

	return NULL;
}

static int sukisu_kpm_load_module(const void *data, unsigned long len, const char *args, const char *event,
				  void __user *reserved)
{
	struct sukisu_kpm_load_info load_info = {
		.len = len,
		.hdr = data,
	};
	struct sukisu_kpm_load_info *info = &load_info;
	struct sukisu_kpm_module *mod;
	long init_rc;
	int rc;

	rc = sukisu_kpm_elf_header_check(info);
	if (rc)
		return rc;

	rc = sukisu_kpm_setup_load_info(info);
	if (rc)
		return rc;

	rc = sukisu_kpm_count_got_relocations(info);
	if (rc)
		return rc;

	mutex_lock(&sukisu_kpm_module_lock);
	if (sukisu_kpm_find_module_locked(info->info.name)) {
		mutex_unlock(&sukisu_kpm_module_lock);
		return -EEXIST;
	}
	mutex_unlock(&sukisu_kpm_module_lock);

	mod = kzalloc(sizeof(*mod), GFP_KERNEL);
	if (!mod)
		return -ENOMEM;

	INIT_LIST_HEAD(&mod->list);
	if (args && args[0]) {
		mod->args = kstrdup(args, GFP_KERNEL);
		if (!mod->args) {
			rc = -ENOMEM;
			goto free_mod;
		}
	}

	sukisu_kpm_layout_sections(mod, info);
	if (!mod->size) {
		rc = -ENOEXEC;
		goto free_mod;
	}

	rc = sukisu_kpm_move_module(mod, info);
	if (rc)
		goto free_mod;

	rc = sukisu_kpm_simplify_symbols(mod, info);
	if (rc)
		goto free_mod;

	rc = sukisu_kpm_apply_relocations(mod, info);
	if (rc)
		goto free_mod;

	rc = sukisu_kpm_validate_entrypoints(mod);
	if (rc)
		goto free_mod;

	rc = sukisu_kpm_enable_text_exec(mod);
	if (rc)
		goto free_mod;

	init_rc = (*mod->init)(mod->args ? mod->args : "", event, reserved);
	if (init_rc) {
		rc = init_rc < 0 ? (int)init_rc : -EINVAL;
		(*mod->exit)(reserved);
		goto free_mod;
	}

	mutex_lock(&sukisu_kpm_module_lock);
	if (sukisu_kpm_find_module_locked(mod->info.name)) {
		mutex_unlock(&sukisu_kpm_module_lock);
		(*mod->exit)(reserved);
		rc = -EEXIST;
		goto free_mod;
	}
	list_add_tail(&mod->list, &sukisu_kpm_modules);
	mutex_unlock(&sukisu_kpm_module_lock);

	pr_info("kpm: loaded %s version %s\n", mod->info.name, mod->info.version);
	return 0;

free_mod:
	sukisu_kpm_free_module(mod);
	return rc;
}

int sukisu_kpm_loader_load_module_path(const char *path, const char *args, void __user *reserved)
{
	struct file *filp;
	void *data = NULL;
	loff_t pos = 0;
	loff_t len;
	ssize_t read;
	int rc;

	if (!path || !path[0])
		return -EINVAL;

	filp = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(filp)) {
		pr_err("kpm: open module %s failed: %ld\n", path, PTR_ERR(filp));
		return PTR_ERR(filp);
	}

	len = vfs_llseek(filp, 0, SEEK_END);
	if (len <= 0 || len > SUKISU_KPM_MAX_MODULE_SIZE) {
		rc = -EFBIG;
		goto close_file;
	}
	vfs_llseek(filp, 0, SEEK_SET);

	data = vmalloc(len);
	if (!data) {
		rc = -ENOMEM;
		goto close_file;
	}

	read = kernel_read(filp, data, len, &pos);
	if (read != len) {
		rc = read < 0 ? read : -EIO;
		goto free_data;
	}

	rc = sukisu_kpm_load_module(data, len, args, "load-file", reserved);

free_data:
	vfree(data);
close_file:
	filp_close(filp, NULL);
	return rc;
}

int sukisu_kpm_loader_unload_module(const char *name, void __user *reserved)
{
	struct sukisu_kpm_module *mod;
	long rc;

	if (!name || !name[0])
		return -EINVAL;

	mutex_lock(&sukisu_kpm_module_lock);
	mod = sukisu_kpm_find_module_locked(name);
	if (!mod) {
		mutex_unlock(&sukisu_kpm_module_lock);
		return -ENOENT;
	}
	list_del(&mod->list);
	mutex_unlock(&sukisu_kpm_module_lock);

	rc = (*mod->exit)(reserved);
	pr_info("kpm: unloaded %s rc=%ld\n", name, rc);
	sukisu_kpm_free_module(mod);
	return (int)rc;
}

int sukisu_kpm_loader_num(void)
{
	struct sukisu_kpm_module *pos;
	int n = 0;

	mutex_lock(&sukisu_kpm_module_lock);
	list_for_each_entry(pos, &sukisu_kpm_modules, list)
		n++;
	mutex_unlock(&sukisu_kpm_module_lock);

	return n;
}

int sukisu_kpm_loader_list(char *out, int size)
{
	struct sukisu_kpm_module *pos;
	int off = 0;

	if (!out || size <= 0)
		return -EINVAL;

	out[0] = '\0';

	mutex_lock(&sukisu_kpm_module_lock);
	list_for_each_entry(pos, &sukisu_kpm_modules, list) {
		int left = size - off;
		int written;

		if (left <= 1)
			break;

		written = scnprintf(out + off, left, "%s\n", pos->info.name);
		off += written;
	}
	mutex_unlock(&sukisu_kpm_module_lock);

	if (off > 0 && out[off - 1] == '\n')
		out[off - 1] = '\0';

	return off;
}

int sukisu_kpm_loader_info(const char *name, char *out, int size)
{
	struct sukisu_kpm_module *mod;
	int ret;

	if (!name || !out || size <= 0)
		return -EINVAL;

	mutex_lock(&sukisu_kpm_module_lock);
	mod = sukisu_kpm_find_module_locked(name);
	if (!mod) {
		mutex_unlock(&sukisu_kpm_module_lock);
		return -ENOENT;
	}

	ret = scnprintf(out, size,
			"name=%s\n"
			"version=%s\n"
			"license=%s\n"
			"author=%s\n"
			"description=%s\n"
			"args=%s\n",
			mod->info.name ? mod->info.name : "", mod->info.version ? mod->info.version : "",
			mod->info.license ? mod->info.license : "", mod->info.author ? mod->info.author : "",
			mod->info.description ? mod->info.description : "", mod->args ? mod->args : "");
	mutex_unlock(&sukisu_kpm_module_lock);

	return ret;
}

int sukisu_kpm_loader_control(const char *name, const char *args)
{
	struct sukisu_kpm_module *mod;
	long rc;

	if (!name || !name[0])
		return -EINVAL;

	mutex_lock(&sukisu_kpm_module_lock);
	mod = sukisu_kpm_find_module_locked(name);
	if (!mod) {
		mutex_unlock(&sukisu_kpm_module_lock);
		return -ENOENT;
	}
	if (!mod->ctl0 || !*mod->ctl0) {
		mutex_unlock(&sukisu_kpm_module_lock);
		return -ENOSYS;
	}

	kfree(mod->ctl_args);
	mod->ctl_args = kstrdup(args ? args : "", GFP_KERNEL);
	if (!mod->ctl_args) {
		mutex_unlock(&sukisu_kpm_module_lock);
		return -ENOMEM;
	}

	rc = (*mod->ctl0)(mod->ctl_args, NULL, 0);
	mutex_unlock(&sukisu_kpm_module_lock);

	return (int)rc;
}

int sukisu_kpm_loader_version(char *out, int size)
{
	if (!out || size <= 0)
		return -EINVAL;

	return scnprintf(out, size, "%s", SUKISU_KPM_LOADER_VERSION);
}
