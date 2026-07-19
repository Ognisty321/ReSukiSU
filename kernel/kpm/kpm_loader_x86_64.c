// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Experimental direct KPM ELF loader for ReSukiSU on WSA x86_64.
 *
 * This bypasses KernelPatch kpimg/kptools because that payload is ARM64-only.
 * It loads ET_REL x86_64 KPM objects using the standard .kpm.* metadata and
 * callback sections plus common non-PIC x86_64 relocations.
 */

#include <linux/cred.h>
#include <linux/ctype.h>
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
#include <linux/overflow.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include <linux/static_call.h>
#include <linux/string.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
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

#define SUKISU_KPM_MAX_MODULE_SIZE (16 * 1024 * 1024)
#define SUKISU_KPM_MAX_LOADED_SIZE (32 * 1024 * 1024)
#define SUKISU_KPM_MAX_SECTIONS 4096
#define SUKISU_KPM_MAX_MODINFO_SIZE 4096
#define SUKISU_KPM_MAX_NAME_LEN 31
#define SUKISU_KPM_MAX_VERSION_LEN 127
#define SUKISU_KPM_HOOK_NO_ERR 0
#define SUKISU_KPM_HOOK_BAD_ADDRESS 4095
#define SUKISU_KPM_HOOK_DUPLICATED 4094
#define SUKISU_KPM_HOOK_NO_MEM 4093
#define SUKISU_KPM_HOOK_BAD_RELO 4092
#define SUKISU_KPM_HOOK_TRANSIT_NO_MEM 4091
#define SUKISU_KPM_HOOK_CHAIN_FULL 4090
#define SUKISU_KPM_HOOK_RESERVED_TEXT 4089
#define SUKISU_KPM_HOOK_TEXT_POKE_FAILED 4088
#define SUKISU_KPM_HOOK_PERM_FAILED 4087
#define SUKISU_KPM_HOOK_BAD_REPLACEMENT 4086
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
#define SUKISU_KPM_CHAIN_ITEM_RETIRING 2
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
#ifndef SHF_TLS
#define SHF_TLS 0x400
#endif
#ifndef SHF_COMPRESSED
#define SHF_COMPRESSED 0x800
#endif
#ifndef SHN_XINDEX
#define SHN_XINDEX 0xffff
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
    char *source_path;
    void *start;
    unsigned int size;
    unsigned int text_size;
    unsigned int ro_size;
    sukisu_kpm_initcall_t *init;
    sukisu_kpm_ctl0call_t *ctl0;
    sukisu_kpm_ctl1call_t *ctl1;
    sukisu_kpm_exitcall_t *exit;
    unsigned int inline_hook_count;
    unsigned int fp_hook_count;
    unsigned int wrap_item_count;
    unsigned int fp_wrap_item_count;
    unsigned int syscall_wrap_item_count;
    unsigned int quiescing_count;
    atomic_t active_callbacks;
    bool load_failed;
    bool unloading;
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
    struct sukisu_kpm_module *owner;
    struct work_struct retire_work;
    struct callback_head retire_task_work;
    u8 original[SUKISU_KPM_X86_MAX_STOLEN_SIZE];
};

struct sukisu_kpm_fp_hook {
    struct list_head list;
    unsigned long fp_addr;
    void *replace;
    void *backup;
    struct sukisu_kpm_module *owner;
    struct work_struct retire_work;
    struct callback_head retire_task_work;
};

struct sukisu_kpm_wrap_chain {
    struct sukisu_kpm_kp_hook hook;
    s32 chain_items_max;
    s8 states[SUKISU_KPM_HOOK_CHAIN_NUM];
    struct sukisu_kpm_module *owners[SUKISU_KPM_HOOK_CHAIN_NUM];
    void *udata[SUKISU_KPM_HOOK_CHAIN_NUM];
    void *befores[SUKISU_KPM_HOOK_CHAIN_NUM];
    void *afters[SUKISU_KPM_HOOK_CHAIN_NUM];
    u32 transit[SUKISU_KPM_TRANSIT_INST_NUM];
    struct list_head list;
    atomic_t active;
    wait_queue_head_t idle_wait;
    int argno;
    bool disabled;
    void *stub;
    struct sukisu_kpm_module *owner;
    struct work_struct retire_work;
    struct sukisu_kpm_inline_hook *retired_hook;
};

struct sukisu_kpm_fp_wrap_chain {
    struct sukisu_kpm_kp_fp_hook hook;
    s32 chain_items_max;
    s8 states[SUKISU_KPM_FP_HOOK_CHAIN_NUM];
    struct sukisu_kpm_module *owners[SUKISU_KPM_FP_HOOK_CHAIN_NUM];
    void *udata[SUKISU_KPM_FP_HOOK_CHAIN_NUM];
    void *befores[SUKISU_KPM_FP_HOOK_CHAIN_NUM];
    void *afters[SUKISU_KPM_FP_HOOK_CHAIN_NUM];
    u32 transit[SUKISU_KPM_TRANSIT_INST_NUM];
    struct list_head list;
    atomic_t active;
    wait_queue_head_t idle_wait;
    int argno;
    bool disabled;
    void *stub;
    struct sukisu_kpm_module *owner;
    struct work_struct retire_work;
};

struct sukisu_kpm_syscall_wrap_chain {
    unsigned long slot_addr;
    int nr;
    int argno;
    s8 states[SUKISU_KPM_SYSCALL_HOOK_CHAIN_NUM];
    struct sukisu_kpm_module *owners[SUKISU_KPM_SYSCALL_HOOK_CHAIN_NUM];
    void *udata[SUKISU_KPM_SYSCALL_HOOK_CHAIN_NUM];
    void *befores[SUKISU_KPM_SYSCALL_HOOK_CHAIN_NUM];
    void *afters[SUKISU_KPM_SYSCALL_HOOK_CHAIN_NUM];
    struct list_head list;
    atomic_t active;
    wait_queue_head_t idle_wait;
    bool disabled;
    void *stub;
    void *origin;
    struct sukisu_kpm_module *owner;
    struct work_struct retire_work;
};

struct sukisu_kpm_context_frame {
    struct list_head list;
    struct task_struct *task;
    struct sukisu_kpm_module *module;
};

static LIST_HEAD(sukisu_kpm_modules);
static LIST_HEAD(sukisu_kpm_inline_hooks);
static LIST_HEAD(sukisu_kpm_fp_hooks);
static LIST_HEAD(sukisu_kpm_wrap_chains);
static LIST_HEAD(sukisu_kpm_fp_wrap_chains);
static LIST_HEAD(sukisu_kpm_syscall_wrap_chains);
static LIST_HEAD(sukisu_kpm_context_frames);
static DEFINE_MUTEX(sukisu_kpm_module_lock);
static DEFINE_MUTEX(sukisu_kpm_hook_lock);
static DEFINE_MUTEX(sukisu_kpm_context_lock);

static u32 sukisu_kpm_kver = LINUX_VERSION_CODE;
static u32 sukisu_kpm_kpver = KERNEL_VERSION(0, 1, 0);
static int sukisu_kpm_endian;
static s64 sukisu_kpm_page_size = PAGE_SIZE;
static s64 sukisu_kpm_page_shift = PAGE_SHIFT;
static int sukisu_kpm_has_syscall_wrapper = 1;
static int sukisu_kpm_has_config_compat;
static const char sukisu_kpm_loader_version_string[] = SUKISU_KPM_LOADER_VERSION;
static const u32 sukisu_kpm_loader_abi_version = SUKISU_KPM_X86_64_ABI_VERSION;
static const u64 sukisu_kpm_loader_feature_bits = SUKISU_KPM_X86_64_FEATURE_BITS;
static atomic64_t sukisu_kpm_load_attempts = ATOMIC64_INIT(0);
static atomic64_t sukisu_kpm_load_successes = ATOMIC64_INIT(0);
static atomic64_t sukisu_kpm_load_failures = ATOMIC64_INIT(0);
static atomic64_t sukisu_kpm_unload_attempts = ATOMIC64_INIT(0);
static atomic64_t sukisu_kpm_unload_successes = ATOMIC64_INIT(0);
static atomic64_t sukisu_kpm_unload_failures = ATOMIC64_INIT(0);

static void sukisu_kpm_retire_inline_hook_work(struct work_struct *work);
static void sukisu_kpm_retire_fp_hook_work(struct work_struct *work);
static void sukisu_kpm_retire_inline_hook_task_work(struct callback_head *work);
static void sukisu_kpm_retire_fp_hook_task_work(struct callback_head *work);

enum sukisu_kpm_ref_kind {
    SUKISU_KPM_REF_INLINE,
    SUKISU_KPM_REF_FP,
    SUKISU_KPM_REF_WRAP,
    SUKISU_KPM_REF_FP_WRAP,
    SUKISU_KPM_REF_SYSCALL_WRAP,
};

static int sukisu_kpm_enter_module_context(struct sukisu_kpm_module *mod)
{
    struct sukisu_kpm_context_frame *frame;

    if (!mod)
        return -EINVAL;

    frame = kzalloc(sizeof(*frame), GFP_KERNEL);
    if (!frame) {
        pr_err("kpm: failed to allocate module context for %s\n", mod->info.name ? mod->info.name : "<unknown>");
        return -ENOMEM;
    }

    frame->task = current;
    frame->module = mod;

    mutex_lock(&sukisu_kpm_context_lock);
    list_add(&frame->list, &sukisu_kpm_context_frames);
    mutex_unlock(&sukisu_kpm_context_lock);
    return 0;
}

static void sukisu_kpm_exit_module_context(struct sukisu_kpm_module *mod)
{
    struct sukisu_kpm_context_frame *frame;
    struct sukisu_kpm_context_frame *tmp;

    mutex_lock(&sukisu_kpm_context_lock);
    list_for_each_entry_safe (frame, tmp, &sukisu_kpm_context_frames, list) {
        if (frame->task == current && frame->module == mod) {
            list_del(&frame->list);
            kfree(frame);
            break;
        }
    }
    mutex_unlock(&sukisu_kpm_context_lock);
}

static struct sukisu_kpm_module *sukisu_kpm_current_module(void)
{
    struct sukisu_kpm_context_frame *frame;
    struct sukisu_kpm_module *mod = NULL;

    mutex_lock(&sukisu_kpm_context_lock);
    list_for_each_entry (frame, &sukisu_kpm_context_frames, list) {
        if (frame->task == current) {
            mod = frame->module;
            break;
        }
    }
    mutex_unlock(&sukisu_kpm_context_lock);
    return mod;
}

static void sukisu_kpm_module_ref_delta(struct sukisu_kpm_module *mod, enum sukisu_kpm_ref_kind kind, int delta)
{
    unsigned int *counter;

    if (!mod)
        return;

    switch (kind) {
    case SUKISU_KPM_REF_INLINE:
        counter = &mod->inline_hook_count;
        break;
    case SUKISU_KPM_REF_FP:
        counter = &mod->fp_hook_count;
        break;
    case SUKISU_KPM_REF_WRAP:
        counter = &mod->wrap_item_count;
        break;
    case SUKISU_KPM_REF_FP_WRAP:
        counter = &mod->fp_wrap_item_count;
        break;
    case SUKISU_KPM_REF_SYSCALL_WRAP:
        counter = &mod->syscall_wrap_item_count;
        break;
    default:
        return;
    }

    if (delta > 0) {
        (*counter)++;
    } else if (*counter) {
        (*counter)--;
    } else {
        pr_warn("kpm: hook audit counter underflow for %s\n", mod->info.name ? mod->info.name : "<unknown>");
    }
}

static void sukisu_kpm_begin_owner_quiesce_locked(struct sukisu_kpm_module *mod)
{
    if (mod)
        mod->quiescing_count++;
}

static void sukisu_kpm_end_owner_quiesce_locked(struct sukisu_kpm_module *mod)
{
    if (!mod)
        return;

    if (mod->quiescing_count)
        mod->quiescing_count--;
    else
        pr_warn("kpm: quiescing counter underflow for %s\n", mod->info.name ? mod->info.name : "<unknown>");
}

static void sukisu_kpm_end_owner_quiesce(struct sukisu_kpm_module *mod)
{
    if (!mod)
        return;

    mutex_lock(&sukisu_kpm_hook_lock);
    sukisu_kpm_end_owner_quiesce_locked(mod);
    mutex_unlock(&sukisu_kpm_hook_lock);
}

static unsigned int sukisu_kpm_module_hook_refs(const struct sukisu_kpm_module *mod)
{
    if (!mod)
        return 0;

    return mod->inline_hook_count + mod->fp_hook_count + mod->wrap_item_count + mod->fp_wrap_item_count +
           mod->syscall_wrap_item_count;
}

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
    if (rc) {
        pr_err("kpm: set_memory_nx before ROX failed for %px size=%zu rc=%d\n", ptr, size, rc);
        return rc;
    }
    rc = set_memory_ro(start, pages);
    if (rc) {
        pr_err("kpm: set_memory_ro failed for %px size=%zu rc=%d\n", ptr, size, rc);
        return rc;
    }
    rc = set_memory_x(start, pages);
    if (rc) {
        pr_err("kpm: set_memory_x failed for %px size=%zu rc=%d\n", ptr, size, rc);
        set_memory_rw(start, pages);
        set_memory_nx(start, pages);
        return rc;
    }
    flush_icache_range(start, start + size);
    return 0;
}

static int sukisu_kpm_set_exec_rw_nx(void *ptr, size_t size)
{
    unsigned long start = (unsigned long)ptr;
    unsigned long pages = sukisu_kpm_pages_for_size(size);
    int rc;

    if (!ptr || !pages)
        return -EINVAL;

    rc = set_memory_nx(start, pages);
    if (rc) {
        pr_err("kpm: set_memory_nx failed for %px size=%zu rc=%d\n", ptr, size, rc);
        return rc;
    }

    rc = set_memory_rw(start, pages);
    if (rc) {
        pr_err("kpm: set_memory_rw failed for %px size=%zu rc=%d\n", ptr, size, rc);
        return rc;
    }

    return 0;
}

static void sukisu_kpm_sync_before_exec_free(void)
{
    synchronize_rcu();
    synchronize_rcu_tasks_rude();
    synchronize_rcu_tasks();
}

static int sukisu_kpm_free_generated_exec(void *ptr, size_t size, bool sync)
{
    int rc;

    if (!ptr)
        return 0;
    if (sync)
        sukisu_kpm_sync_before_exec_free();

    rc = sukisu_kpm_set_exec_rw_nx(ptr, size);
    if (rc) {
        pr_err("kpm: refusing to free generated exec buffer %px size=%zu after permission transition failure: %d\n",
               ptr, size, rc);
        return rc;
    }

    module_memfree(ptr);
    return 0;
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

static bool sukisu_kpm_module_text_contains(const struct sukisu_kpm_module *mod, unsigned long addr)
{
    unsigned long start;
    unsigned long end;

    if (!mod || !mod->start || !mod->text_size)
        return false;

    start = (unsigned long)mod->start;
    end = start + mod->text_size;
    if (end < start)
        return false;

    return addr >= start && addr < end;
}

static bool sukisu_kpm_bad_hook_target_addr(unsigned long addr)
{
    if (sukisu_kpm_bad_kernel_addr(addr))
        return true;

    return !kernel_text_address(addr);
}

static bool sukisu_kpm_bad_hook_target_range(unsigned long addr, size_t len)
{
    unsigned long last;

    if (!len || check_add_overflow(addr, len - 1, &last))
        return true;
    return sukisu_kpm_bad_hook_target_addr(addr) || !kernel_text_address(last);
}

static bool sukisu_kpm_bad_exec_addr(unsigned long addr, bool allow_generated_exec)
{
    struct sukisu_kpm_module *mod;

    if (sukisu_kpm_bad_kernel_addr(addr))
        return true;
    if (kernel_text_address(addr))
        return false;

    mod = sukisu_kpm_current_module();
    if (sukisu_kpm_module_text_contains(mod, addr))
        return false;

    return !allow_generated_exec;
}

static int sukisu_kpm_patch_bytes(void *addr, const void *bytes, size_t len)
{
    if (!addr || !bytes || !len)
        return -EINVAL;
    if (offset_in_page(addr) + len > PAGE_SIZE)
        return -ERANGE;
    if (WARN_ON_ONCE(in_interrupt() || irqs_disabled()))
        return -EWOULDBLOCK;
    might_sleep();

    return ksu_patch_text(addr, (void *)bytes, len, SUKISU_KPM_PATCH_FLAGS);
}

static int sukisu_kpm_patch_bytes_if_matches(void *addr, const void *expected, const void *replacement, size_t len)
{
    u8 live[SUKISU_KPM_X86_MAX_STOLEN_SIZE];
    int rc;

    if (!expected || !replacement || !len || len > sizeof(live))
        return -EINVAL;

    rc = copy_from_kernel_nofault(live, addr, len);
    if (rc)
        return rc;
    if (memcmp(live, expected, len))
        return -EBUSY;

    return sukisu_kpm_patch_bytes(addr, replacement, len);
}

static int sukisu_kpm_patch_pointer_if_matches(unsigned long addr, void *expected, void *replacement)
{
    return sukisu_kpm_patch_bytes_if_matches((void *)addr, &expected, &replacement, sizeof(expected));
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

static int sukisu_kpm_restore_rel32_hook_bp(void *addr, const void *original, const void *emulate_target)
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
        len = __copy_instruction((u8 *)trampoline + copied, (u8 *)func + copied, (u8 *)trampoline + copied, &insn);
        if (len <= 0 || len > MAX_INSN_SIZE)
            return -EINVAL;
        if (sukisu_kpm_insn_is_unsafe_to_copy(&insn))
            return -EINVAL;

        copied += len;
        if (copied > SUKISU_KPM_X86_MAX_STOLEN_SIZE)
            return -EOVERFLOW;
    }

    if (sukisu_kpm_rel32_fits((u8 *)trampoline + copied, (u8 *)func + copied, JMP32_INSN_SIZE))
        sukisu_kpm_make_rel32_jmp((u8 *)trampoline + copied, (u8 *)trampoline + copied, (u8 *)func + copied);
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
    unsigned long first = (unsigned long)start;
    unsigned long last;
    void *end;

    if (!len)
        return true;

    if (check_add_overflow(first, (unsigned long)len - 1, &last))
        return true;

    end = (void *)last;
    if (ftrace_location_range(first, last))
        return true;
#ifdef CONFIG_KPROBES
    for (;;) {
        if (within_kprobe_blacklist(first) || get_kprobe((kprobe_opcode_t *)first))
            return true;
        if (first == last)
            break;
        first++;
    }
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

    list_for_each_entry (pos, &sukisu_kpm_inline_hooks, list) {
        if (pos->func == func)
            return pos;
    }

    return NULL;
}

static int sukisu_kpm_install_inline_hook_locked(void *func, void *replace, void **backup, bool allow_generated_replace)
{
    struct sukisu_kpm_inline_hook *hook;
    u8 patch[SUKISU_KPM_X86_MAX_STOLEN_SIZE];
    unsigned int min_stolen_size;
    bool use_rel32;
    int rc;
    int hook_rc = SUKISU_KPM_HOOK_BAD_RELO;

    if (backup)
        *backup = NULL;
    if (sukisu_kpm_bad_hook_target_addr((unsigned long)func))
        return SUKISU_KPM_HOOK_BAD_ADDRESS;
    if (sukisu_kpm_bad_exec_addr((unsigned long)replace, allow_generated_replace))
        return SUKISU_KPM_HOOK_BAD_REPLACEMENT;
    if (sukisu_kpm_find_inline_hook_locked(func))
        return SUKISU_KPM_HOOK_DUPLICATED;

    use_rel32 = sukisu_kpm_rel32_fits(func, replace, JMP32_INSN_SIZE);
    min_stolen_size = use_rel32 ? JMP32_INSN_SIZE : SUKISU_KPM_X86_JMP_ABS_SIZE;

    hook = kzalloc(sizeof(*hook), GFP_KERNEL);
    if (!hook)
        return SUKISU_KPM_HOOK_NO_MEM;
    INIT_WORK(&hook->retire_work, sukisu_kpm_retire_inline_hook_work);
    init_task_work(&hook->retire_task_work, sukisu_kpm_retire_inline_hook_task_work);

    hook->trampoline = module_alloc(SUKISU_KPM_X86_MAX_STOLEN_SIZE + SUKISU_KPM_X86_JMP_ABS_SIZE);
    if (!hook->trampoline) {
        kfree(hook);
        return SUKISU_KPM_HOOK_TRANSIT_NO_MEM;
    }
    rc = sukisu_kpm_set_exec_rw_nx(hook->trampoline, SUKISU_KPM_X86_MAX_STOLEN_SIZE + SUKISU_KPM_X86_JMP_ABS_SIZE);
    if (rc) {
        hook_rc = SUKISU_KPM_HOOK_PERM_FAILED;
        goto err_free;
    }
    memset(hook->trampoline, 0xcc, SUKISU_KPM_X86_MAX_STOLEN_SIZE + SUKISU_KPM_X86_JMP_ABS_SIZE);

    rc = sukisu_kpm_build_trampoline(func, hook->trampoline, min_stolen_size, &hook->stolen_size);
    if (rc)
        goto err_free;

    if (sukisu_kpm_text_range_reserved(func, hook->stolen_size)) {
        rc = -EBUSY;
        hook_rc = SUKISU_KPM_HOOK_RESERVED_TEXT;
        goto err_free;
    }
    if (sukisu_kpm_bad_hook_target_range((unsigned long)func, hook->stolen_size)) {
        rc = -EINVAL;
        hook_rc = SUKISU_KPM_HOOK_BAD_ADDRESS;
        goto err_free;
    }

    rc = copy_from_kernel_nofault(hook->original, func, hook->stolen_size);
    if (rc) {
        hook_rc = SUKISU_KPM_HOOK_BAD_ADDRESS;
        goto err_free;
    }

    rc = sukisu_kpm_set_exec_rox(hook->trampoline, SUKISU_KPM_X86_MAX_STOLEN_SIZE + SUKISU_KPM_X86_JMP_ABS_SIZE);
    if (rc) {
        hook_rc = SUKISU_KPM_HOOK_PERM_FAILED;
        goto err_free;
    }

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
    if (rc) {
        hook_rc = SUKISU_KPM_HOOK_TEXT_POKE_FAILED;
        goto err_free;
    }

    hook->func = func;
    hook->replace = replace;
    hook->owner = sukisu_kpm_current_module();
    sukisu_kpm_module_ref_delta(hook->owner, SUKISU_KPM_REF_INLINE, 1);
    list_add(&hook->list, &sukisu_kpm_inline_hooks);
    if (backup)
        *backup = hook->trampoline;
    return SUKISU_KPM_HOOK_NO_ERR;

err_free:
    pr_warn("kpm: x86_64 inline hook failed func=%px replace=%px rc=%d hook_rc=%d\n", func, replace, rc, hook_rc);
    sukisu_kpm_free_generated_exec(hook->trampoline, SUKISU_KPM_X86_MAX_STOLEN_SIZE + SUKISU_KPM_X86_JMP_ABS_SIZE,
                                   false);
    kfree(hook);
    return hook_rc;
}

static int sukisu_kpm_unhook_locked(void *func, struct sukisu_kpm_inline_hook **retired)
{
    struct sukisu_kpm_inline_hook *hook;
    u8 expected[SUKISU_KPM_X86_MAX_STOLEN_SIZE];
    int rc;

    if (retired)
        *retired = NULL;

    hook = sukisu_kpm_find_inline_hook_locked(func);
    if (!hook)
        return -ENOENT;

    if (hook->uses_text_poke_bp) {
        rc = sukisu_kpm_restore_rel32_hook_bp(func, hook->original, hook->replace);
    } else {
        memset(expected, 0x90, sizeof(expected));
        sukisu_kpm_make_abs_jmp(expected, hook->replace);
        rc = sukisu_kpm_patch_bytes_if_matches(func, expected, hook->original, hook->patch_size);
    }
    if (rc)
        return rc;

    list_del(&hook->list);
    sukisu_kpm_begin_owner_quiesce_locked(hook->owner);
    sukisu_kpm_module_ref_delta(hook->owner, SUKISU_KPM_REF_INLINE, -1);
    if (retired)
        *retired = hook;
    return 0;
}

static bool sukisu_kpm_should_defer_owner_retire(struct sukisu_kpm_module *owner)
{
    if (!owner || READ_ONCE(owner->unloading) || sukisu_kpm_current_module() == owner)
        return false;
    return true;
}

static void sukisu_kpm_finish_inline_hook_retire(struct sukisu_kpm_inline_hook *hook)
{
    if (!hook)
        return;

    sukisu_kpm_free_generated_exec(hook->trampoline, SUKISU_KPM_X86_MAX_STOLEN_SIZE + SUKISU_KPM_X86_JMP_ABS_SIZE,
                                   false);
    sukisu_kpm_end_owner_quiesce(hook->owner);
    kfree(hook);
}

static void sukisu_kpm_retire_inline_hook_work(struct work_struct *work)
{
    struct sukisu_kpm_inline_hook *hook = container_of(work, struct sukisu_kpm_inline_hook, retire_work);

    sukisu_kpm_sync_before_exec_free();
    sukisu_kpm_finish_inline_hook_retire(hook);
}

static void sukisu_kpm_retire_inline_hook_task_work(struct callback_head *work)
{
    struct sukisu_kpm_inline_hook *hook = container_of(work, struct sukisu_kpm_inline_hook, retire_task_work);

    if (!schedule_work(&hook->retire_work))
        pr_err("kpm: failed to queue inline hook retirement for %px; allocation retained\n", hook->func);
}

static void sukisu_kpm_retire_inline_hook(struct sukisu_kpm_inline_hook *hook, bool sync)
{
    if (!hook)
        return;

    if (sync && sukisu_kpm_should_defer_owner_retire(hook->owner)) {
        if (task_work_add(current, &hook->retire_task_work, TWA_RESUME))
            pr_err("kpm: failed to queue inline hook task retirement for %px; allocation retained\n", hook->func);
        return;
    }
    if (sync)
        sukisu_kpm_sync_before_exec_free();
    sukisu_kpm_finish_inline_hook_retire(hook);
}

static void sukisu_kpm_retire_fp_hook_work(struct work_struct *work)
{
    struct sukisu_kpm_fp_hook *hook = container_of(work, struct sukisu_kpm_fp_hook, retire_work);

    sukisu_kpm_sync_before_exec_free();
    sukisu_kpm_end_owner_quiesce(hook->owner);
    kfree(hook);
}

static void sukisu_kpm_retire_fp_hook_task_work(struct callback_head *work)
{
    struct sukisu_kpm_fp_hook *hook = container_of(work, struct sukisu_kpm_fp_hook, retire_task_work);

    if (!schedule_work(&hook->retire_work))
        pr_err("kpm: failed to queue function-pointer hook retirement for %px; record retained\n",
               (void *)hook->fp_addr);
}

static int sukisu_kpm_hotpatch_nosync(void *addr, u32 value)
{
    if (sukisu_kpm_bad_hook_target_range((unsigned long)addr, sizeof(value)) ||
        sukisu_kpm_text_range_reserved(addr, sizeof(value)))
        return -EINVAL;
    return sukisu_kpm_patch_bytes(addr, &value, sizeof(value));
}

static int sukisu_kpm_hotpatch(void *addrs[], u32 values[], int cnt)
{
    u32 *old_values;
    int i;
    int rc = 0;

    if (!addrs || !values || cnt < 0 || cnt > 1024)
        return -EINVAL;
    if (!cnt)
        return 0;

    old_values = kmalloc_array(cnt, sizeof(*old_values), GFP_KERNEL);
    if (!old_values)
        return -ENOMEM;

    for (i = 0; i < cnt; i++) {
        int j;

        if (sukisu_kpm_bad_hook_target_range((unsigned long)addrs[i], sizeof(values[i])) ||
            sukisu_kpm_text_range_reserved(addrs[i], sizeof(values[i]))) {
            rc = -EINVAL;
            goto out;
        }
        for (j = 0; j < i; j++) {
            if (addrs[j] == addrs[i]) {
                rc = -EINVAL;
                goto out;
            }
        }
        rc = copy_from_kernel_nofault(&old_values[i], addrs[i], sizeof(old_values[i]));
        if (rc)
            goto out;
    }

    for (i = 0; i < cnt; i++) {
        rc = sukisu_kpm_patch_bytes_if_matches(addrs[i], &old_values[i], &values[i], sizeof(values[i]));
        if (rc)
            break;
    }

    if (rc) {
        while (i-- > 0) {
            int rollback_rc =
                sukisu_kpm_patch_bytes_if_matches(addrs[i], &values[i], &old_values[i], sizeof(old_values[i]));

            if (rollback_rc)
                pr_err("kpm: hotpatch rollback failed for %px: %d\n", addrs[i], rollback_rc);
        }
    }

out:
    kfree(old_values);
    return rc;
}

static int sukisu_kpm_patch_function_pointer(unsigned long fp_addr, void *replace, void **backup)
{
    void *origin;
    int rc;

    if (backup)
        *backup = NULL;
    if (sukisu_kpm_bad_kernel_addr(fp_addr) || !IS_ALIGNED(fp_addr, sizeof(void *)) ||
        sukisu_kpm_bad_exec_addr((unsigned long)replace, false))
        return -EINVAL;

    rc = copy_from_kernel_nofault(&origin, (void *)fp_addr, sizeof(origin));
    if (rc)
        return rc;
    if (sukisu_kpm_bad_exec_addr((unsigned long)origin, false))
        return -EINVAL;
    if (backup)
        *backup = origin;

    return sukisu_kpm_patch_pointer_if_matches(fp_addr, origin, replace);
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
        return ((u64(*)(u64, u64, u64, u64, u64, u64))origin)(args[0], args[1], args[2], args[3], args[4], args[5]);
    case 7:
        return ((u64(*)(u64, u64, u64, u64, u64, u64, u64))origin)(args[0], args[1], args[2], args[3], args[4], args[5],
                                                                   args[6]);
    case 8:
        return ((u64(*)(u64, u64, u64, u64, u64, u64, u64, u64))origin)(args[0], args[1], args[2], args[3], args[4],
                                                                        args[5], args[6], args[7]);
    case 9:
        return ((u64(*)(u64, u64, u64, u64, u64, u64, u64, u64, u64))origin)(
            args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8]);
    case 10:
        return ((u64(*)(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64))origin)(
            args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9]);
    case 11:
        return ((u64(*)(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64))origin)(
            args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10]);
    default:
        return ((u64(*)(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64))origin)(
            args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9], args[10],
            args[11]);
    }
}

struct sukisu_kpm_chain_call {
    sukisu_kpm_chain_callback_t callback;
    struct sukisu_kpm_module *owner;
    void *udata;
};

static bool sukisu_kpm_acquire_chain_call(s8 *state, void **callbacks, void **udata, struct sukisu_kpm_module **owners,
                                          struct sukisu_kpm_chain_call *call)
{
    bool acquired = false;

    memset(call, 0, sizeof(*call));
    rcu_read_lock();
    if (smp_load_acquire(state) != SUKISU_KPM_CHAIN_ITEM_READY)
        goto out;

    call->callback = READ_ONCE(*callbacks);
    call->owner = READ_ONCE(*owners);
    call->udata = READ_ONCE(*udata);
    if (!call->callback)
        goto out;

    if (call->owner)
        atomic_inc(&call->owner->active_callbacks);

    /* Pair with RETIRING publication in the removal path. */
    if (unlikely(smp_load_acquire(state) != SUKISU_KPM_CHAIN_ITEM_READY)) {
        if (call->owner)
            atomic_dec(&call->owner->active_callbacks);
        memset(call, 0, sizeof(*call));
        goto out;
    }
    acquired = true;
out:
    rcu_read_unlock();
    return acquired;
}

static void sukisu_kpm_release_chain_call(struct sukisu_kpm_chain_call *call)
{
    if (call->owner)
        atomic_dec(&call->owner->active_callbacks);
}

static u64 sukisu_kpm_wrap_dispatch_common(void *chain, atomic_t *active, wait_queue_head_t *idle_wait, bool *disabled,
                                           int argno, int max_items, s8 *states, void **befores, void **afters,
                                           void **udata, struct sukisu_kpm_module **owners, void *origin,
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

    if (!smp_load_acquire(disabled)) {
        for (i = 0; i < max_items; i++) {
            struct sukisu_kpm_chain_call call;

            if (!sukisu_kpm_acquire_chain_call(&states[i], &befores[i], &udata[i], &owners[i], &call))
                continue;
            call.callback(fargs, call.udata);
            sukisu_kpm_release_chain_call(&call);
        }
    }

    if (!fargs->skip_origin)
        fargs->ret = sukisu_kpm_call_origin(origin, argno, fargs->args);

    if (!smp_load_acquire(disabled)) {
        for (i = 0; i < max_items; i++) {
            struct sukisu_kpm_chain_call call;

            if (!sukisu_kpm_acquire_chain_call(&states[i], &afters[i], &udata[i], &owners[i], &call))
                continue;
            call.callback(fargs, call.udata);
            sukisu_kpm_release_chain_call(&call);
        }
    }

    ret = fargs->ret;
    if (atomic_dec_and_test(active))
        wake_up_all(idle_wait);
    return ret;
}

static u64 sukisu_kpm_wrap_dispatch(struct sukisu_kpm_wrap_chain *chain, struct sukisu_kpm_hook_fargs12 *fargs)
{
    return sukisu_kpm_wrap_dispatch_common(chain, &chain->active, &chain->idle_wait, &chain->disabled, chain->argno,
                                           SUKISU_KPM_HOOK_CHAIN_NUM, chain->states, chain->befores, chain->afters,
                                           chain->udata, chain->owners, (void *)chain->hook.relo_addr, fargs);
}

static u64 sukisu_kpm_fp_wrap_dispatch(struct sukisu_kpm_fp_wrap_chain *chain, struct sukisu_kpm_hook_fargs12 *fargs)
{
    return sukisu_kpm_wrap_dispatch_common(chain, &chain->active, &chain->idle_wait, &chain->disabled, chain->argno,
                                           SUKISU_KPM_FP_HOOK_CHAIN_NUM, chain->states, chain->befores, chain->afters,
                                           chain->udata, chain->owners, (void *)chain->hook.origin_fp, fargs);
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

static void sukisu_kpm_emit_mov_rsi_rdi(u8 **p)
{
    sukisu_kpm_emit1(p, 0x48);
    sukisu_kpm_emit1(p, 0x89);
    sukisu_kpm_emit1(p, 0xfe);
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

    rc = sukisu_kpm_set_exec_rw_nx(stub, SUKISU_KPM_X86_WRAP_STUB_SIZE);
    if (rc) {
        module_memfree(stub);
        return NULL;
    }
    memset(stub, 0xcc, SUKISU_KPM_X86_WRAP_STUB_SIZE);
    p = stub;

    sukisu_kpm_emit_sub_rsp(&p, SUKISU_KPM_WRAP_FRAME_SIZE);

    capture = min(argno, 6);
    for (i = 0; i < capture; i++)
        sukisu_kpm_emit_mov_mrsp_reg(&p, SUKISU_KPM_WRAP_FRAME_ARGS + i * sizeof(u64), arg_regs[i]);

    for (i = 6; i < argno; i++) {
        sukisu_kpm_emit_mov_rax_mrsp(&p, SUKISU_KPM_WRAP_FRAME_SIZE + sizeof(u64) + (i - 6) * sizeof(u64));
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
        sukisu_kpm_free_generated_exec(stub, SUKISU_KPM_X86_WRAP_STUB_SIZE, false);
        return NULL;
    }

    rc = sukisu_kpm_set_exec_rox(stub, SUKISU_KPM_X86_WRAP_STUB_SIZE);
    if (rc) {
        sukisu_kpm_free_generated_exec(stub, SUKISU_KPM_X86_WRAP_STUB_SIZE, false);
        return NULL;
    }
    return stub;
}

static int sukisu_kpm_add_chain_item(s8 *states, struct sukisu_kpm_module **owners, int max_items, void **befores,
                                     void **afters, void **udata, void *before, void *after, void *data,
                                     struct sukisu_kpm_module *owner, enum sukisu_kpm_ref_kind kind)
{
    int i;
    int empty = -1;

    if (!before && !after)
        return SUKISU_KPM_HOOK_BAD_ADDRESS;

    for (i = 0; i < max_items; i++) {
        if (READ_ONCE(states[i]) == SUKISU_KPM_CHAIN_ITEM_READY && READ_ONCE(befores[i]) == before &&
            READ_ONCE(afters[i]) == after)
            return SUKISU_KPM_HOOK_DUPLICATED;
        if (empty < 0 && READ_ONCE(states[i]) == SUKISU_KPM_CHAIN_ITEM_EMPTY)
            empty = i;
    }

    if (empty < 0)
        return SUKISU_KPM_HOOK_CHAIN_FULL;

    WRITE_ONCE(befores[empty], before);
    WRITE_ONCE(afters[empty], after);
    WRITE_ONCE(udata[empty], data);
    WRITE_ONCE(owners[empty], owner);
    smp_store_release(&states[empty], SUKISU_KPM_CHAIN_ITEM_READY);
    sukisu_kpm_module_ref_delta(owner, kind, 1);
    return SUKISU_KPM_HOOK_NO_ERR;
}

static bool sukisu_kpm_remove_chain_item(s8 *states, struct sukisu_kpm_module **owners, int max_items, void **befores,
                                         void **afters, void **udata, void *before, void *after,
                                         enum sukisu_kpm_ref_kind kind, struct sukisu_kpm_module **retired_owner,
                                         int *retired_index)
{
    int i;

    if (retired_owner)
        *retired_owner = NULL;
    if (retired_index)
        *retired_index = -1;

    for (i = 0; i < max_items; i++) {
        if (READ_ONCE(states[i]) != SUKISU_KPM_CHAIN_ITEM_READY)
            continue;
        if (READ_ONCE(befores[i]) != before || READ_ONCE(afters[i]) != after)
            continue;

        if (retired_owner)
            *retired_owner = READ_ONCE(owners[i]);
        if (retired_index)
            *retired_index = i;
        sukisu_kpm_begin_owner_quiesce_locked(READ_ONCE(owners[i]));
        smp_store_release(&states[i], SUKISU_KPM_CHAIN_ITEM_RETIRING);
        sukisu_kpm_module_ref_delta(READ_ONCE(owners[i]), kind, -1);
        return true;
    }

    return false;
}

static void sukisu_kpm_finish_chain_item_locked(s8 *states, struct sukisu_kpm_module **owners, void **befores,
                                                void **afters, void **udata, int index,
                                                struct sukisu_kpm_module *retired_owner)
{
    if (index < 0 || smp_load_acquire(&states[index]) != SUKISU_KPM_CHAIN_ITEM_RETIRING)
        return;

    WRITE_ONCE(befores[index], NULL);
    WRITE_ONCE(afters[index], NULL);
    WRITE_ONCE(udata[index], NULL);
    WRITE_ONCE(owners[index], NULL);
    smp_store_release(&states[index], SUKISU_KPM_CHAIN_ITEM_EMPTY);
    sukisu_kpm_end_owner_quiesce_locked(retired_owner);
}

static bool sukisu_kpm_has_chain_items(s8 *states, int max_items)
{
    int i;

    for (i = 0; i < max_items; i++) {
        if (smp_load_acquire(&states[i]) != SUKISU_KPM_CHAIN_ITEM_EMPTY)
            return true;
    }

    return false;
}

static void sukisu_kpm_wait_chain_idle(atomic_t *active, wait_queue_head_t *idle_wait)
{
    wait_event(*idle_wait, !atomic_read(active));
}

static void sukisu_kpm_retire_wrap_chain_work(struct work_struct *work)
{
    struct sukisu_kpm_wrap_chain *chain = container_of(work, struct sukisu_kpm_wrap_chain, retire_work);

    sukisu_kpm_sync_before_exec_free();
    sukisu_kpm_wait_chain_idle(&chain->active, &chain->idle_wait);
    sukisu_kpm_retire_inline_hook(chain->retired_hook, false);
    sukisu_kpm_free_generated_exec(chain->stub, SUKISU_KPM_X86_WRAP_STUB_SIZE, false);
    kfree(chain);
}

static void sukisu_kpm_retire_fp_wrap_chain_work(struct work_struct *work)
{
    struct sukisu_kpm_fp_wrap_chain *chain = container_of(work, struct sukisu_kpm_fp_wrap_chain, retire_work);

    sukisu_kpm_sync_before_exec_free();
    sukisu_kpm_wait_chain_idle(&chain->active, &chain->idle_wait);
    sukisu_kpm_free_generated_exec(chain->stub, SUKISU_KPM_X86_WRAP_STUB_SIZE, false);
    kfree(chain);
}

static void sukisu_kpm_retire_syscall_wrap_chain_work(struct work_struct *work)
{
    struct sukisu_kpm_syscall_wrap_chain *chain = container_of(work, struct sukisu_kpm_syscall_wrap_chain, retire_work);

    sukisu_kpm_sync_before_exec_free();
    sukisu_kpm_wait_chain_idle(&chain->active, &chain->idle_wait);
    sukisu_kpm_free_generated_exec(chain->stub, SUKISU_KPM_X86_WRAP_STUB_SIZE, false);
    kfree(chain);
}

static void sukisu_kpm_retire_wrap_chain(struct sukisu_kpm_wrap_chain *chain,
                                         struct sukisu_kpm_inline_hook *retired_hook)
{
    sukisu_kpm_sync_before_exec_free();
    if (atomic_read(&chain->active)) {
        chain->retired_hook = retired_hook;
        if (!schedule_work(&chain->retire_work))
            pr_err("kpm: failed to queue inline wrapper retirement for %px; allocation retained\n",
                   (void *)(unsigned long)chain->hook.func_addr);
        return;
    }

    sukisu_kpm_retire_inline_hook(retired_hook, false);
    sukisu_kpm_free_generated_exec(chain->stub, SUKISU_KPM_X86_WRAP_STUB_SIZE, false);
    kfree(chain);
}

static void sukisu_kpm_retire_fp_wrap_chain(struct sukisu_kpm_fp_wrap_chain *chain)
{
    sukisu_kpm_sync_before_exec_free();
    if (atomic_read(&chain->active)) {
        if (!schedule_work(&chain->retire_work))
            pr_err("kpm: failed to queue function-pointer wrapper retirement for %px; allocation retained\n",
                   (void *)chain->hook.fp_addr);
        return;
    }

    sukisu_kpm_free_generated_exec(chain->stub, SUKISU_KPM_X86_WRAP_STUB_SIZE, false);
    kfree(chain);
}

static void sukisu_kpm_retire_syscall_wrap_chain(struct sukisu_kpm_syscall_wrap_chain *chain)
{
    sukisu_kpm_sync_before_exec_free();
    if (atomic_read(&chain->active)) {
        if (!schedule_work(&chain->retire_work))
            pr_err("kpm: failed to queue syscall wrapper retirement for nr=%d; allocation retained\n", chain->nr);
        return;
    }

    sukisu_kpm_free_generated_exec(chain->stub, SUKISU_KPM_X86_WRAP_STUB_SIZE, false);
    kfree(chain);
}

static struct sukisu_kpm_wrap_chain *sukisu_kpm_find_wrap_chain_locked(void *func)
{
    struct sukisu_kpm_wrap_chain *pos;

    list_for_each_entry (pos, &sukisu_kpm_wrap_chains, list) {
        if ((void *)pos->hook.func_addr == func)
            return pos;
    }

    return NULL;
}

static struct sukisu_kpm_wrap_chain *sukisu_kpm_find_wrap_chain_by_chain_locked(void *chain)
{
    struct sukisu_kpm_wrap_chain *pos;

    list_for_each_entry (pos, &sukisu_kpm_wrap_chains, list) {
        if ((void *)pos == chain)
            return pos;
    }

    return NULL;
}

static struct sukisu_kpm_fp_wrap_chain *sukisu_kpm_find_fp_wrap_chain_locked(unsigned long fp_addr)
{
    struct sukisu_kpm_fp_wrap_chain *pos;

    list_for_each_entry (pos, &sukisu_kpm_fp_wrap_chains, list) {
        if (pos->hook.fp_addr == fp_addr)
            return pos;
    }

    return NULL;
}

static struct sukisu_kpm_fp_hook *sukisu_kpm_find_fp_hook_locked(unsigned long fp_addr, void *backup)
{
    struct sukisu_kpm_fp_hook *pos;

    list_for_each_entry (pos, &sukisu_kpm_fp_hooks, list) {
        if (pos->fp_addr == fp_addr && (!backup || pos->backup == backup))
            return pos;
    }

    return NULL;
}

static unsigned long sukisu_kpm_sys_call_table_addr(void)
{
    unsigned long addr;

    addr = sukisu_compact_find_symbol("sys_call_table");
    if (!addr)
        addr = kallsyms_lookup_name("sys_call_table");
    return addr;
}

static unsigned long *sukisu_kpm_syscalln_slot(int nr, int is_compat)
{
    unsigned long *table;

    if (is_compat || nr < 0 || nr >= __NR_syscalls)
        return NULL;
    table = (unsigned long *)sukisu_kpm_sys_call_table_addr();
    if (!table)
        return NULL;
    return &table[nr];
}

static struct sukisu_kpm_syscall_wrap_chain *sukisu_kpm_find_syscall_wrap_chain_locked(int nr)
{
    struct sukisu_kpm_syscall_wrap_chain *pos;

    list_for_each_entry (pos, &sukisu_kpm_syscall_wrap_chains, list) {
        if (pos->nr == nr)
            return pos;
    }

    return NULL;
}

static void sukisu_kpm_syscall_regs_to_args(struct pt_regs *regs, u64 *args)
{
    memset(args, 0, sizeof(u64) * SUKISU_KPM_WRAP_ARG_MAX);
    if (!regs)
        return;
    args[0] = regs->di;
    args[1] = regs->si;
    args[2] = regs->dx;
    args[3] = regs->r10;
    args[4] = regs->r8;
    args[5] = regs->r9;
}

static void sukisu_kpm_syscall_args_to_regs(struct pt_regs *regs, const u64 *args)
{
    if (!regs || !args)
        return;
    regs->di = args[0];
    regs->si = args[1];
    regs->dx = args[2];
    regs->r10 = args[3];
    regs->r8 = args[4];
    regs->r9 = args[5];
}

static u64 sukisu_kpm_syscall_wrap_dispatch(struct sukisu_kpm_syscall_wrap_chain *chain, struct pt_regs *regs)
{
    struct sukisu_kpm_hook_fargs12 fargs;
    u64 ret;
    int i;
    int argno;

    if (!chain || !regs)
        return -EINVAL;

    argno = chain->argno;
    if (argno < 0)
        argno = 0;
    if (argno > 6)
        argno = 6;

    atomic_inc(&chain->active);
    memset(&fargs, 0, sizeof(fargs));
    fargs.chain = chain;
    sukisu_kpm_syscall_regs_to_args(regs, fargs.args);

    if (!smp_load_acquire(&chain->disabled)) {
        for (i = 0; i < SUKISU_KPM_SYSCALL_HOOK_CHAIN_NUM; i++) {
            struct sukisu_kpm_chain_call call;

            if (!sukisu_kpm_acquire_chain_call(&chain->states[i], &chain->befores[i], &chain->udata[i],
                                               &chain->owners[i], &call))
                continue;
            call.callback(&fargs, call.udata);
            sukisu_kpm_release_chain_call(&call);
        }
    }

    if (!fargs.skip_origin) {
        sukisu_kpm_syscall_args_to_regs(regs, fargs.args);
        fargs.ret = ((long (*)(const struct pt_regs *))chain->origin)(regs);
    }

    if (!smp_load_acquire(&chain->disabled)) {
        for (i = 0; i < SUKISU_KPM_SYSCALL_HOOK_CHAIN_NUM; i++) {
            struct sukisu_kpm_chain_call call;

            if (!sukisu_kpm_acquire_chain_call(&chain->states[i], &chain->afters[i], &chain->udata[i],
                                               &chain->owners[i], &call))
                continue;
            call.callback(&fargs, call.udata);
            sukisu_kpm_release_chain_call(&call);
        }
    }

    ret = fargs.ret;
    if (atomic_dec_and_test(&chain->active))
        wake_up_all(&chain->idle_wait);
    return ret;
}

static void *sukisu_kpm_make_syscall_wrap_stub(struct sukisu_kpm_syscall_wrap_chain *chain)
{
    u8 *stub;
    u8 *p;
    int rc;

    stub = module_alloc(SUKISU_KPM_X86_WRAP_STUB_SIZE);
    if (!stub)
        return NULL;

    rc = sukisu_kpm_set_exec_rw_nx(stub, SUKISU_KPM_X86_WRAP_STUB_SIZE);
    if (rc) {
        module_memfree(stub);
        return NULL;
    }

    memset(stub, 0xcc, SUKISU_KPM_X86_WRAP_STUB_SIZE);
    p = stub;
    sukisu_kpm_emit_sub_rsp(&p, 8);
    sukisu_kpm_emit_mov_rsi_rdi(&p);
    sukisu_kpm_emit_movabs_rdi(&p, (u64)chain);
    sukisu_kpm_emit_movabs_rax(&p, (u64)sukisu_kpm_syscall_wrap_dispatch);
    sukisu_kpm_emit1(&p, 0xff);
    sukisu_kpm_emit1(&p, 0xd0);
    sukisu_kpm_emit_add_rsp(&p, 8);
    sukisu_kpm_emit1(&p, 0xc3);

    if (p - stub > SUKISU_KPM_X86_WRAP_STUB_SIZE) {
        sukisu_kpm_free_generated_exec(stub, SUKISU_KPM_X86_WRAP_STUB_SIZE, false);
        return NULL;
    }

    rc = sukisu_kpm_set_exec_rox(stub, SUKISU_KPM_X86_WRAP_STUB_SIZE);
    if (rc) {
        sukisu_kpm_free_generated_exec(stub, SUKISU_KPM_X86_WRAP_STUB_SIZE, false);
        return NULL;
    }
    return stub;
}

static int sukisu_kpm_syscall_wrap(int nr, int narg, int is_compat, void *before, void *after, void *udata)
{
    struct sukisu_kpm_syscall_wrap_chain *chain;
    unsigned long *slot;
    bool created = false;
    void *origin = NULL;
    int rc;

    if (is_compat)
        return -EOPNOTSUPP;
    if (narg < 0 || narg > 6)
        return SUKISU_KPM_HOOK_BAD_ADDRESS;

    slot = sukisu_kpm_syscalln_slot(nr, is_compat);
    if (!slot)
        return SUKISU_KPM_HOOK_BAD_ADDRESS;

    mutex_lock(&sukisu_kpm_hook_lock);
    chain = sukisu_kpm_find_syscall_wrap_chain_locked(nr);
    if (chain) {
        if (chain->argno != narg) {
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

    chain->nr = nr;
    chain->argno = narg;
    chain->slot_addr = (unsigned long)slot;
    chain->owner = sukisu_kpm_current_module();
    atomic_set(&chain->active, 0);
    init_waitqueue_head(&chain->idle_wait);
    INIT_WORK(&chain->retire_work, sukisu_kpm_retire_syscall_wrap_chain_work);
    chain->stub = sukisu_kpm_make_syscall_wrap_stub(chain);
    if (!chain->stub) {
        kfree(chain);
        mutex_unlock(&sukisu_kpm_hook_lock);
        return SUKISU_KPM_HOOK_TRANSIT_NO_MEM;
    }

    rc = copy_from_kernel_nofault(&origin, slot, sizeof(origin));
    if (rc) {
        sukisu_kpm_free_generated_exec(chain->stub, SUKISU_KPM_X86_WRAP_STUB_SIZE, false);
        kfree(chain);
        mutex_unlock(&sukisu_kpm_hook_lock);
        return SUKISU_KPM_HOOK_BAD_ADDRESS;
    }

    chain->origin = origin;
    rc = sukisu_kpm_patch_pointer_if_matches((unsigned long)slot, origin, chain->stub);
    if (rc) {
        sukisu_kpm_free_generated_exec(chain->stub, SUKISU_KPM_X86_WRAP_STUB_SIZE, false);
        kfree(chain);
        mutex_unlock(&sukisu_kpm_hook_lock);
        return SUKISU_KPM_HOOK_TEXT_POKE_FAILED;
    }

    list_add(&chain->list, &sukisu_kpm_syscall_wrap_chains);
    created = true;

add_item:
    rc = sukisu_kpm_add_chain_item(chain->states, chain->owners, SUKISU_KPM_SYSCALL_HOOK_CHAIN_NUM, chain->befores,
                                   chain->afters, chain->udata, before, after, udata, sukisu_kpm_current_module(),
                                   SUKISU_KPM_REF_SYSCALL_WRAP);
    if (rc && created) {
        smp_store_release(&chain->disabled, true);
        if (!sukisu_kpm_patch_pointer_if_matches(chain->slot_addr, chain->stub, origin)) {
            list_del(&chain->list);
            mutex_unlock(&sukisu_kpm_hook_lock);
            sukisu_kpm_retire_syscall_wrap_chain(chain);
            return rc;
        }
        smp_store_release(&chain->disabled, false);
    }
    mutex_unlock(&sukisu_kpm_hook_lock);
    return rc;
}

static void sukisu_kpm_syscall_unwrap(int nr, int is_compat, void *before, void *after)
{
    struct sukisu_kpm_syscall_wrap_chain *chain;
    struct sukisu_kpm_module *retired_owner = NULL;
    bool retire_chain = false;
    bool removed;
    int retired_index = -1;
    int rc = 0;

    if (is_compat)
        return;

    mutex_lock(&sukisu_kpm_hook_lock);
    chain = sukisu_kpm_find_syscall_wrap_chain_locked(nr);
    if (!chain) {
        mutex_unlock(&sukisu_kpm_hook_lock);
        return;
    }

    removed = sukisu_kpm_remove_chain_item(chain->states, chain->owners, SUKISU_KPM_SYSCALL_HOOK_CHAIN_NUM,
                                           chain->befores, chain->afters, chain->udata, before, after,
                                           SUKISU_KPM_REF_SYSCALL_WRAP, &retired_owner, &retired_index);
    if (!removed) {
        mutex_unlock(&sukisu_kpm_hook_lock);
        return;
    }
    mutex_unlock(&sukisu_kpm_hook_lock);

    sukisu_kpm_sync_before_exec_free();

    mutex_lock(&sukisu_kpm_hook_lock);
    sukisu_kpm_finish_chain_item_locked(chain->states, chain->owners, chain->befores, chain->afters, chain->udata,
                                        retired_index, retired_owner);
    if (sukisu_kpm_has_chain_items(chain->states, SUKISU_KPM_SYSCALL_HOOK_CHAIN_NUM)) {
        mutex_unlock(&sukisu_kpm_hook_lock);
        return;
    }
    smp_store_release(&chain->disabled, true);
    rc = sukisu_kpm_patch_pointer_if_matches(chain->slot_addr, chain->stub, chain->origin);
    if (!rc) {
        list_del(&chain->list);
        retire_chain = true;
    } else
        smp_store_release(&chain->disabled, false);
    mutex_unlock(&sukisu_kpm_hook_lock);

    if (retire_chain)
        sukisu_kpm_retire_syscall_wrap_chain(chain);
    else if (rc)
        pr_warn("kpm: syscall unwrap restore refused for nr=%d: %d\n", nr, rc);
}

static unsigned long sukisu_kpm_syscalln_addr(int nr, int is_compat)
{
    unsigned long *slot;

    slot = sukisu_kpm_syscalln_slot(nr, is_compat);
    if (!slot)
        return 0;
    return READ_ONCE(*slot);
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

static int sukisu_kpm_inline_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata)
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

    if (!kp_hook || sukisu_kpm_bad_hook_target_addr((unsigned long)kp_hook->func_addr) ||
        sukisu_kpm_bad_exec_addr((unsigned long)kp_hook->replace_addr, false))
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
    if (sukisu_kpm_install_inline_hook_locked((void *)kp_hook->func_addr, (void *)kp_hook->replace_addr, &backup,
                                              false) == SUKISU_KPM_HOOK_NO_ERR)
        kp_hook->relo_addr = (u64)backup;
    mutex_unlock(&sukisu_kpm_hook_lock);
}

static void sukisu_kpm_hook_uninstall(void *hook)
{
    struct sukisu_kpm_kp_hook *kp_hook = hook;
    struct sukisu_kpm_inline_hook *retired = NULL;

    if (!kp_hook)
        return;

    mutex_lock(&sukisu_kpm_hook_lock);
    sukisu_kpm_unhook_locked((void *)kp_hook->func_addr, &retired);
    mutex_unlock(&sukisu_kpm_hook_lock);
    sukisu_kpm_retire_inline_hook(retired, true);
}

static int sukisu_kpm_hook(void *func, void *replace, void **backup)
{
    int rc;

    mutex_lock(&sukisu_kpm_hook_lock);
    rc = sukisu_kpm_install_inline_hook_locked(func, replace, backup, false);
    mutex_unlock(&sukisu_kpm_hook_lock);
    return rc;
}

static void sukisu_kpm_unhook(void *func)
{
    struct sukisu_kpm_inline_hook *retired = NULL;
    int rc;

    mutex_lock(&sukisu_kpm_hook_lock);
    rc = sukisu_kpm_unhook_locked(func, &retired);
    mutex_unlock(&sukisu_kpm_hook_lock);

    if (!rc)
        sukisu_kpm_retire_inline_hook(retired, true);
    else
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

    rc = sukisu_kpm_add_chain_item(wrap->states, wrap->owners, SUKISU_KPM_HOOK_CHAIN_NUM, wrap->befores, wrap->afters,
                                   wrap->udata, before, after, udata, sukisu_kpm_current_module(), SUKISU_KPM_REF_WRAP);
    mutex_unlock(&sukisu_kpm_hook_lock);
    return rc;
}

static void sukisu_kpm_hook_chain_remove(void *chain, void *before, void *after)
{
    struct sukisu_kpm_module *retired_owner = NULL;
    struct sukisu_kpm_wrap_chain *wrap;
    bool removed;
    int retired_index = -1;

    mutex_lock(&sukisu_kpm_hook_lock);
    wrap = sukisu_kpm_find_wrap_chain_by_chain_locked(chain);
    if (!wrap) {
        mutex_unlock(&sukisu_kpm_hook_lock);
        return;
    }

    removed =
        sukisu_kpm_remove_chain_item(wrap->states, wrap->owners, SUKISU_KPM_HOOK_CHAIN_NUM, wrap->befores, wrap->afters,
                                     wrap->udata, before, after, SUKISU_KPM_REF_WRAP, &retired_owner, &retired_index);
    mutex_unlock(&sukisu_kpm_hook_lock);

    if (removed) {
        sukisu_kpm_sync_before_exec_free();
        mutex_lock(&sukisu_kpm_hook_lock);
        sukisu_kpm_finish_chain_item_locked(wrap->states, wrap->owners, wrap->befores, wrap->afters, wrap->udata,
                                            retired_index, retired_owner);
        mutex_unlock(&sukisu_kpm_hook_lock);
    }
}

static int sukisu_kpm_hook_wrap(void *func, int argno, void *before, void *after, void *udata)
{
    struct sukisu_kpm_wrap_chain *chain;
    struct sukisu_kpm_inline_hook *retired_hook = NULL;
    bool created = false;
    bool retire_chain = false;
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
    chain->owner = sukisu_kpm_current_module();
    atomic_set(&chain->active, 0);
    init_waitqueue_head(&chain->idle_wait);
    INIT_WORK(&chain->retire_work, sukisu_kpm_retire_wrap_chain_work);
    chain->stub = sukisu_kpm_make_wrap_stub(chain, argno, sukisu_kpm_wrap_dispatch);
    if (!chain->stub) {
        kfree(chain);
        mutex_unlock(&sukisu_kpm_hook_lock);
        return SUKISU_KPM_HOOK_TRANSIT_NO_MEM;
    }

    rc = sukisu_kpm_install_inline_hook_locked(func, chain->stub, &backup, true);
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
    rc = sukisu_kpm_add_chain_item(chain->states, chain->owners, SUKISU_KPM_HOOK_CHAIN_NUM, chain->befores,
                                   chain->afters, chain->udata, before, after, udata, sukisu_kpm_current_module(),
                                   SUKISU_KPM_REF_WRAP);
    if (rc && created) {
        smp_store_release(&chain->disabled, true);
        if (!sukisu_kpm_unhook_locked(func, &retired_hook)) {
            list_del(&chain->list);
            retire_chain = true;
        } else {
            smp_store_release(&chain->disabled, false);
        }
    }
    mutex_unlock(&sukisu_kpm_hook_lock);

    if (retire_chain)
        sukisu_kpm_retire_wrap_chain(chain, retired_hook);
    return rc;
}

static void sukisu_kpm_hook_unwrap_remove(void *func, void *before, void *after, int remove)
{
    struct sukisu_kpm_wrap_chain *chain;
    struct sukisu_kpm_inline_hook *retired_hook = NULL;
    struct sukisu_kpm_module *retired_owner = NULL;
    bool retire_chain = false;
    bool removed;
    int retired_index = -1;
    int rc = 0;

    mutex_lock(&sukisu_kpm_hook_lock);
    chain = sukisu_kpm_find_wrap_chain_locked(func);
    if (!chain) {
        mutex_unlock(&sukisu_kpm_hook_lock);
        return;
    }

    removed = sukisu_kpm_remove_chain_item(chain->states, chain->owners, SUKISU_KPM_HOOK_CHAIN_NUM, chain->befores,
                                           chain->afters, chain->udata, before, after, SUKISU_KPM_REF_WRAP,
                                           &retired_owner, &retired_index);
    if (!removed) {
        mutex_unlock(&sukisu_kpm_hook_lock);
        return;
    }

    mutex_unlock(&sukisu_kpm_hook_lock);

    sukisu_kpm_sync_before_exec_free();

    mutex_lock(&sukisu_kpm_hook_lock);
    sukisu_kpm_finish_chain_item_locked(chain->states, chain->owners, chain->befores, chain->afters, chain->udata,
                                        retired_index, retired_owner);
    if (!remove || sukisu_kpm_has_chain_items(chain->states, SUKISU_KPM_HOOK_CHAIN_NUM)) {
        mutex_unlock(&sukisu_kpm_hook_lock);
        return;
    }
    smp_store_release(&chain->disabled, true);
    rc = sukisu_kpm_unhook_locked(func, &retired_hook);
    if (!rc) {
        list_del(&chain->list);
        retire_chain = true;
    } else
        smp_store_release(&chain->disabled, false);
    mutex_unlock(&sukisu_kpm_hook_lock);

    if (retire_chain)
        sukisu_kpm_retire_wrap_chain(chain, retired_hook);
    else if (rc)
        pr_warn("kpm: x86_64 unwrap restore refused for %px: %d\n", func, rc);
}

static void sukisu_kpm_fp_hook(unsigned long fp_addr, void *replace, void **backup)
{
    struct sukisu_kpm_fp_hook *hook;
    void *origin = NULL;
    int rc;

    if (backup)
        *backup = NULL;

    hook = kzalloc(sizeof(*hook), GFP_KERNEL);
    if (!hook) {
        pr_warn("kpm: x86_64 fp_hook failed for %px: %d\n", (void *)fp_addr, -ENOMEM);
        return;
    }
    INIT_WORK(&hook->retire_work, sukisu_kpm_retire_fp_hook_work);
    init_task_work(&hook->retire_task_work, sukisu_kpm_retire_fp_hook_task_work);

    mutex_lock(&sukisu_kpm_hook_lock);
    if (sukisu_kpm_find_fp_hook_locked(fp_addr, NULL) || sukisu_kpm_find_fp_wrap_chain_locked(fp_addr)) {
        mutex_unlock(&sukisu_kpm_hook_lock);
        kfree(hook);
        pr_warn("kpm: x86_64 fp_hook duplicate for %px\n", (void *)fp_addr);
        return;
    }

    rc = sukisu_kpm_patch_function_pointer(fp_addr, replace, &origin);
    if (!rc) {
        hook->fp_addr = fp_addr;
        hook->replace = replace;
        hook->backup = origin;
        hook->owner = sukisu_kpm_current_module();
        list_add(&hook->list, &sukisu_kpm_fp_hooks);
        sukisu_kpm_module_ref_delta(hook->owner, SUKISU_KPM_REF_FP, 1);
        if (backup)
            *backup = origin;
    }
    mutex_unlock(&sukisu_kpm_hook_lock);

    if (rc) {
        kfree(hook);
        pr_warn("kpm: x86_64 fp_hook failed for %px: %d\n", (void *)fp_addr, rc);
    }
}

static void sukisu_kpm_fp_unhook(unsigned long fp_addr, void *backup)
{
    struct sukisu_kpm_fp_hook *hook;
    int rc;

    if (!backup || sukisu_kpm_bad_kernel_addr(fp_addr))
        return;

    mutex_lock(&sukisu_kpm_hook_lock);
    hook = sukisu_kpm_find_fp_hook_locked(fp_addr, backup);
    if (!hook) {
        mutex_unlock(&sukisu_kpm_hook_lock);
        pr_warn("kpm: x86_64 fp_unhook missing record for %px\n", (void *)fp_addr);
        return;
    }

    rc = sukisu_kpm_patch_pointer_if_matches(fp_addr, hook->replace, backup);
    if (rc) {
        mutex_unlock(&sukisu_kpm_hook_lock);
        pr_warn("kpm: x86_64 fp_unhook failed for %px: %d\n", (void *)fp_addr, rc);
        return;
    }

    list_del(&hook->list);
    sukisu_kpm_begin_owner_quiesce_locked(hook->owner);
    sukisu_kpm_module_ref_delta(hook->owner, SUKISU_KPM_REF_FP, -1);
    mutex_unlock(&sukisu_kpm_hook_lock);

    if (sukisu_kpm_should_defer_owner_retire(hook->owner)) {
        if (task_work_add(current, &hook->retire_task_work, TWA_RESUME))
            pr_err("kpm: failed to queue function-pointer hook task retirement for %px; record retained\n",
                   (void *)fp_addr);
        return;
    }
    sukisu_kpm_sync_before_exec_free();
    sukisu_kpm_end_owner_quiesce(hook->owner);
    kfree(hook);
}

static int sukisu_kpm_fp_hook_wrap(unsigned long fp_addr, int argno, void *before, void *after, void *udata)
{
    struct sukisu_kpm_fp_wrap_chain *chain;
    bool created = false;
    bool retire_chain = false;
    void *backup = NULL;
    int rc;

    if (argno < 0 || argno > SUKISU_KPM_WRAP_ARG_MAX)
        return SUKISU_KPM_HOOK_BAD_ADDRESS;

    mutex_lock(&sukisu_kpm_hook_lock);
    if (sukisu_kpm_find_fp_hook_locked(fp_addr, NULL)) {
        mutex_unlock(&sukisu_kpm_hook_lock);
        return SUKISU_KPM_HOOK_DUPLICATED;
    }
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
    chain->owner = sukisu_kpm_current_module();
    atomic_set(&chain->active, 0);
    init_waitqueue_head(&chain->idle_wait);
    INIT_WORK(&chain->retire_work, sukisu_kpm_retire_fp_wrap_chain_work);
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
    rc = sukisu_kpm_add_chain_item(chain->states, chain->owners, SUKISU_KPM_FP_HOOK_CHAIN_NUM, chain->befores,
                                   chain->afters, chain->udata, before, after, udata, sukisu_kpm_current_module(),
                                   SUKISU_KPM_REF_FP_WRAP);
    if (rc && created) {
        smp_store_release(&chain->disabled, true);
        if (!sukisu_kpm_patch_pointer_if_matches(fp_addr, chain->stub, backup)) {
            list_del(&chain->list);
            retire_chain = true;
        } else {
            smp_store_release(&chain->disabled, false);
        }
    }
    mutex_unlock(&sukisu_kpm_hook_lock);

    if (retire_chain)
        sukisu_kpm_retire_fp_wrap_chain(chain);
    return rc;
}

static void sukisu_kpm_fp_hook_unwrap(unsigned long fp_addr, void *before, void *after)
{
    struct sukisu_kpm_fp_wrap_chain *chain;
    struct sukisu_kpm_module *retired_owner = NULL;
    bool retire_chain = false;
    bool removed;
    int retired_index = -1;
    int rc = 0;

    mutex_lock(&sukisu_kpm_hook_lock);
    chain = sukisu_kpm_find_fp_wrap_chain_locked(fp_addr);
    if (!chain) {
        mutex_unlock(&sukisu_kpm_hook_lock);
        return;
    }

    removed = sukisu_kpm_remove_chain_item(chain->states, chain->owners, SUKISU_KPM_FP_HOOK_CHAIN_NUM, chain->befores,
                                           chain->afters, chain->udata, before, after, SUKISU_KPM_REF_FP_WRAP,
                                           &retired_owner, &retired_index);
    if (!removed) {
        mutex_unlock(&sukisu_kpm_hook_lock);
        return;
    }

    mutex_unlock(&sukisu_kpm_hook_lock);

    sukisu_kpm_sync_before_exec_free();

    mutex_lock(&sukisu_kpm_hook_lock);
    sukisu_kpm_finish_chain_item_locked(chain->states, chain->owners, chain->befores, chain->afters, chain->udata,
                                        retired_index, retired_owner);
    if (sukisu_kpm_has_chain_items(chain->states, SUKISU_KPM_FP_HOOK_CHAIN_NUM)) {
        mutex_unlock(&sukisu_kpm_hook_lock);
        return;
    }
    smp_store_release(&chain->disabled, true);
    rc = sukisu_kpm_patch_pointer_if_matches(fp_addr, chain->stub, (void *)chain->hook.origin_fp);
    if (!rc) {
        list_del(&chain->list);
        retire_chain = true;
    } else
        smp_store_release(&chain->disabled, false);
    mutex_unlock(&sukisu_kpm_hook_lock);

    if (retire_chain)
        sukisu_kpm_retire_fp_wrap_chain(chain);
    else if (rc)
        pr_warn("kpm: x86_64 fp unwrap restore refused for %px: %d\n", (void *)fp_addr, rc);
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
    { "kpm_loader_version", (unsigned long)&sukisu_kpm_loader_version_string },
    { "kpm_loader_abi_version", (unsigned long)&sukisu_kpm_loader_abi_version },
    { "kpm_abi_version", (unsigned long)&sukisu_kpm_loader_abi_version },
    { "kpm_loader_feature_bits", (unsigned long)&sukisu_kpm_loader_feature_bits },
    { "kpm_feature_bits", (unsigned long)&sukisu_kpm_loader_feature_bits },
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

static bool sukisu_kpm_string_in_table(const char *table, size_t table_size, size_t offset)
{
    if (!table || offset >= table_size)
        return false;

    return memchr(table + offset, '\0', table_size - offset) != NULL;
}

static bool sukisu_kpm_file_ranges_overlap(u64 first_offset, u64 first_size, u64 second_offset, u64 second_size)
{
    return first_size && second_size && first_offset < second_offset + second_size &&
           second_offset < first_offset + first_size;
}

static int sukisu_kpm_add_layout_size(unsigned int *size, const Elf_Shdr *sechdr, Elf64_Xword *offset)
{
    u64 align = sechdr->sh_addralign ? sechdr->sh_addralign : 1;
    u64 aligned;
    u64 next;

    if (check_add_overflow((u64)*size, align - 1, &aligned))
        return -EOVERFLOW;
    aligned &= ~(align - 1);
    if (check_add_overflow(aligned, (u64)sechdr->sh_size, &next) || next > SUKISU_KPM_MAX_LOADED_SIZE)
        return -EFBIG;

    *offset = aligned;
    *size = next;
    return 0;
}

static int sukisu_kpm_page_align_layout(unsigned int *size)
{
    u64 aligned;

    if (check_add_overflow((u64)*size, (u64)PAGE_SIZE - 1, &aligned))
        return -EOVERFLOW;
    aligned &= PAGE_MASK;
    if (aligned > SUKISU_KPM_MAX_LOADED_SIZE)
        return -EFBIG;

    *size = aligned;
    return 0;
}

static bool sukisu_kpm_reloc_uses_got(unsigned int type)
{
    return type == R_X86_64_GOTPCREL || type == R_X86_64_GOTPCRELX || type == R_X86_64_REX_GOTPCRELX;
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
            if (sukisu_kpm_reloc_uses_got(ELF64_R_TYPE(rel[j].r_info))) {
                if (count >= SUKISU_KPM_MAX_LOADED_SIZE / sizeof(u64))
                    return -EFBIG;
                count++;
            }
        }
    }

    info->got_entries = count;
    return 0;
}

static int sukisu_kpm_layout_sections(struct sukisu_kpm_module *mod, struct sukisu_kpm_load_info *info)
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

            if ((s->sh_flags & masks[m][0]) != masks[m][0] || (s->sh_flags & masks[m][1]) || s->sh_entsize != ~0UL)
                continue;

            if (sukisu_kpm_add_layout_size(&mod->size, s, &s->sh_entsize))
                return -EFBIG;
        }

        if (sukisu_kpm_page_align_layout(&mod->size))
            return -EFBIG;
        if (m == 0) {
            mod->text_size = mod->size;
        } else if (m == 1) {
            mod->ro_size = mod->size;
        }
    }

    if (info->got_entries) {
        u64 got_size;

        if (check_mul_overflow((u64)info->got_entries, (u64)sizeof(u64), &got_size))
            return -EOVERFLOW;
        mod->size = ALIGN(mod->size, sizeof(u64));
        info->got_offset = mod->size;
        if (got_size > SUKISU_KPM_MAX_LOADED_SIZE - mod->size)
            return -EFBIG;
        mod->size += got_size;
        if (sukisu_kpm_page_align_layout(&mod->size))
            return -EFBIG;
    }

    return mod->size ? 0 : -ENOEXEC;
}

static int sukisu_kpm_rewrite_section_headers(struct sukisu_kpm_load_info *info)
{
    const Elf_Shdr *shstr = &info->sechdrs[info->hdr->e_shstrndx];
    u64 shdr_bytes = (u64)info->hdr->e_shnum * sizeof(Elf_Shdr);
    int i;

    info->sechdrs[0].sh_addr = 0;
    for (i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];

        if (!sukisu_kpm_string_in_table(info->secstrings, shstr->sh_size, shdr->sh_name))
            return -ENOEXEC;
        if (shdr->sh_addralign > PAGE_SIZE || (shdr->sh_addralign && !is_power_of_2(shdr->sh_addralign)))
            return -ENOEXEC;
        if (shdr->sh_addralign > 1 && !IS_ALIGNED(shdr->sh_offset, shdr->sh_addralign))
            return -ENOEXEC;
        if ((shdr->sh_flags & (SHF_WRITE | SHF_EXECINSTR)) == (SHF_WRITE | SHF_EXECINSTR))
            return -ENOEXEC;
        if ((shdr->sh_flags & SHF_ALLOC) && shdr->sh_type != SHT_PROGBITS && shdr->sh_type != SHT_NOBITS)
            return -ENOEXEC;
        if (shdr->sh_type == SHT_NOBITS && (shdr->sh_flags & SHF_EXECINSTR))
            return -ENOEXEC;
        if ((shdr->sh_flags & SHF_ALLOC) &&
            ((shdr->sh_flags & (SHF_COMPRESSED | SHF_TLS)) || shdr->sh_size > SUKISU_KPM_MAX_LOADED_SIZE))
            return -ENOEXEC;

        if (shdr->sh_type != SHT_NOBITS) {
            int j;

            if (shdr->sh_offset > info->len || shdr->sh_size > info->len - shdr->sh_offset)
                return -ENOEXEC;
            if (sukisu_kpm_file_ranges_overlap(shdr->sh_offset, shdr->sh_size, 0, sizeof(*info->hdr)) ||
                sukisu_kpm_file_ranges_overlap(shdr->sh_offset, shdr->sh_size, info->hdr->e_shoff, shdr_bytes))
                return -ENOEXEC;
            for (j = 1; j < i; j++) {
                const Elf_Shdr *prev = &info->sechdrs[j];

                if (prev->sh_type != SHT_NOBITS &&
                    sukisu_kpm_file_ranges_overlap(shdr->sh_offset, shdr->sh_size, prev->sh_offset, prev->sh_size))
                    return -ENOEXEC;
            }
            shdr->sh_addr = (unsigned long)info->hdr + shdr->sh_offset;
        } else if (shdr->sh_offset > info->len) {
            return -ENOEXEC;
        }
    }

    return 0;
}

static bool sukisu_kpm_is_immutable_metadata_section(const char *name)
{
    return !strcmp(name, ".kpm.info") || !strcmp(name, ".kpm.init") || !strcmp(name, ".kpm.exit") ||
           !strcmp(name, ".kpm.ctl0") || !strcmp(name, ".kpm.ctl1");
}

static int sukisu_kpm_validate_special_sections(const struct sukisu_kpm_load_info *info)
{
    static const struct {
        const char *name;
        size_t size;
        bool required;
    } special[] = {
        { ".kpm.info", 0, true },
        { ".kpm.init", sizeof(sukisu_kpm_initcall_t), true },
        { ".kpm.exit", sizeof(sukisu_kpm_exitcall_t), true },
        { ".kpm.ctl0", sizeof(sukisu_kpm_ctl0call_t), false },
        { ".kpm.ctl1", sizeof(sukisu_kpm_ctl1call_t), false },
    };
    unsigned int counts[ARRAY_SIZE(special)] = { 0 };
    int i;
    int j;

    for (i = 1; i < info->hdr->e_shnum; i++) {
        const Elf_Shdr *shdr = &info->sechdrs[i];
        const char *name;

        if (!(shdr->sh_flags & SHF_ALLOC))
            continue;
        name = info->secstrings + shdr->sh_name;
        for (j = 0; j < ARRAY_SIZE(special); j++) {
            if (strcmp(name, special[j].name))
                continue;
            counts[j]++;
            if (counts[j] > 1 || shdr->sh_type != SHT_PROGBITS || (special[j].size && shdr->sh_size != special[j].size))
                return -ENOEXEC;
        }
    }

    for (j = 0; j < ARRAY_SIZE(special); j++) {
        if (special[j].required && counts[j] != 1)
            return -ENOEXEC;
    }
    return 0;
}

static int sukisu_kpm_validate_metadata_string(const char *value, size_t max_len, bool module_name)
{
    size_t i;
    size_t len;

    if (!value)
        return -ENOEXEC;
    len = strlen(value);
    if (!len || len > max_len)
        return -ENOEXEC;

    for (i = 0; i < len; i++) {
        unsigned char c = value[i];

        if (c < 0x20 || c == 0x7f)
            return -ENOEXEC;
        if (module_name && !isalnum(c) && c != '_' && c != '-' && c != '.')
            return -ENOEXEC;
    }

    return 0;
}

static int sukisu_kpm_setup_load_info(struct sukisu_kpm_load_info *info)
{
    int i;
    int rc;
    Elf_Shdr *info_sec;

    rc = sukisu_kpm_rewrite_section_headers(info);
    if (rc)
        return rc;

    for (i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];
        const char *name = info->secstrings + shdr->sh_name;

        if (sukisu_kpm_is_immutable_metadata_section(name)) {
            if (!(shdr->sh_flags & SHF_ALLOC) || (shdr->sh_flags & SHF_EXECINSTR))
                return -ENOEXEC;
            shdr->sh_flags &= ~SHF_WRITE;
        }
    }

    rc = sukisu_kpm_validate_special_sections(info);
    if (rc) {
        pr_err("kpm: malformed or duplicate .kpm.* section\n");
        return rc;
    }

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
    if (!info_sec->sh_size || info_sec->sh_size > SUKISU_KPM_MAX_MODINFO_SIZE ||
        ((char *)info->hdr + info_sec->sh_offset)[info_sec->sh_size - 1]) {
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

    if (sukisu_kpm_validate_metadata_string(info->info.name, SUKISU_KPM_MAX_NAME_LEN, true) ||
        sukisu_kpm_validate_metadata_string(info->info.version, SUKISU_KPM_MAX_VERSION_LEN, false)) {
        pr_err("kpm: module name/version not found\n");
        return -ENOEXEC;
    }
    if ((info->info.license && sukisu_kpm_validate_metadata_string(info->info.license, 255, false)) ||
        (info->info.author && sukisu_kpm_validate_metadata_string(info->info.author, 255, false)) ||
        (info->info.description && sukisu_kpm_validate_metadata_string(info->info.description, 2047, false)))
        return -ENOEXEC;

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
    if (!info->sechdrs[info->index.sym].sh_size || info->sechdrs[info->index.sym].sh_size % sizeof(Elf_Sym) ||
        info->sechdrs[info->index.sym].sh_entsize != sizeof(Elf_Sym)) {
        pr_err("kpm: malformed symbol table size\n");
        return -ENOEXEC;
    }
    if (info->sechdrs[info->index.sym].sh_info > info->sechdrs[info->index.sym].sh_size / sizeof(Elf_Sym))
        return -ENOEXEC;
    if (info->sechdrs[info->index.str].sh_type != SHT_STRTAB || !info->sechdrs[info->index.str].sh_size) {
        pr_err("kpm: module has no usable string table\n");
        return -ENOEXEC;
    }

    info->strtab = (char *)info->hdr + info->sechdrs[info->index.str].sh_offset;
    if (info->strtab[info->sechdrs[info->index.str].sh_size - 1]) {
        pr_err("kpm: symbol string table is not NUL-terminated\n");
        return -ENOEXEC;
    }

    for (i = 1; i < info->hdr->e_shnum; i++) {
        Elf_Shdr *shdr = &info->sechdrs[i];

        if (shdr->sh_type == SHT_REL)
            return -ENOEXEC;
        if (shdr->sh_type != SHT_RELA)
            continue;
        if (shdr->sh_info >= info->hdr->e_shnum || shdr->sh_link != info->index.sym)
            return -ENOEXEC;
        if (shdr->sh_type == SHT_RELA && (shdr->sh_entsize != sizeof(Elf_Rela) || shdr->sh_size % sizeof(Elf_Rela)))
            return -ENOEXEC;
    }

    return 0;
}

static int sukisu_kpm_elf_header_check(struct sukisu_kpm_load_info *info)
{
    const Elf_Ehdr *hdr = info->hdr;
    const Elf_Shdr *shstr;
    unsigned long shdr_size;

    if (info->len < sizeof(*hdr))
        return -ENOEXEC;
    if (memcmp(hdr->e_ident, ELFMAG, SELFMAG))
        return -ENOEXEC;
    if (hdr->e_ident[EI_CLASS] != ELFCLASS64 || hdr->e_ident[EI_DATA] != ELFDATA2LSB ||
        hdr->e_ident[EI_VERSION] != EV_CURRENT || hdr->e_version != EV_CURRENT)
        return -ENOEXEC;
    if (hdr->e_type != ET_REL || hdr->e_machine != EM_X86_64)
        return -ENOEXEC;
    if (hdr->e_ehsize != sizeof(*hdr) || hdr->e_phnum || hdr->e_shentsize != sizeof(Elf_Shdr) || !hdr->e_shnum ||
        hdr->e_shnum > SUKISU_KPM_MAX_SECTIONS)
        return -ENOEXEC;
    if (hdr->e_shstrndx == SHN_UNDEF || hdr->e_shstrndx == SHN_XINDEX || hdr->e_shstrndx >= hdr->e_shnum)
        return -ENOEXEC;

    if (check_mul_overflow((unsigned long)hdr->e_shnum, sizeof(Elf_Shdr), &shdr_size))
        return -ENOEXEC;
    if (hdr->e_shoff < sizeof(*hdr) || hdr->e_shoff > info->len || shdr_size > info->len - hdr->e_shoff)
        return -ENOEXEC;

    info->sechdrs = (void *)hdr + hdr->e_shoff;
    if (info->sechdrs[0].sh_type != SHT_NULL || info->sechdrs[0].sh_size || info->sechdrs[0].sh_addr)
        return -ENOEXEC;

    shstr = &info->sechdrs[hdr->e_shstrndx];
    if (shstr->sh_type != SHT_STRTAB || !shstr->sh_size || shstr->sh_offset > info->len ||
        shstr->sh_size > info->len - shstr->sh_offset)
        return -ENOEXEC;
    info->secstrings = (void *)hdr + shstr->sh_offset;
    if (info->secstrings[shstr->sh_size - 1])
        return -ENOEXEC;

    return 0;
}

static int sukisu_kpm_move_module(struct sukisu_kpm_module *mod, struct sukisu_kpm_load_info *info)
{
    int i;
    int rc;

    mod->start = module_alloc(mod->size);
    if (!mod->start)
        return -ENOMEM;

    rc = sukisu_kpm_set_exec_rw_nx(mod->start, mod->size);
    if (rc) {
        module_memfree(mod->start);
        mod->start = NULL;
        return rc;
    }
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
        unsigned long value;

        if (!sukisu_kpm_string_in_table(info->strtab, info->sechdrs[info->index.str].sh_size, sym[i].st_name))
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
            if (sym[i].st_shndx >= SHN_LORESERVE || sym[i].st_shndx >= info->hdr->e_shnum)
                return -ENOEXEC;
            if (!(info->sechdrs[sym[i].st_shndx].sh_flags & SHF_ALLOC))
                return -ENOEXEC;
            if (sym[i].st_value > info->sechdrs[sym[i].st_shndx].sh_size ||
                sym[i].st_size > info->sechdrs[sym[i].st_shndx].sh_size - sym[i].st_value)
                return -ENOEXEC;
            secbase = info->sechdrs[sym[i].st_shndx].sh_addr;
            if (check_add_overflow(secbase, (unsigned long)sym[i].st_value, &value))
                return -EOVERFLOW;
            sym[i].st_value = value;
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
    return addr >= (unsigned long)mod->start && addr < (unsigned long)mod->start + mod->text_size;
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

        symval = symtab[sym_index].st_value;
        val = symval + rel[i].r_addend;

        switch (type) {
        case R_X86_64_NONE:
            break;
        case R_X86_64_64:
            if (sukisu_kpm_check_reloc_range(target, &rel[i], sizeof(u64)))
                return -ENOEXEC;
            loc = (void *)target->sh_addr + rel[i].r_offset;
            *(u64 *)loc = val;
            break;
        case R_X86_64_32:
            if (sukisu_kpm_check_reloc_range(target, &rel[i], sizeof(u32)))
                return -ENOEXEC;
            if (val != (u32)val)
                return -ERANGE;
            loc = (void *)target->sh_addr + rel[i].r_offset;
            *(u32 *)loc = val;
            break;
        case R_X86_64_32S:
            if (sukisu_kpm_check_reloc_range(target, &rel[i], sizeof(s32)))
                return -ENOEXEC;
            if ((s64)val != (s32)val)
                return -ERANGE;
            loc = (void *)target->sh_addr + rel[i].r_offset;
            *(s32 *)loc = val;
            break;
        case R_X86_64_PC32:
        case R_X86_64_PLT32:
            if (sukisu_kpm_check_reloc_range(target, &rel[i], sizeof(s32)))
                return -ENOEXEC;
            loc = (void *)target->sh_addr + rel[i].r_offset;
            sval = (s64)val - (s64)(unsigned long)loc;
            if (sval != (s32)sval) {
                pr_err("kpm: PC-relative relocation overflow for %s; use -mcmodel=kernel -fno-pic\n", mod->info.name);
                return -ERANGE;
            }
            *(s32 *)loc = (s32)sval;
            break;
        case R_X86_64_PC64:
            if (sukisu_kpm_check_reloc_range(target, &rel[i], sizeof(s64)))
                return -ENOEXEC;
            loc = (void *)target->sh_addr + rel[i].r_offset;
            *(s64 *)loc = (s64)val - (s64)(unsigned long)loc;
            break;
        case R_X86_64_GOTPCREL:
        case R_X86_64_GOTPCRELX:
        case R_X86_64_REX_GOTPCRELX:
            if (sukisu_kpm_check_reloc_range(target, &rel[i], sizeof(s32)))
                return -ENOEXEC;
            if (!info->got_entries || info->got_next >= info->got_entries)
                return -ENOEXEC;
            loc = (void *)target->sh_addr + rel[i].r_offset;
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

static int sukisu_kpm_disable_text_exec(struct sukisu_kpm_module *mod)
{
    int rc;

    if (!mod->start || !mod->size)
        return -EINVAL;

    rc = set_memory_nx((unsigned long)mod->start, mod->size >> PAGE_SHIFT);
    if (rc) {
        pr_err("kpm: set_memory_nx failed while disabling %s rc=%d\n", mod->info.name ? mod->info.name : "<unknown>",
               rc);
        return rc;
    }
    rc = set_memory_rw((unsigned long)mod->start, mod->size >> PAGE_SHIFT);
    if (rc)
        pr_err("kpm: set_memory_rw failed while disabling %s rc=%d\n", mod->info.name ? mod->info.name : "<unknown>",
               rc);
    return rc;
}

static void sukisu_kpm_free_module(struct sukisu_kpm_module *mod)
{
    if (!mod)
        return;

    kfree(mod->args);
    kfree(mod->ctl_args);
    kfree(mod->source_path);
    if (mod->start) {
        sukisu_kpm_sync_before_exec_free();
        if (!sukisu_kpm_disable_text_exec(mod))
            module_memfree(mod->start);
        else
            pr_err("kpm: leaking module allocation %px for safety after permission transition failure\n", mod->start);
    }
    kfree(mod);
}

static struct sukisu_kpm_module *sukisu_kpm_find_module_locked(const char *name)
{
    struct sukisu_kpm_module *pos;

    list_for_each_entry (pos, &sukisu_kpm_modules, list) {
        if (!strcmp(name, pos->info.name))
            return pos;
    }

    return NULL;
}

static unsigned int sukisu_kpm_module_active_callbacks_locked(const struct sukisu_kpm_module *mod)
{
    int active = mod ? atomic_read(&mod->active_callbacks) : 0;

    return active > 0 ? active : 0;
}

static int sukisu_kpm_module_unload_gate_locked(const struct sukisu_kpm_module *mod, unsigned int *active_callbacks)
{
    unsigned int refs = sukisu_kpm_module_hook_refs(mod);

    *active_callbacks = sukisu_kpm_module_active_callbacks_locked(mod);
    if (refs || mod->quiescing_count || *active_callbacks)
        return -EBUSY;
    return 0;
}

static bool sukisu_kpm_keep_failed_module_if_busy(struct sukisu_kpm_module *mod, const char *stage, int original_rc)
{
    unsigned int active_callbacks = 0;
    unsigned int quiescing;
    unsigned int refs;
    int gate_rc;

    mutex_lock(&sukisu_kpm_hook_lock);
    gate_rc = sukisu_kpm_module_unload_gate_locked(mod, &active_callbacks);
    refs = sukisu_kpm_module_hook_refs(mod);
    quiescing = mod->quiescing_count;
    mutex_unlock(&sukisu_kpm_hook_lock);

    if (!gate_rc)
        return false;

    mutex_lock(&sukisu_kpm_module_lock);
    if (!sukisu_kpm_find_module_locked(mod->info.name)) {
        mod->load_failed = true;
        mod->unloading = false;
        list_add_tail(&mod->list, &sukisu_kpm_modules);
        mutex_unlock(&sukisu_kpm_module_lock);
        pr_err("kpm: keeping %s resident after %s rc=%d; refs=%u quiescing=%u callbacks=%u\n", mod->info.name, stage,
               original_rc, refs, quiescing, active_callbacks);
        return true;
    }
    mutex_unlock(&sukisu_kpm_module_lock);

    pr_err("kpm: cannot free failed module %s after %s rc=%d; refs=%u quiescing=%u callbacks=%u\n", mod->info.name,
           stage, original_rc, refs, quiescing, active_callbacks);
    return true;
}

static int sukisu_kpm_load_module(const void *data, unsigned long len, const char *args, const char *event,
                                  const char *source_path, void __user *reserved)
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
    atomic_set(&mod->active_callbacks, 0);
    if (args && args[0]) {
        mod->args = kstrdup(args, GFP_KERNEL);
        if (!mod->args) {
            rc = -ENOMEM;
            goto free_mod;
        }
    }
    if (source_path && source_path[0]) {
        mod->source_path = kstrdup(source_path, GFP_KERNEL);
        if (!mod->source_path) {
            rc = -ENOMEM;
            goto free_mod;
        }
    }

    rc = sukisu_kpm_layout_sections(mod, info);
    if (rc)
        goto free_mod;

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

    rc = sukisu_kpm_enter_module_context(mod);
    if (rc)
        goto free_mod;
    init_rc = (*mod->init)(mod->args ? mod->args : "", event, reserved);
    sukisu_kpm_exit_module_context(mod);
    if (init_rc) {
        rc = init_rc < 0 ? (int)init_rc : -EINVAL;
        if (!sukisu_kpm_enter_module_context(mod)) {
            (*mod->exit)(reserved);
            sukisu_kpm_exit_module_context(mod);
        }
        if (sukisu_kpm_keep_failed_module_if_busy(mod, "init failure", rc))
            return -EBUSY;
        goto free_mod;
    }

    mutex_lock(&sukisu_kpm_module_lock);
    if (sukisu_kpm_find_module_locked(mod->info.name)) {
        mutex_unlock(&sukisu_kpm_module_lock);
        if (!sukisu_kpm_enter_module_context(mod)) {
            (*mod->exit)(reserved);
            sukisu_kpm_exit_module_context(mod);
        }
        if (sukisu_kpm_keep_failed_module_if_busy(mod, "duplicate registration", -EEXIST))
            return -EBUSY;
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
    bool write_denied = false;
    int rc;

    atomic64_inc(&sukisu_kpm_load_attempts);
    if (!path || !path[0]) {
        atomic64_inc(&sukisu_kpm_load_failures);
        return -EINVAL;
    }

    filp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(filp)) {
        pr_err("kpm: open module %s failed: %ld\n", path, PTR_ERR(filp));
        atomic64_inc(&sukisu_kpm_load_failures);
        return PTR_ERR(filp);
    }

    if (!S_ISREG(file_inode(filp)->i_mode)) {
        rc = -EINVAL;
        goto close_file;
    }
    rc = deny_write_access(filp);
    if (rc)
        goto close_file;
    write_denied = true;

    len = i_size_read(file_inode(filp));
    if (len <= 0 || len > SUKISU_KPM_MAX_MODULE_SIZE) {
        rc = -EFBIG;
        goto close_file;
    }

    data = vmalloc(len);
    if (!data) {
        rc = -ENOMEM;
        goto close_file;
    }

    while (pos < len) {
        read = kernel_read(filp, data + pos, len - pos, &pos);
        if (read <= 0) {
            rc = read < 0 ? read : -EIO;
            goto free_data;
        }
    }

    rc = sukisu_kpm_load_module(data, len, args, "load-file", path, reserved);

free_data:
    vfree(data);
close_file:
    if (write_denied)
        allow_write_access(filp);
    filp_close(filp, NULL);
    if (rc)
        atomic64_inc(&sukisu_kpm_load_failures);
    else
        atomic64_inc(&sukisu_kpm_load_successes);
    return rc;
}

int sukisu_kpm_loader_unload_module(const char *name, void __user *reserved)
{
    struct sukisu_kpm_module *mod;
    long rc;

    atomic64_inc(&sukisu_kpm_unload_attempts);
    if (!name || !name[0]) {
        atomic64_inc(&sukisu_kpm_unload_failures);
        return -EINVAL;
    }

    mutex_lock(&sukisu_kpm_module_lock);
    mod = sukisu_kpm_find_module_locked(name);
    if (!mod) {
        mutex_unlock(&sukisu_kpm_module_lock);
        atomic64_inc(&sukisu_kpm_unload_failures);
        return -ENOENT;
    }
    if (mod->unloading) {
        mutex_unlock(&sukisu_kpm_module_lock);
        atomic64_inc(&sukisu_kpm_unload_failures);
        return -EBUSY;
    }
    mod->unloading = true;
    mutex_unlock(&sukisu_kpm_module_lock);

    rc = sukisu_kpm_enter_module_context(mod);
    if (rc) {
        mutex_lock(&sukisu_kpm_module_lock);
        mod->unloading = false;
        mutex_unlock(&sukisu_kpm_module_lock);
        atomic64_inc(&sukisu_kpm_unload_failures);
        return rc;
    }
    rc = (*mod->exit)(reserved);
    sukisu_kpm_exit_module_context(mod);
    if (rc) {
        mutex_lock(&sukisu_kpm_module_lock);
        mod->unloading = false;
        mutex_unlock(&sukisu_kpm_module_lock);
        pr_err("kpm: unload of %s refused by exit rc=%ld; module kept loaded\n", name, rc);
        atomic64_inc(&sukisu_kpm_unload_failures);
        return rc < 0 ? (int)rc : -EINVAL;
    }

    mutex_lock(&sukisu_kpm_hook_lock);
    {
        unsigned int active_callbacks = 0;
        int gate_rc = sukisu_kpm_module_unload_gate_locked(mod, &active_callbacks);

        if (gate_rc) {
            unsigned int quiescing = mod->quiescing_count;
            unsigned int refs = sukisu_kpm_module_hook_refs(mod);

            mutex_unlock(&sukisu_kpm_hook_lock);
            mutex_lock(&sukisu_kpm_module_lock);
            mod->unloading = false;
            mutex_unlock(&sukisu_kpm_module_lock);
            pr_err("kpm: unload of %s refused; active refs=%u quiescing=%u callbacks=%u\n", name, refs, quiescing,
                   active_callbacks);
            atomic64_inc(&sukisu_kpm_unload_failures);
            return gate_rc;
        }
    }
    mutex_unlock(&sukisu_kpm_hook_lock);

    mutex_lock(&sukisu_kpm_module_lock);
    list_del(&mod->list);
    mutex_unlock(&sukisu_kpm_module_lock);

    pr_info("kpm: unloaded %s rc=%ld\n", name, rc);
    sukisu_kpm_free_module(mod);
    atomic64_inc(&sukisu_kpm_unload_successes);
    return 0;
}

int sukisu_kpm_loader_num(void)
{
    struct sukisu_kpm_module *pos;
    int n = 0;

    mutex_lock(&sukisu_kpm_module_lock);
    list_for_each_entry (pos, &sukisu_kpm_modules, list)
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
    list_for_each_entry (pos, &sukisu_kpm_modules, list) {
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

    mutex_lock(&sukisu_kpm_hook_lock);
    ret = scnprintf(out, size,
                    "name=%s\n"
                    "version=%s\n"
                    "license=%s\n"
                    "author=%s\n"
                    "description=%s\n"
                    "state=%s\n"
                    "args=%s\n"
                    "source_path=%s\n"
                    "size=%u\n"
                    "text_size=%u\n"
                    "ro_size=%u\n"
                    "inline_hooks=%u\n"
                    "fp_hooks=%u\n"
                    "wrap_items=%u\n"
                    "fp_wrap_items=%u\n"
                    "syscall_wrap_items=%u\n"
                    "quiescing=%u\n"
                    "active_callbacks=%d\n",
                    mod->info.name ? mod->info.name : "", mod->info.version ? mod->info.version : "",
                    mod->info.license ? mod->info.license : "", mod->info.author ? mod->info.author : "",
                    mod->info.description ? mod->info.description : "",
                    mod->load_failed ? "load_failed" :
                    mod->unloading   ? "unloading" :
                                       "loaded",
                    mod->args ? mod->args : "", mod->source_path ? mod->source_path : "", mod->size, mod->text_size,
                    mod->ro_size, mod->inline_hook_count, mod->fp_hook_count, mod->wrap_item_count,
                    mod->fp_wrap_item_count, mod->syscall_wrap_item_count, mod->quiescing_count,
                    atomic_read(&mod->active_callbacks));
    mutex_unlock(&sukisu_kpm_hook_lock);
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
    if (mod->unloading) {
        mutex_unlock(&sukisu_kpm_module_lock);
        return -EBUSY;
    }

    kfree(mod->ctl_args);
    mod->ctl_args = kstrdup(args ? args : "", GFP_KERNEL);
    if (!mod->ctl_args) {
        mutex_unlock(&sukisu_kpm_module_lock);
        return -ENOMEM;
    }

    rc = sukisu_kpm_enter_module_context(mod);
    if (rc) {
        mutex_unlock(&sukisu_kpm_module_lock);
        return rc;
    }
    rc = (*mod->ctl0)(mod->ctl_args, NULL, 0);
    sukisu_kpm_exit_module_context(mod);
    mutex_unlock(&sukisu_kpm_module_lock);

    return (int)rc;
}

static int sukisu_kpm_audit_append(char *out, int size, int *off, const char *fmt, ...)
{
    va_list args;
    int left;
    int written;

    if (!out || !off || *off < 0 || size <= 0)
        return -EINVAL;
    if (*off >= size)
        return -ENOBUFS;

    left = size - *off;
    va_start(args, fmt);
    written = vscnprintf(out + *off, left, fmt, args);
    va_end(args);

    *off += written;
    if (written >= left)
        return -ENOBUFS;
    return 0;
}

static const char *sukisu_kpm_audit_owner_name(const struct sukisu_kpm_module *mod)
{
    return mod && mod->info.name ? mod->info.name : "";
}

int sukisu_kpm_loader_audit(char *out, int size)
{
    struct sukisu_kpm_module *mod;
    struct sukisu_kpm_inline_hook *inline_hook;
    struct sukisu_kpm_fp_hook *fp_hook;
    struct sukisu_kpm_wrap_chain *wrap;
    struct sukisu_kpm_fp_wrap_chain *fp_wrap;
    struct sukisu_kpm_syscall_wrap_chain *syscall_wrap;
    int off = 0;
    int modules = 0;
    int inline_hooks = 0;
    int fp_hooks = 0;
    int wrap_chains = 0;
    int fp_wrap_chains = 0;
    int syscall_wrap_chains = 0;
    int rc = 0;

    if (!out || size <= 0)
        return -EINVAL;
    out[0] = '\0';

    mutex_lock(&sukisu_kpm_module_lock);
    mutex_lock(&sukisu_kpm_hook_lock);

    list_for_each_entry (mod, &sukisu_kpm_modules, list)
        modules++;
    list_for_each_entry (inline_hook, &sukisu_kpm_inline_hooks, list)
        inline_hooks++;
    list_for_each_entry (fp_hook, &sukisu_kpm_fp_hooks, list)
        fp_hooks++;
    list_for_each_entry (wrap, &sukisu_kpm_wrap_chains, list)
        wrap_chains++;
    list_for_each_entry (fp_wrap, &sukisu_kpm_fp_wrap_chains, list)
        fp_wrap_chains++;
    list_for_each_entry (syscall_wrap, &sukisu_kpm_syscall_wrap_chains, list)
        syscall_wrap_chains++;

    rc =
        sukisu_kpm_audit_append(out, size, &off,
                                "loader_version=%s\n"
                                "abi_version=%u\n"
                                "feature_bits=0x%llx\n"
                                "modules=%d\n"
                                "inline_hooks=%d\n"
                                "fp_hooks=%d\n"
                                "wrap_chains=%d\n"
                                "fp_wrap_chains=%d\n"
                                "syscall_wrap_chains=%d\n"
                                "load_attempts=%lld\n"
                                "load_successes=%lld\n"
                                "load_failures=%lld\n"
                                "unload_attempts=%lld\n"
                                "unload_successes=%lld\n"
                                "unload_failures=%lld\n",
                                SUKISU_KPM_LOADER_VERSION, SUKISU_KPM_X86_64_ABI_VERSION,
                                SUKISU_KPM_X86_64_FEATURE_BITS, modules, inline_hooks, fp_hooks, wrap_chains,
                                fp_wrap_chains, syscall_wrap_chains, atomic64_read(&sukisu_kpm_load_attempts),
                                atomic64_read(&sukisu_kpm_load_successes), atomic64_read(&sukisu_kpm_load_failures),
                                atomic64_read(&sukisu_kpm_unload_attempts), atomic64_read(&sukisu_kpm_unload_successes),
                                atomic64_read(&sukisu_kpm_unload_failures));
    if (rc)
        goto out_unlock;

    list_for_each_entry (mod, &sukisu_kpm_modules, list) {
        unsigned int active_callbacks = sukisu_kpm_module_active_callbacks_locked(mod);

        rc = sukisu_kpm_audit_append(
            out, size, &off,
            "module name=%s version=%s state=%s source_path=%s size=%u text_size=%u ro_size=%u inline_hooks=%u fp_hooks=%u wrap_items=%u fp_wrap_items=%u syscall_wrap_items=%u quiescing=%u active_callbacks=%u\n",
            mod->info.name ? mod->info.name : "", mod->info.version ? mod->info.version : "",
            mod->load_failed ? "load_failed" :
            mod->unloading   ? "unloading" :
                               "loaded",
            mod->source_path ? mod->source_path : "", mod->size, mod->text_size, mod->ro_size, mod->inline_hook_count,
            mod->fp_hook_count, mod->wrap_item_count, mod->fp_wrap_item_count, mod->syscall_wrap_item_count,
            mod->quiescing_count, active_callbacks);
        if (rc)
            goto out_unlock;
    }

    list_for_each_entry (inline_hook, &sukisu_kpm_inline_hooks, list) {
        rc = sukisu_kpm_audit_append(
            out, size, &off,
            "inline_hook owner=%s func=%px replace=%px trampoline=%px stolen_size=%u patch_size=%u text_poke_bp=%u\n",
            sukisu_kpm_audit_owner_name(inline_hook->owner), inline_hook->func, inline_hook->replace,
            inline_hook->trampoline, inline_hook->stolen_size, inline_hook->patch_size, inline_hook->uses_text_poke_bp);
        if (rc)
            goto out_unlock;
    }

    list_for_each_entry (fp_hook, &sukisu_kpm_fp_hooks, list) {
        rc = sukisu_kpm_audit_append(out, size, &off, "fp_hook owner=%s fp_addr=%px replace=%px backup=%px\n",
                                     sukisu_kpm_audit_owner_name(fp_hook->owner), (void *)fp_hook->fp_addr,
                                     fp_hook->replace, fp_hook->backup);
        if (rc)
            goto out_unlock;
    }

    list_for_each_entry (wrap, &sukisu_kpm_wrap_chains, list) {
        rc = sukisu_kpm_audit_append(
            out, size, &off,
            "wrap_chain owner=%s func=%px replace=%px origin=%px stub=%px active=%d argno=%d disabled=%u\n",
            sukisu_kpm_audit_owner_name(wrap->owner), (void *)(unsigned long)wrap->hook.func_addr,
            (void *)(unsigned long)wrap->hook.replace_addr, (void *)(unsigned long)wrap->hook.origin_addr, wrap->stub,
            atomic_read(&wrap->active), wrap->argno, wrap->disabled);
        if (rc)
            goto out_unlock;
    }

    list_for_each_entry (fp_wrap, &sukisu_kpm_fp_wrap_chains, list) {
        rc = sukisu_kpm_audit_append(
            out, size, &off,
            "fp_wrap_chain owner=%s fp_addr=%px replace=%px origin_fp=%px stub=%px active=%d argno=%d disabled=%u\n",
            sukisu_kpm_audit_owner_name(fp_wrap->owner), (void *)fp_wrap->hook.fp_addr,
            (void *)(unsigned long)fp_wrap->hook.replace_addr, (void *)(unsigned long)fp_wrap->hook.origin_fp,
            fp_wrap->stub, atomic_read(&fp_wrap->active), fp_wrap->argno, fp_wrap->disabled);
        if (rc)
            goto out_unlock;
    }

    list_for_each_entry (syscall_wrap, &sukisu_kpm_syscall_wrap_chains, list) {
        rc = sukisu_kpm_audit_append(
            out, size, &off,
            "syscall_wrap_chain owner=%s nr=%d slot=%px origin=%px stub=%px active=%d argno=%d disabled=%u\n",
            sukisu_kpm_audit_owner_name(syscall_wrap->owner), syscall_wrap->nr, (void *)syscall_wrap->slot_addr,
            syscall_wrap->origin, syscall_wrap->stub, atomic_read(&syscall_wrap->active), syscall_wrap->argno,
            syscall_wrap->disabled);
        if (rc)
            goto out_unlock;
    }

out_unlock:
    mutex_unlock(&sukisu_kpm_hook_lock);
    mutex_unlock(&sukisu_kpm_module_lock);
    return rc ? rc : off;
}

int sukisu_kpm_loader_version(char *out, int size)
{
    if (!out || size <= 0)
        return -EINVAL;

    return scnprintf(out, size, "%s", SUKISU_KPM_LOADER_VERSION);
}
