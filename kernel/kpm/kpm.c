/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2025 Liankong (xhsw.new@outlook.com). All Rights Reserved.
 * 本代码由GPL-2授权
 *
 * 适配KernelSU的KPM 内核模块加载器兼容实现
 *
 * 集成了 ELF 解析、内存布局、符号处理、重定位（支持 ARM64 重定位类型）
 * 并参照KernelPatch的标准KPM格式实现加载和控制
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/kernfs.h>
#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/elf.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <asm/elf.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <asm/cacheflush.h>
#include <linux/module.h>
#include <linux/set_memory.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <asm/insn.h>
#include <linux/kprobes.h>
#include <linux/stacktrace.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0) && defined(CONFIG_MODULES)
#include <linux/moduleloader.h>
#endif
#include "kpm.h"
#include "compact.h"
#include "kpm_loader_x86_64.h"
#include "compat/kernel_compat.h"
#include "uapi/supercall.h"

#define KPM_NAME_LEN 32
#define KPM_ARGS_LEN 1024
#define KPM_INFO_LEN 1024
#define KPM_AUDIT_LEN 8192

#ifndef NO_OPTIMIZE
#if defined(__GNUC__) && !defined(__clang__)
#define NO_OPTIMIZE __attribute__((optimize("O0")))
#elif defined(__clang__)
#define NO_OPTIMIZE __attribute__((optnone))
#else
#define NO_OPTIMIZE
#endif
#endif

noinline NO_OPTIMIZE void sukisu_kpm_load_module_path(const char *path, const char *args, void *ptr, int *result)
{
    int rc = sukisu_kpm_loader_load_module_path(path, args, ptr);

    __asm__ volatile("nop");
    if (result)
        *result = rc;
}
EXPORT_SYMBOL(sukisu_kpm_load_module_path);

noinline NO_OPTIMIZE void sukisu_kpm_unload_module(const char *name, void *ptr, int *result)
{
    int rc = sukisu_kpm_loader_unload_module(name, ptr);

    __asm__ volatile("nop");
    if (result)
        *result = rc;
}
EXPORT_SYMBOL(sukisu_kpm_unload_module);

noinline NO_OPTIMIZE void sukisu_kpm_num(int *result)
{
    int rc = sukisu_kpm_loader_num();

    __asm__ volatile("nop");
    if (result)
        *result = rc;
}
EXPORT_SYMBOL(sukisu_kpm_num);

noinline NO_OPTIMIZE void sukisu_kpm_info(const char *name, char *buf, int bufferSize, int *size)
{
    int rc = sukisu_kpm_loader_info(name, buf, bufferSize);

    __asm__ volatile("nop");
    if (size)
        *size = rc < 0 ? rc : rc + 1;
}
EXPORT_SYMBOL(sukisu_kpm_info);

noinline NO_OPTIMIZE void sukisu_kpm_list(void *out, int bufferSize, int *result)
{
    int rc = sukisu_kpm_loader_list(out, bufferSize);

    if (result)
        *result = rc;
}
EXPORT_SYMBOL(sukisu_kpm_list);

noinline NO_OPTIMIZE void sukisu_kpm_control(const char *name, const char *args, long arg_len, int *result)
{
    int rc = sukisu_kpm_loader_control(name, arg_len <= 0 ? "" : args);

    __asm__ volatile("nop");
    if (result)
        *result = rc;
}
EXPORT_SYMBOL(sukisu_kpm_control);

noinline NO_OPTIMIZE void sukisu_kpm_version(char *buf, int bufferSize)
{
    int rc = sukisu_kpm_loader_version(buf, bufferSize);

    if (rc < 0 && buf && bufferSize > 0)
        buf[0] = '\0';
}
EXPORT_SYMBOL(sukisu_kpm_version);

noinline NO_OPTIMIZE void sukisu_kpm_audit(char *buf, int bufferSize, int *result)
{
    int rc = sukisu_kpm_loader_audit(buf, bufferSize);

    if (result)
        *result = rc;
}
EXPORT_SYMBOL(sukisu_kpm_audit);

static void sukisu_kpm_caps(struct ksu_kpm_caps *caps)
{
    if (!caps)
        return;

    memset(caps, 0, sizeof(*caps));
    caps->abi_version = SUKISU_KPM_X86_64_ABI_VERSION;
    caps->feature_bits = SUKISU_KPM_X86_64_FEATURE_BITS;
    sukisu_kpm_version(caps->loader_version, sizeof(caps->loader_version));
}

static int sukisu_kpm_copy_to_user(unsigned long dst, const void *src, unsigned long len)
{
    if (!dst || !ksu_access_ok(dst, len))
        return -EFAULT;
    if (copy_to_user((void __user *)dst, src, len) != 0)
        return -EFAULT;
    return 0;
}

static int sukisu_kpm_copy_user_string(char *dst, size_t dst_size, unsigned long src, bool allow_null, bool allow_empty)
{
    long copied;

    if (!dst || dst_size < 2)
        return -EINVAL;

    dst[0] = '\0';
    if (!src)
        return allow_null ? 0 : -EINVAL;
    if (!ksu_access_ok(src, 1))
        return -EFAULT;

    copied = strncpy_from_user(dst, (const char __user *)src, dst_size);
    if (copied < 0)
        return copied;
    if (copied >= dst_size) {
        dst[dst_size - 1] = '\0';
        return -ENAMETOOLONG;
    }
    if (!copied && !allow_empty)
        return -EINVAL;

    return copied;
}

noinline int sukisu_handle_kpm(unsigned long control_code, unsigned long arg1, unsigned long arg2,
                               unsigned long result_code)
{
    int res = -EINVAL;

    if (!result_code || !ksu_access_ok(result_code, sizeof(res))) {
        pr_err("kpm: invalid result_code pointer %px\n", (void *)result_code);
        return -EFAULT;
    }

    if (control_code == KSU_KPM_LOAD) {
        char kernel_load_path[256] = { 0 };
        char kernel_args_buffer[256] = { 0 };
        int copied;

        copied = sukisu_kpm_copy_user_string(kernel_load_path, sizeof(kernel_load_path), arg1, false, false);
        if (copied < 0) {
            res = copied;
            goto exit;
        }

        copied = sukisu_kpm_copy_user_string(kernel_args_buffer, sizeof(kernel_args_buffer), arg2, true, true);
        if (copied < 0) {
            res = copied;
            goto exit;
        }

        sukisu_kpm_load_module_path(kernel_load_path, kernel_args_buffer, NULL, &res);
    } else if (control_code == KSU_KPM_UNLOAD) {
        char kernel_name_buffer[256] = { 0 };
        int copied = sukisu_kpm_copy_user_string(kernel_name_buffer, sizeof(kernel_name_buffer), arg1, false, false);

        if (copied < 0) {
            res = copied;
            goto exit;
        }

        sukisu_kpm_unload_module(kernel_name_buffer, NULL, &res);
    } else if (control_code == KSU_KPM_NUM) {
        sukisu_kpm_num(&res);
    } else if (control_code == KSU_KPM_INFO) {
        char kernel_name_buffer[256] = { 0 };
        char buf[KPM_INFO_LEN] = { 0 };
        int size = 0;
        int copied;

        if (!arg2)
            goto exit;

        copied = sukisu_kpm_copy_user_string(kernel_name_buffer, sizeof(kernel_name_buffer), arg1, false, false);
        if (copied < 0) {
            res = copied;
            goto exit;
        }

        sukisu_kpm_info(kernel_name_buffer, buf, sizeof(buf), &size);

        if (size < 0) {
            res = size;
            goto exit;
        }

        res = sukisu_kpm_copy_to_user(arg2, buf, size);

    } else if (control_code == KSU_KPM_LIST) {
        char buf[1024] = { 0 };
        unsigned long len = arg2;

        if (!arg1 || !len) {
            res = -EINVAL;
            goto exit;
        }

        sukisu_kpm_list(buf, sizeof(buf), &res);

        if (res < 0) {
            goto exit;
        }

        if ((unsigned long)res >= len) {
            res = -ENOBUFS;
            goto exit;
        }

        res = sukisu_kpm_copy_to_user(arg1, buf, res + 1);

    } else if (control_code == KSU_KPM_CONTROL) {
        char kpm_name[KPM_NAME_LEN] = { 0 };
        char kpm_args[KPM_ARGS_LEN] = { 0 };
        int name_len;
        int arg_len;

        name_len = sukisu_kpm_copy_user_string(kpm_name, sizeof(kpm_name), arg1, false, false);
        if (name_len < 0) {
            res = name_len;
            goto exit;
        }

        arg_len = sukisu_kpm_copy_user_string(kpm_args, sizeof(kpm_args), arg2, true, true);
        if (arg_len < 0) {
            res = arg_len;
            goto exit;
        }

        sukisu_kpm_control(kpm_name, kpm_args, arg_len, &res);

    } else if (control_code == KSU_KPM_VERSION) {
        char buffer[256] = { 0 };
        unsigned long outlen = min_t(unsigned long, arg2, sizeof(buffer));
        size_t len;

        if (!arg1 || !outlen) {
            res = -EINVAL;
            goto exit;
        }

        sukisu_kpm_version(buffer, sizeof(buffer));
        len = strnlen(buffer, sizeof(buffer) - 1);

        if (len >= outlen)
            len = outlen - 1;

        buffer[len] = '\0';
        res = sukisu_kpm_copy_to_user(arg1, buffer, len + 1);
    } else if (control_code == KSU_KPM_CAPS) {
        struct ksu_kpm_caps caps;

        if (!arg1 || arg2 < sizeof(caps)) {
            res = -EINVAL;
            goto exit;
        }

        sukisu_kpm_caps(&caps);
        res = sukisu_kpm_copy_to_user(arg1, &caps, sizeof(caps));
    } else if (control_code == KSU_KPM_AUDIT) {
        char *buf;
        unsigned long outlen = min_t(unsigned long, arg2, KPM_AUDIT_LEN);

        if (!arg1 || !outlen) {
            res = -EINVAL;
            goto exit;
        }
        if (!ksu_access_ok(arg1, outlen)) {
            goto invalid_arg;
        }

        buf = kzalloc(outlen, GFP_KERNEL);
        if (!buf) {
            res = -ENOMEM;
            goto exit;
        }

        sukisu_kpm_audit(buf, outlen, &res);
        if (res >= 0) {
            if (res >= outlen) {
                res = -ENOBUFS;
            } else
                res = sukisu_kpm_copy_to_user(arg1, buf, res + 1);
        }
        kfree(buf);
    }

exit:
    if (copy_to_user(result_code, &res, sizeof(res)) != 0)
        pr_info("kpm: Copy to user failed.");

    return 0;
invalid_arg:
    pr_err("kpm: invalid pointer detected! arg1: %px arg2: %px\n", (void *)arg1, (void *)arg2);
    res = -EFAULT;
    goto exit;
}
EXPORT_SYMBOL(sukisu_handle_kpm);

int sukisu_is_kpm_control_code(unsigned long control_code)
{
    return (control_code >= CMD_KPM_CONTROL && control_code <= CMD_KPM_CONTROL_MAX) ? 1 : 0;
}

int do_kpm(void __user *arg)
{
    struct ksu_kpm_cmd cmd;

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        pr_err("kpm: copy_from_user failed\n");
        return -EFAULT;
    }

    if (!cmd.result_code || !ksu_access_ok(cmd.result_code, sizeof(int))) {
        pr_err("kpm: invalid result_code pointer %px\n", (void *)cmd.result_code);
        return -EFAULT;
    }

    return sukisu_handle_kpm(cmd.control_code, cmd.arg1, cmd.arg2, cmd.result_code);
}
