// SPDX-License-Identifier: GPL-2.0-or-later
#include "kpm_x86_64.h"

extern void fp_hook(unsigned long fp_addr, void *replace, void **backup);
extern void fp_unhook(unsigned long fp_addr, void *backup);

static void *backup;

static long original_value(void)
{
	return 41;
}

static long replacement_value(void)
{
	return 42;
}

static long (*target_fp)(void) = original_value;

static long fp_hook_init(const char *args, const char *event, void *reserved)
{
	(void)args;
	(void)event;
	(void)reserved;

	fp_hook((unsigned long)&target_fp, replacement_value, &backup);
	if (!backup)
		return -1;
	if (target_fp() != 42)
		return -2;
	return 0;
}

static long fp_hook_exit(void *reserved)
{
	(void)reserved;

	if (backup)
		fp_unhook((unsigned long)&target_fp, backup);
	return 0;
}

static long fp_hook_ctl0(const char *args, char *out_msg, int outlen)
{
	(void)args;
	(void)out_msg;
	(void)outlen;

	return target_fp();
}

KPM_INFO("fp_hook", "1.0", "GPL", "ReSukiSU", "Function pointer hook sample");
KPM_INIT(fp_hook_init);
KPM_EXIT(fp_hook_exit);
KPM_CTL0(fp_hook_ctl0);
