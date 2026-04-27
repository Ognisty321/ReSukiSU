// SPDX-License-Identifier: GPL-2.0-or-later
#include "kpm_x86_64.h"

extern void fp_hook(unsigned long fp_addr, void *replace, void **backup);
extern void fp_unhook(unsigned long fp_addr, void *backup);

static void *backup;
static int cleanup_on_exit;

static int streq(const char *a, const char *b)
{
	while (*a && *b && *a == *b) {
		a++;
		b++;
	}
	return *a == *b;
}

static long original_value(void)
{
	return 41;
}

static long replacement_value(void)
{
	return 42;
}

static long (*target_fp)(void) = original_value;

static void cleanup_hook(void)
{
	if (backup) {
		fp_unhook((unsigned long)&target_fp, backup);
		backup = 0;
	}
}

static long owner_init(const char *args, const char *event, void *reserved)
{
	(void)args;
	(void)event;
	(void)reserved;

	backup = 0;
	cleanup_on_exit = 0;
	target_fp = original_value;
	return 0;
}

static long owner_exit(void *reserved)
{
	(void)reserved;

	if (cleanup_on_exit)
		cleanup_hook();
	return 0;
}

static long owner_ctl0(const char *args, char *out_msg, int outlen)
{
	(void)out_msg;
	(void)outlen;

	if (args && streq(args, "install")) {
		if (!backup)
			fp_hook((unsigned long)&target_fp, replacement_value, &backup);
		if (!backup)
			return -1;
		return target_fp() == 42 ? 0 : -2;
	}

	if (args && streq(args, "cleanup")) {
		cleanup_hook();
		return target_fp() == 41 ? 0 : -3;
	}

	if (args && streq(args, "cleanup-on-exit")) {
		cleanup_on_exit = 1;
		return 0;
	}

	return target_fp();
}

KPM_INFO("control_owner", "1.0", "GPL", "ReSukiSU", "Control callback owner context sample");
KPM_INIT(owner_init);
KPM_EXIT(owner_exit);
KPM_CTL0(owner_ctl0);
