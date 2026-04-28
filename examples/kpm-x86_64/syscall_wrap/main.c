// SPDX-License-Identifier: GPL-2.0-or-later
#include "kpm_x86_64.h"

#define __NR_getpid 39

extern int hook_syscalln(int nr, int narg, void *before, void *after, void *udata);
extern void unhook_syscalln(int nr, void *before, void *after);

static volatile unsigned long before_count;
static volatile unsigned long after_count;
static int installed;

static int streq(const char *a, const char *b)
{
	while (*a && *b && *a == *b) {
		a++;
		b++;
	}
	return *a == *b;
}

static void before_getpid(void *data, void *udata)
{
	struct kpm_hook_fargs12 *fargs = data;

	(void)udata;
	if (fargs)
		before_count++;
}

static void after_getpid(void *data, void *udata)
{
	struct kpm_hook_fargs12 *fargs = data;

	(void)udata;
	if (fargs)
		after_count++;
}

static long syscall_wrap_init(const char *args, const char *event, void *reserved)
{
	int rc;

	(void)args;
	(void)event;
	(void)reserved;

	rc = hook_syscalln(__NR_getpid, 0, before_getpid, after_getpid, 0);
	if (rc)
		return rc;
	installed = 1;
	return 0;
}

static long syscall_wrap_exit(void *reserved)
{
	(void)reserved;
	if (installed) {
		unhook_syscalln(__NR_getpid, before_getpid, after_getpid);
		installed = 0;
	}
	return 0;
}

static long syscall_wrap_ctl0(const char *args, char *out_msg, int outlen)
{
	(void)out_msg;
	(void)outlen;

	if (args && streq(args, "before"))
		return before_count;
	if (args && streq(args, "after"))
		return after_count;
	if (args && streq(args, "ready"))
		return installed;
	return before_count + after_count;
}

KPM_INFO("syscall_wrap", "1.0", "GPL", "ReSukiSU", "Syscall wrapper sample");
KPM_INIT(syscall_wrap_init);
KPM_EXIT(syscall_wrap_exit);
KPM_CTL0(syscall_wrap_ctl0);
