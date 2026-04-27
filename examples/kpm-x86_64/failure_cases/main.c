// SPDX-License-Identifier: GPL-2.0-or-later
#include "kpm_x86_64.h"

static int allow_exit;

static int streq(const char *a, const char *b)
{
	while (*a && *b && *a == *b) {
		a++;
		b++;
	}
	return *a == *b;
}

static long failure_init(const char *args, const char *event, void *reserved)
{
	(void)args;
	(void)event;
	(void)reserved;
	allow_exit = 0;
	return 0;
}

static long failure_exit(void *reserved)
{
	(void)reserved;
	return allow_exit ? 0 : -16;
}

static long failure_ctl0(const char *args, char *out_msg, int outlen)
{
	(void)out_msg;
	(void)outlen;

	if (args && streq(args, "allow-exit")) {
		allow_exit = 1;
		return 0;
	}
	if (args && streq(args, "deny-exit")) {
		allow_exit = 0;
		return 0;
	}
	return allow_exit;
}

KPM_INFO("failure_cases", "1.0", "GPL", "ReSukiSU", "Unload failure sample");
KPM_INIT(failure_init);
KPM_EXIT(failure_exit);
KPM_CTL0(failure_ctl0);
