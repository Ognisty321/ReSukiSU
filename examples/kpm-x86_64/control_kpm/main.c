// SPDX-License-Identifier: GPL-2.0-or-later
#include "kpm_x86_64.h"

static int streq(const char *a, const char *b)
{
	while (*a && *b && *a == *b) {
		a++;
		b++;
	}
	return *a == *b;
}

static long control_init(const char *args, const char *event, void *reserved)
{
	(void)args;
	(void)event;
	(void)reserved;
	return 0;
}

static long control_exit(void *reserved)
{
	(void)reserved;
	return 0;
}

static long control_ctl0(const char *args, char *out_msg, int outlen)
{
	(void)out_msg;
	(void)outlen;

	if (args && streq(args, "ping"))
		return 200;
	if (args && streq(args, "fail"))
		return -22;
	return 0;
}

KPM_INFO("control_kpm", "1.0", "GPL", "ReSukiSU", "Control callback sample");
KPM_INIT(control_init);
KPM_EXIT(control_exit);
KPM_CTL0(control_ctl0);
