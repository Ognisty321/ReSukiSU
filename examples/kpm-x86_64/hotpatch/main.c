// SPDX-License-Identifier: GPL-2.0-or-later
#include "kpm_x86_64.h"

extern int hotpatch(void *addrs[], unsigned int values[], int cnt);

static long hotpatch_init(const char *args, const char *event, void *reserved)
{
	(void)args;
	(void)event;
	(void)reserved;
	return 0;
}

static long hotpatch_exit(void *reserved)
{
	(void)reserved;
	return 0;
}

static long hotpatch_ctl0(const char *args, char *out_msg, int outlen)
{
	void *addrs[1] = { 0 };
	unsigned int values[1] = { 0 };

	(void)args;
	(void)out_msg;
	(void)outlen;

	return hotpatch(addrs, values, 0);
}

KPM_INFO("hotpatch", "1.0", "GPL", "ReSukiSU", "Hotpatch API sample");
KPM_INIT(hotpatch_init);
KPM_EXIT(hotpatch_exit);
KPM_CTL0(hotpatch_ctl0);
