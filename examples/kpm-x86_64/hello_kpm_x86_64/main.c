// SPDX-License-Identifier: GPL-2.0-or-later
#include "kpm_x86_64.h"

static long hello_init(const char *args, const char *event, void *reserved)
{
	(void)args;
	(void)event;
	(void)reserved;
	return 0;
}

static long hello_exit(void *reserved)
{
	(void)reserved;
	return 0;
}

KPM_INFO("hello_kpm_x86_64", "1.0", "GPL", "ReSukiSU", "Minimal x86_64 KPM sample");
KPM_INIT(hello_init);
KPM_EXIT(hello_exit);
