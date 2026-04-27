// SPDX-License-Identifier: GPL-2.0-or-later
#include "kpm_x86_64.h"

extern unsigned long symbol_lookup_name(const char *name);
extern int hook(void *func, void *replace, void **backup);
extern void unhook(void *func);

static void *target;
static void *origin;

static unsigned long replacement(unsigned long index, unsigned long size)
{
	if (origin)
		return ((unsigned long (*)(unsigned long, unsigned long))origin)(index, size);
	return 0;
}

static long inline_init(const char *args, const char *event, void *reserved)
{
	(void)args;
	(void)event;
	(void)reserved;

	target = (void *)symbol_lookup_name("array_index_mask_nospec");
	if (!target)
		return -2;
	return hook(target, replacement, &origin);
}

static long inline_exit(void *reserved)
{
	(void)reserved;
	if (origin)
		unhook(target);
	origin = 0;
	target = 0;
	return 0;
}

KPM_INFO("inline_hook", "1.0", "GPL", "ReSukiSU", "Inline hook sample");
KPM_INIT(inline_init);
KPM_EXIT(inline_exit);
