/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RESUKISU_KPM_X86_64_H
#define RESUKISU_KPM_X86_64_H

#define KPM_USED __attribute__((used))
#define KPM_SECTION(name) __attribute__((section(name), used))

typedef long (*kpm_init_t)(const char *args, const char *event, void *reserved);
typedef long (*kpm_exit_t)(void *reserved);
typedef long (*kpm_ctl0_t)(const char *args, char *out_msg, int outlen);
typedef long (*kpm_ctl1_t)(void *a1, void *a2, void *a3);

struct kpm_hook_local {
	unsigned long data[8];
};

struct kpm_hook_fargs12 {
	void *chain;
	int skip_origin;
	struct kpm_hook_local local;
	unsigned long ret;
	union {
		struct {
			unsigned long arg0;
			unsigned long arg1;
			unsigned long arg2;
			unsigned long arg3;
			unsigned long arg4;
			unsigned long arg5;
			unsigned long arg6;
			unsigned long arg7;
			unsigned long arg8;
			unsigned long arg9;
			unsigned long arg10;
			unsigned long arg11;
		};
		unsigned long args[12];
	};
};

#define KPM_INFO(_name, _version, _license, _author, _description) \
	static const char __kpm_info[] KPM_SECTION(".kpm.info") = \
		"name=" _name "\0" \
		"version=" _version "\0" \
		"license=" _license "\0" \
		"author=" _author "\0" \
		"description=" _description "\0"

#define KPM_INIT(fn) static kpm_init_t __kpm_init KPM_SECTION(".kpm.init") = (fn)
#define KPM_EXIT(fn) static kpm_exit_t __kpm_exit KPM_SECTION(".kpm.exit") = (fn)
#define KPM_CTL0(fn) static kpm_ctl0_t __kpm_ctl0 KPM_SECTION(".kpm.ctl0") = (fn)
#define KPM_CTL1(fn) static kpm_ctl1_t __kpm_ctl1 KPM_SECTION(".kpm.ctl1") = (fn)

#endif
