#ifndef __SUKISU_KPM_LOADER_X86_64_H
#define __SUKISU_KPM_LOADER_X86_64_H

#include <linux/errno.h>

#define SUKISU_KPM_LOADER_NAME "ReSukiSU-x86_64-KPM-loader"
#define SUKISU_KPM_LOADER_SEMVER "0.20"
#define SUKISU_KPM_LOADER_VERSION SUKISU_KPM_LOADER_NAME "/" SUKISU_KPM_LOADER_SEMVER

#define SUKISU_KPM_X86_64_ABI_VERSION 1
#define SUKISU_KPM_X86_64_FEATURE_ET_REL		(1ULL << 0)
#define SUKISU_KPM_X86_64_FEATURE_RELA			(1ULL << 1)
#define SUKISU_KPM_X86_64_FEATURE_GOTPCREL		(1ULL << 2)
#define SUKISU_KPM_X86_64_FEATURE_INLINE_HOOK		(1ULL << 3)
#define SUKISU_KPM_X86_64_FEATURE_FP_HOOK		(1ULL << 4)
#define SUKISU_KPM_X86_64_FEATURE_HOTPATCH		(1ULL << 5)
#define SUKISU_KPM_X86_64_FEATURE_ROX_ALLOC		(1ULL << 6)
#define SUKISU_KPM_X86_64_FEATURE_RCU_EXEC_FREE		(1ULL << 7)
#define SUKISU_KPM_X86_64_FEATURE_TEXT_POKE_BP		(1ULL << 8)
#define SUKISU_KPM_X86_64_FEATURE_HOOK_TARGET_GUARDS	(1ULL << 9)
#define SUKISU_KPM_X86_64_FEATURE_AUDIT		(1ULL << 10)
#define SUKISU_KPM_X86_64_FEATURE_UNLOAD_GATE		(1ULL << 11)
#define SUKISU_KPM_X86_64_FEATURE_BITS \
	(SUKISU_KPM_X86_64_FEATURE_ET_REL | \
	 SUKISU_KPM_X86_64_FEATURE_RELA | \
	 SUKISU_KPM_X86_64_FEATURE_GOTPCREL | \
	 SUKISU_KPM_X86_64_FEATURE_INLINE_HOOK | \
	 SUKISU_KPM_X86_64_FEATURE_FP_HOOK | \
	 SUKISU_KPM_X86_64_FEATURE_HOTPATCH | \
	 SUKISU_KPM_X86_64_FEATURE_ROX_ALLOC | \
	 SUKISU_KPM_X86_64_FEATURE_RCU_EXEC_FREE | \
	 SUKISU_KPM_X86_64_FEATURE_TEXT_POKE_BP | \
	 SUKISU_KPM_X86_64_FEATURE_HOOK_TARGET_GUARDS | \
	 SUKISU_KPM_X86_64_FEATURE_AUDIT | \
	 SUKISU_KPM_X86_64_FEATURE_UNLOAD_GATE)

#ifdef CONFIG_X86_64
int sukisu_kpm_loader_load_module_path(const char *path, const char *args, void __user *reserved);
int sukisu_kpm_loader_unload_module(const char *name, void __user *reserved);
int sukisu_kpm_loader_num(void);
int sukisu_kpm_loader_list(char *out, int size);
int sukisu_kpm_loader_info(const char *name, char *out, int size);
int sukisu_kpm_loader_control(const char *name, const char *args);
int sukisu_kpm_loader_version(char *out, int size);
int sukisu_kpm_loader_audit(char *out, int size);
#else
static inline int sukisu_kpm_loader_load_module_path(const char *path, const char *args, void __user *reserved)
{
	return -EOPNOTSUPP;
}

static inline int sukisu_kpm_loader_unload_module(const char *name, void __user *reserved)
{
	return -EOPNOTSUPP;
}

static inline int sukisu_kpm_loader_num(void)
{
	return -EOPNOTSUPP;
}

static inline int sukisu_kpm_loader_list(char *out, int size)
{
	return -EOPNOTSUPP;
}

static inline int sukisu_kpm_loader_info(const char *name, char *out, int size)
{
	return -EOPNOTSUPP;
}

static inline int sukisu_kpm_loader_control(const char *name, const char *args)
{
	return -EOPNOTSUPP;
}

static inline int sukisu_kpm_loader_version(char *out, int size)
{
	return -EOPNOTSUPP;
}

static inline int sukisu_kpm_loader_audit(char *out, int size)
{
	return -EOPNOTSUPP;
}
#endif

#endif
