#ifndef __SUKISU_KPM_LOADER_X86_64_H
#define __SUKISU_KPM_LOADER_X86_64_H

#include <linux/errno.h>

#ifdef CONFIG_X86_64
int sukisu_kpm_loader_load_module_path(const char *path, const char *args, void __user *reserved);
int sukisu_kpm_loader_unload_module(const char *name, void __user *reserved);
int sukisu_kpm_loader_num(void);
int sukisu_kpm_loader_list(char *out, int size);
int sukisu_kpm_loader_info(const char *name, char *out, int size);
int sukisu_kpm_loader_control(const char *name, const char *args);
int sukisu_kpm_loader_version(char *out, int size);
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
#endif

#endif
