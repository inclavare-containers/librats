/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include "rats_syscalls.h"
#include "cpu.h"

void rats_ocall_exit(void)
{
	exit(EXIT_FAILURE);
}

void rats_ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate
	 * the input string to prevent buffer overflow.
	 */
	printf("%s", str);
}

void rats_ocall_getenv(const char *name, char *value, size_t len)
{
	memset(value, 0, len);

	char *env_value = getenv(name);
	if (env_value != NULL)
		snprintf(value, len, "%s", env_value);
	else
		*value = '\0';
}

static double current_time(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return (double)((1000000.0f * (double)tv.tv_sec + (double)tv.tv_usec) / 1000000.0f);
}

void rats_ocall_current_time(double *time)
{
	if (!time)
		return;

	*time = current_time();

	return;
}

void rats_ocall_low_res_time(int *time)
{
	if (!time)
		return;

	struct timeval tv;

	gettimeofday(&tv, NULL);
	*time = (int)tv.tv_sec;
}

void rats_ocall_cpuid(int *eax, int *ebx, int *ecx, int *edx)
{
#if defined(__x86_64__)
	__asm__ volatile("cpuid"
			 : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
			 : "0"(*eax), "1"(*ebx), "2"(*ecx), "3"(*edx)
			 : "memory");
#else
	/* on 32bit, ebx can NOT be used as PIC code */
	__asm__ volatile("xchgl %%ebx, %1; cpuid; xchgl %%ebx, %1"
			 : "=a"(*eax), "=r"(*ebx), "=c"(*ecx), "=d"(*edx)
			 : "0"(*eax), "1"(*ebx), "2"(*ecx), "3"(*edx)
			 : "memory");
#endif
}

void rats_ocall_is_sgx_dev(bool *retval, const char *dev)
{
	struct stat st;

	if (stat(dev, &st)) {
		*retval = false;
		return;
	}

	*retval = S_ISCHR(st.st_mode) && (major(st.st_rdev) == SGX_DEVICE_MAJOR_NUM);
}
