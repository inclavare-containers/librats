/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _INTERNAL_CORE_H
#define _INTERNAL_CORE_H

// clang-format off
#include <sys/types.h>
#include <librats/attester.h>

#ifdef SGX
#include "librats/rats_syscalls.h"
#endif
// clang-format on

#ifdef SGX
typedef struct rats_ocall_dirent rats_dirent;
#else
typedef struct dirent rats_dirent;
#endif

extern rats_core_context_t rats_global_core_context;

extern void rats_exit(void);

extern rats_log_level_t rats_loglevel_getenv(const char *name);

extern char *rats_strcpy(char *dest, const char *src);

#endif
