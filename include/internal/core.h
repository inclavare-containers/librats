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

extern ssize_t rats_write(int fd, const void *buf, size_t count);

extern ssize_t rats_read(int fd, void *buf, size_t count);

extern uint64_t rats_opendir(const char *name);

extern int rats_readdir(uint64_t dirp, rats_dirent **ptr);

extern int rats_closedir(uint64_t dir);

extern char *rats_strcpy(char *dest, const char *src);

// Whether the quote instance is initialized
#define RATS_CTX_FLAGS_QUOTING_INITIALIZED (1 << 0)

#endif
