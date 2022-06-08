/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _RATS_LOG_H_
#define _RATS_LOG_H_

// clang-format off
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <librats/api.h>
#include <librats/conf.h>

#ifdef SGX
#include <librats/sgx.h>
#elif defined(OCCLUM)
  #define FPRINTF(io, fmt, ...)                  \
	do {                                     \
		fprintf(io, fmt, ##__VA_ARGS__); \
		fflush(io);                      \
	} while (0)
#else
  #define FPRINTF(io, fmt, ...)                  \
	do {                                     \
		fprintf(io, fmt, ##__VA_ARGS__); \
	} while (0)
#endif

extern rats_log_level_t rats_global_log_level;

#define RATS_FATAL(fmt, ...)                               \
	do {                                               \
		__PR__(FATAL, stderr, fmt, ##__VA_ARGS__); \
	} while (0)

#define RATS_ERR(fmt, ...)                                 \
	do {                                               \
		__PR__(ERROR, stderr, fmt, ##__VA_ARGS__); \
	} while (0)

#define RATS_WARN(fmt, ...)                               \
	do {                                              \
		__PR__(WARN, stdout, fmt, ##__VA_ARGS__); \
	} while (0)

#define RATS_INFO(fmt, ...)                               \
	do {                                              \
		__PR__(INFO, stdout, fmt, ##__VA_ARGS__); \
	} while (0)

#define RATS_DEBUG(fmt, ...)                               \
	do {                                               \
		__PR__(DEBUG, stdout, fmt, ##__VA_ARGS__); \
	} while (0)

#ifdef SGX
  #define __PR__(level, io, fmt, ...)                                                 \
	do {                                                                          \
		if (rats_global_log_level <= RATS_LOG_LEVEL_##level)                \
			printf("[" #level "] %s()@L%d: " fmt, __FUNCTION__, __LINE__, \
			       ##__VA_ARGS__);                                        \
	} while (0)
#else
  #define __PR__(level, io, fmt, ...)                                                   \
	do {                                                                            \
		if (rats_global_log_level <= RATS_LOG_LEVEL_##level) {                \
			if (RATS_LOG_LEVEL_##level !=                            \
			    RATS_LOG_LEVEL_DEBUG) {                              \
				FPRINTF(io, "[" #level "] " fmt, ##__VA_ARGS__);        \
			} else {                                                        \
				time_t __t__ = time(NULL);                              \
				struct tm __loc__;                                      \
				localtime_r(&__t__, &__loc__);                          \
				char __buf__[64];                                       \
				strftime(__buf__, sizeof(__buf__), "%a %b %e %T %Z %Y", \
					 &__loc__);                                     \
				FPRINTF(io, "%s: [" #level "] %s()@L%d: " fmt, __buf__, \
					__FUNCTION__, __LINE__, ##__VA_ARGS__);         \
			}                                                               \
		}                                                                       \
	} while (0)
#endif
// clang-format on

#endif
