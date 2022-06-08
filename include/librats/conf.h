/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _LIBRATS_CONF_H
#define _LIBRATS_CONF_H

typedef enum {
	RATS_LOG_LEVEL_DEBUG,
	RATS_LOG_LEVEL_INFO,
	RATS_LOG_LEVEL_WARN,
	RATS_LOG_LEVEL_ERROR,
	RATS_LOG_LEVEL_FATAL,
	RATS_LOG_LEVEL_NONE,
	RATS_LOG_LEVEL_MAX,
	RATS_LOG_LEVEL_DEFAULT = RATS_LOG_LEVEL_ERROR
} rats_log_level_t;

typedef struct rats_conf {
	unsigned int api_version;
	unsigned long flags;
	rats_log_level_t log_level;
	char attester_type[32];
	char verifier_type[32];
	unsigned long long enclave_id;
} rats_conf_t;

#endif
