/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _LIBRATS_CONF_H
#define _LIBRATS_CONF_H

#include <librats/hash.h>

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

typedef enum {
	RATS_KEY_ALGO_RSA_3072,
	RATS_KEY_ALGO_ECC_256,
	RATS_KEY_ALGO_MAX,
	RATS_KEY_ALGO_DEFAULT = RATS_KEY_ALGO_ECC_256,
} rats_key_algo_t;

typedef struct rats_conf {
	unsigned int api_version;
	unsigned long flags;
	char attester_type[32];
	char verifier_type[32];
	char crypto_type[32];
	rats_key_algo_t key_algo;
	rats_hash_algo_t hash_algo;
} rats_conf_t;

#endif
