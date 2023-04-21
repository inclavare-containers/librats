/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// clang-format off
#include <stdlib.h>
#ifndef SGX
#include <dlfcn.h>
#include <strings.h>
#include <dirent.h>
#endif
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <librats/conf.h>
#include <librats/api.h>
#include <librats/log.h>
#include <internal/core.h>

#ifdef SGX
#include "rats_t.h"

extern rats_attester_err_t libattester_null_init(void);
extern rats_verifier_err_t libverifier_null_init(void);
extern rats_attester_err_t libattester_sgx_ecdsa_init(void);
extern rats_verifier_err_t libverifier_sgx_ecdsa_qve_init(void);
extern rats_attester_err_t libattester_sgx_la_init(void);
extern rats_verifier_err_t libverifier_sgx_la_init(void);
extern crypto_wrapper_err_t libcrypto_wrapper_nullcrypto_init(void);
extern crypto_wrapper_err_t libcrypto_wrapper_openssl_init(void);
#endif
// clang-format on

rats_core_context_t rats_global_core_context = {
    .config = {
        .api_version = RATS_API_VERSION_DEFAULT,
        .flags = 0L,
        .attester_type = "\0",
        .verifier_type = "\0",
		.crypto_type = "\0",
		.log_level = RATS_LOG_LEVEL_DEFAULT,
    },
    .flags = 0L,
    .attester = NULL,
    .verifier = NULL,
    .crypto_wrapper = NULL,
};

/* The global log level used by log.h */
rats_log_level_t rats_global_log_level = RATS_LOG_LEVEL_DEFAULT;

rats_log_level_t _log_level_from_str(const char *log_level_str)
{
	if (log_level_str) {
		if (!strcmp(log_level_str, "debug") || !strcmp(log_level_str, "DEBUG")) {
			return RATS_LOG_LEVEL_DEBUG;
		} else if (!strcmp(log_level_str, "info") || !strcmp(log_level_str, "INFO")) {
			return RATS_LOG_LEVEL_INFO;
		} else if (!strcmp(log_level_str, "warn") || !strcmp(log_level_str, "WARN")) {
			return RATS_LOG_LEVEL_WARN;
		} else if (!strcmp(log_level_str, "error") || !strcmp(log_level_str, "ERROR")) {
			return RATS_LOG_LEVEL_ERROR;
		} else if (!strcmp(log_level_str, "fatal") || !strcmp(log_level_str, "FATAL")) {
			return RATS_LOG_LEVEL_FATAL;
		} else if (!strcmp(log_level_str, "off") || !strcmp(log_level_str, "OFF")) {
			return RATS_LOG_LEVEL_NONE;
		}
	}
	return RATS_LOG_LEVEL_DEFAULT;
}

#ifdef SGX
void rats_exit(void)
{
	rats_ocall_exit();
}

rats_log_level_t rats_loglevel_getenv(const char *name)
{
	const size_t log_level_len = 32;
	char log_level_str[log_level_len];
	memset(log_level_str, 0, log_level_len);

	rats_ocall_getenv(name, log_level_str, log_level_len);
	log_level_str[log_level_len - 1] = '\0';
	return _log_level_from_str(log_level_str);
}

rats_attester_err_t rats_attester_init_static(const char *name)
{
	rats_attester_err_t err = RATS_ATTESTER_ERR_UNKNOWN;

	if (!strcmp(name, "nullattester")) {
		err = libattester_null_init();
	} else if (!strcmp(name, "sgx_ecdsa")) {
		err = libattester_sgx_ecdsa_init();
	} else if (!strcmp(name, "sgx_la")) {
		err = libattester_sgx_la_init();
	} else
		return RATS_ATTESTER_ERR_INVALID;

	if (err != RATS_ATTESTER_ERR_NONE)
		return err;

	err = rats_attester_post_init(name, NULL);
	if (err != RATS_ATTESTER_ERR_NONE)
		return err;

	return RATS_ATTESTER_ERR_NONE;
}

rats_verifier_err_t rats_verifier_init_static(const char *name)
{
	rats_verifier_err_t err = RATS_VERIFIER_ERR_UNKNOWN;

	if (!strcmp(name, "nullverifier")) {
		err = libverifier_null_init();
	} else if (!strcmp(name, "sgx_ecdsa_qve")) {
		err = libverifier_sgx_ecdsa_qve_init();
	} else if (!strcmp(name, "sgx_la")) {
		err = libverifier_sgx_la_init();
	} else
		return RATS_VERIFIER_ERR_INVALID;

	if (err != RATS_VERIFIER_ERR_NONE)
		return err;

	err = rats_verifier_post_init(name, NULL);
	if (err != RATS_VERIFIER_ERR_NONE)
		return err;

	return RATS_VERIFIER_ERR_NONE;
}

crypto_wrapper_err_t crypto_wrapper_init_static(const char *name)
{
	crypto_wrapper_err_t err = CRYPTO_WRAPPER_ERR_UNKNOWN;

	if (!strcmp(name, "nullcrypto")) {
		err = libcrypto_wrapper_nullcrypto_init();
	} else if (!strcmp(name, "openssl")) {
		err = libcrypto_wrapper_openssl_init();
	} else {
		return CRYPTO_WRAPPER_ERR_INVALID;
	}

	if (err != CRYPTO_WRAPPER_ERR_NONE)
		return err;

	err = crypto_wrapper_post_init(name, NULL);
	if (err != CRYPTO_WRAPPER_ERR_NONE)
		return err;

	return CRYPTO_WRAPPER_ERR_NONE;
}

char *rats_strcpy(char *dest, const char *src)
{
	if (dest == NULL)
		return NULL;
	size_t src_size = strlen(src);
	strncpy(dest, src, src_size);
	dest[src_size] = '\0';
	return dest;
}

#else
void rats_exit(void)
{
	exit(EXIT_FAILURE);
}

rats_log_level_t rats_loglevel_getenv(const char *name)
{
	char *log_level_str = log_level_str = getenv(name);

	return _log_level_from_str(log_level_str);
}

char *rats_strcpy(char *dest, const char *src)
{
	return strcpy(dest, src);
}
#endif
