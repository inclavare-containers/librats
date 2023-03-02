/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _RATS_CRYPTO_WRAPPER_H
#define _RATS_CRYPTO_WRAPPER_H

#include <stdint.h>
#include <stddef.h>
#include <librats/err.h>
#include <librats/api.h>
#include <librats/cert.h>
#include <librats/hash.h>

#define CRYPTO_TYPE_NAME_SIZE	32
#define CRYPTO_WRAPPER_TYPE_MAX 32

#define CRYPTO_WRAPPER_API_VERSION_1	   1
#define CRYPTO_WRAPPER_API_VERSION_MAX	   CRYPTO_WRAPPER_API_VERSION_1
#define CRYPTO_WRAPPER_API_VERSION_DEFAULT CRYPTO_WRAPPER_API_VERSION_1

typedef struct rats_core_context rats_core_context_t;
typedef struct crypto_wrapper_ctx crypto_wrapper_ctx_t;

extern crypto_wrapper_err_t rats_crypto_wrapper_init(rats_conf_t *conf, rats_core_context_t *ctx);

typedef struct {
	uint8_t api_version;
	unsigned long flags;
	const char name[CRYPTO_TYPE_NAME_SIZE];
	uint8_t priority;

	/* Optional */
	crypto_wrapper_err_t (*pre_init)(void);
	crypto_wrapper_err_t (*init)(crypto_wrapper_ctx_t *ctx);
	crypto_wrapper_err_t (*use_privkey)(crypto_wrapper_ctx_t *ctx, const uint8_t *privkey,
					    size_t privkey_len);
	crypto_wrapper_err_t (*gen_privkey)(crypto_wrapper_ctx_t *ctx, rats_key_algo_t key_algo,
					    uint8_t **privkey, size_t *privkey_len);
	crypto_wrapper_err_t (*get_pubkey_hash)(crypto_wrapper_ctx_t *ctx,
						rats_hash_algo_t hash_algo, uint8_t *hash);
	crypto_wrapper_err_t (*gen_hash)(crypto_wrapper_ctx_t *ctx, rats_hash_algo_t hash_algo,
					 const uint8_t *data, size_t size, uint8_t *hash);
	crypto_wrapper_err_t (*gen_cert)(crypto_wrapper_ctx_t *ctx, rats_hash_algo_t hash_algo,
					 rats_cert_info_t *cert_info);
	crypto_wrapper_err_t (*verify_cert)(crypto_wrapper_ctx_t *ctx, const uint8_t *certificate,
					    size_t certificate_size);
	crypto_wrapper_err_t (*cleanup)(crypto_wrapper_ctx_t *ctx);
} crypto_wrapper_opts_t;

struct crypto_wrapper_ctx {
	rats_core_context_t *rats_handle;
	rats_verify_claims_callback_t verify_claims_callback;
	void *args;
	crypto_wrapper_opts_t *opts;
	void *crypto_private;
	void *handle;
};

static inline int crypto_wrapper_cmp(const void *a, const void *b)
{
	return (*(crypto_wrapper_ctx_t **)b)->opts->priority -
	       (*(crypto_wrapper_ctx_t **)a)->opts->priority;
}

extern crypto_wrapper_err_t crypto_wrapper_register(const crypto_wrapper_opts_t *);

extern crypto_wrapper_err_t crypto_wrapper_verify_certificate_extension(
	crypto_wrapper_ctx_t *crypto_ctx,
	const uint8_t *pubkey_buffer /* in SubjectPublicKeyInfo format */,
	size_t pubkey_buffer_size, uint8_t *evidence_buffer /* optional, for nullverifier */,
	size_t evidence_buffer_size, uint8_t *endorsements_buffer /* optional */,
	size_t endorsements_buffer_size);

#endif /* _RATS_CRYPTO_WRAPPER_H */
