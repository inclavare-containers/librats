/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/crypto_wrapper.h>
#include <librats/log.h>
#include <librats/cert.h>

extern crypto_wrapper_err_t openssl_pre_init(void);
extern crypto_wrapper_err_t openssl_init(crypto_wrapper_ctx_t *ctx);
extern crypto_wrapper_err_t openssl_use_privkey(crypto_wrapper_ctx_t *ctx, const uint8_t *privkey,
						size_t privkey_len);
extern crypto_wrapper_err_t openssl_gen_privkey(crypto_wrapper_ctx_t *ctx, rats_key_algo_t key_algo,
						uint8_t **privkey, size_t *privkey_len);
extern crypto_wrapper_err_t openssl_get_pubkey_hash(crypto_wrapper_ctx_t *ctx,
						    rats_hash_algo_t key_algo, uint8_t *hash);
extern crypto_wrapper_err_t openssl_gen_hash(crypto_wrapper_ctx_t *ctx, rats_hash_algo_t hash_algo,
					     const uint8_t *data, size_t size, uint8_t *hash);
extern crypto_wrapper_err_t openssl_gen_cert(crypto_wrapper_ctx_t *ctx, rats_hash_algo_t hash_algo,
					     rats_cert_info_t *cert_info);
extern crypto_wrapper_err_t
openssl_verify_cert(crypto_wrapper_ctx_t *ctx, const uint8_t *certificate, size_t certificate_size);
extern crypto_wrapper_err_t openssl_cleanup(crypto_wrapper_ctx_t *ctx);

static const crypto_wrapper_opts_t openssl_opts = {
	.api_version = CRYPTO_WRAPPER_API_VERSION_DEFAULT,
	.name = "openssl",
	.priority = 25,
	.pre_init = openssl_pre_init,
	.init = openssl_init,
	.use_privkey = openssl_use_privkey,
	.gen_privkey = openssl_gen_privkey,
	.get_pubkey_hash = openssl_get_pubkey_hash,
	.gen_hash = openssl_gen_hash,
	.gen_cert = openssl_gen_cert,
	.verify_cert = openssl_verify_cert,
	.cleanup = openssl_cleanup,
};

#ifdef SGX
void libcrypto_wrapper_openssl_init(void)
#else
static void __attribute__((constructor)) libcrypto_wrapper_openssl_init(void)
#endif
{
	RATS_DEBUG("called\n");

	crypto_wrapper_err_t err = crypto_wrapper_register(&openssl_opts);
	if (err != CRYPTO_WRAPPER_ERR_NONE)
		RATS_ERR("failed to register the crypto wrapper 'openssl' %#x\n", err);
}
