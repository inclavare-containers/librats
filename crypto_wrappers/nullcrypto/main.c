/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/crypto_wrapper.h>
#include <librats/log.h>

extern crypto_wrapper_err_t nullcrypto_pre_init(void);
extern crypto_wrapper_err_t nullcrypto_init(crypto_wrapper_ctx_t *ctx);
extern crypto_wrapper_err_t nullcrypto_use_privkey(crypto_wrapper_ctx_t *ctx,
						   const uint8_t *privkey, size_t privkey_len);
extern crypto_wrapper_err_t nullcrypto_gen_privkey(crypto_wrapper_ctx_t *ctx,
						   rats_key_algo_t key_algo, uint8_t **privkey,
						   size_t *privkey_len);
extern crypto_wrapper_err_t nullcrypto_get_pubkey_hash(crypto_wrapper_ctx_t *ctx,
						       rats_hash_algo_t hash_algo, uint8_t *hash);
extern crypto_wrapper_err_t nullcrypto_gen_hash(crypto_wrapper_ctx_t *ctx,
						rats_hash_algo_t hash_algo, const uint8_t *data,
						size_t size, uint8_t *hash);
extern crypto_wrapper_err_t nullcrypto_gen_cert(crypto_wrapper_ctx_t *ctx,
						rats_hash_algo_t hash_algo,
						rats_cert_info_t *cert_info);
extern crypto_wrapper_err_t nullcrypto_verify_cert(crypto_wrapper_ctx_t *ctx,
						   const uint8_t *certificate,
						   size_t certificate_size);
extern crypto_wrapper_err_t nullcrypto_cleanup(crypto_wrapper_ctx_t *ctx);

static crypto_wrapper_opts_t nullcrypto_opts = {
	.api_version = CRYPTO_WRAPPER_API_VERSION_DEFAULT,
	.name = "nullcrypto",
	.priority = 0,
	.pre_init = nullcrypto_pre_init,
	.init = nullcrypto_init,
	.use_privkey = nullcrypto_use_privkey,
	.gen_privkey = nullcrypto_gen_privkey,
	.get_pubkey_hash = nullcrypto_get_pubkey_hash,
	.gen_hash = nullcrypto_gen_hash,
	.gen_cert = nullcrypto_gen_cert,
	.verify_cert = nullcrypto_verify_cert,
	.cleanup = nullcrypto_cleanup,
};

#ifdef SGX
void libcrypto_wrapper_nullcrypto_init(void)
#else
void __attribute__((constructor)) libcrypto_wrapper_nullcrypto_init(void)
#endif
{
	RATS_DEBUG("called\n");

	crypto_wrapper_err_t err = crypto_wrapper_register(&nullcrypto_opts);
	if (err != CRYPTO_WRAPPER_ERR_NONE)
		RATS_ERR("failed to register the crypto wrapper 'nullcrypto' %#x\n", err);
}
