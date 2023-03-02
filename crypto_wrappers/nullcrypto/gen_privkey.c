/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/err.h>
#include <librats/crypto_wrapper.h>

crypto_wrapper_err_t nullcrypto_gen_privkey(crypto_wrapper_ctx_t *ctx, rats_key_algo_t key_algo,
					    uint8_t **privkey, size_t *privkey_len)
{
	RATS_DEBUG("ctx: %p, key_algo: %d, privkey: %p, privkey_len: %p\n", ctx, key_algo, privkey,
		   privkey_len);

	/* Indicate no private key generated */
	if (privkey_len)
		*privkey_len = 0;
	if (privkey)
		*privkey = NULL;

	return CRYPTO_WRAPPER_ERR_NONE;
}
