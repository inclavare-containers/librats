/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/crypto_wrapper.h>

crypto_wrapper_err_t nullcrypto_get_pubkey_hash(crypto_wrapper_ctx_t *ctx, rats_key_algo_t key_algo,
						uint8_t *hash)
{
	RATS_DEBUG("ctx: %p, key_algo: %d, hash: %p\n", ctx, key_algo, hash);

	return CRYPTO_WRAPPER_ERR_NONE;
}