/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/crypto_wrapper.h>

crypto_wrapper_err_t nullcrypto_gen_hash(crypto_wrapper_ctx_t *ctx, rats_hash_algo_t hash_algo,
					 const uint8_t *data, size_t size, uint8_t *hash)
{
	RATS_DEBUG("ctx %p, hash_algo %d, data %p, size %zu hash %p\n", ctx, hash_algo, data, size,
		   hash);

	return CRYPTO_WRAPPER_ERR_NONE;
}
