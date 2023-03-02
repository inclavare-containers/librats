/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/crypto_wrapper.h>
#include <openssl/sha.h>

crypto_wrapper_err_t openssl_gen_hash(crypto_wrapper_ctx_t *ctx, rats_hash_algo_t hash_algo,
				      const uint8_t *data, size_t size, uint8_t *hash)
{
	RATS_DEBUG("ctx %p, hash_algo %d, data %p, size %zu hash %p\n", ctx, hash_algo, data, size,
		   hash);

	switch (hash_algo) {
	case RATS_HASH_ALGO_RESERVED:
	case RATS_HASH_ALGO_SHA256:
		SHA256(data, size, hash);
		break;
	case RATS_HASH_ALGO_SHA384:
		SHA384(data, size, hash);
		break;
	case RATS_HASH_ALGO_SHA512:
		SHA512(data, size, hash);
		break;
	default:
		return CRYPTO_WRAPPER_ERR_UNSUPPORTED_HASH_ALGO;
	}
	return CRYPTO_WRAPPER_ERR_NONE;
}
