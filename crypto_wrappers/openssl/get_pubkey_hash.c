/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/crypto_wrapper.h>
#include "openssl.h"

crypto_wrapper_err_t openssl_get_pubkey_hash(crypto_wrapper_ctx_t *ctx, rats_hash_algo_t hash_algo,
					     uint8_t *hash)
{
	crypto_wrapper_err_t ret = CRYPTO_WRAPPER_ERR_NONE;
	openssl_ctx *octx = NULL;
	uint8_t *pubkey_blob = NULL;
	int pubkey_blob_size;

	RATS_DEBUG("ctx %p, hash_algo %d, hash %p\n", ctx, hash_algo, hash);

	if (!ctx || !hash)
		return CRYPTO_WRAPPER_ERR_INVALID;

	octx = ctx->crypto_private;

	/* Calculate hash of SubjectPublicKeyInfo object */
	ret = CRYPTO_WRAPPER_ERR_PUB_KEY_LEN;
	pubkey_blob_size = i2d_PUBKEY(octx->privkey, &pubkey_blob);
	if (pubkey_blob_size < 0)
		goto err;

	ret = ctx->opts->gen_hash(ctx, hash_algo, pubkey_blob, pubkey_blob_size, hash);
	if (ret != CRYPTO_WRAPPER_ERR_NONE) {
		RATS_ERR("failed to generate pubkey hash, hash_algo: %d ret : %#x\n", hash_algo,
			 ret);
		goto err;
	}

	size_t hash_len = hash_size_of_algo(hash_algo);
	if (hash_len != 0 && hash_len > 32) {
		RATS_DEBUG(
			"the sha256 of public key [%zu] %02x%02x%02x%02x%02x%02x%02x%02x...%02x%02x%02x%02x\n",
			hash_len, hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6],
			hash[7], hash[28], hash[29], hash[30], hash[31]);
	}

	ret = CRYPTO_WRAPPER_ERR_NONE;
err:
	if (pubkey_blob)
		free(pubkey_blob);
	return ret;
}
