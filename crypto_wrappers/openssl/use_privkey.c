/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/crypto_wrapper.h>
#include "openssl.h"

crypto_wrapper_err_t openssl_use_privkey(crypto_wrapper_ctx_t *ctx, uint8_t *privkey,
					 size_t privkey_len)
{
	crypto_wrapper_err_t ret;
	EVP_PKEY *pkey = NULL;
	BIO *bio = NULL;
	openssl_ctx *octx = NULL;

	RATS_DEBUG("ctx: %p, privkey: %p, privkey_len: %zu\n", ctx, privkey, privkey_len);

	octx = ctx->crypto_private;

	/* Parse the private key in PEM format */
	ret = CRYPTO_WRAPPER_ERR_NO_MEM;
	pkey = EVP_PKEY_new();
	if (!pkey)
		goto err;

	bio = BIO_new_mem_buf(privkey, privkey_len);
	if (!bio)
		goto err;

	ret = RATS_ATTESTER_ERR_CERT_PRIV_KEY;
	if (!PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL))
		goto err;
	BIO_free(bio);
	bio = NULL;

	octx->privkey = pkey;
	pkey = NULL;

	ret = CRYPTO_WRAPPER_ERR_NONE;
err:
	if (pkey)
		EVP_PKEY_free(pkey);
	if (bio)
		BIO_free(bio);
	return ret;
}
