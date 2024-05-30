/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/crypto_wrapper.h>
#include "openssl.h"

crypto_wrapper_err_t openssl_gen_privkey(crypto_wrapper_ctx_t *ctx, rats_key_algo_t key_algo,
					 uint8_t **privkey, size_t *privkey_len)
{
	openssl_ctx *octx = NULL;
	RSA *rsa_key = NULL;
	EC_KEY *ec_key = NULL;

	BIO *bio = NULL;
	BUF_MEM *bptr = NULL;

	crypto_wrapper_err_t ret = CRYPTO_WRAPPER_ERR_NONE;

	RATS_DEBUG("ctx %p, key_algo %d, privkey %p, privkey_len %p\n", ctx, key_algo, privkey,
		   privkey_len);

	if (!ctx || !privkey_len || !privkey)
		return CRYPTO_WRAPPER_ERR_INVALID;

	octx = ctx->crypto_private;

	ret = CRYPTO_WRAPPER_ERR_NO_MEM;

	if (key_algo == RATS_KEY_ALGO_ECC_256) {
		ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		if (ec_key == NULL)
			goto err;

		ret = CRYPTO_WRAPPER_ERR_PRIV_KEY_LEN;

		EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);

		/* Generating public-private key */
		if (!EC_KEY_generate_key(ec_key))
			goto err;

		/* check key */
		if (!EC_KEY_check_key(ec_key))
			goto err;

		octx->privkey = EVP_PKEY_new();
		EVP_PKEY_assign_EC_KEY(octx->privkey, ec_key);
		ec_key = NULL;
	} else if (key_algo == RATS_KEY_ALGO_RSA_3072) {
		rsa_key = RSA_new();
		if (rsa_key == NULL)
			goto err;

		BIGNUM *e = BN_new();
		if (e == NULL)
			goto err;

		ret = CRYPTO_WRAPPER_ERR_PRIV_KEY_LEN;
		BN_set_word(e, RSA_F4);
		if (!RSA_generate_key_ex(rsa_key, 3072, e, NULL)) {
			BN_free(e);
			goto err;
		}
		BN_free(e);

		octx->privkey = EVP_PKEY_new();
		EVP_PKEY_assign_RSA(octx->privkey, rsa_key);
		rsa_key = NULL;
	} else {
		return CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;
	}

	ret = CRYPTO_WRAPPER_ERR_NO_MEM;
	/* Encode private key */
	bio = BIO_new(BIO_s_mem());
	if (!bio)
		goto err;

	if (!PEM_write_bio_PrivateKey(bio, octx->privkey, NULL, NULL, 0, 0, NULL))
		goto err;

	*privkey_len = BIO_get_mem_data(bio, (char **)privkey);
	if (*privkey_len <= 0)
		goto err;

	RATS_DEBUG("private key (%zu-byte) in PEM format\n", *privkey_len);

	ret = CRYPTO_WRAPPER_ERR_NONE;

err:
	if (bio) {
		BIO_get_mem_ptr(bio, &bptr);
		(void)BIO_set_close(bio, BIO_NOCLOSE);
		BIO_free(bio);
		bio = NULL;
		bptr->data = NULL;
		BUF_MEM_free(bptr);
		bptr = NULL;
	}

	if (key_algo == RATS_KEY_ALGO_ECC_256) {
		if (ec_key) {
			EC_KEY_free(ec_key);
			ec_key = NULL;
		}
	} else if (key_algo == RATS_KEY_ALGO_RSA_3072) {
		if (rsa_key) {
			RSA_free(rsa_key);
			rsa_key = NULL;
		}
	}
	return ret;
}
