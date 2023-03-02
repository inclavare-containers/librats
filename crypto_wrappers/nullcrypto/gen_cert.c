/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/crypto_wrapper.h>
#include <librats/cert.h>

crypto_wrapper_err_t nullcrypto_gen_cert(crypto_wrapper_ctx_t *ctx, rats_hash_algo_t hash_algo,
					 rats_cert_info_t *cert_info)
{
	RATS_DEBUG("ctx: %p, hash_algo: %d, cert_info: %p\n", ctx, hash_algo, cert_info);

	return CRYPTO_WRAPPER_ERR_NONE;
}
