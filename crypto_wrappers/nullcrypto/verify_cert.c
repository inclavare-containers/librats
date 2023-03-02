/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/crypto_wrapper.h>
#include <librats/cert.h>

crypto_wrapper_err_t nullcrypto_verify_cert(crypto_wrapper_ctx_t *ctx, const uint8_t *certificate,
					    size_t certificate_size)
{
	RATS_DEBUG("ctx: %p, certificate: %p, certificate_size %zu\n", ctx, certificate,
		   certificate_size);

	return CRYPTO_WRAPPER_ERR_NONE;
}
