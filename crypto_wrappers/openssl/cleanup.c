/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <librats/log.h>
#include <librats/crypto_wrapper.h>
#include "openssl.h"

crypto_wrapper_err_t openssl_cleanup(crypto_wrapper_ctx_t *ctx)
{
	RATS_DEBUG("ctx %p\n", ctx);

	openssl_ctx *octx = ctx->crypto_private;

	EVP_PKEY_free(octx->privkey);
	free(octx);

	return CRYPTO_WRAPPER_ERR_NONE;
}
