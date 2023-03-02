/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/crypto_wrapper.h>

crypto_wrapper_err_t nullcrypto_cleanup(crypto_wrapper_ctx_t *ctx)
{
	RATS_DEBUG("ctx %p\n", ctx);

	return CRYPTO_WRAPPER_ERR_NONE;
}
