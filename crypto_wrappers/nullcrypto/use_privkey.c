/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/err.h>
#include <librats/crypto_wrapper.h>

crypto_wrapper_err_t nullcrypto_use_privkey(crypto_wrapper_ctx_t *ctx, uint8_t *privkey,
					    size_t privkey_len)
{
	RATS_DEBUG("ctx: %p, privkey: %p, privkey_len: %zu\n", ctx, privkey, privkey_len);

	return CRYPTO_WRAPPER_ERR_NONE;
}
