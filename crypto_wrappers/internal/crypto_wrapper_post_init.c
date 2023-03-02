/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <librats/err.h>
#include <librats/log.h>
#include "internal/core.h"
#include "internal/crypto_wrapper.h"

crypto_wrapper_err_t crypto_wrapper_post_init(const char *name, void *handle)
{
	unsigned int i = 0;
	crypto_wrapper_opts_t *opts = NULL;
	for (i = 0; i < registerd_crypto_wrapper_nums; ++i) {
		opts = crypto_wrappers_opts[i];

		if (!strcmp(name, opts->name))
			break;
	}

	if (i == registerd_crypto_wrapper_nums) {
		RATS_DEBUG("the crypto wrapper '%s' failed to register\n", name);
		return CRYPTO_WRAPPER_ERR_NOT_REGISTERED;
	}

	if (opts->pre_init) {
		crypto_wrapper_err_t err_cw = opts->pre_init();
		if (err_cw != CRYPTO_WRAPPER_ERR_NONE) {
			RATS_ERR("failed on pre_init() of crypto wrapper '%s' %#x\n", name, err_cw);
			return CRYPTO_WRAPPER_ERR_INVALID;
		}
	}

	crypto_wrapper_ctx_t *crypto_ctx = calloc(1, sizeof(*crypto_ctx));
	if (!crypto_ctx)
		return CRYPTO_WRAPPER_ERR_NO_MEM;

	crypto_ctx->opts = opts;
	crypto_ctx->handle = handle;

	crypto_wrappers_ctx[crypto_wrappers_nums++] = crypto_ctx;

	return CRYPTO_WRAPPER_ERR_NONE;
}
