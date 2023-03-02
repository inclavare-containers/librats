/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <librats/err.h>
#include <librats/log.h>
#include "internal/core.h"
#include "internal/crypto_wrapper.h"

static crypto_wrapper_err_t init_crypto_wrapper(crypto_wrapper_ctx_t *crypto_ctx)
{
	crypto_wrapper_err_t err = crypto_ctx->opts->init(crypto_ctx);
	if (err != CRYPTO_WRAPPER_ERR_NONE)
		return err;

	if (!crypto_ctx->crypto_private)
		return CRYPTO_WRAPPER_ERR_INIT;

	return CRYPTO_WRAPPER_ERR_NONE;
}

crypto_wrapper_err_t crypto_wrapper_select(rats_core_context_t *ctx, const char *name)
{
	RATS_DEBUG("selecting the crypto wrapper '%s' ...\n", name);

	crypto_wrapper_ctx_t *crypto_ctx = NULL;
	for (unsigned int i = 0; i < registerd_crypto_wrapper_nums; ++i) {
		if (name && strcmp(name, crypto_wrappers_ctx[i]->opts->name))
			continue;

		crypto_ctx = malloc(sizeof(*crypto_ctx));
		if (!crypto_ctx)
			return CRYPTO_WRAPPER_ERR_NO_MEM;

		*crypto_ctx = *crypto_wrappers_ctx[i];

		if (init_crypto_wrapper(crypto_ctx) == CRYPTO_WRAPPER_ERR_NONE)
			break;

		free(crypto_ctx);
		crypto_ctx = NULL;
	}

	if (!crypto_ctx) {
		if (!name)
			RATS_ERR("failed to select a crypto wrapper\n");
		else
			RATS_ERR("failed to select the crypto wrapper '%s'\n", name);

		return CRYPTO_WRAPPER_ERR_INIT;
	}

	ctx->crypto_wrapper = crypto_ctx;
	crypto_ctx->rats_handle = ctx;

	RATS_INFO("the crypto wrapper '%s' selected\n", crypto_ctx->opts->name);

	return CRYPTO_WRAPPER_ERR_NONE;
}
