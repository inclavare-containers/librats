/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <librats/err.h>
#include <librats/log.h>
#include "internal/verifier.h"
#include "internal/core.h"

static rats_verifier_err_t init_rats_verifier(rats_core_context_t *ctx,
					      rats_verifier_ctx_t *verifier_ctx)
{
	RATS_DEBUG("init rats verifier rats_core_context: %p\n", ctx);
	rats_verifier_err_t err = verifier_ctx->opts->init(verifier_ctx);

	if (err != RATS_VERIFIER_ERR_NONE)
		return RATS_VERIFIER_ERR_INIT;

	if (!verifier_ctx->verifier_private)
		return RATS_VERIFIER_ERR_INIT;

	return RATS_VERIFIER_ERR_NONE;
}

rats_verifier_err_t rats_verifier_select(rats_core_context_t *ctx, const char *name)
{
	RATS_DEBUG("selecting the rats verifier '%s' ...\n", name);

	rats_verifier_ctx_t *verifier_ctx = NULL;
	for (unsigned int i = 0; i < rats_verifier_nums; ++i) {
		if (name && strcmp(name, rats_verifiers_ctx[i]->opts->name))
			continue;

		verifier_ctx = (rats_verifier_ctx_t *)malloc(sizeof(*verifier_ctx));
		if (!verifier_ctx)
			return RATS_VERIFIER_ERR_NO_MEM;

		memcpy(verifier_ctx, rats_verifiers_ctx[i], sizeof(*verifier_ctx));

		/* Set necessary configurations from rats_init() to
		 * make init() working correctly.
		 */
		verifier_ctx->log_level = ctx->config.log_level;

		if (init_rats_verifier(ctx, verifier_ctx) == RATS_VERIFIER_ERR_NONE)
			break;

		free(verifier_ctx);
		verifier_ctx = NULL;
	}

	if (!verifier_ctx) {
		if (!name)
			RATS_ERR("failed to select an rats verifier\n");
		else
			RATS_ERR("failed to select the rats verifier '%s'\n", name);

		return RATS_VERIFIER_ERR_INVALID;
	}

	/* Explicitly specify the rats verifier which will never be changed */
	if (name)
		ctx->flags |= RATS_CONF_FLAGS_VERIFIER_ENFORCED;

	ctx->verifier = verifier_ctx;

	RATS_INFO("the rats verifier '%s' selected\n", ctx->verifier->opts->name);

	return RATS_VERIFIER_ERR_NONE;
}
