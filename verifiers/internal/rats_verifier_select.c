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
	RATS_DEBUG("selecting the rats verifier of name '%s' ...\n", name);

	rats_verifier_ctx_t *verifier_ctx = NULL;
	for (unsigned int i = 0; i < rats_verifier_nums; ++i) {
		if (name && strcmp(name, rats_verifiers_ctx[i]->opts->name))
			continue;

		verifier_ctx = (rats_verifier_ctx_t *)malloc(sizeof(*verifier_ctx));
		if (!verifier_ctx)
			return RATS_VERIFIER_ERR_NO_MEM;

		memcpy(verifier_ctx, rats_verifiers_ctx[i], sizeof(*verifier_ctx));

		if (init_rats_verifier(ctx, verifier_ctx) == RATS_VERIFIER_ERR_NONE)
			break;

		free(verifier_ctx);
		verifier_ctx = NULL;
	}

	if (!verifier_ctx) {
		if (!name)
			RATS_ERR("failed to select a rats verifier\n");
		else
			RATS_ERR("failed to select the rats verifier of name '%s'\n", name);

		return RATS_VERIFIER_ERR_INVALID;
	}

	ctx->verifier = verifier_ctx;

	RATS_INFO("the rats verifier '%s' selected\n", ctx->verifier->opts->name);

	return RATS_VERIFIER_ERR_NONE;
}

rats_verifier_err_t rats_verifier_select_by_type(rats_core_context_t *ctx, const char *verifier_type)
{
	RATS_DEBUG("selecting the rats verifier of type '%s' ...\n", verifier_type);

	rats_verifier_ctx_t *verifier_ctx = NULL;
	for (unsigned int i = 0; i < rats_verifier_nums; ++i) {
		if (verifier_type && strcmp(verifier_type, rats_verifiers_ctx[i]->opts->type))
			continue;

		verifier_ctx = (rats_verifier_ctx_t *)malloc(sizeof(*verifier_ctx));
		if (!verifier_ctx)
			return RATS_VERIFIER_ERR_NO_MEM;

		memcpy(verifier_ctx, rats_verifiers_ctx[i], sizeof(*verifier_ctx));

		if (init_rats_verifier(ctx, verifier_ctx) == RATS_VERIFIER_ERR_NONE)
			break;

		free(verifier_ctx);
		verifier_ctx = NULL;
	}

	if (!verifier_ctx) {
		if (!verifier_type)
			RATS_ERR("failed to select a rats verifier\n");
		else
			RATS_ERR("failed to select the rats verifier of type '%s'\n", verifier_type);

		return RATS_VERIFIER_ERR_INVALID;
	}

	ctx->verifier = verifier_ctx;

	RATS_INFO("the rats verifier '%s' selected\n", ctx->verifier->opts->name);

	return RATS_VERIFIER_ERR_NONE;
}
