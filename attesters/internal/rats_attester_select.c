/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <librats/api.h>
#include <librats/log.h>
#include <librats/core.h>
#include <internal/core.h>
#include <internal/attester.h>

static rats_attester_err_t init_rats_attester(rats_core_context_t *ctx,
					      rats_attester_ctx_t *attester_ctx)
{
	RATS_DEBUG("called rats core ctx: %p rats attester ctx: %p\n", ctx, attester_ctx);

	rats_attester_err_t err = attester_ctx->opts->init(attester_ctx);
	if (err != RATS_ATTESTER_ERR_NONE)
		return RATS_ATTESTER_ERR_INIT;

	if (!attester_ctx->attester_private)
		return RATS_ATTESTER_ERR_INIT;

	return RATS_ATTESTER_ERR_NONE;
}

rats_attester_err_t rats_attester_select(rats_core_context_t *ctx, const char *name)
{
	RATS_DEBUG("selecting the rats attester '%s'...\n", name);

	/* Explicitly specify the rats attester which will never be changed */
	if (name)
		ctx->flags |= RATS_CONF_FLAGS_ATTESTER_ENFORCED;

	rats_attester_ctx_t *attester_ctx = NULL;
	for (unsigned int i = 0; i < rats_attester_nums; ++i) {
		if (name && strcmp(name, rats_attesters_ctx[i]->opts->name))
			continue;

		attester_ctx = (rats_attester_ctx_t *)malloc(sizeof(*attester_ctx));
		if (!attester_ctx)
			return RATS_ATTESTER_ERR_NO_MEM;

		memcpy(attester_ctx, rats_attesters_ctx[i], sizeof(*attester_ctx));

		/* Set necessary configurations from rats_init() to
		 * make init() working correctly.
		 */
		attester_ctx->enclave_id = ctx->config.enclave_id;
		attester_ctx->log_level = ctx->config.log_level;

		if (init_rats_attester(ctx, attester_ctx) == RATS_ATTESTER_ERR_NONE)
			break;

		free(attester_ctx);
		attester_ctx = NULL;
	}

	if (!attester_ctx) {
		if (!name)
			RATS_ERR("failed to select an rats attester\n");
		else
			RATS_ERR("failed to select the rats attester '%s'\n", name);

		return RATS_ATTESTER_ERR_INVALID;
	}

	ctx->attester = attester_ctx;
	ctx->flags |= RATS_CTX_FLAGS_QUOTING_INITIALIZED;

	RATS_INFO("the rats attester '%s' selected\n", ctx->attester->opts->name);

	return RATS_ATTESTER_ERR_NONE;
}
