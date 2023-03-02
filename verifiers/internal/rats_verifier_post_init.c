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
#include "internal/verifier.h"

rats_verifier_err_t rats_verifier_post_init(const char *name, void *handle)
{
	unsigned int i = 0;
	rats_verifier_opts_t *opts = NULL;
	for (; i < registerd_rats_verifier_nums; ++i) {
		opts = rats_verifiers_opts[i];

		if (!strcmp(name, opts->name))
			break;
	}

	if (i == registerd_rats_verifier_nums) {
		RATS_DEBUG("the rats verifier '%s' failed to be registered\n", name);
		return RATS_VERIFIER_ERR_NOT_REGISTERED;
	}

	if (opts->pre_init) {
		rats_verifier_err_t err_ev = opts->pre_init();

		if (err_ev != RATS_VERIFIER_ERR_NONE) {
			RATS_ERR("failed on pre_init() of rats verifier '%s' %#x\n", name, err_ev);
			return RATS_VERIFIER_ERR_INVALID;
		}
	}

	rats_verifier_ctx_t *verifier_ctx = (rats_verifier_ctx_t *)calloc(1, sizeof(*verifier_ctx));
	if (!verifier_ctx)
		return RATS_VERIFIER_ERR_NO_MEM;

	verifier_ctx->opts = opts;
	verifier_ctx->handle = handle;

	rats_verifiers_ctx[rats_verifier_nums++] = verifier_ctx;

	return RATS_VERIFIER_ERR_NONE;
}
