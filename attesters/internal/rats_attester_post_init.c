/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#ifndef SGX
	#include <dlfcn.h>
#endif
#include <librats/err.h>
#include <librats/log.h>
#include "librats/core.h"
#include "librats/attester.h"
#include "internal/attester.h"
#include "internal/core.h"

rats_attester_err_t rats_attester_post_init(const char *name, void *handle)
{
	unsigned int i = 0;
	rats_attester_opts_t *opts = NULL;
	for (; i < registerd_rats_attester_nums; ++i) {
		opts = rats_attesters_opts[i];

		if (!strcmp(name, opts->name))
			break;
	}

	if (i == registerd_rats_attester_nums) {
		RATS_DEBUG("the rats attester '%s' failed to register\n", name);
		return RATS_ATTESTER_ERR_NOT_REGISTERED;
	}

	if (opts->pre_init) {
		rats_attester_err_t err_ea = opts->pre_init();
		if (err_ea != RATS_ATTESTER_ERR_NONE) {
			RATS_ERR("failed on pre_init() of rats attester '%s' %#x\n", name, err_ea);
			return RATS_ATTESTER_ERR_INVALID;
		}
	}

	rats_attester_ctx_t *attester_ctx = (rats_attester_ctx_t *)calloc(1, sizeof(*attester_ctx));
	if (!attester_ctx)
		return RATS_ATTESTER_ERR_NO_MEM;

	attester_ctx->opts = opts;
	attester_ctx->handle = handle;

	rats_attesters_ctx[rats_attester_nums++] = attester_ctx;

	return RATS_ATTESTER_ERR_NONE;
}
