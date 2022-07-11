/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <librats/err.h>
#include <librats/log.h>
#include "librats/core.h"
#include "librats/attester.h"
#include "internal/attester.h"
#include "internal/core.h"

// clang-format off
#define PATTERN_PREFIX "libattester_"
#ifdef SGX
#define PATTERN_SUFFIX ".a"
#else
#define PATTERN_SUFFIX ".so"
#endif
// clang-format on

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
		return -RATS_ATTESTER_ERR_NOT_REGISTERED;
	}

	if (opts->pre_init) {
		rats_attester_err_t err_ea = opts->pre_init();
		if (err_ea != RATS_ATTESTER_ERR_NONE) {
			RATS_ERR("failed on pre_init() of rats attester '%s' %#x\n", name, err_ea);
			return -RATS_ATTESTER_ERR_INVALID;
		}
	}

	rats_attester_ctx_t *attester_ctx = calloc(1, sizeof(*attester_ctx));
	if (!attester_ctx)
		return -RATS_ATTESTER_ERR_NO_MEM;

	attester_ctx->opts = opts;
	attester_ctx->log_level = rats_global_core_context.config.log_level;
	attester_ctx->handle = handle;

	rats_attesters_ctx[rats_attester_nums++] = attester_ctx;

	return RATS_ATTESTER_ERR_NONE;
}

rats_attester_err_t rats_attester_load_single(const char *fname)
{
	RATS_DEBUG("loading the rats attester instance '%s' ...\n", fname);

	/* Check whether the filename pattern matches up librats_attester_<name>.so */
	if (strlen(fname) <= strlen(PATTERN_PREFIX) + strlen(PATTERN_SUFFIX) ||
	    strncmp(fname, PATTERN_PREFIX, strlen(PATTERN_PREFIX)) ||
	    strncmp(fname + strlen(fname) - strlen(PATTERN_SUFFIX), PATTERN_SUFFIX,
		    strlen(PATTERN_SUFFIX))) {
		RATS_ERR("The filename pattern of '%s' NOT match " PATTERN_PREFIX
			 "<name>" PATTERN_SUFFIX "\n",
			 fname);
		return -RATS_ATTESTER_ERR_INVALID;
	}

	char realpath[strlen(RATS_ATTESTERS_DIR) + strlen(fname) + 1];
	snprintf(realpath, sizeof(realpath), "%s%s", RATS_ATTESTERS_DIR, fname);

	size_t name_len = strlen(fname) - strlen(PATTERN_PREFIX) - strlen(PATTERN_SUFFIX);
	char name[name_len + 1];
	snprintf(name, sizeof(name), "%s", fname + strlen(PATTERN_PREFIX));

	void *handle = NULL;
	rats_attester_err_t err = rats_attester_init(name, realpath, &handle);
	if (err != RATS_ATTESTER_ERR_NONE)
		return err;

	err = rats_attester_post_init(name, handle);
	if (err != RATS_ATTESTER_ERR_NONE)
		return err;

	RATS_DEBUG("the rats attester '%s' loaded\n", name);

	return RATS_ATTESTER_ERR_NONE;
}
