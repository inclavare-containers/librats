/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// clang-format off
#include <stdlib.h>
#include <string.h>
#include <librats/err.h>
#include <librats/log.h>
#include "internal/core.h"
#include "internal/verifier.h"

#define PATTERN_PREFIX "libverifier_"
#ifdef SGX
#define PATTERN_SUFFIX ".a"
#else
#define PATTERN_SUFFIX ".so"
#endif
// clang-format on

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
	verifier_ctx->log_level = rats_global_core_context.config.log_level;
	verifier_ctx->handle = handle;

	rats_verifiers_ctx[rats_verifier_nums++] = verifier_ctx;

	return RATS_VERIFIER_ERR_NONE;
}

rats_verifier_err_t rats_verifier_load_single(const char *fname)
{
	RATS_DEBUG("loading the rats verifier instance '%s' ...\n", fname);

	/* Check whether the filename pattern matches up librats_verifier_<name>.so */
	if (strlen(fname) <= strlen(PATTERN_PREFIX) + strlen(PATTERN_SUFFIX) ||
	    strncmp(fname, PATTERN_PREFIX, strlen(PATTERN_PREFIX)) ||
	    strncmp(fname + strlen(fname) - strlen(PATTERN_SUFFIX), PATTERN_SUFFIX,
		    strlen(PATTERN_SUFFIX))) {
		RATS_ERR("The filename pattern of '%s' NOT match " PATTERN_PREFIX
			 "<name>" PATTERN_SUFFIX "\n",
			 fname);
		return RATS_VERIFIER_ERR_INVALID;
	}

	char realpath[strlen(RATS_VERIFIERS_DIR) + strlen(fname) + 1];
	snprintf(realpath, sizeof(realpath), "%s%s", RATS_VERIFIERS_DIR, fname);

	size_t name_len = strlen(fname) - strlen(PATTERN_PREFIX) - strlen(PATTERN_SUFFIX);
	char name[name_len + 1];
	snprintf(name, sizeof(name), "%s", fname + strlen(PATTERN_PREFIX));

	void *handle = NULL;
	rats_verifier_err_t err = rats_verifier_init(name, realpath, &handle);
	if (err != RATS_VERIFIER_ERR_NONE)
		return err;

	err = rats_verifier_post_init(name, handle);
	if (err != RATS_VERIFIER_ERR_NONE)
		return err;

	RATS_DEBUG("the rats verifier '%s' loaded\n", name);

	return RATS_VERIFIER_ERR_NONE;
}
