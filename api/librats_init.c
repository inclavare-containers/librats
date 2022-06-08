/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// clang-format off
#include <stdlib.h>
#include <string.h>
#include <librats/log.h>
#include <librats/err.h>
#include "librats/attester.h"
#include <internal/attester.h>
#include "librats/verifier.h"
#include <internal/verifier.h>
#include <internal/core.h>

#ifdef SGX
#include "rats_t.h"
#endif
// clang-format on

#ifdef SGX
// clang-format off
#define RATS_NUM    5
#define RATS_NAME   32
// clang-format on
char rats_instance_name[RATS_NUM][RATS_NAME] = { "nullattester", "nullverifier", "sgx_ecdsa",
						 "sgx_ecdsa_qve", "sgx_la" };
#endif

rats_err_t librats_init(rats_conf_t *conf, rats_core_context_t *ctx)
{
	RATS_DEBUG("called\n");

	rats_global_log_level = rats_loglevel_getenv("RATS_GLOBAL_LOG_LEVEL");
	if (rats_global_log_level == (rats_log_level_t)-1) {
		RATS_FATAL("failed to get log level from env\n");
		rats_exit();
	}

	rats_global_core_context.config.api_version = RATS_API_VERSION_DEFAULT;
	rats_global_core_context.config.log_level = rats_global_log_level;

	if (!conf)
		return -RATS_ERR_INVALID;

	RATS_DEBUG("conf %p\n", conf);

	if (!ctx)
		return -RATS_ERR_NO_MEM;

	ctx->config = *conf;

	rats_err_t err = -RATS_ERR_INVALID;

	if (ctx->config.api_version > RATS_API_VERSION_MAX) {
		RATS_ERR("unsupported rats api version %d > %d\n", ctx->config.api_version,
			 RATS_API_VERSION_MAX);
		goto err_ctx;
	}

	if (ctx->config.log_level < 0 || ctx->config.log_level >= RATS_LOG_LEVEL_MAX) {
		ctx->config.log_level = rats_global_core_context.config.log_level;
		RATS_WARN("log level reset to global value %d\n",
			  rats_global_core_context.config.log_level);
	}

	rats_global_log_level = ctx->config.log_level;

#ifdef SGX
	for (uint8_t i = 0; i < RATS_NUM; i++) {
		err = rats_instance_init(rats_instance_name[i], NULL, NULL);
		if (err != RATS_ERR_NONE) {
			RATS_ERR("failed to initialize rats instance: %s\n", rats_instance_name[i]);
			rats_exit();
		}
	}
#else
	/* Load all rats attester instances */
	err = rats_attester_load_all();
	if (err != RATS_ERR_NONE) {
		RATS_FATAL("failed to load any rats attester %#x\n", err);
		rats_exit();
	}
	/* Load all rats verifier instances */
	err = rats_verifier_load_all();
	if (err != RATS_ERR_NONE) {
		RATS_FATAL("failed to load any rats verifier %#x\n", err);
		rats_exit();
	}
#endif
	/* Select the target attester to be used */
	char *choice = ctx->config.attester_type;
	if (choice[0] == '\0') {
		choice = rats_global_core_context.config.attester_type;
		if (choice[0] == '\0')
			choice = NULL;
	}
	err = rats_attester_select(ctx, choice);
	if (err != RATS_ERR_NONE)
		goto err_ctx;

	/* Select the target verifier to be used */
	choice = ctx->config.verifier_type;
	if (choice[0] == '\0') {
		choice = rats_global_core_context.config.verifier_type;
		if (choice[0] == '\0')
			choice = NULL;
	}
	err = rats_verifier_select(ctx, choice);
	if (err != RATS_ERR_NONE)
		goto err_ctx;

err_ctx:
	free(ctx);
	return err;
}
