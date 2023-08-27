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
#include "librats/crypto_wrapper.h"
#include <internal/crypto_wrapper.h>
#include <internal/core.h>

#ifdef SGX
#include "rats_t.h"
#endif

#ifdef SGX

#define RATS_ATTESTER_NUM	(sizeof(rats_attester_name) / sizeof(rats_attester_name[0]))
#define RATS_VERIFIER_NUM	(sizeof(rats_verifier_name) / sizeof(rats_verifier_name[0]))
#define CRYPTO_WRAPPERS_NUM	(sizeof(crypto_wrappers_name) / sizeof(crypto_wrappers_name[0]))
#define RATS_NAME   		32

// clang-format on
char rats_attester_name[][RATS_NAME] = { "nullattester", "sgx_la", "sgx_ecdsa" };
char rats_verifier_name[][RATS_NAME] = { "nullverifier", "sgx_la", "sgx_ecdsa_qve" };
char crypto_wrappers_name[][RATS_NAME] = { "nullcrypto", "openssl" };
#endif

int common_init(rats_conf_t *conf, rats_core_context_t *ctx)
{
	if (!conf || !ctx)
		return 1;

	ctx->config = *conf;

	if (conf->log_level == RATS_LOG_LEVEL_MAX) {
		rats_global_log_level = rats_loglevel_getenv("RATS_GLOBAL_LOG_LEVEL");
		if (rats_global_log_level == (rats_log_level_t)-1) {
			RATS_FATAL("failed to get log level from env\n");
			rats_exit();
		}
	}

	rats_global_core_context.config.api_version = RATS_API_VERSION_DEFAULT;

	if (ctx->config.api_version > RATS_API_VERSION_MAX) {
		RATS_ERR("unsupported rats api version %d > %d\n", ctx->config.api_version,
			 RATS_API_VERSION_MAX);
		return 1;
	}
	return 0;
}

rats_attester_err_t rats_attester_init(rats_conf_t *conf, rats_core_context_t *ctx)
{
	RATS_DEBUG("called, conf %p\n", conf);

	char attester_type[32] = "nullattester";
	char *choice = NULL;

	rats_attester_err_t err = RATS_ATTESTER_ERR_INVALID;

	if (common_init(conf, ctx))
		goto err_ctx;

	if (rats_attester_nums == 0) {
#ifdef SGX
		for (uint8_t i = 0; i < RATS_ATTESTER_NUM; i++) {
			err = rats_attester_init_static(rats_attester_name[i]);
			if (err != RATS_ATTESTER_ERR_NONE) {
				RATS_ERR("failed to initialize rats instance: %s\n",
					 rats_attester_name[i]);
				rats_exit();
			}
		}
#else
		/* Load all rats attester instances */
		err = rats_attester_load_all();
		if (err != RATS_ATTESTER_ERR_NONE) {
			RATS_FATAL("failed to load any rats attester %#x\n", err);
			rats_exit();
		}
#endif
		qsort(rats_attesters_ctx, rats_attester_nums, sizeof(rats_attester_ctx_t *),
		      rats_attester_cmp);
	}
	choice = ctx->config.attester_type;
	if (choice[0] == '\0') {
// clang-format off
#if defined(SGX) || defined(OCCLUM)
	memset(attester_type, 0, 32);
#ifdef SGX_ECDSA
	memcpy(attester_type, "sgx_ecdsa", 32);
#elif defined(SGX_LA)
	memcpy(attester_type, "sgx_la", 32);
#endif
#else
	memcpy(attester_type, rats_attesters_ctx[0]->opts->name, 32);
	if (rats_global_core_context.config.attester_type[0] != '\0')
		memcpy(attester_type, rats_global_core_context.config.attester_type, 32);
#endif
		// clang-format on

		err = rats_attester_select(ctx, attester_type);
		if (err != RATS_ATTESTER_ERR_NONE)
			goto err_ctx;
	} else {
		err = rats_attester_select(ctx, choice);
		if (err != RATS_ATTESTER_ERR_NONE)
			goto err_ctx;
	}

err_ctx:
	return err;
}

rats_verifier_err_t rats_verifier_init(rats_conf_t *conf, rats_core_context_t *ctx,
				       attestation_evidence_t *evidence)
{
	RATS_DEBUG("called, conf %p\n", conf);

	char *choice = NULL;

	rats_verifier_err_t err = RATS_VERIFIER_ERR_INVALID;

	if (common_init(conf, ctx))
		goto err_ctx;

	if (rats_verifier_nums == 0) {
#ifdef SGX
		for (uint8_t i = 0; i < RATS_VERIFIER_NUM; i++) {
			err = rats_verifier_init_static(rats_verifier_name[i]);
			if (err != RATS_VERIFIER_ERR_NONE) {
				RATS_ERR("failed to initialize rats instance %s %#x\n",
					 rats_verifier_name[i], err);
				rats_exit();
			}
		}
#else
		/* Load all rats verifier instances */
		err = rats_verifier_load_all();
		if (err != RATS_VERIFIER_ERR_NONE) {
			RATS_FATAL("failed to load any rats verifier %#x\n", err);
			rats_exit();
		}
#endif
		qsort(rats_verifiers_ctx, rats_verifier_nums, sizeof(rats_verifier_ctx_t *),
		      rats_verifier_cmp);
	}
	if (evidence) {
		err = rats_verifier_select_by_type(ctx, evidence->type);
	} else {
		/* Select the target verifier to be used */
		choice = ctx->config.verifier_type;
		if (choice[0] == '\0') {
			choice = rats_global_core_context.config.verifier_type;
			if (choice[0] == '\0')
				choice = NULL;
		}
		err = rats_verifier_select(ctx, choice);
	}
	if (err != RATS_VERIFIER_ERR_NONE)
		goto err_ctx;

err_ctx:
	return err;
}

crypto_wrapper_err_t rats_crypto_wrapper_init(rats_conf_t *conf, rats_core_context_t *ctx)
{
	RATS_DEBUG("called, conf %p\n", conf);

	char *choice = NULL;

	crypto_wrapper_err_t err = CRYPTO_WRAPPER_ERR_INVALID;

	if (common_init(conf, ctx))
		goto err_ctx;

	if (crypto_wrappers_nums == 0) {
#ifdef SGX
		for (uint8_t i = 0; i < CRYPTO_WRAPPERS_NUM; i++) {
			err = crypto_wrapper_init_static(crypto_wrappers_name[i]);
			if (err != CRYPTO_WRAPPER_ERR_NONE) {
				RATS_ERR("failed to initialize rats instance %s %#x\n",
					 crypto_wrappers_name[i], err);
				rats_exit();
			}
		}
#else
		/* Load all rats crypto_wrapper instances */
		err = crypto_wrapper_load_all();
		if (err != CRYPTO_WRAPPER_ERR_NONE) {
			RATS_FATAL("failed to load any rats crypto_wrapper %#x\n", err);
			rats_exit();
		}
#endif
		qsort(crypto_wrappers_ctx, crypto_wrappers_nums, sizeof(crypto_wrapper_ctx_t *),
		      crypto_wrapper_cmp);
	}
	/* Select the target crypto_wrapper to be used */
	choice = ctx->config.crypto_type;
	if (choice[0] == '\0') {
		choice = rats_global_core_context.config.crypto_type;
		if (choice[0] == '\0')
			choice = NULL;
	}
	err = crypto_wrapper_select(ctx, choice);
	if (err != CRYPTO_WRAPPER_ERR_NONE)
		goto err_ctx;

err_ctx:
	return err;
}
