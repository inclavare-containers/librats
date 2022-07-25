/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <librats/api.h>
#include <librats/log.h>

rats_attester_err_t librats_collect_evidence(attestation_evidence_t *evidence, uint8_t *hash)
{
	uint32_t hash_len = 32;
	rats_core_context_t ctx;
	rats_conf_t conf;

	conf.api_version = RATS_API_VERSION_DEFAULT;
	conf.log_level = RATS_LOG_LEVEL_DEFAULT;

	if (rats_attest_init(&conf, &ctx) != RATS_ATTESTER_ERR_NONE)
		return RATS_ATTESTER_ERR_INIT;
	rats_attester_err_t q_err =
		ctx.attester->opts->collect_evidence(ctx.attester, evidence, hash, hash_len);
	
	if (ctx.attester->opts->cleanup(ctx.attester) != RATS_ATTESTER_ERR_NONE) {
		RATS_ERR("failed to clean up attester\n");
	}

	return q_err;
}
