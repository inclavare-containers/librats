/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <librats/attester.h>
#include <librats/log.h>

extern rats_attester_err_t rats_attester_register(rats_attester_opts_t *opts);
extern rats_attester_err_t csv_attester_pre_init(void);
extern rats_attester_err_t csv_attester_init(rats_attester_ctx_t *ctx);
extern rats_attester_err_t csv_collect_evidence(rats_attester_ctx_t *ctx,
						attestation_evidence_t *evidence, uint8_t *hash,
						uint32_t hash_len);
extern rats_attester_err_t csv_attester_cleanup(rats_attester_ctx_t *ctx);

static rats_attester_opts_t csv_attester_opts = {
	.api_version = RATS_ATTESTER_API_VERSION_DEFAULT,
	.flags = RATS_ATTESTER_OPTS_FLAGS_CSV_GUEST,
	.name = "csv",
	.type = "csv",
	.priority = 20,
	.pre_init = csv_attester_pre_init,
	.init = csv_attester_init,
	.collect_evidence = csv_collect_evidence,
	.cleanup = csv_attester_cleanup,
};

void __attribute__((constructor)) libattester_csv_init(void)
{
	RATS_DEBUG("called\n");

	rats_attester_err_t err = rats_attester_register(&csv_attester_opts);
	if (err != RATS_ATTESTER_ERR_NONE)
		RATS_DEBUG("failed to register the rats register 'csv' %#x\n", err);
}
