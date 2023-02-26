/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/verifier.h>
#include <stdio.h>

extern rats_verifier_err_t rats_verifier_register(rats_verifier_opts_t *opts);
extern rats_verifier_err_t sev_snp_verifier_pre_init(void);
extern rats_verifier_err_t sev_snp_verifier_init(rats_verifier_ctx_t *ctx);
extern rats_verifier_err_t sev_snp_verify_evidence(rats_verifier_ctx_t *ctx,
						   attestation_evidence_t *evidence,
						   const uint8_t *hash, uint32_t hash_len,
						   attestation_endorsement_t *endorsements,
						   claim_t **claims, size_t *claims_length);
extern rats_verifier_err_t sev_snp_verifier_cleanup(rats_verifier_ctx_t *ctx);

static rats_verifier_opts_t sev_snp_verifier_opts = {
	.api_version = RATS_VERIFIER_API_VERSION_DEFAULT,
	.flags = RATS_VERIFIER_OPTS_FLAGS_SNP,
	.name = "sev_snp",
	.type = "sev_snp",
	.priority = 42,
	.pre_init = sev_snp_verifier_pre_init,
	.init = sev_snp_verifier_init,
	.verify_evidence = sev_snp_verify_evidence,
	.cleanup = sev_snp_verifier_cleanup,
};

void __attribute__((constructor)) libverifier_sev_snp_init(void)
{
	RATS_DEBUG("called\n");

	rats_verifier_err_t err = rats_verifier_register(&sev_snp_verifier_opts);
	if (err != RATS_VERIFIER_ERR_NONE)
		RATS_ERR("failed to register the rats verifier 'sev_snp' %#x\n", err);
}
