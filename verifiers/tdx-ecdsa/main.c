/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <librats/log.h>
#include <librats/verifier.h>

extern rats_verifier_err_t rats_verifier_register(rats_verifier_opts_t *opts);
extern rats_verifier_err_t tdx_ecdsa_verifier_pre_init(void);
extern rats_verifier_err_t tdx_ecdsa_verifier_init(rats_verifier_ctx_t *ctx);
extern rats_verifier_err_t tdx_ecdsa_verify_evidence(rats_verifier_ctx_t *ctx,
						     attestation_evidence_t *evidence,
						     const uint8_t *hash, uint32_t hash_len,
						     claim_t **claims, size_t *claims_length);
extern rats_verifier_err_t tdx_ecdsa_verifier_cleanup(rats_verifier_ctx_t *ctx);

static rats_verifier_opts_t tdx_ecdsa_verifier_opts = {
	.api_version = RATS_VERIFIER_API_VERSION_DEFAULT,
	.flags = RATS_VERIFIER_OPTS_FLAGS_TDX,
	.name = "tdx_ecdsa",
	.type = "tdx_ecdsa",
	.priority = 42,
	.pre_init = tdx_ecdsa_verifier_pre_init,
	.init = tdx_ecdsa_verifier_init,
	.verify_evidence = tdx_ecdsa_verify_evidence,
	.cleanup = tdx_ecdsa_verifier_cleanup,
};

void __attribute__((constructor)) libverifier_tdx_ecdsa_init(void)
{
	RATS_DEBUG("called\n");

	rats_verifier_err_t err = rats_verifier_register(&tdx_ecdsa_verifier_opts);
	if (err != RATS_VERIFIER_ERR_NONE)
		RATS_ERR("failed to register the rats verifier 'tdx_ecdsa' %#x\n", err);
}
