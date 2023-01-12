/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <librats/verifier.h>
#include <librats/log.h>

extern rats_verifier_err_t rats_verifier_register(rats_verifier_opts_t *opts);
extern rats_verifier_err_t sgx_ecdsa_verifier_pre_init(void);
extern rats_verifier_err_t sgx_ecdsa_verifier_init(rats_verifier_ctx_t *ctx);
extern rats_verifier_err_t sgx_ecdsa_verify_evidence(rats_verifier_ctx_t *ctx,
						     attestation_evidence_t *evidence,
						     const uint8_t *hash, uint32_t hash_len,
						     attestation_endorsement_t *endorsements,
						     claim_t **claims, size_t *claims_length);
extern rats_verifier_err_t sgx_ecdsa_verifier_cleanup(rats_verifier_ctx_t *ctx);

static rats_verifier_opts_t sgx_ecdsa_qve_opts = {
	.api_version = RATS_VERIFIER_API_VERSION_DEFAULT,
	.flags = RATS_VERIFIER_OPTS_FLAGS_DEFAULT,
	.name = "sgx_ecdsa_qve",
	.type = "sgx_ecdsa",
	.priority = 53,
	.pre_init = sgx_ecdsa_verifier_pre_init,
	.init = sgx_ecdsa_verifier_init,
	.verify_evidence = sgx_ecdsa_verify_evidence,
	.cleanup = sgx_ecdsa_verifier_cleanup,
};

#ifdef SGX
rats_verifier_err_t libverifier_sgx_ecdsa_qve_init(void)
#else
void __attribute__((constructor)) libverifier_sgx_ecdsa_qve_init(void)
#endif
{
	RATS_DEBUG("called\n");

	rats_verifier_err_t err = rats_verifier_register(&sgx_ecdsa_qve_opts);
	if (err != RATS_VERIFIER_ERR_NONE)
		RATS_DEBUG("failed to register the rats verifier 'sgx_ecdsa_qve' %#x\n", err);
#ifdef SGX
	return err;
#endif
}
