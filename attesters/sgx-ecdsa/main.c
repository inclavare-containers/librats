/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <librats/attester.h>
#include <librats/log.h>

extern rats_attester_err_t rats_attester_register(rats_attester_opts_t *opts);
extern rats_attester_err_t sgx_ecdsa_attester_pre_init(void);
extern rats_attester_err_t sgx_ecdsa_attester_init(rats_attester_ctx_t *ctx);
extern rats_attester_err_t sgx_ecdsa_collect_evidence(rats_attester_ctx_t *ctx,
						      attestation_evidence_t *evidence,
						      const uint8_t *hash, uint32_t hash_len);
extern rats_attester_err_t sgx_ecdsa_collect_endorsements(rats_attester_ctx_t *ctx,
							  attestation_evidence_t *evidence,
							  attestation_endorsement_t *endorsements);
extern rats_attester_err_t sgx_ecdsa_attester_cleanup(rats_attester_ctx_t *ctx);

static rats_attester_opts_t sgx_ecdsa_attester_opts = {
	.api_version = RATS_ATTESTER_API_VERSION_DEFAULT,
	.flags = RATS_ATTESTER_OPTS_FLAGS_SGX_ENCLAVE,
	.name = "sgx_ecdsa",
	.type = "sgx_ecdsa",
	.priority = 52,
	.pre_init = sgx_ecdsa_attester_pre_init,
	.init = sgx_ecdsa_attester_init,
	.collect_evidence = sgx_ecdsa_collect_evidence,
	.collect_endorsements = sgx_ecdsa_collect_endorsements,
	.cleanup = sgx_ecdsa_attester_cleanup,
};

#ifdef SGX
rats_attester_err_t libattester_sgx_ecdsa_init(void)
#else
void __attribute__((constructor)) libattester_sgx_ecdsa_init(void)
#endif
{
	RATS_DEBUG("called\n");

	rats_attester_err_t err = rats_attester_register(&sgx_ecdsa_attester_opts);
	if (err != RATS_ATTESTER_ERR_NONE)
		RATS_DEBUG("failed to register the rats attester 'sgx_ecdsa' %#x\n", err);
#ifdef SGX
	return err;
#endif
}
