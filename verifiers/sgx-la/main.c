/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <librats/verifier.h>
#include <librats/log.h>

extern rats_verifier_err_t rats_verifier_register(rats_verifier_opts_t *);
extern rats_verifier_err_t sgx_la_verifier_pre_init(void);
extern rats_verifier_err_t sgx_la_verifier_init(rats_verifier_ctx_t *);
extern rats_verifier_err_t sgx_la_verify_evidence(rats_verifier_ctx_t *, attestation_evidence_t *,
						  uint8_t *, unsigned int hash_len);
extern rats_verifier_err_t sgx_la_verifier_cleanup(rats_verifier_ctx_t *);

static rats_verifier_opts_t sgx_la_verifier_opts = {
	.api_version = RATS_VERIFIER_API_VERSION_DEFAULT,
	.flags = RATS_VERIFIER_OPTS_FLAGS_DEFAULT,
	.name = "sgx_la",
	.priority = 15,
	.pre_init = sgx_la_verifier_pre_init,
	.init = sgx_la_verifier_init,
	.verify_evidence = sgx_la_verify_evidence,
	.cleanup = sgx_la_verifier_cleanup,
};

#ifdef SGX
void libverifier_sgx_la_init(void)
#else
void __attribute__((constructor)) libverifier_sgx_la_init(void)
#endif
{
	RATS_DEBUG("called\n");

	rats_verifier_err_t err = rats_verifier_register(&sgx_la_verifier_opts);
	if (err != RATS_VERIFIER_ERR_NONE)
		RATS_DEBUG("failed to register the rats verifier 'sgx_la' %#x\n", err);
}
