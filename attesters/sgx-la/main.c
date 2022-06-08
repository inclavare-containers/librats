/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <librats/attester.h>
#include <librats/log.h>

extern rats_attester_err_t rats_attester_register(rats_attester_opts_t *);
extern rats_attester_err_t sgx_la_attester_pre_init(void);
extern rats_attester_err_t sgx_la_attester_init(rats_attester_ctx_t *);
extern rats_attester_err_t sgx_la_collect_evidence(rats_attester_ctx_t *, attestation_evidence_t *,
						   uint8_t *, uint32_t hash_len);
extern rats_attester_err_t sgx_la_attester_cleanup(rats_attester_ctx_t *);

static rats_attester_opts_t sgx_la_attester_opts = {
	.api_version = RATS_ATTESTER_API_VERSION_DEFAULT,
	.flags = RATS_ATTESTER_OPTS_FLAGS_SGX_ENCLAVE,
	.name = "sgx_la",
	.priority = 15,
	.pre_init = sgx_la_attester_pre_init,
	.init = sgx_la_attester_init,
	.collect_evidence = sgx_la_collect_evidence,
	.cleanup = sgx_la_attester_cleanup,
};

#ifdef SGX
void libattester_sgx_la_init(void)
#else
void __attribute__((constructor)) libattester_sgx_la_init(void)
#endif
{
	RATS_DEBUG("called\n");

	rats_attester_err_t err = rats_attester_register(&sgx_la_attester_opts);
	if (err != RATS_ATTESTER_ERR_NONE)
		RATS_ERR("failed to register the rats attester 'sgx_la' %#x\n", err);
}
