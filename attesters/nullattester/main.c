/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <librats/attester.h>
#include <librats/log.h>

extern rats_attester_err_t rats_attester_register(rats_attester_opts_t *);
extern rats_attester_err_t nullattester_pre_init(void);
extern rats_attester_err_t nullattester_init(rats_attester_ctx_t *);
extern rats_attester_err_t nullattester_collect_evidence(rats_attester_ctx_t *,
							 attestation_evidence_t *, uint8_t *,
							 uint32_t hash_len);
extern rats_attester_err_t nullattester_cleanup(rats_attester_ctx_t *);

static rats_attester_opts_t nullattester_opts = {
	.api_version = RATS_ATTESTER_API_VERSION_DEFAULT,
	.flags = RATS_ATTESTER_FLAGS_DEFAULT,
	.name = "nullattester",
	.priority = 0,
	.pre_init = nullattester_pre_init,
	.init = nullattester_init,
	.collect_evidence = nullattester_collect_evidence,
	.cleanup = nullattester_cleanup,
};

#ifdef SGX
void libattester_null_init(void)
#else
void __attribute__((constructor)) libattester_null_init(void)
#endif
{
	RATS_DEBUG("called\n");

	rats_attester_err_t err = rats_attester_register(&nullattester_opts);
	if (err != RATS_ATTESTER_ERR_NONE)
		RATS_ERR("failed to register the rats attester 'nullattester' %#x\n", err);
}
