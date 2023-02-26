/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <librats/verifier.h>
#include <librats/log.h>

extern rats_verifier_err_t rats_verifier_register(rats_verifier_opts_t *opts);
extern rats_verifier_err_t nullverifier_pre_init(void);
extern rats_verifier_err_t nullverifier_init(rats_verifier_ctx_t *);
extern rats_verifier_err_t nullverifier_verify_evidence(rats_verifier_ctx_t *,
							attestation_evidence_t *, const uint8_t *,
							uint32_t hash_len,
							attestation_endorsement_t *endorsements,
							claim_t **claims, size_t *claims_length);
extern rats_verifier_err_t nullverifier_cleanup(rats_verifier_ctx_t *);

static rats_verifier_opts_t nullverifier_opts = {
	.api_version = RATS_VERIFIER_API_VERSION_DEFAULT,
	.flags = RATS_VERIFIER_OPTS_FLAGS_DEFAULT,
	.name = "nullverifier",
	.type = "nullverifier",
	.priority = 0,
	.pre_init = nullverifier_pre_init,
	.init = nullverifier_init,
	.verify_evidence = nullverifier_verify_evidence,
	.cleanup = nullverifier_cleanup,
};

#ifdef SGX
rats_verifier_err_t libverifier_null_init(void)
#else
void __attribute__((constructor)) libverifier_null_init(void)
#endif
{
	RATS_DEBUG("called\n");

	rats_verifier_err_t err = rats_verifier_register(&nullverifier_opts);
	if (err != RATS_VERIFIER_ERR_NONE)
		RATS_ERR("failed to register the rats verifier 'nullverifier' %#x\n", err);
#ifdef SGX
	return err;
#endif
}
