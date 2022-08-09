/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/verifier.h>

rats_verifier_err_t nullverifier_verify_evidence(rats_verifier_ctx_t *ctx,
						 attestation_evidence_t *evidence,
						 const uint8_t *hash,
						 __attribute__((unused)) unsigned int hash_len)
{
	RATS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	return RATS_VERIFIER_ERR_NONE;
}
