/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/verifier.h>
#include "sgx_error.h"
#include "sgx_la.h"
#include "rats_t.h"

/* Refer to explanation in sgx_la_collect_evidence */
rats_verifier_err_t sgx_la_verify_evidence(rats_verifier_ctx_t *ctx,
					   attestation_evidence_t *evidence, const uint8_t *hash,
					   uint32_t hash_len,
					   __attribute__((unused)) claim_t **claims,
					   __attribute__((unused)) size_t *claims_length)
{
	rats_verifier_err_t err = RATS_VERIFIER_ERR_UNKNOWN;

	rats_ocall_la_verify_evidence(&err, ctx, evidence, sizeof(attestation_evidence_t), hash,
				 hash_len);

	return err;
}
