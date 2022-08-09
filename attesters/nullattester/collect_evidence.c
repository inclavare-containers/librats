/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/attester.h>

rats_attester_err_t nullattester_collect_evidence(rats_attester_ctx_t *ctx,
						  attestation_evidence_t *evidence,
						  const uint8_t *hash,
						  __attribute__((unused)) uint32_t hash_len)
{
	RATS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	return RATS_ATTESTER_ERR_NONE;
}
