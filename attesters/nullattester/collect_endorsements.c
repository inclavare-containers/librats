/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/attester.h>

rats_attester_err_t nullattester_collect_endorsements(rats_attester_ctx_t *ctx,
						      attestation_evidence_t *evidence,
						      attestation_endorsement_t *endorsements)
{
	RATS_DEBUG("ctx %p, evidence %p, endorsements %p\n", ctx, evidence, endorsements);

	return RATS_ATTESTER_ERR_NONE;
}
