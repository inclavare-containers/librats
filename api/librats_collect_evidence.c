/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <librats/api.h>

rats_attester_err_t librats_collect_evidence(rats_attester_ctx_t *ctx,
					     attestation_evidence_t *evidence, uint8_t *hash,
					     uint32_t hash_len)
{
	rats_attester_err_t q_err = ctx->opts->collect_evidence(ctx, evidence, hash, hash_len);

	return q_err;
}
