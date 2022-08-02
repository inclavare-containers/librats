/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/attester.h>

#include "sgx_la.h"

rats_attester_err_t sgx_la_attester_init(rats_attester_ctx_t *ctx)
{
	RATS_DEBUG("ctx %p\n", ctx);

	sgx_la_ctx_t *sgx_la_ctx = (sgx_la_ctx_t *)calloc(1, sizeof(*sgx_la_ctx));
	if (!sgx_la_ctx)
		return RATS_ATTESTER_ERR_NO_MEM;

	sgx_la_ctx->eid = ctx->enclave_id;
	ctx->attester_private = sgx_la_ctx;

	return RATS_ATTESTER_ERR_NONE;
}
