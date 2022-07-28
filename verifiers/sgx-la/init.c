/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/verifier.h>

#include "sgx_la.h"

rats_verifier_err_t sgx_la_verifier_init(rats_verifier_ctx_t *ctx)
{
	RATS_DEBUG("ctx %p\n", ctx);

	sgx_la_ctx_t *sgx_la_ctx = calloc(1, sizeof(*sgx_la_ctx));
	if (!sgx_la_ctx)
		return RATS_VERIFIER_ERR_NO_MEM;

	sgx_la_ctx->eid = ctx->enclave_id;
	ctx->verifier_private = sgx_la_ctx;

	return RATS_VERIFIER_ERR_NONE;
}
