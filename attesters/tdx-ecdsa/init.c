/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <librats/log.h>
#include <librats/attester.h>
#include "../../verifiers/tdx-ecdsa/tdx-ecdsa.h"

rats_attester_err_t tdx_ecdsa_attester_init(rats_attester_ctx_t *ctx)
{
	RATS_DEBUG("ctx %p\n", ctx);

	tdx_ctx_t *tdx_ctx = calloc(1, sizeof(*tdx_ctx));
	if (!tdx_ctx)
		return -RATS_ATTESTER_ERR_NO_MEM;

	memset(tdx_ctx->mrowner, 0, sizeof(tdx_ctx->mrowner));
	ctx->attester_private = tdx_ctx;

	return RATS_ATTESTER_ERR_NONE;
}
