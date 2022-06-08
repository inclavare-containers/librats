/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <librats/log.h>
#include <librats/verifier.h>
#include "tdx-ecdsa.h"

rats_verifier_err_t tdx_ecdsa_verifier_init(rats_verifier_ctx_t *ctx)
{
	RATS_DEBUG("ctx %p\n", ctx);

	tdx_ctx_t *tdx_ctx = calloc(1, sizeof(*tdx_ctx));
	if (!tdx_ctx)
		return -RATS_VERIFIER_ERR_NO_MEM;

	memset(tdx_ctx->mrowner, 0, sizeof(tdx_ctx->mrowner));
	ctx->verifier_private = tdx_ctx;

	return RATS_VERIFIER_ERR_NONE;
}
