/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/attester.h>
#include "../../verifiers/tdx-ecdsa/tdx-ecdsa.h"

rats_attester_err_t tdx_ecdsa_attester_cleanup(rats_attester_ctx_t *ctx)
{
	RATS_DEBUG("called\n");

	tdx_ctx_t *tdx_ctx = (tdx_ctx_t *)ctx->attester_private;

	free(tdx_ctx);

	return RATS_ATTESTER_ERR_NONE;
}
