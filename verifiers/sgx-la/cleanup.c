/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/verifier.h>
#include "sgx_la.h"

rats_verifier_err_t sgx_la_verifier_cleanup(rats_verifier_ctx_t *ctx)
{
	RATS_DEBUG("called\n");

	sgx_la_ctx_t *la_ctx = (sgx_la_ctx_t *)ctx->verifier_private;

	free(la_ctx);

	return RATS_VERIFIER_ERR_NONE;
}
