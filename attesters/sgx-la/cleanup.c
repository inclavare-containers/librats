/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/attester.h>
#include "sgx_la.h"

rats_attester_err_t sgx_la_attester_cleanup(rats_attester_ctx_t *ctx)
{
	RATS_DEBUG("called\n");

	sgx_la_ctx_t *la_ctx = (sgx_la_ctx_t *)ctx->attester_private;

	free(la_ctx);

	return RATS_ATTESTER_ERR_NONE;
}
