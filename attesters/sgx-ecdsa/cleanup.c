/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/attester.h>
#include "sgx_ecdsa.h"

rats_attester_err_t sgx_ecdsa_attester_cleanup(rats_attester_ctx_t *ctx)
{
	RATS_DEBUG("called\n");

	sgx_ecdsa_ctx_t *ecdsa_ctx = (sgx_ecdsa_ctx_t *)ctx->attester_private;

	if (ecdsa_ctx)
		free(ecdsa_ctx);

	return RATS_ATTESTER_ERR_NONE;
}
