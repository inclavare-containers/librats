/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <librats/log.h>
#include <librats/attester.h>

static unsigned int dummy_private;

rats_attester_err_t tdx_ecdsa_attester_init(rats_attester_ctx_t *ctx)
{
	RATS_DEBUG("ctx %p\n", ctx);

	ctx->attester_private = &dummy_private;

	return RATS_ATTESTER_ERR_NONE;
}
