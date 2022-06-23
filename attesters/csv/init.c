/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/attester.h>

static unsigned int dummy_private;

rats_verifier_err_t csv_attester_init(rats_attester_ctx_t *ctx)
{
	RTLS_DEBUG("ctx %p\n", ctx);

	ctx->attester_private = &dummy_private;

	return RATS_ATTESTER_ERR_NONE;
}
