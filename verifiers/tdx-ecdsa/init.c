/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <librats/log.h>
#include <librats/verifier.h>

static unsigned int dummy_private;

rats_verifier_err_t tdx_ecdsa_verifier_init(rats_verifier_ctx_t *ctx)
{
	RATS_DEBUG("ctx %p\n", ctx);

	ctx->verifier_private = &dummy_private;

	return RATS_VERIFIER_ERR_NONE;
}
