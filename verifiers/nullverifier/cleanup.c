/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/verifier.h>

rats_verifier_err_t nullverifier_cleanup(rats_verifier_ctx_t *ctx)
{
	RATS_DEBUG("called enclave verifier ctx: %p\n", ctx);

	return RATS_VERIFIER_ERR_NONE;
}
