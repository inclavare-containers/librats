/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/attester.h>

rats_attester_err_t nullattester_cleanup(__attribute__((unused)) rats_attester_ctx_t *ctx)
{
	RATS_DEBUG("called\n");

	return RATS_ATTESTER_ERR_NONE;
}
