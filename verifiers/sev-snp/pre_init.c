/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/verifier.h>

#define TOOL_NUM  3
#define TOOL_NAME 10

rats_verifier_err_t sev_snp_verifier_pre_init(void)
{
	RATS_DEBUG("called\n");

	return RATS_VERIFIER_ERR_NONE;
}
