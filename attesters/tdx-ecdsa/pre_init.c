/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <internal/cpu.h>
#include <librats/attester.h>
#include <librats/log.h>

rats_attester_err_t tdx_ecdsa_attester_pre_init(void)
{
	RATS_DEBUG("called\n");

	return RATS_ATTESTER_ERR_NONE;
}
