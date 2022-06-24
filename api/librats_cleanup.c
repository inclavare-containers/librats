/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <librats/api.h>
#include <librats/log.h>

rats_err_t librats_cleanup(rats_core_context_t *handle)
{
	RATS_DEBUG("handle %p\n", handle);

	if (!handle || !handle->attester || !handle->attester->opts ||
	    !handle->attester->opts->cleanup || !handle->verifier || !handle->verifier->opts ||
	    !handle->verifier->opts->cleanup)
		return -RATS_ERR_INVALID;

	rats_attester_err_t err_ra = handle->attester->opts->cleanup(handle->attester);
	if (err_ra != RATS_ATTESTER_ERR_NONE) {
		RATS_DEBUG("failed to clean up attester %#x\n", err_ra);
		return -RATS_ERR_INVALID;
	}

	rats_verifier_err_t err_rv = handle->verifier->opts->cleanup(handle->verifier);
	if (err_rv != RATS_VERIFIER_ERR_NONE) {
		RATS_DEBUG("failed to clean up verifier %#x\n", err_rv);
		return -RATS_ERR_INVALID;
	}

	return RATS_ERR_NONE;
}
