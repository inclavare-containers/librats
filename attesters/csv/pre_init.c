/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/attester.h>
#include <librats/log.h>

rats_verifier_err_t csv_attester_pre_init(void)
{
	RATS_DEBUG("called\n");

	rats_verifier_err_t err = RATS_ATTESTER_ERR_NONE;

	char *cmdline_str = "which wget 1> /dev/null 2> /dev/null";
	if (system(cmdline_str) != 0) {
		RATS_ERR("please install wget for csv attest\n");
		err = -RATS_ATTESTER_ERR_NO_TOOL;
	}

	return err;
}
