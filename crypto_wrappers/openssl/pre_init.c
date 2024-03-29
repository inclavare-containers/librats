/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/crypto_wrapper.h>

crypto_wrapper_err_t openssl_pre_init(void)
{
	RATS_DEBUG("called\n");

	return CRYPTO_WRAPPER_ERR_NONE;
}
