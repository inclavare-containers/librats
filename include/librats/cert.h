/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2023 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _RATS_CERT_H
#define _RATS_CERT_H

#include <stdint.h>

typedef struct {
	const char *organization;
	const char *organization_unit;
	const char *common_name;
} rats_cert_subject_t;

typedef struct {
	rats_cert_subject_t subject;
	unsigned int cert_len;
	uint8_t cert_buf[8192];
	uint8_t *evidence_buffer;
	size_t evidence_buffer_size;
	uint8_t *endorsements_buffer;
	size_t endorsements_buffer_size;
} rats_cert_info_t;

#endif
