/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "utils.h"

#include "../../attesters/sev-snp/utils.c"

bool reverse_bytes(uint8_t *bytes, size_t size)
{
	uint8_t *start = bytes;
	uint8_t *end = bytes + size - 1;

	if (!bytes)
		return false;

	while (start < end) {
		uint8_t byte = *start;
		*start = *end;
		*end = byte;
		start++;
		end--;
	}

	return true;
}
