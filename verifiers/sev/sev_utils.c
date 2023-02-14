/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <librats/log.h>
#include "sev_utils.h"
// clang-format off
#ifndef WASM
#include <curl/curl.h>
#endif
// clang-format on

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

int get_file_size(char *name)
{
	struct stat statbuf;

	if (stat(name, &statbuf) == 0)
		return statbuf.st_size;

	return 0;
}

int read_file(const char *filename, void *buffer, size_t len)
{
	FILE *fp = NULL;
	size_t count = 0;

	if ((fp = fopen(filename, "r")) == NULL) {
		RATS_ERR("failed to open %s\n", filename);
		return 0;
	}

	if ((count = fread(buffer, 1, len, fp)) != len) {
		fclose(fp);
		RATS_ERR("failed to read %s with count %lu\n", filename, count);
		return 0;
	}

	fclose(fp);
	return count;
}
