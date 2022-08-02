/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// clang-format off
#include <string.h>
#include <stdlib.h>
#ifndef SGX
#include <dirent.h>
#endif
#include <librats/err.h>
#include <librats/log.h>
#include "internal/attester.h"
#include "internal/core.h"
#define PATTERN_SUFFIX ".so"
#ifdef SGX
#include <sgx_error.h>
#include "rats_t.h"
#define DT_REG 8
#define DT_LNK 10
#endif
// clang-format on

static int rats_attester_cmp(const void *a, const void *b)
{
	return (*(rats_attester_ctx_t **)b)->opts->priority -
	       (*(rats_attester_ctx_t **)a)->opts->priority;
}

rats_attester_err_t rats_attester_load_all(void)
{
	RATS_DEBUG("called\n");

	uint64_t dir = rats_opendir(RATS_ATTESTERS_DIR);
	if (!dir) {
		RATS_ERR("failed to open %s", RATS_ATTESTERS_DIR);
		return RATS_ATTESTER_ERR_UNKNOWN;
	}

	unsigned int total_loaded = 0;
	rats_dirent *ptr;
	while ((rats_readdir(dir, &ptr)) != 1) {
		if (!strcmp(ptr->d_name, ".") || !strcmp(ptr->d_name, ".."))
			continue;
		if (strncmp(ptr->d_name + strlen(ptr->d_name) - strlen(PATTERN_SUFFIX),
			    PATTERN_SUFFIX, strlen(PATTERN_SUFFIX)))
			continue;

#ifdef OCCLUM
		/* Occlum can't identify the d_type of the file, always return DT_UNKNOWN */
		if (strncmp(ptr->d_name + strlen(ptr->d_name) - strlen(PATTERN_SUFFIX),
			    PATTERN_SUFFIX, strlen(PATTERN_SUFFIX)) == 0) {
#else
		if (ptr->d_type == DT_REG || ptr->d_type == DT_LNK) {
#endif
			if (rats_attester_load_single(ptr->d_name) == RATS_ATTESTER_ERR_NONE)
				++total_loaded;
		}
	}

	rats_closedir(dir);

	if (!total_loaded) {
		RATS_ERR("unavailable rats attester instance under %s\n", RATS_ATTESTERS_DIR);
		return RATS_ATTESTER_ERR_INIT;
	}

	/* Sort all rats_attester_ctx_t instances in the rats_attesters_ctx, and the higher priority
	 * instance should be sorted in front of the rats_attesters_ctx array.
	 */
	qsort(rats_attesters_ctx, rats_attester_nums, sizeof(rats_attester_ctx_t *),
	      rats_attester_cmp);

	return RATS_ATTESTER_ERR_NONE;
}
