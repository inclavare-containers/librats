/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <dlfcn.h>
#include <librats/err.h>
#include <librats/log.h>
#include "internal/verifier.h"
#include "internal/core.h"

#define PATTERN_PREFIX "libverifier_"
#define PATTERN_SUFFIX ".so"

rats_verifier_err_t rats_verifier_load_single(const char *fname)
{
	RATS_DEBUG("loading the rats verifier instance '%s' ...\n", fname);

	/* Check whether the filename pattern matches up librats_verifier_<name>.so */
	if (strlen(fname) <= strlen(PATTERN_PREFIX) + strlen(PATTERN_SUFFIX) ||
	    strncmp(fname, PATTERN_PREFIX, strlen(PATTERN_PREFIX)) ||
	    strncmp(fname + strlen(fname) - strlen(PATTERN_SUFFIX), PATTERN_SUFFIX,
		    strlen(PATTERN_SUFFIX))) {
		RATS_ERR("The filename pattern of '%s' NOT match " PATTERN_PREFIX
			 "<name>" PATTERN_SUFFIX "\n",
			 fname);
		return RATS_VERIFIER_ERR_INVALID;
	}

	char realpath[strlen(RATS_VERIFIERS_DIR) + strlen(fname) + 1];
	snprintf(realpath, sizeof(realpath), "%s%s", RATS_VERIFIERS_DIR, fname);

	size_t name_len = strlen(fname) - strlen(PATTERN_PREFIX) - strlen(PATTERN_SUFFIX);
	char name[name_len + 1];
	snprintf(name, sizeof(name), "%s", fname + strlen(PATTERN_PREFIX));

	void *handle = dlopen(realpath, RTLD_LAZY);
	if (handle == NULL) {
		RATS_ERR("failed on dlopen(): %s\n", dlerror());
		return RATS_VERIFIER_ERR_DLOPEN;
	}

	rats_verifier_err_t err = rats_verifier_post_init(name, handle);
	if (err != RATS_VERIFIER_ERR_NONE)
		return err;

	RATS_DEBUG("the rats verifier '%s' loaded\n", name);

	return RATS_VERIFIER_ERR_NONE;
}

rats_verifier_err_t rats_verifier_load_all(void)
{
	RATS_DEBUG("called\n");

	DIR *dir = opendir(RATS_VERIFIERS_DIR);
	if (!dir) {
		RATS_ERR("failed to open %s\n", RATS_VERIFIERS_DIR);
		return RATS_VERIFIER_ERR_UNKNOWN;
	}

	unsigned int total_loaded = 0;
	struct dirent *ptr = NULL;
	while ((ptr = readdir(dir)) != NULL) {
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
			if (rats_verifier_load_single(ptr->d_name) == RATS_VERIFIER_ERR_NONE)
				++total_loaded;
		}
	}

	closedir(dir);

	if (!total_loaded) {
		RATS_ERR("unavailable rats verifier instance under %s\n", RATS_VERIFIERS_DIR);
		return RATS_VERIFIER_ERR_INIT;
	}
	return RATS_VERIFIER_ERR_NONE;
}
