/* Copyright (c) 2021 Intel Corporation
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
#include "internal/core.h"
#include "internal/crypto_wrapper.h"

#define PATTERN_PREFIX "libcrypto_wrapper_"
#define PATTERN_SUFFIX ".so"

crypto_wrapper_err_t rats_crypto_wrapper_load_single(const char *fname)
{
	RATS_DEBUG("loading the crypto wrapper instance '%s' ...\n", fname);

	/* Check whether the filename pattern matches up libcrypto_wrapper_<name>.so */
	if (strlen(fname) <= strlen(PATTERN_PREFIX) + strlen(PATTERN_SUFFIX) ||
	    strncmp(fname, PATTERN_PREFIX, strlen(PATTERN_PREFIX)) ||
	    strncmp(fname + strlen(fname) - strlen(PATTERN_SUFFIX), PATTERN_SUFFIX,
		    strlen(PATTERN_SUFFIX))) {
		RATS_ERR("The filename pattern of '%s' NOT match " PATTERN_PREFIX
			 "<name>" PATTERN_SUFFIX "\n",
			 fname);
		return CRYPTO_WRAPPER_ERR_INVALID;
	}

	char realpath[strlen(CRYPTO_WRAPPERS_DIR) + strlen(fname) + 1];
	snprintf(realpath, sizeof(realpath), "%s%s", CRYPTO_WRAPPERS_DIR, fname);

	uint32_t name_len = (uint32_t)strlen(fname) - (uint32_t)strlen(PATTERN_PREFIX) -
			    (uint32_t)strlen(PATTERN_SUFFIX);
	char name[name_len + 1];
	snprintf(name, sizeof(name), "%s", fname + strlen(PATTERN_PREFIX));

	void *handle = dlopen(realpath, RTLD_LAZY);
	if (handle == NULL) {
		RATS_ERR("failed on dlopen(): %s\n", dlerror());
		return CRYPTO_WRAPPER_ERR_DLOPEN;
	}

	crypto_wrapper_err_t err = crypto_wrapper_post_init(name, handle);
	if (err != CRYPTO_WRAPPER_ERR_NONE)
		return err;

	RATS_DEBUG("the crypto wrapper '%s' loaded\n", name);

	return CRYPTO_WRAPPER_ERR_NONE;
}

crypto_wrapper_err_t crypto_wrapper_load_all(void)
{
	RATS_DEBUG("called\n");

	DIR *dir = opendir(CRYPTO_WRAPPERS_DIR);
	if (!dir) {
		RATS_ERR("failed to open %s\n", CRYPTO_WRAPPERS_DIR);
		return CRYPTO_WRAPPER_ERR_UNKNOWN;
	}

	unsigned int total_loaded = 0;
	struct dirent *ptr = NULL;
	while ((ptr = readdir(dir)) != NULL) {
		if (!strcmp(ptr->d_name, ".") || !strcmp(ptr->d_name, "..")) {
			continue;
		}
		if (strncmp(ptr->d_name + strlen(ptr->d_name) - strlen(PATTERN_SUFFIX),
			    PATTERN_SUFFIX, strlen(PATTERN_SUFFIX))) {
			continue;
		}
#ifdef OCCLUM
		/* Occlum can't identify the d_type of the file, always return DT_UNKNOWN */
		if (strncmp(ptr->d_name + strlen(ptr->d_name) - strlen(PATTERN_SUFFIX),
			    PATTERN_SUFFIX, strlen(PATTERN_SUFFIX)) == 0) {
#else
		if (ptr->d_type == DT_REG || ptr->d_type == DT_LNK) {
#endif
			if (rats_crypto_wrapper_load_single(ptr->d_name) == CRYPTO_WRAPPER_ERR_NONE)
				++total_loaded;
		}
	}

	closedir(dir);

	if (!total_loaded) {
		RATS_ERR("unavailable crypto wrapper instance under %s\n", CRYPTO_WRAPPERS_DIR);
		return CRYPTO_WRAPPER_ERR_INIT;
	}

	return CRYPTO_WRAPPER_ERR_NONE;
}
