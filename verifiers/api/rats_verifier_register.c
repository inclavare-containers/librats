/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <librats/err.h>
#include <librats/log.h>
#include "internal/verifier.h"
#include "internal/cpu.h"

rats_verifier_err_t rats_verifier_register(const rats_verifier_opts_t *opts)
{
	if (!opts)
		return -RATS_VERIFIER_ERR_INVALID;

	RATS_DEBUG("registering the rats verifier '%s' ...\n", opts->name);

	rats_verifier_opts_t *new_opts = (rats_verifier_opts_t *)malloc(sizeof(*new_opts));
	if (!new_opts)
		return -RATS_VERIFIER_ERR_NO_MEM;

	memcpy(new_opts, opts, sizeof(*new_opts));

	if ((new_opts->name[0] == '\0') || (strlen(new_opts->name) >= sizeof(new_opts->name))) {
		RATS_ERR("invalid rats verifier name\n");
		goto err;
	}

	if (strlen(new_opts->type) >= sizeof(new_opts->type)) {
		RATS_ERR("invalid rats verifier type\n");
		goto err;
	}

	if (new_opts->api_version > RATS_VERIFIER_API_VERSION_MAX) {
		RATS_ERR("unsupported rats verifier api version %d > %d\n", new_opts->api_version,
			 RATS_VERIFIER_API_VERSION_MAX);
		goto err;
	}

	/* Default type equals to name */
	if (new_opts->type[0] == '\0')
		snprintf(new_opts->type, sizeof(new_opts->type), "%s", new_opts->name);

	rats_verifiers_opts[registerd_rats_verifier_nums++] = new_opts;

	RATS_INFO("the rats verifier '%s' registered with type '%s'\n", new_opts->name,
		  new_opts->type);

	return RATS_VERIFIER_ERR_NONE;

err:
	free(new_opts);
	return -RATS_VERIFIER_ERR_INVALID;
}
