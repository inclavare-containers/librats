/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <librats/err.h>
#include <librats/log.h>
#include <librats/attester.h>
#include <internal/attester.h>
#include <internal/cpu.h>

rats_attester_err_t rats_attester_register(const rats_attester_opts_t *opts)
{
	if (!opts)
		return -RATS_ATTESTER_ERR_INVALID;

	RATS_DEBUG("registering the rats attester '%s' ...\n", opts->name);

	if (opts->flags & RATS_ATTESTER_OPTS_FLAGS_SGX_ENCLAVE) {
		if (!is_sgx2_supported()) {
			// clang-format off
			RATS_DEBUG("failed to register the attester '%s' due to lack of SGX capability\n",
				   opts->type);
			// clang-format on
			return -RATS_ATTESTER_ERR_CPU_UNSUPPORTED;
		}
	}

	if (opts->flags & RATS_ATTESTER_OPTS_FLAGS_TDX_GUEST) {
		if (!is_tdguest_supported()) {
			// clang-format off
			RATS_DEBUG("failed to register the attester '%s' due to lack of TDX Guest capability\n",
				   opts->type);
			// clang-format on
			return -RATS_ATTESTER_ERR_CPU_UNSUPPORTED;
		}
	}

	if (opts->flags & RATS_ATTESTER_OPTS_FLAGS_SNP_GUEST) {
		if (!is_snpguest_supported()) {
			// clang-format off
			RATS_DEBUG("failed to register the attester '%s' due to lack of SNP Guest capability\n",
				   opts->type);
			// clang-format on
			return -RATS_ATTESTER_ERR_CPU_UNSUPPORTED;
		}
	}

	if (opts->flags & RATS_ATTESTER_OPTS_FLAGS_SEV_GUEST) {
		if (!is_sevguest_supported()) {
			// clang-format off
			RATS_DEBUG("failed to register the attester '%s' due to lack of SEV(-ES) Guest capability\n",
				   opts->type);
			// clang-format on
			return -RATS_ATTESTER_ERR_CPU_UNSUPPORTED;
		}
	}

	if (opts->flags & RATS_ATTESTER_OPTS_FLAGS_CSV_GUEST) {
		if (!is_csvguest_supported()) {
			// clang-format off
			RATS_DEBUG("failed to register the attester '%s' due to lack of CSV Guest capability\n",
				   opts->type);
			// clang-format on
			return -RATS_ATTESTER_ERR_CPU_UNSUPPORTED;
		}
	}

	rats_attester_opts_t *new_opts = (rats_attester_opts_t *)malloc(sizeof(*new_opts));
	if (!new_opts)
		return -RATS_ATTESTER_ERR_NO_MEM;

	memcpy(new_opts, opts, sizeof(*new_opts));

	if ((new_opts->name[0] == '\0') || (strlen(new_opts->name) >= sizeof(new_opts->name))) {
		RATS_ERR("invalid rats attester name\n");
		goto err;
	}

	if (strlen(new_opts->type) >= sizeof(new_opts->type)) {
		RATS_ERR("invalid rats attester type\n");
		goto err;
	}

	if (new_opts->api_version > RATS_ATTESTER_API_VERSION_MAX) {
		RATS_ERR("unsupported rats attester api version %d > %d\n", new_opts->api_version,
			 RATS_ATTESTER_API_VERSION_MAX);
		goto err;
	}

	/* Default type equals to name */
	if (new_opts->type[0] == '\0')
		snprintf(new_opts->type, sizeof(new_opts->type), "%s", new_opts->name);

	rats_attesters_opts[registerd_rats_attester_nums++] = new_opts;

	RATS_INFO("the rats attester '%s' registered with type '%s'\n", new_opts->name,
		  new_opts->type);

	return RATS_ATTESTER_ERR_NONE;

err:
	free(new_opts);
	return -RATS_ATTESTER_ERR_INVALID;
}
