/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <librats/claim.h>

static void _free_claim(claim_t *claim)
{
	free(claim->name);
	free(claim->value);
}

void free_claims_list(claim_t *claims, size_t claims_length)
{
	if (!claims)
		return;

	for (size_t j = 0; j < claims_length; j++)
		_free_claim(&claims[j]);

	free(claims);
}

int librats_add_claim(claim_t *claim, const void *name, size_t name_size, const void *value,
		      size_t value_size)
{
	claim->name = (char *)malloc(name_size);
	if (claim->name == NULL)
		return 1;
	memcpy(claim->name, name, name_size);

	claim->value = (uint8_t *)malloc(value_size);
	if (claim->value == NULL) {
		free(claim->name);
		claim->name = NULL;
		return 1;
	}
	memcpy(claim->value, value, value_size);
	claim->value_size = value_size;

	return 0;
}
