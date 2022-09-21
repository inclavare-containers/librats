/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
// clang-format off
#ifdef SGX
#include "internal/sgx.h"
#else
#include <arpa/inet.h>
#endif
// clang-format on
#include <librats/claim.h>
#include <librats/err.h>

static void _free_claim(claim_t *claim)
{
	free(claim->name);
	free(claim->value);
}

rats_err_t free_claims_list(claim_t *claims, size_t claims_length)
{
	if (!claims)
		return RATS_ERR_NONE;

	for (size_t j = 0; j < claims_length; j++)
		_free_claim(&claims[j]);

	free(claims);

	return RATS_ERR_NONE;
}

rats_err_t librats_add_claim(claim_t *claim, const void *name, size_t name_size, const void *value,
			     size_t value_size)
{
	if (*((uint8_t *)name + name_size - 1) != '\0')
		return RATS_ERR_INVALID_PARAMETER;

	claim->name = (char *)malloc(name_size);
	if (claim->name == NULL)
		return RATS_ERR_NO_MEM;
	memcpy(claim->name, name, name_size);

	claim->value = (uint8_t *)malloc(value_size);
	if (claim->value == NULL) {
		free(claim->name);
		claim->name = NULL;
		return RATS_ERR_NO_MEM;
	}
	memcpy(claim->value, value, value_size);
	claim->value_size = value_size;

	return RATS_ERR_NONE;
}

/* Serialize the entire claims list into raw buffer.
 *
 * The following diagram describes the layout of the serialized claims list.
 *
 * ~~~~
 *
 * +--------------------+------------+-------+---------------------+----------------------
 * | name (end with \0) | value_size | value |         ...         |         ...
 * +--------------------+------------+-------+---------------------+----------------------
 * \--------------- claims[0] --------------/ \---- claims[1] ----/ \---- claims[...] ----
 *
 * ~~~~
 *
 * Note that memory will ALWAYS be allocated for writing the serialized data, which means that the
 * value of *claims_buffer will be overwritten to the starting address of the allocated memory.
 *
 * This function will return RATS_ERR_NONE, or other error code if any error occurs.
 */
rats_err_t serialize_claims_list(const claim_t *claims, size_t claims_length,
				 uint8_t **claims_buffer, size_t *claims_buffer_size)
{
	size_t name_size[claims_length];
	uint8_t *tmp = NULL;
	size_t size;
	rats_err_t ret = RATS_ERR_NONE;

	if (!claims || !claims_buffer || !claims_buffer_size)
		return RATS_ERR_NONE;

	/* Calculate size of claims_buffer */
	size = 0;
	for (size_t i = 0; i < claims_length; i++) {
		name_size[i] = strlen(claims[i].name) + 1;
		size += name_size[i];
		size += sizeof(uint32_t);
		size += claims[i].value_size;
	}

	ret = RATS_ERR_NO_MEM;
	tmp = (uint8_t *)malloc(size);
	if (!tmp)
		goto err;

	/* Copy claims into buffer */
	size_t offset = 0;
	for (size_t i = 0; i < claims_length; i++) {
		memcpy(tmp + offset, claims[i].name, name_size[i]);
		offset += name_size[i];
		uint32_t value_size = htonl(claims[i].value_size);
		memcpy(tmp + offset, &value_size, sizeof(value_size));
		offset += sizeof(value_size);
		memcpy(tmp + offset, claims[i].value, claims[i].value_size);
		offset += claims[i].value_size;
	}

	*claims_buffer = tmp;
	tmp = NULL;
	*claims_buffer_size = size;
	ret = RATS_ERR_NONE;
err:
	if (tmp)
		free(tmp);

	return ret;
}

/* Deserialize raw buffer at *claims_buffer to a array of claim_t.
 *
 * Note that memory will ALWAYS be allocated for the claim_t array. If successful, *output_claims
 * will be pointed to the new claim_t array.
 *
 * This function will return RATS_ERR_NONE, or other error code if any error occurs. */
rats_err_t deserialize_claims_list(const uint8_t *claims_buffer, size_t claims_buffer_size,
				   claim_t **output_claims, size_t *output_claims_length)
{
	size_t count = 0;
	claim_t claims[MAX_CUSTOM_CLAIMS_LENGTH];
	claim_t *tmp = NULL;
	rats_err_t ret = RATS_ERR_NONE;

	if (!claims_buffer || !output_claims || !output_claims_length)
		return RATS_ERR_NONE;

	/* Parse claims */
	ret = RATS_ERR_INVALID_PARAMETER;
	size_t offset = 0;
	for (size_t i = 0; offset < claims_buffer_size; i++) {
		if (i >= MAX_CUSTOM_CLAIMS_LENGTH)
			goto err;
		/* Parse claim name */
		const void *name = claims_buffer + offset;
		size_t name_size =
			strnlen((const char *)claims_buffer + offset, claims_buffer_size - offset);
		if (name_size == claims_buffer_size - offset)
			goto err;
		name_size += 1;
		offset += name_size;
		/* Parse claim value size */
		uint32_t value_size;
		if (claims_buffer_size - offset < sizeof(value_size))
			goto err;
		memcpy(&value_size, claims_buffer + offset, sizeof(value_size));
		value_size = ntohl(value_size);
		offset += sizeof(value_size);
		/* Parse claim value */
		if (claims_buffer_size - offset < value_size)
			goto err;
		const void *value = claims_buffer + offset;
		librats_add_claim(&claims[i], name, name_size, value, value_size);
		offset += value_size;

		count++;
	}

	ret = RATS_ERR_NO_MEM;
	tmp = (claim_t *)malloc(sizeof(claim_t) * count);
	if (!tmp)
		goto err;

	memcpy(tmp, claims, sizeof(claim_t) * count);
	*output_claims = tmp;
	*output_claims_length = count;
	tmp = NULL;
	count = 0;
	ret = RATS_ERR_NONE;

err:
	if (tmp)
		free(tmp);
	if (count)
		for (size_t i = 0; i < count; i++) {
			_free_claim(&claims[i]);
		}
	return ret;
}
