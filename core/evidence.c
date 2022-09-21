/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <librats/err.h>
#include <librats/log.h>
#include <librats/evidence.h>

int _size_of_evidence(const char *type)
{
	if (!strcmp(type, "sgx_ecdsa")) {
		return sizeof(ecdsa_attestation_evidence_t);
	} else if (!strcmp(type, "tdx_ecdsa")) {
		return sizeof(tdx_attestation_evidence_t);
	} else if (!strcmp(type, "sgx_la")) {
		return sizeof(la_attestation_evidence_t);
	} else if (!strcmp(type, "sev_snp")) {
		return sizeof(snp_attestation_evidence_t);
	} else if (!strcmp(type, "sev")) {
		return sizeof(sev_attestation_evidence_t);
	} else if (!strcmp(type, "csv")) {
		return sizeof(csv_attestation_evidence_t);
	}

	RATS_FATAL("Unhandled evidence type '%s'\n", type);
	return -1;
}

/* Serialize the attestation_evidence_t into raw buffer.
 *
 * If buffer is NULL, this function can be used to get the length of serialized data.
 * If *buffer is NULL, memory will be allocated for writing the serialized data, and *buffer will
 * be overwritten to the starting address of new buffer.
 * If *buffer is not NULL, serialized data will be written at *buffer, and increments it to point
 * after the data just written.
 *
 * If successful and buffer_size is not NULL, the serialized data length will be written to *buffer_size.
 *
 * This function will return return RATS_ERR_NONE, or other error code if any error occurs.
 */
rats_err_t serialize_evidence(const attestation_evidence_t *evidence, uint8_t **buffer,
			      size_t *buffer_size)
{
	size_t data_size = 0;
	size_t evidence_size;
	uint8_t *tmp = NULL;
	uint8_t *p;
	rats_err_t ret = RATS_ERR_NONE;

	if (!evidence)
		return RATS_ERR_INVALID_PARAMETER;

	data_size += sizeof(evidence->type);

	// TODO: report can be shorter
	int t = _size_of_evidence(evidence->type);
	if (t == -1)
		return RATS_ERR_INVALID_PARAMETER;
	evidence_size = (size_t)t;
	data_size += evidence_size;

	if (!buffer) {
		if (buffer_size)
			*buffer_size = data_size;
		return RATS_ERR_NONE;
	}

	if (!*buffer) {
		ret = RATS_ERR_NO_MEM;
		tmp = malloc(data_size);
		if (!tmp)
			goto err;
		p = tmp;
	} else {
		p = *buffer;
	}

	memcpy(p, (uint8_t *)evidence, sizeof(evidence->type));
	p += sizeof(evidence->type);
	memcpy(p, (uint8_t *)&evidence->ecdsa, evidence_size);
	p += evidence_size;

	if (!*buffer) {
		*buffer = tmp;
		tmp = NULL;
	} else {
		*buffer = p;
	}

	if (buffer_size)
		*buffer_size = data_size;

	ret = RATS_ERR_NONE;
err:
	if (tmp)
		free(tmp);

	return ret;
}

/* Deserialize data at *buffer to fill the attestation_evidence_t struct.
 *
 * If successful, *buffer will be incremented to the byte following the parsed data.
 *
 * This function will return return RATS_ERR_NONE, or other error code if any error occurs.
 */
rats_err_t deserialize_evidence(attestation_evidence_t *evidence, uint8_t **buffer)
{
	size_t evidence_size;
	uint8_t *p;

	if (!evidence || !buffer || !*buffer)
		return RATS_ERR_INVALID_PARAMETER;

	int t = _size_of_evidence((char *)*buffer);
	if (t == -1)
		return RATS_ERR_INVALID_PARAMETER;
	evidence_size = (size_t)t;

	p = *buffer;

	memcpy((uint8_t *)evidence, p, sizeof(evidence->type));
	p += sizeof(evidence->type);
	memcpy(((uint8_t *)evidence) + offsetof(attestation_evidence_t, ecdsa), p, evidence_size);
	p += evidence_size;

	*buffer = p;

	return RATS_ERR_NONE;
}
