/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdlib.h>
#include <openssl/sha.h>
#include <librats/api.h>
#include <librats/log.h>
// clang-format off
#ifdef ENABLE_JSON
#include "internal/cJSON.h"
#include "internal/base64.h"
#endif
// clang-format on

rats_attester_err_t librats_collect_evidence(const claim_t *custom_claims,
					     size_t custom_claims_length, uint8_t **evidence_buffer,
					     size_t *evidence_buffer_size,
					     uint8_t **endorsements_buffer,
					     size_t *endorsements_buffer_size)
{
	rats_core_context_t ctx;
	rats_conf_t conf;
	uint8_t *custom_claims_buffer = NULL;
	size_t custom_claims_buffer_size = 0;
	uint32_t hash_len = SHA256_DIGEST_LENGTH;
	uint8_t hash[SHA256_DIGEST_LENGTH];
	attestation_evidence_t evidence;
	uint8_t *tmp = NULL;
	uint8_t *p;
	size_t evidence_size;
	rats_attester_err_t ret;

	if (!evidence_buffer || !evidence_buffer_size || !endorsements_buffer ||
	    !endorsements_buffer_size) {
		RATS_ERR("Bad parameters\n");
		return RATS_ATTESTER_ERR_INVALID;
	}

	/* Initialize pointer parameters */
	*evidence_buffer = NULL;
	*evidence_buffer_size = 0;
	*endorsements_buffer = NULL;
	*endorsements_buffer_size = 0;

	memset(&ctx, 0, sizeof(rats_core_context_t));
	memset(&conf, 0, sizeof(rats_conf_t));
	memset(&evidence, 0, sizeof(attestation_evidence_t));

	conf.api_version = RATS_API_VERSION_DEFAULT;
	conf.log_level = RATS_LOG_LEVEL_DEFAULT;

	if (rats_attest_init(&conf, &ctx) != RATS_ATTESTER_ERR_NONE)
		return RATS_ATTESTER_ERR_INIT;

	ret = RATS_ATTESTER_ERR_INVALID;
	if (serialize_claims_list(custom_claims, custom_claims_length, &custom_claims_buffer,
				  &custom_claims_buffer_size) != RATS_ERR_NONE)
		goto err;

	SHA256(custom_claims_buffer, custom_claims_buffer_size, hash);

	ret = ctx.attester->opts->collect_evidence(ctx.attester, &evidence, hash, hash_len);
	if (ret != RATS_ATTESTER_ERR_NONE)
		goto err;

	/* Get evidence length */
	ret = RATS_ATTESTER_ERR_INVALID;
	if (serialize_evidence(&evidence, NULL, &evidence_size) != RATS_ERR_NONE)
		goto err;

	ret = RATS_ATTESTER_ERR_NO_MEM;
	tmp = malloc(evidence_size + custom_claims_buffer_size);
	if (!tmp)
		goto err;

	p = tmp;
	ret = RATS_ATTESTER_ERR_INVALID;
	if (serialize_evidence(&evidence, &p, &evidence_size) != RATS_ERR_NONE)
		goto err;
	memcpy(p, custom_claims_buffer, custom_claims_buffer_size);

	*evidence_buffer = tmp;
	tmp = NULL;
	*evidence_buffer_size = evidence_size + custom_claims_buffer_size;
	/* We have not implemented the collection of endorsements so far, so just return a empty
	 * buffer */
	*endorsements_buffer = NULL;
	*endorsements_buffer_size = 0;

	ret = RATS_ATTESTER_ERR_NONE;

err:
	if (tmp)
		free(tmp);
	if (custom_claims_buffer)
		free(custom_claims_buffer);
	if (ctx.attester->opts->cleanup(ctx.attester) != RATS_ATTESTER_ERR_NONE) {
		RATS_ERR("failed to clean up attester\n");
	}
	return ret;
}

#ifdef ENABLE_JSON
int convert_evidence_to_json(uint8_t *evidence_buffer, size_t evidence_buffer_size,
			     uint8_t *endorsements_buffer, size_t endorsements_buffer_size,
			     char **json_string)
{
	if (evidence_buffer == NULL || endorsements_buffer == NULL)
		return -1;
	int ret_code = -1;
	*json_string = NULL;
	char *evidence_base64 = NULL;
	char *endorsements_base64 = NULL;
	cJSON *evidence_json = cJSON_CreateObject();
	if (evidence_json == NULL)
		return -1;

	if (rats_base64_encode(evidence_buffer, evidence_buffer_size,
			       (unsigned char **)&evidence_base64, NULL) != 0)
		goto err;

	cJSON_AddStringToObject(evidence_json, "evidence_base64", evidence_base64);

	if (rats_base64_encode(endorsements_buffer, endorsements_buffer_size,
			       (unsigned char **)&endorsements_base64, NULL) != 0)
		goto err;

	cJSON_AddStringToObject(evidence_json, "endorsements_base64", endorsements_base64);

	*json_string = cJSON_PrintUnformatted(evidence_json);
	ret_code = 0;

err:
	if (evidence_base64)
		free(evidence_base64);
	if (endorsements_base64)
		free(endorsements_base64);
	if (evidence_json)
		cJSON_free(evidence_json);
	return ret_code;
}

int librats_collect_evidence_to_json(const uint8_t *hash, char **evidence_json_out)
{
	uint8_t *evidence_buffer = NULL;
	size_t evidence_buffer_size;
	uint8_t *endorsements_buffer = NULL;
	size_t endorsements_buffer_size;
	char *evidence_json = NULL;

	size_t custom_claims_length = 1;
	size_t hash_len = SHA256_DIGEST_LENGTH;
	const claim_t custom_claims = {
		.name = "hash",
		.value = (uint8_t *)hash,
		.value_size = hash_len,
	};
	rats_attester_err_t ret;

	ret = librats_collect_evidence(&custom_claims, custom_claims_length, &evidence_buffer,
				       &evidence_buffer_size, &endorsements_buffer,
				       &endorsements_buffer_size);
	if (ret != RATS_ATTESTER_ERR_NONE) {
		RATS_ERR("failed to librats_collect_evidence return %#x\n", ret);
		goto err;
	}

	ret = RATS_ATTESTER_ERR_JSON;
	if (convert_evidence_to_json(evidence_buffer, evidence_buffer_size, endorsements_buffer,
				     endorsements_buffer_size, &evidence_json) != 0)
		goto err;

	*evidence_json_out = evidence_json;
	ret = RATS_ATTESTER_ERR_NONE;
err:
	if (evidence_json)
		free(evidence_json);
	if (evidence_buffer)
		free(evidence_buffer);
	if (endorsements_buffer)
		free(endorsements_buffer);
	return (int)ret;
}
#endif