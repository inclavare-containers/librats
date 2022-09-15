/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <librats/api.h>
#include <librats/log.h>
// clang-format off
#ifdef ENABLE_JSON
#include "internal/cJSON.h"
#include "internal/base64.h"
#endif
// clang-format on

rats_attester_err_t librats_collect_evidence(attestation_evidence_t *evidence, const uint8_t *hash)
{
	uint32_t hash_len = 32;
	rats_core_context_t ctx;
	rats_conf_t conf;

	memset(&ctx, 0, sizeof(rats_core_context_t));
	memset(&conf, 0, sizeof(rats_conf_t));
	memset(evidence, 0, sizeof(attestation_evidence_t));

	conf.api_version = RATS_API_VERSION_DEFAULT;
	conf.log_level = RATS_LOG_LEVEL_DEFAULT;

	if (rats_attest_init(&conf, &ctx) != RATS_ATTESTER_ERR_NONE)
		return RATS_ATTESTER_ERR_INIT;
	rats_attester_err_t q_err =
		ctx.attester->opts->collect_evidence(ctx.attester, evidence, hash, hash_len);

	if (ctx.attester->opts->cleanup(ctx.attester) != RATS_ATTESTER_ERR_NONE) {
		RATS_ERR("failed to clean up attester\n");
	}

	return q_err;
}

#ifdef ENABLE_JSON
int convert_evidence_to_json(attestation_evidence_t *evidence, char **json_string)
{
	if (evidence == NULL)
		return -1;
	int ret_code = -1;
	*json_string = NULL;
	unsigned char *report_base64 = NULL;
	unsigned char *vcek_base64 = NULL;
	size_t report_len = 0;
	cJSON *evidence_json = cJSON_CreateObject();
	if (evidence_json == NULL)
		return -1;
	cJSON_AddStringToObject(evidence_json, "type", evidence->type);
	if (strcmp(evidence->type, "csv") == 0) {
		if (rats_base64_encode(evidence->csv.report, evidence->csv.report_len, &report_base64,
				  NULL) != 0)
			goto err;
		report_len = evidence->csv.report_len;
	} else if (strcmp(evidence->type, "sev") == 0) {
		if (rats_base64_encode(evidence->sev.report, evidence->sev.report_len, &report_base64,
				  NULL) != 0)
			goto err;
		report_len = evidence->sev.report_len;
	} else if (strcmp(evidence->type, "sev_snp") == 0) {
		if (rats_base64_encode(evidence->snp.report, evidence->snp.report_len, &report_base64,
				  NULL) != 0)
			goto err;
		report_len = evidence->snp.report_len;
		if (evidence->snp.vcek_len) {
			if (rats_base64_encode(evidence->snp.vcek, evidence->snp.vcek_len, &vcek_base64,
					  NULL) != 0)
				goto err;
			cJSON_AddStringToObject(evidence_json, "vcek_base64",
						(const char *)vcek_base64);
			cJSON_AddNumberToObject(evidence_json, "vcek_len", evidence->snp.vcek_len);
		}
	} else if (strcmp(evidence->type, "sgx_ecdsa") == 0) {
		if (rats_base64_encode(evidence->ecdsa.quote, evidence->ecdsa.quote_len, &report_base64,
				  NULL) != 0)
			goto err;
		report_len = evidence->ecdsa.quote_len;
	} else if (strcmp(evidence->type, "sgx_la") == 0) {
		if (rats_base64_encode(evidence->la.report, evidence->la.report_len, &report_base64,
				  NULL) != 0)
			goto err;
		report_len = evidence->la.report_len;
	} else if (strcmp(evidence->type, "tdx_ecdsa") == 0) {
		if (rats_base64_encode(evidence->tdx.quote, evidence->tdx.quote_len, &report_base64,
				  NULL) != 0)
			goto err;
		report_len = evidence->tdx.quote_len;
	}
	cJSON_AddStringToObject(evidence_json, "report_base64",
				report_base64 ? (const char *)report_base64 : "");
	cJSON_AddNumberToObject(evidence_json, "report_len", report_len);
	*json_string = cJSON_PrintUnformatted(evidence_json);
	ret_code = 0;

err:
	if (report_base64)
		free(report_base64);
	if (vcek_base64)
		free(vcek_base64);
	if (evidence_json)
		cJSON_free(evidence_json);
	return ret_code;
}

int librats_collect_evidence_to_json(const uint8_t *hash, char **evidence_json)
{
	attestation_evidence_t evidence;
	rats_attester_err_t ret = librats_collect_evidence(&evidence, hash);
	if (ret != RATS_ATTESTER_ERR_NONE) {
		RATS_ERR("failed to librats_collect_evidence return %#x\n", ret);
		return (int)ret;
	}
	if (convert_evidence_to_json(&evidence, evidence_json) != 0) {
		if (*evidence_json)
			free(*evidence_json);
		return RATS_ATTESTER_ERR_JSON;
	}
	return 0;
}
#endif
