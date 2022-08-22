#include <stdint.h>
#include <string.h>
#include <librats/api.h>
#include <librats/claim.h>
#include <librats/log.h>
// clang-format off
#ifdef ENABLE_JSON
#include "internal/cJSON.h"
#include "internal/base64.h"
#endif
// clang-format on

rats_verifier_err_t librats_verify_evidence(attestation_evidence_t *evidence, const uint8_t *hash,
					    claim_t **claims, size_t *claims_length)
{
	uint32_t hash_len = 32;
	rats_core_context_t ctx;
	rats_conf_t conf;

	conf.api_version = RATS_API_VERSION_DEFAULT;
	conf.log_level = RATS_LOG_LEVEL_DEFAULT;
	memcpy(conf.verifier_type, evidence->type, sizeof(conf.verifier_type));

	if (rats_verify_init(&conf, &ctx) != RATS_VERIFIER_ERR_NONE)
		return RATS_VERIFIER_ERR_INIT;

	rats_verifier_err_t err = ctx.verifier->opts->verify_evidence(
		ctx.verifier, evidence, hash, hash_len, claims, claims_length);

	if (ctx.verifier->opts->cleanup(ctx.verifier) != RATS_VERIFIER_ERR_NONE) {
		RATS_ERR("failed to clean up verifier\n");
	}

	return err;
}

#ifdef ENABLE_JSON
int get_evidence_from_json(const char *json_string, attestation_evidence_t *evidence)
{
	if (json_string == NULL || evidence == NULL)
		return -1;
	memset(evidence, 0, sizeof(attestation_evidence_t));
	int ret_code = -1;
	char *evidence_type = NULL;
	char *report_base64 = NULL;
	char *vcek_base64 = NULL;
	uint8_t *report = NULL;
	size_t report_len = 0;
	uint8_t *vcek = NULL;
	size_t vcek_len = 0;
	cJSON *evidence_json = cJSON_Parse(json_string);
	if (evidence_json == NULL)
		return -1;
	if (!cJSON_HasObjectItem(evidence_json, "type") ||
	    !cJSON_IsString(cJSON_GetObjectItem(evidence_json, "type"))) {
		RATS_ERR("failed to get_evidence_from_json, no 'type' in json\n");
		goto err;
	}
	evidence_type = cJSON_GetObjectItem(evidence_json, "type")->valuestring;
	memcpy(evidence->type, evidence_type, strlen(evidence_type));
	if (!cJSON_HasObjectItem(evidence_json, "report_base64") ||
	    !cJSON_IsString(cJSON_GetObjectItem(evidence_json, "report_base64")) ||
	    !cJSON_HasObjectItem(evidence_json, "report_len") ||
	    !cJSON_IsNumber(cJSON_GetObjectItem(evidence_json, "report_len"))) {
		RATS_ERR("failed to get_evidence_from_json, no 'report_base64' in json\n");
		goto err;
	}
	report_base64 = cJSON_GetObjectItem(evidence_json, "report_base64")->valuestring;
	if (!strlen(report_base64)) {
		ret_code = 0;
		goto err;
	}
	if (rats_base64_decode((const unsigned char *)report_base64, strlen(report_base64), &report, &report_len) != 0 ||
	    !report || !report_len) {
		RATS_ERR("failed to get_evidence_from_json, rats_base64_decode report error\n");
		goto err;
	}
	if (report_len != (size_t)cJSON_GetObjectItem(evidence_json, "report_len")->valueint) {
		RATS_ERR("failed to get_evidence_from_json, report_len mismatched\n");
		goto err;
	}
	if (strcmp(evidence->type, "csv") == 0) {
		memcpy(evidence->csv.report, report, report_len);
		evidence->csv.report_len = report_len;
	} else if (strcmp(evidence->type, "sev") == 0) {
		memcpy(evidence->sev.report, report, report_len);
		evidence->sev.report_len = report_len;
	} else if (strcmp(evidence->type, "sev_snp") == 0) {
		memcpy(evidence->snp.report, report, report_len);
		evidence->snp.report_len = report_len;
		if (cJSON_HasObjectItem(evidence_json, "vcek_base64") &&
		    cJSON_IsString(cJSON_GetObjectItem(evidence_json, "vcek_base64")) &&
		    cJSON_HasObjectItem(evidence_json, "vcek_len") &&
		    cJSON_IsNumber(cJSON_GetObjectItem(evidence_json, "vcek_base64"))) {
			vcek_base64 =
				cJSON_GetObjectItem(evidence_json, "vcek_base64")->valuestring;
			if (rats_base64_decode((const unsigned char *)vcek_base64, strlen(vcek_base64), &vcek, &vcek_len) !=
				    0 ||
			    !vcek || !vcek_len) {
				RATS_ERR(
					"failed to get_evidence_from_json, rats_base64_decode vcek error\n");
				goto err;
			}
			if (vcek_len != (size_t)cJSON_GetObjectItem(evidence_json, "vcek_len")->valueint) {
				RATS_ERR("failed to get_evidence_from_json, vcek_len mismatched\n");
				goto err;
			}
			memcpy(evidence->snp.vcek, vcek, vcek_len);
			evidence->snp.vcek_len = vcek_len;
		}
	} else if (strcmp(evidence->type, "sgx_ecdsa") == 0) {
		memcpy(evidence->ecdsa.quote, report, report_len);
		evidence->ecdsa.quote_len = report_len;
	} else if (strcmp(evidence->type, "sgx_la") == 0) {
		memcpy(evidence->la.report, report, report_len);
		evidence->la.report_len = report_len;
	} else if (strcmp(evidence->type, "tdx_ecdsa") == 0) {
		memcpy(evidence->tdx.quote, report, report_len);
		evidence->tdx.quote_len = report_len;
	}
	ret_code = 0;

err:
	if (evidence_json)
		cJSON_free(evidence_json);
	if (report)
		free(report);
	if (vcek)
		free(vcek);

	if (ret_code != 0)
		memset(evidence, 0, sizeof(attestation_evidence_t));
	return ret_code;
}

int librats_verify_evidence_from_json(const char *json_string, const uint8_t *hash)
{
	attestation_evidence_t evidence;
	rats_global_log_level = RATS_LOG_LEVEL_DEFAULT;
	if (get_evidence_from_json(json_string, &evidence) != 0)
		return RATS_VERIFIER_ERR_JSON;
	rats_verifier_err_t ret = librats_verify_evidence(&evidence, hash, NULL, NULL);
	if (ret != RATS_VERIFIER_ERR_NONE) {
		RATS_ERR("failed to librats_verify_evidence return %#x\n", ret);
		return (int)ret;
	}
	return 0;
}
#endif
