#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <librats/api.h>
#include <librats/claim.h>
#include <librats/log.h>
// clang-format off
#ifdef ENABLE_JSON
#include "internal/cJSON.h"
#include "internal/base64.h"
#endif
// clang-format on

rats_verifier_err_t librats_verify_evidence(uint8_t *evidence_buffer, size_t evidence_buffer_size,
					    uint8_t *endorsements_buffer,
					    size_t endorsements_buffer_size, claim_t **claims,
					    size_t *claims_length)
{
	rats_core_context_t ctx;
	rats_conf_t conf;
	uint32_t hash_len = SHA256_DIGEST_LENGTH;
	uint8_t hash[SHA256_DIGEST_LENGTH];
	attestation_evidence_t evidence;
	uint8_t *p;
	uint8_t *custom_claims_buffer = NULL;
	size_t custom_claims_buffer_size = 0;
	claim_t *custom_claims = NULL;
	size_t custom_claims_length = 0;
	claim_t *builtin_claims = NULL;
	size_t builtin_claims_length = 0;
	claim_t *mixed_claims = NULL;
	size_t mixed_claims_length = 0;

	rats_verifier_err_t ret = RATS_VERIFIER_ERR_NONE;

	if (!claims || !claims_length) {
		RATS_ERR("Bad parameters\n");
		return RATS_ATTESTER_ERR_INVALID;
	}

	/* Initialize pointer parameters */
	*claims = NULL;
	*claims_length = 0;

	memset(&ctx, 0, sizeof(rats_core_context_t));
	memset(&conf, 0, sizeof(rats_conf_t));

	/* Deserialize evidence */
	p = evidence_buffer;
	ret = RATS_VERIFIER_ERR_INVALID;
	if (deserialize_evidence(&evidence, &p) != RATS_ERR_NONE)
		goto err;

	/* Calculate hash of custom_claims_buffer */
	custom_claims_buffer = p;
	custom_claims_buffer_size = evidence_buffer_size - (custom_claims_buffer - evidence_buffer);

	SHA256(custom_claims_buffer, custom_claims_buffer_size, hash);

	conf.api_version = RATS_API_VERSION_DEFAULT;
	conf.log_level = RATS_LOG_LEVEL_DEFAULT;
	memcpy(conf.verifier_type, evidence.type, sizeof(conf.verifier_type));
	ret = RATS_VERIFIER_ERR_INIT;
	if (rats_verify_init(&conf, &ctx) != RATS_VERIFIER_ERR_NONE)
		goto err;

	ret = ctx.verifier->opts->verify_evidence(ctx.verifier, &evidence, hash, hash_len,
						  &builtin_claims, &builtin_claims_length);
	if (ret != RATS_VERIFIER_ERR_NONE)
		goto err;

	ret = RATS_VERIFIER_ERR_INVALID;
	if (deserialize_claims_list(custom_claims_buffer, custom_claims_buffer_size, &custom_claims,
				    &custom_claims_length) != RATS_ERR_NONE)
		goto err;

	mixed_claims = builtin_claims;
	mixed_claims_length = builtin_claims_length;
	builtin_claims = NULL;

	if (custom_claims) {
		/* Need a realloc */
		void *t = realloc(mixed_claims,
				  sizeof(claim_t) * (builtin_claims_length + custom_claims_length));
		if (!t) {
			ret = RATS_VERIFIER_ERR_NO_MEM;
			goto err;
		}
		mixed_claims = (claim_t *)t;
		memcpy(mixed_claims + mixed_claims_length, custom_claims,
		       sizeof(claim_t) * custom_claims_length);
		free(custom_claims); /* Just free claims array but keep its content  */
		custom_claims = NULL;
		mixed_claims_length += custom_claims_length;
	}

	*claims = mixed_claims;
	*claims_length = mixed_claims_length;
	mixed_claims = NULL;

	ret = RATS_VERIFIER_ERR_NONE;

err:
	if (custom_claims)
		free_claims_list(custom_claims, custom_claims_length);

	if (builtin_claims)
		free_claims_list(builtin_claims, builtin_claims_length);

	if (mixed_claims)
		free_claims_list(mixed_claims, mixed_claims_length);

	if (ctx.verifier->opts->cleanup(ctx.verifier) != RATS_VERIFIER_ERR_NONE) {
		RATS_ERR("failed to clean up verifier\n");
	}

	return ret;
}

#ifdef ENABLE_JSON
int get_evidence_from_json(const char *json_string, uint8_t **evidence_buffer_out,
			   size_t *evidence_buffer_size_out, uint8_t **endorsements_buffer_out,
			   size_t *endorsements_buffer_size_out)
{
	char *evidence_base64;
	char *endorsements_base64;
	uint8_t *evidence_buffer = NULL;
	size_t evidence_buffer_size = 0;
	uint8_t *endorsements_buffer = NULL;
	size_t endorsements_buffer_size = 0;
	int ret_code = -1;

	if (json_string == NULL || evidence_buffer_out == NULL ||
	    evidence_buffer_size_out == NULL || endorsements_buffer_out == NULL ||
	    endorsements_buffer_size_out == NULL)
		return -1;

	cJSON *evidence_json = cJSON_Parse(json_string);
	if (evidence_json == NULL)
		goto err;

	if (!cJSON_HasObjectItem(evidence_json, "evidence_base64") ||
	    !cJSON_IsString(cJSON_GetObjectItem(evidence_json, "evidence_base64"))) {
		RATS_ERR("failed to get_evidence_from_json, no 'evidence_base64' in json\n");
		goto err;
	}
	evidence_base64 = cJSON_GetObjectItem(evidence_json, "evidence_base64")->valuestring;
	if (rats_base64_decode((const unsigned char *)evidence_base64, strlen(evidence_base64),
			       &evidence_buffer, &evidence_buffer_size)) {
		RATS_ERR("failed to get_evidence_from_json, rats_base64_decode report error\n");
		goto err;
	}

	if (!cJSON_HasObjectItem(evidence_json, "endorsements_base64") ||
	    !cJSON_IsString(cJSON_GetObjectItem(evidence_json, "endorsements_base64"))) {
		RATS_ERR("failed to get_evidence_from_json, no 'endorsements_base64' in json\n");
		goto err;
	}
	endorsements_base64 =
		cJSON_GetObjectItem(evidence_json, "endorsements_base64")->valuestring;
	if (rats_base64_decode((const unsigned char *)endorsements_base64,
			       strlen(endorsements_base64), &endorsements_buffer,
			       &endorsements_buffer_size)) {
		RATS_ERR("failed to get_evidence_from_json, rats_base64_decode report error\n");
		goto err;
	}

	*evidence_buffer_out = evidence_buffer;
	evidence_buffer = NULL;
	*evidence_buffer_size_out = evidence_buffer_size;
	*endorsements_buffer_out = endorsements_buffer;
	endorsements_buffer = NULL;
	*endorsements_buffer_size_out = endorsements_buffer_size;
	ret_code = 0;

err:
	if (evidence_json)
		cJSON_free(evidence_json);
	if (evidence_buffer)
		free(evidence_buffer);
	if (endorsements_buffer)
		free(endorsements_buffer);
	return ret_code;
}

int librats_verify_evidence_from_json(const char *json_string, const uint8_t *hash)
{
	uint8_t *evidence_buffer = NULL;
	size_t evidence_buffer_size = 0;
	uint8_t *endorsements_buffer = NULL;
	size_t endorsements_buffer_size = 0;
	claim_t *claims = NULL;
	size_t claims_length = 0;
	size_t hash_len = SHA256_DIGEST_LENGTH;
	rats_verifier_err_t ret;

	rats_global_log_level = RATS_LOG_LEVEL_DEFAULT;

	/* Prase evidence buffer and endorsements buffer from json */
	ret = RATS_VERIFIER_ERR_JSON;
	if (get_evidence_from_json(json_string, &evidence_buffer, &evidence_buffer_size,
				   &endorsements_buffer, &endorsements_buffer_size) != 0)
		goto err;

	/* Verify evidence and got claims */
	ret = librats_verify_evidence(evidence_buffer, evidence_buffer_size, endorsements_buffer,
				      endorsements_buffer_size, &claims, &claims_length);
	if (ret != RATS_VERIFIER_ERR_NONE) {
		RATS_ERR("failed to librats_verify_evidence return %#x\n", ret);
		goto err;
	}

	/* Verify claims */
	ret = RATS_VERIFIER_ERR_INVALID;
	if (claims_length < 1 || strcmp(claims[0].name, "hash")) {
		RATS_ERR("failed to find 'hash' from claims list\n");
		goto err;
	}
	if (claims[0].value_size != hash_len || memcmp(claims[0].value, hash, hash_len)) {
		RATS_ERR("unmatched hash value in evidence.\n");
		goto err;
	}

	ret = RATS_VERIFIER_ERR_NONE;
err:
	if (claims)
		free_claims_list(claims, claims_length);
	if (evidence_buffer)
		free(evidence_buffer);
	if (endorsements_buffer)
		free(endorsements_buffer);

	return ret;
}
#endif
