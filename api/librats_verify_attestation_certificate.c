#include <string.h>
#include <librats/log.h>
#include <librats/api.h>
#include <librats/log.h>
#include <librats/claim.h>
#include <librats/cert.h>
#include <internal/dice.h>
#include <internal/core.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

rats_verifier_err_t
librats_verify_attestation_certificate(uint8_t *certificate, size_t certificate_size,
				       rats_verify_claims_callback_t verify_claims_callback,
				       void *args)
{
	rats_verifier_err_t ret;

	EVP_PKEY *pkey = NULL;

	uint8_t *evidence_buffer = NULL;
	size_t evidence_buffer_size = 0;
	uint8_t *claims_buffer = NULL;
	size_t claims_buffer_size = 0;
	uint8_t *endorsements_buffer = NULL;
	size_t endorsements_buffer_size = 0;

	claim_t *custom_claims = NULL;
	size_t custom_claims_length = 0;
	claim_t *builtin_claims = NULL;
	size_t builtin_claims_length = 0;
	claim_t *claims = NULL;
	size_t claims_length = 0;

	const size_t hash_len = SHA256_DIGEST_LENGTH;
	uint8_t hash[SHA256_DIGEST_LENGTH];

	rats_core_context_t ctx;
	rats_conf_t conf;
	attestation_evidence_t evidence;

	bool verifier_initialized = false;

	memset(&ctx, 0, sizeof(rats_core_context_t));
	memset(&conf, 0, sizeof(rats_conf_t));

	/* Parse cert */
	ret = openssl_parse_cert(certificate, certificate_size, &pkey, &evidence_buffer,
				 &evidence_buffer_size, &endorsements_buffer,
				 &endorsements_buffer_size);
	if (ret != RATS_VERIFIER_ERR_NONE) {
		RATS_ERR("failed to parse certificate: %#x\n", ret);
		goto err;
	}

	if (!evidence_buffer) {
		/* The evidence_buffer is empty, which means that the other party is using a non-dice certificate or is using a nullattester */
		RATS_WARN("there is no evidence in peer's certificate.\n");
		memset(&evidence, 0, sizeof(attestation_evidence_t));
	} else {
		/* Get evidence struct and claims_buffer(optional) from evidence_buffer */
		ret = dice_parse_evidence_buffer_with_tag(evidence_buffer, evidence_buffer_size,
							  &evidence, &claims_buffer,
							  &claims_buffer_size);
		if (ret != RATS_VERIFIER_ERR_NONE)
			goto err;
	}

	RATS_DEBUG("evidence.type: '%s'\n", evidence.type);

	/* Verify evidence struct */
	conf.api_version = RATS_API_VERSION_DEFAULT;
	conf.log_level = rats_loglevel_getenv("RATS_GLOBAL_LOG_LEVEL");
	memcpy(conf.verifier_type, evidence.type, sizeof(conf.verifier_type));
	ret = RATS_VERIFIER_ERR_INIT;
	if (rats_verify_init(&conf, &ctx) != RATS_VERIFIER_ERR_NONE)
		goto err;
	verifier_initialized = true;

	if (claims_buffer) {
		/* If claims_buffer exists, the hash value in evidence user-data field shall be the SHA256 hash of the `claims-buffer` byte string */
		RATS_DEBUG("check evidence user-data field with sha256 of claims_buffer\n");
		SHA256(claims_buffer, claims_buffer_size, hash);
		if (hash_len >= 16)
			RATS_DEBUG(
				"sha256 of claims_buffer [%zu] %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x...\n",
				hash_len, hash[0], hash[1], hash[2], hash[3], hash[4], hash[5],
				hash[6], hash[7], hash[8], hash[9], hash[10], hash[11], hash[12],
				hash[13], hash[14], hash[15]);
		ret = ctx.verifier->opts->verify_evidence(ctx.verifier, &evidence, hash, hash_len,
							  &builtin_claims, &builtin_claims_length);
	} else {
		/* Or the user-data field shall hold pubkey-hash-value */
		/* NOTE: Since there is no universal way to get user-data field, we need a little trick here: generate sha265 pubkey-hash-value for the public key of the certificate being verified */
		RATS_DEBUG("check evidence user-data field with pubkey-hash-value\n");
		/* Calculate sha256 hash for pubkey */
		ret = RATS_ATTESTER_ERR_INVALID;
		if (openssl_calc_pubkey_sha256(pkey, hash) != 0)
			goto err;
		uint8_t *pubkey_hash_value_buffer = NULL;
		size_t pubkey_hash_value_buffer_size = 0;
		rats_attester_err_t gen_ret = dice_generate_pubkey_hash_value_buffer(
			hash, &pubkey_hash_value_buffer, &pubkey_hash_value_buffer_size);
		if (gen_ret != RATS_ATTESTER_ERR_NONE) {
			RATS_ERR(
				"failed to verify evidence: unable to verify pubkey-hash-value, internal error code: %#x\n",
				gen_ret);
			ret = gen_ret == RATS_ATTESTER_ERR_NO_MEM ? RATS_VERIFIER_ERR_NO_MEM :
								    RATS_VERIFIER_ERR_INVALID;
			goto err;
		}
		if (pubkey_hash_value_buffer_size >= 16) {
			uint8_t *data = pubkey_hash_value_buffer;
			RATS_DEBUG(
				"pubkey-hash-value [%zu] %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x...\n",
				pubkey_hash_value_buffer_size, data[0], data[1], data[2], data[3],
				data[4], data[5], data[6], data[7], data[8], data[9], data[10],
				data[11], data[12], data[13], data[14], data[15]);
		}
		ret = ctx.verifier->opts->verify_evidence(ctx.verifier, &evidence,
							  pubkey_hash_value_buffer,
							  pubkey_hash_value_buffer_size,
							  &builtin_claims, &builtin_claims_length);
		free(pubkey_hash_value_buffer);
	}
	if (ret != RATS_VERIFIER_ERR_NONE) {
		RATS_ERR("failed to verify evidence: %#x\n", ret);
		goto err;
	}

	/* Parse verify claims buffer from evidence buffer */
	if (claims_buffer) {
		/* Calculate sha256 hash for pubkey */
		ret = RATS_ATTESTER_ERR_INVALID;
		if (openssl_calc_pubkey_sha256(pkey, hash) != 0)
			goto err;

		ret = dice_parse_and_verify_claims_buffer(hash, claims_buffer, claims_buffer_size,
							  &custom_claims, &custom_claims_length);
		if (ret != RATS_VERIFIER_ERR_NONE)
			goto err;
	}

	claims = builtin_claims;
	claims_length = builtin_claims_length;
	builtin_claims = NULL;

	if (custom_claims) {
		/* Need a realloc */
		void *t = realloc(claims,
				  sizeof(claim_t) * (builtin_claims_length + custom_claims_length));
		if (!t) {
			ret = RATS_VERIFIER_ERR_NO_MEM;
			goto err;
		}
		claims = (claim_t *)t;
		memcpy(claims + claims_length, custom_claims,
		       sizeof(claim_t) * custom_claims_length);
		free(custom_claims); /* Just free claims array but keep its content  */
		custom_claims = NULL;
		claims_length += custom_claims_length;
	}

	/* Verify remain claims via callback function given by caller */
	if (verify_claims_callback) {
		rats_err_t callback_ret = verify_claims_callback(claims, claims_length, args);
		if (callback_ret != RATS_ERR_NONE) {
			RATS_ERR("verify_claims_callback failed with code: %#x\n", callback_ret);
			ret = RATS_VERIFIER_ERR_INVALID;
			goto err;
		}
	}

	ret = RATS_VERIFIER_ERR_NONE;
err:
	if (verifier_initialized &&
	    ctx.verifier->opts->cleanup(ctx.verifier) != RATS_VERIFIER_ERR_NONE) {
		RATS_ERR("failed to clean up verifier\n");
	}
	if (custom_claims)
		free_claims_list(custom_claims, custom_claims_length);
	if (builtin_claims)
		free_claims_list(builtin_claims, builtin_claims_length);
	if (claims)
		/* We have to free the claims array and content of each claims */
		free_claims_list(claims, claims_length);
	if (evidence_buffer)
		free(evidence_buffer);
	if (endorsements_buffer)
		free(endorsements_buffer);
	if (pkey)
		EVP_PKEY_free(pkey);

	return ret;
}