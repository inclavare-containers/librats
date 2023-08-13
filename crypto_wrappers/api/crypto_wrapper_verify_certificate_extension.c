/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <librats/log.h>
#include <librats/err.h>

#include "internal/crypto_wrapper.h"
#include "internal/attester.h"
#include "internal/verifier.h"
#include "internal/dice.h"

crypto_wrapper_err_t
crypto_wrapper_verify_evidence(crypto_wrapper_ctx_t *crypto_ctx, attestation_evidence_t *evidence,
			       uint8_t *hash, uint32_t hash_len,
			       attestation_endorsement_t *endorsements /* Optional */,
			       claim_t **claims, size_t *claims_length)
{
	RATS_DEBUG("crypto_wrapper_verify_evidence() called with evidence type: '%s'\n",
		   evidence->type);

	if (!crypto_ctx || !crypto_ctx->rats_handle || !crypto_ctx->rats_handle->verifier ||
	    !crypto_ctx->rats_handle->verifier->opts ||
	    !crypto_ctx->rats_handle->verifier->opts->verify_evidence)
		return CRYPTO_WRAPPER_ERR_INVALID;

	if (strcmp(crypto_ctx->rats_handle->verifier->opts->type, evidence->type)) {
		RATS_WARN("type doesn't match between verifier '%s' and evidence '%s'\n",
			  crypto_ctx->rats_handle->verifier->opts->name, evidence->type);
		rats_verifier_err_t verifier_ret =
			rats_verifier_select_by_type(crypto_ctx->rats_handle, evidence->type);
		if (verifier_ret != RATS_VERIFIER_ERR_NONE) {
			RATS_ERR("the verifier selecting err %#x during verifying cert extension\n",
				 verifier_ret);
			return CRYPTO_WRAPPER_ERR_INVALID;
		}
	}

	rats_verifier_err_t err = crypto_ctx->rats_handle->verifier->opts->verify_evidence(
		crypto_ctx->rats_handle->verifier, evidence, hash, hash_len, endorsements, claims,
		claims_length);
	if (err != RATS_VERIFIER_ERR_NONE) {
		RATS_ERR("failed to verify evidence %#x\n", err);
		return CRYPTO_WRAPPER_ERR_INVALID;
	}

	return CRYPTO_WRAPPER_ERR_NONE;
}

crypto_wrapper_err_t crypto_wrapper_verify_certificate_extension(
	crypto_wrapper_ctx_t *crypto_ctx, const uint8_t *pubkey_buffer, size_t pubkey_buffer_size,
	uint8_t *evidence_buffer, size_t evidence_buffer_size, uint8_t *endorsements_buffer,
	size_t endorsements_buffer_size)
{
	crypto_wrapper_err_t ret;

	attestation_evidence_t evidence;
	attestation_endorsement_t endorsements;

	uint8_t *claims_buffer = NULL;
	size_t claims_buffer_size = 0;

	claim_t *custom_claims = NULL;
	size_t custom_claims_length = 0;
	claim_t *builtin_claims = NULL;
	size_t builtin_claims_length = 0;
	claim_t *claims = NULL;
	size_t claims_length = 0;

	RATS_DEBUG(
		"crypto_ctx: %p, pubkey_buffer: %p, pubkey_buffer_size: %zu, evidence_buffer: %p, evidence_buffer_size: %zu, endorsements_buffer: %p, endorsements_buffer_size: %zu\n",
		crypto_ctx, pubkey_buffer, pubkey_buffer_size, evidence_buffer,
		evidence_buffer_size, endorsements_buffer, endorsements_buffer_size);

	if (!crypto_ctx || !crypto_ctx->rats_handle || !crypto_ctx->rats_handle->verifier ||
	    !crypto_ctx->rats_handle->verifier->opts ||
	    !crypto_ctx->rats_handle->verifier->opts->verify_evidence || !pubkey_buffer)
		return CRYPTO_WRAPPER_ERR_INVALID;

	memset(&evidence, 0, sizeof(attestation_evidence_t));
	memset(&endorsements, 0, sizeof(attestation_endorsement_t));

	/* Get evidence struct and claims_buffer from evidence_buffer. */
	if (!evidence_buffer) {
		/* evidence_buffer is empty, which means that the other party is using a non-dice certificate or is using a nullattester */
		RATS_WARN("there is no evidence buffer in peer's certificate.\n");
		// TODO: This would be a security issue. An attacker who does not provide any evidence extension may make librats choose nullverifier accidentally. So we need a way to determine if the nullverifier is the one the user expected.
		memcpy(evidence.type, "nullverifier", sizeof("nullverifier"));
	} else {
		rats_verifier_err_t verifier_ret = dice_parse_evidence_buffer_with_tag(
			evidence_buffer, evidence_buffer_size, &evidence, &claims_buffer,
			&claims_buffer_size);
		if (verifier_ret != RATS_VERIFIER_ERR_NONE) {
			ret = CRYPTO_WRAPPER_ERR_INVALID;
			RATS_ERR("dice failed to parse evidence from evidence buffer: %#x\n",
				 verifier_ret);
			goto err;
		}
	}
	RATS_DEBUG("evidence->type: '%s'\n", evidence.type);

	/* Get endorsements (optional) from endorsements_buffer */
	bool has_endorsements = endorsements_buffer && endorsements_buffer_size;
	RATS_DEBUG("has_endorsements: %s\n", has_endorsements ? "true" : "false");
	if (has_endorsements) {
		rats_verifier_err_t verifier_ret = dice_parse_endorsements_buffer_with_tag(
			evidence.type, endorsements_buffer, endorsements_buffer_size,
			&endorsements);
		if (verifier_ret != RATS_VERIFIER_ERR_NONE) {
			ret = CRYPTO_WRAPPER_ERR_INVALID;
			RATS_ERR(
				"dice failed to parse endorsements from endorsements buffer: %#x\n",
				verifier_ret);
			goto err;
		}
	}

	/* Prepare hash value as evidence userdata to be verified.
	 * The hash value in evidence user-data field shall be the SHA256 hash of the `claims-buffer` byte string.
	 */
	RATS_DEBUG("check evidence userdata field with sha256 of claims_buffer\n");
	uint8_t claims_buffer_hash[RATS_SHA256_HASH_SIZE];
	size_t claims_buffer_hash_len = sizeof(claims_buffer_hash);
	if (!claims_buffer) {
		/* Note that the custom_buffer will not be null if the evidence_buffer is successfully parsed.
		 * So this branch indicates the case where there is no evidence_buffer in the certificate, i.e. a peer that does not support the evidence extension, or a peer that uses nullattester.
		 */
		RATS_WARN(
			"set claims buffer hash value to 0, since there is no evidence buffer in peer's certificate.\n");
		memset(claims_buffer_hash, 0, claims_buffer_hash_len);
	} else {
		crypto_wrapper_err_t c_err =
			crypto_ctx->rats_handle->crypto_wrapper->opts->gen_hash(
				crypto_ctx->rats_handle->crypto_wrapper, RATS_HASH_ALGO_SHA256,
				claims_buffer, claims_buffer_size, claims_buffer_hash);
		if (c_err != CRYPTO_WRAPPER_ERR_NONE) {
			RATS_ERR("failed to calculate hash of claims_buffer: %#x\n", c_err);
			ret = CRYPTO_WRAPPER_ERR_INVALID;
			goto err;
		}
		if (claims_buffer_hash_len >= 16)
			RATS_DEBUG(
				"sha256 of claims_buffer [%zu] %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x...\n",
				claims_buffer_hash_len, claims_buffer_hash[0],
				claims_buffer_hash[1], claims_buffer_hash[2], claims_buffer_hash[3],
				claims_buffer_hash[4], claims_buffer_hash[5], claims_buffer_hash[6],
				claims_buffer_hash[7], claims_buffer_hash[8], claims_buffer_hash[9],
				claims_buffer_hash[10], claims_buffer_hash[11],
				claims_buffer_hash[12], claims_buffer_hash[13],
				claims_buffer_hash[14], claims_buffer_hash[15]);
	}

	/* Verify evidence and userdata */
	ret = crypto_wrapper_verify_evidence(crypto_ctx, &evidence, claims_buffer_hash,
					     claims_buffer_hash_len,
					     has_endorsements ? &endorsements : NULL,
					     &builtin_claims, &builtin_claims_length);
	if (has_endorsements)
		free_endorsements(evidence.type, &endorsements);
	if (ret != CRYPTO_WRAPPER_ERR_NONE) {
		RATS_ERR("failed to verify evidence: %#x\n", ret);
		goto err;
	}

	/* Parse and verify claims buffer */
	if (claims_buffer) {
		rats_hash_algo_t pubkey_hash_algo = RATS_HASH_ALGO_RESERVED;
		uint8_t pubkey_hash[RATS_MAX_HASH_SIZE];
		rats_verifier_err_t verifier_ret = dice_parse_claims_buffer(
			claims_buffer, claims_buffer_size, &pubkey_hash_algo, pubkey_hash,
			&custom_claims, &custom_claims_length);
		free(claims_buffer);
		claims_buffer = NULL;
		if (verifier_ret != RATS_VERIFIER_ERR_NONE) {
			ret = CRYPTO_WRAPPER_ERR_INVALID;
			RATS_ERR("dice failed to parse claims from claims_buffer: %#x\n",
				 verifier_ret);
			goto err;
		}

		RATS_DEBUG("custom_claims %p, claims_size %zu\n", custom_claims,
			   custom_claims_length);
		for (size_t i = 0; i < custom_claims_length; ++i) {
			RATS_DEBUG("custom_claims[%zu] -> name: '%s' value_size: %zu\n", i,
				   custom_claims[i].name, custom_claims[i].value_size);
		}

		/* Verify pubkey_hash */
		RATS_DEBUG("check pubkey hash. pubkey_hash: %p, pubkey_hash_algo: %d\n",
			   pubkey_hash, pubkey_hash_algo);

		uint8_t calculated_pubkey_hash[RATS_MAX_HASH_SIZE];
		crypto_wrapper_err_t c_err =
			crypto_ctx->rats_handle->crypto_wrapper->opts->gen_hash(
				crypto_ctx->rats_handle->crypto_wrapper, pubkey_hash_algo,
				pubkey_buffer, pubkey_buffer_size, calculated_pubkey_hash);
		if (c_err != CRYPTO_WRAPPER_ERR_NONE) {
			RATS_ERR("failed to calculate hash of pubkey: %#x\n", c_err);
			ret = CRYPTO_WRAPPER_ERR_INVALID;
			goto err;
		}

		size_t hash_size = hash_size_of_algo(pubkey_hash_algo);
		if (hash_size == 0) {
			RATS_FATAL("failed verify hash of pubkey: unsupported hash algo id: %u\n",
				   pubkey_hash_algo);
			ret = CRYPTO_WRAPPER_ERR_INVALID;
			goto err;
		}
		RATS_DEBUG("The hash of public key [%zu] %02x%02x%02x%02x%02x%02x%02x%02x...\n",
			   hash_size, calculated_pubkey_hash[0], calculated_pubkey_hash[1],
			   calculated_pubkey_hash[2], calculated_pubkey_hash[3],
			   calculated_pubkey_hash[4], calculated_pubkey_hash[5],
			   calculated_pubkey_hash[6], calculated_pubkey_hash[7]);

		if (memcmp(pubkey_hash, calculated_pubkey_hash, hash_size)) {
			RATS_ERR("unmatched pubkey hash value in claims buffer\n");
			ret = CRYPTO_WRAPPER_ERR_INVALID;
			goto err;
		}
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
	if (crypto_ctx->verify_claims_callback) {
		int callback_ret =
			crypto_ctx->verify_claims_callback(claims, claims_length, crypto_ctx->args);
		if (callback_ret != 0) {
			RATS_ERR("verify_claims_callback failed with code: %#x\n", callback_ret);
			ret = CRYPTO_WRAPPER_ERR_INVALID;
			goto err;
		}
	}

	ret = CRYPTO_WRAPPER_ERR_NONE;
err:
	if (custom_claims)
		free_claims_list(custom_claims, custom_claims_length);
	if (builtin_claims)
		free_claims_list(builtin_claims, builtin_claims_length);
	if (claims)
		/* We have to free the claims array and content of each claims */
		free_claims_list(claims, claims_length);
	if (claims_buffer)
		free(claims_buffer);
	if (custom_claims)
		free_claims_list(custom_claims, custom_claims_length);

	return ret;
}
