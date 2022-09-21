#include <string.h>
#include <librats/log.h>
#include <librats/api.h>
#include <librats/claim.h>
#include <librats/cert.h>
#include <internal/dice.h>
#include <internal/core.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

rats_attester_err_t librats_get_attestation_certificate(
	const char *subject_name, uint8_t *private_key, size_t private_key_size,
	uint8_t *public_key, size_t public_key_size, const claim_t *custom_claims,
	size_t custom_claims_length, uint8_t **output_certificate, size_t *output_certificate_size)
{
	rats_attester_err_t ret;

	EVP_PKEY *pkey = NULL;
	BIO *bio = NULL;
	uint8_t hash[SHA256_DIGEST_LENGTH];
	size_t hash_len = SHA256_DIGEST_LENGTH;

	uint8_t *claims_buffer = NULL;
	size_t claims_buffer_size = 0;

	uint8_t *evidence_buffer = NULL;
	size_t evidence_buffer_size = 0;
	uint8_t *endorsements_buffer = NULL;
	size_t endorsements_buffer_size = 0;

	rats_core_context_t ctx;
	rats_conf_t conf;
	attestation_evidence_t evidence;
	bool attest_initialized = false;

	if (!private_key || !public_key || !output_certificate || !output_certificate_size ||
	    (!custom_claims && custom_claims_length))
		return RATS_ATTESTER_ERR_INVALID_PARAMETER;

	/* Initialize pointer parameters */
	*output_certificate = NULL;
	*output_certificate_size = 0;

	/* Parse the private key in PEM format */
	ret = RATS_ATTESTER_ERR_NO_MEM;
	pkey = EVP_PKEY_new();
	if (!pkey)
		goto err;

	bio = BIO_new_mem_buf(private_key, private_key_size);
	if (!bio)
		goto err;

	// TODO: Should we also read public key?
	ret = RATS_ATTESTER_ERR_CERT_PRIV_KEY;
	if (!PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL))
		goto err;
	BIO_free(bio);
	bio = NULL;

	/* Calculate sha256 hash for pubkey */
	ret = RATS_ATTESTER_ERR_INVALID;
	if (openssl_calc_pubkey_sha256(pkey, hash) != 0)
		goto err;

	/* Generate evidence with driver layer functions */
	memset(&ctx, 0, sizeof(rats_core_context_t));
	memset(&conf, 0, sizeof(rats_conf_t));
	memset(&evidence, 0, sizeof(attestation_evidence_t));

	conf.api_version = RATS_API_VERSION_DEFAULT;
	conf.log_level = rats_loglevel_getenv("RATS_GLOBAL_LOG_LEVEL");
	ret = RATS_ATTESTER_ERR_INIT;
	if (rats_attest_init(&conf, &ctx) != RATS_ATTESTER_ERR_NONE)
		goto err;
	attest_initialized = true;

	/* Check if we need to create claims_buffer.
	 * For sha256, the length of pubkey-hash-value is 36 bytes, so here we assume that the size of user-data field is 
	 * always larger than the length of pubkey-hash-value. */
	// TODO: We need a way to check the max length of user-data that attester accept.
	if (custom_claims_length) {
		/* Using hash of claims_buffer as user data */
		RATS_DEBUG("fill evidence user-data field with sha256 of claims_buffer\n");
		ret = dice_generate_claims_buffer(hash, custom_claims, custom_claims_length,
						  &claims_buffer, &claims_buffer_size);
		if (ret != RATS_ATTESTER_ERR_NONE)
			goto err;
		SHA256(claims_buffer, claims_buffer_size, hash);
		if (hash_len >= 16)
			RATS_DEBUG(
				"evidence user-data field [%zu] %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x...\n",
				hash_len, hash[0], hash[1], hash[2], hash[3], hash[4], hash[5],
				hash[6], hash[7], hash[8], hash[9], hash[10], hash[11], hash[12],
				hash[13], hash[14], hash[15]);
		ret = ctx.attester->opts->collect_evidence(ctx.attester, &evidence, hash, hash_len);
	} else {
		/* Using pubkey-hash-value as user data */
		RATS_DEBUG("fill evidence user-data field with pubkey-hash-value\n");
		uint8_t *pubkey_hash_value_buffer = NULL;
		size_t pubkey_hash_value_buffer_size = 0;
		ret = dice_generate_pubkey_hash_value_buffer(hash, &pubkey_hash_value_buffer,
							     &pubkey_hash_value_buffer_size);
		if (ret != RATS_ATTESTER_ERR_NONE) {
			RATS_ERR("failed to generate pubkey-hash-value\n");
			goto err;
		}
		if (pubkey_hash_value_buffer_size >= 16) {
			uint8_t *data = pubkey_hash_value_buffer;
			RATS_DEBUG(
				"evidence user-data field [%zu] %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x...\n",
				pubkey_hash_value_buffer_size, data[0], data[1], data[2], data[3],
				data[4], data[5], data[6], data[7], data[8], data[9], data[10],
				data[11], data[12], data[13], data[14], data[15]);
		}
		ret = ctx.attester->opts->collect_evidence(ctx.attester, &evidence,
							   pubkey_hash_value_buffer,
							   pubkey_hash_value_buffer_size);
		free(pubkey_hash_value_buffer);
	}
	if (ret != RATS_ATTESTER_ERR_NONE)
		goto err;
	RATS_DEBUG("evidence.type: '%s'\n", evidence.type);

	/* This check is a workaround for the nullattester.
	 * Note: For nullattester, we do not generate an evidence_buffer. nor do we generate evidence extension.  */
	if (evidence.type[0] == '\0') {
		RATS_WARN(
			"evidence type is empty, which is normal only when you are using nullattester.\n");
	} else {
		/* Get DICE evidence buffer */
		ret = dice_generate_evidence_buffer_with_tag(&evidence, claims_buffer,
							     claims_buffer_size, &evidence_buffer,
							     &evidence_buffer_size);
		if (ret != RATS_ATTESTER_ERR_NONE)
			goto err;
	}
	RATS_DEBUG("evidence buffer size: %zu\n", evidence_buffer_size);

	/* We have not implemented the collection of endorsements so far, so just return a empty buffer */
	endorsements_buffer = NULL;
	endorsements_buffer_size = 0;

	/* Generate certificate */
	rats_cert_info_t cert_info = {
		.subject_name = subject_name,
		.key = {
			.private_key = pkey,
			.public_key = pkey,
		},
		.extension_info = {
			.evidence_buffer = evidence_buffer,
			.evidence_buffer_size = evidence_buffer_size,
			.endorsements_buffer = endorsements_buffer,
			.endorsements_buffer_size = endorsements_buffer_size,
		},
	};

	ret = openssl_gen_cert(&cert_info, output_certificate, output_certificate_size);
	if (ret != RATS_ATTESTER_ERR_NONE)
		goto err;

	ret = RATS_ATTESTER_ERR_NONE;
err:
	if (attest_initialized &&
	    ctx.attester->opts->cleanup(ctx.attester) != RATS_ATTESTER_ERR_NONE) {
		RATS_ERR("failed to clean up attester\n");
	}
	if (evidence_buffer)
		free(evidence_buffer);
	if (endorsements_buffer)
		free(endorsements_buffer);
	if (claims_buffer)
		free(claims_buffer);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (bio)
		BIO_free(bio);
	return ret;
}
