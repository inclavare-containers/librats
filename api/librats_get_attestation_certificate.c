#include <string.h>
#include <librats/log.h>
#include <librats/api.h>
#include <librats/claim.h>
#include <librats/cert.h>
#include <librats/conf.h>
#include <internal/dice.h>
#include <internal/core.h>

/* Function for generating X.509 Certificates compatible with Interoperable RA-TLS.
 * 
 * @param subject_name[IN] - Subject name of the output certificate.
 * @param privkey[IN/OUT] - Pointer to privite key content in PEM format.
 *        If *privkey is NOT NULL, the API will use the key provided by *privkey and *privkey_len to generate the certificate.
 *        If *privkey is NULL, the API will generate a random key for certificate generation. After the function returns, *privkey will hold the data of generated privkey, and *privkey_len will hold the length. Note that in this case, the user is obliged to free the memory pointed by the pointer *privkey.
 * @param privkey_len[IN/OUT] - Pointer to privite key content length.
 * @param custom_claims[IN] - Pointer to header of custom claims list.
 * @param custom_claims_length[IN] - The number of claims in custom_claims.
 * @param provide_endorsements[IN] - Whether to add endorsements extension to the certificate.
 * @param certificate_out[OUT] - The *certificate_out is a pointer to hold the data of generated ceritificate, in DER format. Note that user is obliged to free the memory pointed by *certificate_out.
 * @param certificate_size_out[OUT] - Pointer to hold the size of generated ceritificate.
 */
rats_attester_err_t librats_get_attestation_certificate(
	rats_conf_t conf, rats_cert_subject_t subject_name, uint8_t **privkey, size_t *privkey_len,
	const claim_t *custom_claims, size_t custom_claims_length, bool provide_endorsements,
	uint8_t **certificate_out, size_t *certificate_size_out)
{
	rats_attester_err_t ret = RATS_ATTESTER_ERR_UNKNOWN;
	crypto_wrapper_err_t crypto_ret = CRYPTO_WRAPPER_ERR_UNKNOWN;

	const size_t hash_size = RATS_SHA256_HASH_SIZE;
	uint8_t hash[hash_size];

	uint8_t *claims_buffer = NULL;
	size_t claims_buffer_size = 0;

	uint8_t *evidence_buffer = NULL;
	size_t evidence_buffer_size = 0;
	uint8_t *endorsements_buffer = NULL;
	size_t endorsements_buffer_size = 0;

	rats_core_context_t ctx;
	attestation_evidence_t evidence;
	bool attester_initialized = false;
	bool crypto_wrapper_initialized = false;

	if (!privkey || !privkey_len || (*privkey && !*privkey_len) || !certificate_out ||
	    !certificate_size_out || (!custom_claims && custom_claims_length))
		return RATS_ATTESTER_ERR_INVALID_PARAMETER;

	/* Initialize local variables and pointer parameters */
	*certificate_out = NULL;
	*certificate_size_out = 0;

	memset(&ctx, 0, sizeof(rats_core_context_t));
	memset(&evidence, 0, sizeof(attestation_evidence_t));

	conf.api_version = RATS_API_VERSION_DEFAULT;
	conf.key_algo = RATS_KEY_ALGO_DEFAULT;
	conf.hash_algo = RATS_HASH_ALGO_SHA256;
	if (conf.log_level < 0 || conf.log_level > RATS_LOG_LEVEL_MAX) {
		rats_global_log_level = rats_global_core_context.config.log_level;
		RATS_WARN("log level is illegal, reset to global value %d\n",
			  rats_global_core_context.config.log_level);
	} else {
		rats_global_log_level = conf.log_level;
	}

	if ((ret = rats_attester_init(&conf, &ctx)) != RATS_ATTESTER_ERR_NONE)
		goto err;
	attester_initialized = true;
	if ((crypto_ret = rats_crypto_wrapper_init(&conf, &ctx)) != CRYPTO_WRAPPER_ERR_NONE) {
		RATS_ERR("failed to init crypto_wrapper: %#x\n", crypto_ret);
		ret = RATS_ATTESTER_ERR_INIT;
		goto err;
	}

	RATS_DEBUG("here from log\n");

	crypto_wrapper_initialized = true;

	if (*privkey && *privkey_len) {
		/* Use private key provided by user */
		crypto_ret = ctx.crypto_wrapper->opts->use_privkey(ctx.crypto_wrapper, *privkey,
								   *privkey_len);
	} else {
		/* Generate the new key */
		crypto_ret = ctx.crypto_wrapper->opts->gen_privkey(
			ctx.crypto_wrapper, ctx.config.key_algo, privkey, privkey_len);
	}
	if (crypto_ret != CRYPTO_WRAPPER_ERR_NONE) {
		RATS_ERR("failed to init generate private key: %#x\n", crypto_ret);
		ret = RATS_ATTESTER_ERR_CERT_GEN;
		goto err;
	}

	/* Generate the hash of public key */
	crypto_ret = ctx.crypto_wrapper->opts->get_pubkey_hash(ctx.crypto_wrapper,
							       ctx.config.hash_algo, hash);
	if (crypto_ret != CRYPTO_WRAPPER_ERR_NONE) {
		RATS_ERR("failed to generate pubkey hash: %#x\n", crypto_ret);
		ret = RATS_ATTESTER_ERR_CERT_GEN;
		goto err;
	}

	/* Collect evidence */

	// TODO: implement per-session freshness and put "nonce" in custom claims list.
	/* Using sha256 hash of claims_buffer as user data */
	RATS_DEBUG("fill evidence user-data field with sha256 of claims_buffer\n");
	/* Generate claims_buffer */
	ret = dice_generate_claims_buffer(ctx.config.hash_algo, hash, custom_claims,
					  custom_claims_length, &claims_buffer,
					  &claims_buffer_size);
	if (ret != RATS_ATTESTER_ERR_NONE) {
		RATS_ERR("failed to generate claims_buffer: %#x\n", ret);
		goto err;
	}

	/* Note here we reuse `uint8_t hash[hash_size]` to store sha256 hash of claims_buffer */
	ctx.crypto_wrapper->opts->gen_hash(ctx.crypto_wrapper, ctx.config.hash_algo, claims_buffer,
					   claims_buffer_size, hash);
	if (hash_size >= 16)
		RATS_DEBUG(
			"evidence user-data field [%zu] %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x...\n",
			(size_t)hash_size, hash[0], hash[1], hash[2], hash[3], hash[4], hash[5],
			hash[6], hash[7], hash[8], hash[9], hash[10], hash[11], hash[12], hash[13],
			hash[14], hash[15]);
	ret = ctx.attester->opts->collect_evidence(ctx.attester, &evidence, hash, hash_size);
	if (ret != RATS_ATTESTER_ERR_NONE) {
		RATS_ERR("failed to generate evidence: %#x\n", ret);
		goto err;
	}
	RATS_DEBUG("evidence.type: '%s'\n", evidence.type);

	/* Get DICE evidence buffer */
	/* This check is a workaround for the nullattester.
	 * Note: For nullattester, we do not generate an evidence_buffer. nor do we generate evidence extension.  */
	if (evidence.type[0] == '\0') {
		RATS_WARN(
			"evidence type is empty, which is normal only when you are using nullattester.\n");
	} else {
		ret = dice_generate_evidence_buffer_with_tag(&evidence, claims_buffer,
							     claims_buffer_size, &evidence_buffer,
							     &evidence_buffer_size);
		if (ret != RATS_ATTESTER_ERR_NONE) {
			RATS_ERR("failed to generate evidence buffer: %#x\n", ret);
			goto err;
		}
	}
	RATS_DEBUG("evidence buffer size: %zu\n", evidence_buffer_size);

	/* Collect endorsements if required */
	if ((evidence.type[0] != '\0' /* skip for nullattester */ && provide_endorsements) &&
	    ctx.attester->opts->collect_endorsements) {
		attestation_endorsement_t endorsements;
		memset(&endorsements, 0, sizeof(attestation_endorsement_t));

		rats_attester_err_t q_ret = ctx.attester->opts->collect_endorsements(
			ctx.attester, &evidence, &endorsements);
		if (q_ret != RATS_ATTESTER_ERR_NONE) {
			RATS_WARN("failed to collect collateral: %#x\n", q_ret);
			/* Since endorsements are not essential, we tolerate the failure to occur. */
		} else {
			/* Get DICE endorsements buffer */
			ret = dice_generate_endorsements_buffer_with_tag(evidence.type,
									 &endorsements,
									 &endorsements_buffer,
									 &endorsements_buffer_size);
			free_endorsements(evidence.type, &endorsements);
			if (ret != RATS_ATTESTER_ERR_NONE) {
				RATS_ERR("Failed to generate endorsements buffer: %#x\n", ret);
				goto err;
			}
		}
	}
	RATS_DEBUG("endorsements buffer size: %zu\n", endorsements_buffer_size);

	/* Prepare cert info for cert generation */
	rats_cert_info_t cert_info = {
		.subject = subject_name,
		.cert_len = 0,
		.cert_buf = { 0 },
		.evidence_buffer = evidence_buffer,
		.evidence_buffer_size = evidence_buffer_size,
		.endorsements_buffer = endorsements_buffer,
		.endorsements_buffer_size = endorsements_buffer_size,
	};

	/* Generate the TLS certificate */
	crypto_ret = ctx.crypto_wrapper->opts->gen_cert(ctx.crypto_wrapper, ctx.config.hash_algo,
							&cert_info);
	if (crypto_ret != CRYPTO_WRAPPER_ERR_NONE) {
		RATS_ERR("failed to init generate certificate: %#x\n", crypto_ret);
		ret = RATS_ATTESTER_ERR_CERT_GEN;
		goto err;
	}

	uint8_t *t = (uint8_t *)malloc(cert_info.cert_len);
	if (!t) {
		ret = RATS_ATTESTER_ERR_NO_MEM;
		goto err;
	}
	memcpy(t, cert_info.cert_buf, cert_info.cert_len);
	*certificate_out = t;
	*certificate_size_out = cert_info.cert_len;

	ret = RATS_ATTESTER_ERR_NONE;
err:
	if (crypto_wrapper_initialized &&
	    ctx.crypto_wrapper->opts->cleanup(ctx.crypto_wrapper) != CRYPTO_WRAPPER_ERR_NONE) {
		RATS_ERR("failed to clean up crypto_wrapper\n");
	}
	if (attester_initialized &&
	    ctx.attester->opts->cleanup(ctx.attester) != RATS_ATTESTER_ERR_NONE) {
		RATS_ERR("failed to clean up attester\n");
	}
	if (evidence_buffer)
		free(evidence_buffer);
	if (endorsements_buffer)
		free(endorsements_buffer);
	if (claims_buffer)
		free(claims_buffer);
	return ret;
}
