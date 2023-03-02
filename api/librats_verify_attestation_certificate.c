#include <string.h>
#include <librats/log.h>
#include <librats/api.h>
#include <librats/log.h>
#include <librats/claim.h>
#include <librats/cert.h>
#include <internal/dice.h>
#include <internal/core.h>

/* Function for verifying X.509 Certificates compatible with Interoperable RA-TLS.
 * 
 * @param certificate[IN] - Data of the certificate to be verified, in DER format.
 * @param certificate_size[IN] - Size of the certificate, in bytes.
 * @param verify_claims_callback[IN] - A user-provided callback function pointer, which will be called during validation.
 * @param args[IN] - A pointer that will be used as one of arguments when verify_claims_callback is called.
 */
rats_verifier_err_t
librats_verify_attestation_certificate(uint8_t *certificate, size_t certificate_size,
				       rats_verify_claims_callback_t verify_claims_callback,
				       void *args)
{
	rats_verifier_err_t ret = RATS_VERIFIER_ERR_UNKNOWN;
	crypto_wrapper_err_t crypto_ret = CRYPTO_WRAPPER_ERR_UNKNOWN;

	rats_core_context_t ctx;
	rats_conf_t conf;
	bool verifier_initialized = false;
	bool crypto_wrapper_initialized = false;

	memset(&ctx, 0, sizeof(rats_core_context_t));
	memset(&conf, 0, sizeof(rats_conf_t));

	conf.api_version = RATS_API_VERSION_DEFAULT;
	if ((ret = rats_verifier_init(&conf, &ctx)) != RATS_VERIFIER_ERR_NONE)
		goto err;
	verifier_initialized = true;
	if ((crypto_ret = rats_crypto_wrapper_init(&conf, &ctx)) != CRYPTO_WRAPPER_ERR_NONE) {
		RATS_ERR("failed to init crypto_wrapper: %#x\n", crypto_ret);
		ret = RATS_VERIFIER_ERR_INIT;
		goto err;
	}
	crypto_wrapper_initialized = true;

	ctx.crypto_wrapper->verify_claims_callback = verify_claims_callback;
	ctx.crypto_wrapper->args = args;

	if (!ctx.crypto_wrapper->opts->verify_cert) {
		RATS_FATAL("the current crypto_wrapper does not support verify_cert()\n");
		ret = RATS_VERIFIER_ERR_INVALID;
		goto err;
	}
	crypto_ret = ctx.crypto_wrapper->opts->verify_cert(ctx.crypto_wrapper, certificate,
							   certificate_size);
	if (crypto_ret != CRYPTO_WRAPPER_ERR_NONE) {
		RATS_ERR("certificate verification failed: %#x\n", crypto_ret);
		ret = RATS_ATTESTER_ERR_CERT_GEN;
		goto err;
	}

	ret = RATS_VERIFIER_ERR_NONE;
err:
	if (crypto_wrapper_initialized &&
	    ctx.crypto_wrapper->opts->cleanup(ctx.crypto_wrapper) != CRYPTO_WRAPPER_ERR_NONE) {
		RATS_ERR("failed to clean up crypto_wrapper\n");
	}
	if (verifier_initialized &&
	    ctx.verifier->opts->cleanup(ctx.verifier) != RATS_VERIFIER_ERR_NONE) {
		RATS_ERR("failed to clean up verifier\n");
	}
	return ret;
}