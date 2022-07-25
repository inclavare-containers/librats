#include <stdint.h>
#include <string.h>
#include <librats/api.h>
#include <librats/log.h>

rats_verifier_err_t librats_verify_evidence(attestation_evidence_t *evidence, uint8_t *hash)
{
	uint32_t hash_len = 32;
	rats_core_context_t ctx;
	rats_conf_t conf;

	conf.api_version = RATS_API_VERSION_DEFAULT;
	conf.log_level = RATS_LOG_LEVEL_DEFAULT;
	memcpy(conf.verifier_type, evidence->type, sizeof(conf.verifier_type));

	if (rats_verify_init(&conf, &ctx) != RATS_VERIFIER_ERR_NONE)
		return RATS_VERIFIER_ERR_INIT;

	rats_verifier_err_t err =
		ctx.verifier->opts->verify_evidence(ctx.verifier, evidence, hash, hash_len);

	if (ctx.verifier->opts->cleanup(ctx.verifier) != RATS_VERIFIER_ERR_NONE) {
		RATS_ERR("failed to clean up verifier\n");
	}

	return err;
}
