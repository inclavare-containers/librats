#include <stdint.h>
#include <librats/api.h>

rats_verifier_err_t librats_verify_evidence(rats_verifier_ctx_t *ctx,
					    attestation_evidence_t *evidence, uint8_t *hash,
					    uint32_t hash_len)
{
	rats_verifier_err_t err = ctx->opts->verify_evidence(ctx, evidence, hash, hash_len);

	return err;
}
