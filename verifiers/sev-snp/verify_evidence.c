/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <librats/log.h>
#include <librats/verifier.h>
#include "../../attesters/sev-snp/sev_snp.h"
#include "sevapi.h"
#include "x509cert.h"
#include "crypto.h"
#include "utils.h"

rats_verifier_err_t convert_quote_to_claims(snp_attestation_report_t *report, uint32_t report_size,
					    claim_t **claims_out, size_t *claims_length_out)
{
	if (!claims_out || !claims_length_out)
		return RATS_VERIFIER_ERR_NONE;
	if (!report || !report_size)
		return RATS_VERIFIER_ERR_INVALID_PARAMETER;

	claim_t *claims = NULL;
	size_t claims_length = 0;
	rats_verifier_err_t err = RATS_VERIFIER_ERR_UNKNOWN;
	if (claims == NULL)
		return RATS_VERIFIER_ERR_NO_MEM;

	claims_length = 2 + 14; /* 2 common claims + 14 sev_snp claims */
	claims = malloc(sizeof(claim_t) * claims_length);

	size_t claims_index = 0;

	/* common claims */
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_COMMON_QUOTE, report,
				      report_size));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_COMMON_QUOTE_TYPE,
				      "sev_snp", sizeof("sev_snp")));

	/* sev_snp claims */
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_SEV_SNP_GUEST_SVN,
				      (uint8_t *)&report->guest_svn, sizeof(report->guest_svn)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_SEV_SNP_POLICY,
				      (uint8_t *)&report->policy, sizeof(report->policy)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_SEV_SNP_FAMILY_ID,
				      (uint8_t *)&report->family_id, sizeof(report->family_id)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_SEV_SNP_IMAGE_ID,
				      (uint8_t *)&report->image_id, sizeof(report->image_id)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_SEV_SNP_VMPL,
				      (uint8_t *)&report->vmpl, sizeof(report->vmpl)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_SEV_SNP_CURRENT_TCB,
				      (uint8_t *)&report->current_tcb,
				      sizeof(report->current_tcb)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_SEV_SNP_PLATFORM_INFO,
				      (uint8_t *)&report->platform_info,
				      sizeof(report->platform_info)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_SEV_SNP_MEASUREMENT,
				      (uint8_t *)&report->measurement,
				      sizeof(report->measurement)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_SEV_SNP_HOST_DATA,
				      (uint8_t *)&report->host_data, sizeof(report->host_data)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_SEV_SNP_ID_KEY_DIGEST,
				      (uint8_t *)&report->id_key_digest,
				      sizeof(report->id_key_digest)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_SEV_SNP_REPORT_ID,
				      (uint8_t *)&report->report_id, sizeof(report->report_id)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_SEV_SNP_REPORT_ID_MA,
				      (uint8_t *)&report->report_id_ma,
				      sizeof(report->report_id_ma)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_SEV_SNP_REPORTED_TCB,
				      (uint8_t *)&report->reported_tcb,
				      sizeof(report->reported_tcb)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_SEV_SNP_CHIP_ID,
				      (uint8_t *)&report->chip_id, sizeof(report->chip_id)));

	*claims_out = claims;
	*claims_length_out = claims_length;
	claims = NULL;

	err = RATS_VERIFIER_ERR_NONE;
done:
	if (claims)
		free_claims_list(claims, claims_index);
	return err;
}

rats_verifier_err_t sev_snp_verify_evidence(rats_verifier_ctx_t *ctx,
					    attestation_evidence_t *evidence, const uint8_t *hash,
					    uint32_t hash_len,
					    __attribute__((unused))
					    attestation_endorsement_t *endorsements,
					    claim_t **claims, size_t *claims_length)
{
	RATS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	rats_verifier_err_t err = RATS_VERIFIER_ERR_UNKNOWN;
	snp_attestation_report_t *report = (snp_attestation_report_t *)(evidence->snp.report);
	if (evidence->snp.vcek[0] == '\0') {
#ifdef WASM
		RATS_ERR("No vcek found in evidence");
		return RATS_VERIFIER_ERR_INVALID;
#else
		memset(evidence->snp.vcek, 0, VECK_MAX_SIZE);
		err = sev_snp_get_vcek_der(report->chip_id, sizeof(report->chip_id),
					   &report->current_tcb, &evidence->snp);
		if (err != RATS_ATTESTER_ERR_NONE)
			return err;
#endif
	}

	/* Verify the hash value */
	if (memcmp(hash, report->report_data, hash_len) != 0) {
		RATS_ERR("unmatched hash value in evidence.\n");
		return RATS_VERIFIER_ERR_INVALID;
	}

	X509 *x509_ark = NULL;
	X509 *x509_ask = NULL;
	X509 *x509_vcek = NULL;
	EVP_PKEY *vcek_pub_key = NULL;
	BIO *bio_mem = NULL;
	bool ret = false;

	bio_mem = BIO_new(BIO_s_mem());
	if (!bio_mem) {
		goto errret;
	}
	BIO_puts(bio_mem, ask_pem);
	x509_ask = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
	if (!x509_ask) {
		goto errret;
	}
	BIO_reset(bio_mem);
	BIO_puts(bio_mem, ark_pem);
	x509_ark = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
	if (!x509_ark) {
		goto errret;
	}
	uint8_t *vcek_ptr = evidence->snp.vcek;
	x509_vcek = d2i_X509(NULL, (const unsigned char **)&(vcek_ptr), evidence->snp.vcek_len);
	if (!x509_vcek) {
		goto errret;
	}

	/* Extract the VCEK public key */
	vcek_pub_key = X509_get_pubkey(x509_vcek);
	if (!vcek_pub_key)
		goto errret;

	/* Verify the ARK self-signed the ARK */
	ret = x509_validate_signature(x509_ark, NULL, x509_ark);
	if (!ret) {
		RATS_ERR("failed to validate signature of x509_ark cert\n");
		err = RATS_VERIFIER_ERR_INVALID;
		goto errret;
	}

	/* Verify the ASK signed by ARK */
	ret = x509_validate_signature(x509_ask, NULL, x509_ark);
	if (!ret) {
		RATS_ERR("failed to validate signature of x509_ask cert\n");
		err = RATS_VERIFIER_ERR_INVALID;
		goto errret;
	}

	/* Verify the VCEK signed by ASK */
	ret = x509_validate_signature(x509_vcek, x509_ask, x509_ark);
	if (!ret) {
		RATS_ERR("failed to validate signature of x509_vcek cert\n");
		err = RATS_VERIFIER_ERR_INVALID;
		goto errret;
	}

	/* Verify the attestation report signed by VCEK */
	ret = verify_message((sev_sig *)&report->signature, &vcek_pub_key, (const uint8_t *)report,
			     offsetof(snp_attestation_report_t, signature),
			     SEV_SIG_ALGO_ECDSA_SHA384);
	if (!ret) {
		RATS_ERR("failed to verify snp guest report\n");
		err = RATS_VERIFIER_ERR_INVALID;
		goto errret;
	}

	err = convert_quote_to_claims(report, sizeof(*report), claims, claims_length);
	if (err != RATS_VERIFIER_ERR_NONE) {
		RATS_ERR("failed to convert sev_snp attestation report to builtin claims: %#x\n",
			 err);
		goto errret;
	}

	RATS_INFO("SEV-SNP attestation report validated successfully!\n");

errret:
	X509_free(x509_ark);
	X509_free(x509_ask);
	X509_free(x509_vcek);
	BIO_free(bio_mem);
	EVP_PKEY_free(vcek_pub_key);

	return err;
}
