/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <string.h>
#include <librats/log.h>
#include <librats/verifier.h>
#include <librats/csv.h>
#include "hygoncert.h"

static rats_verifier_err_t verify_cert_chain(csv_evidence *evidence)
{
	rats_verifier_err_t err = RATS_VERIFIER_ERR_INVALID;
	csv_attestation_report *report = &evidence->attestation_report;

	hygon_root_cert_t *hsk_cert = (hygon_root_cert_t *)evidence->hsk_cek_cert;
	csv_cert_t *cek_cert = (csv_cert_t *)(&evidence->hsk_cek_cert[HYGON_CERT_SIZE]);
	csv_cert_t *pek_cert = (csv_cert_t *)report->pek_cert;

	assert(sizeof(hygon_root_cert_t) == HYGON_CERT_SIZE);
	assert(sizeof(csv_cert_t) == HYGON_CSV_CERT_SIZE);

	/* Retrieve PEK cert and ChipId */
	int i, j;

	j = (offsetof(csv_attestation_report, reserved1) -
	     offsetof(csv_attestation_report, pek_cert)) /
	    sizeof(uint32_t);
	for (i = 0; i < j; i++)
		((uint32_t *)report->pek_cert)[i] ^= report->anonce;

	/* Verify HSK cert with HRK */
	if (verify_hsk_cert(hsk_cert) != 1) {
		RATS_ERR("failed to verify HSK cert\n");
		return err;
	}
	RATS_DEBUG("verify HSK cert successfully\n");

	/* Verify CEK cert with HSK */
	if (verify_cek_cert(hsk_cert, cek_cert) != 1) {
		RATS_ERR("failed to verify CEK cert\n");
		return err;
	}
	RATS_DEBUG("verify CEK cert successfully\n");

	/* Verigy PEK cert with CEK */
	if (verify_pek_cert(cek_cert, pek_cert) != 1) {
		RATS_ERR("failed to verify PEK cert\n");
		return err;
	}
	RATS_DEBUG("verify PEK cert successfully\n");

	return RATS_VERIFIER_ERR_NONE;
}

static rats_verifier_err_t verify_attestation_report(csv_attestation_report *report)
{
	rats_verifier_err_t err = RATS_VERIFIER_ERR_INVALID;

	csv_cert_t *pek_cert = (csv_cert_t *)report->pek_cert;

	if (sm2_verify_attestation_report(pek_cert, report) != 1) {
		RATS_ERR("failed to verify csv attestation report\n");
		return err;
	}

	return RATS_VERIFIER_ERR_NONE;
}

rats_verifier_err_t convert_quote_to_claims(csv_attestation_report *report, uint32_t report_size,
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

	claims_length = 2 + 10; /* 2 common claims + 10 csv claims */
	claims = malloc(sizeof(claim_t) * claims_length);

	size_t claims_index = 0;

	/* common claims */
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_COMMON_QUOTE, report,
				      report_size));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_COMMON_QUOTE_TYPE,
				      "csv", sizeof("csv")));

	/* Clear nonce on the range from field `user_pubkey_digest` to field `anonce`, note that
	   pek_cert and chip_id have been retrieved in function verify_cert_chain(). */
	int cnt = (offsetof(csv_attestation_report, anonce) -
		   offsetof(csv_attestation_report, user_pubkey_digest)) /
		  sizeof(uint32_t);
	for (int i = 0; i < cnt; i++) {
		((uint32_t *)report)[i] ^= report->anonce;
	}

	/* csv claims */
	CLAIM_CHECK(librats_add_claim(
		&claims[claims_index++], BUILT_IN_CLAIM_CSV_USER_PUBKEY_DIGEST,
		(uint8_t *)&report->user_pubkey_digest, sizeof(report->user_pubkey_digest)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_CSV_VM_ID,
				      (uint8_t *)&report->vm_id, sizeof(report->vm_id)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_CSV_VM_VERSION,
				      (uint8_t *)&report->vm_version, sizeof(report->vm_version)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_CSV_USER_DATA,
				      (uint8_t *)&report->user_data, sizeof(report->user_data)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_CSV_MNONCE,
				      (uint8_t *)&report->mnonce, sizeof(report->mnonce)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_CSV_MEASURE,
				      (uint8_t *)&report->measure, sizeof(report->measure)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_CSV_POLICY,
				      (uint8_t *)&report->policy, sizeof(report->policy)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_CSV_SIG_USAGE,
				      (uint8_t *)&report->sig_usage, sizeof(report->sig_usage)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_CSV_SIG_ALGO,
				      (uint8_t *)&report->sig_algo, sizeof(report->sig_algo)));
	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_CSV_CHIP_ID,
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

rats_verifier_err_t csv_verify_evidence(rats_verifier_ctx_t *ctx, attestation_evidence_t *evidence,
					const uint8_t *hash, uint32_t hash_len,
					__attribute__((unused))
					attestation_endorsement_t *endorsements,
					claim_t **claims, size_t *claims_length)
{
	RATS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	rats_verifier_err_t err = RATS_VERIFIER_ERR_UNKNOWN;
	csv_evidence *c_evidence = (csv_evidence *)(&evidence->csv.report);
	csv_attestation_report *attestation_report = &c_evidence->attestation_report;

	/* Retrieve user_data from attestation report */
	uint8_t user_data[CSV_ATTESTATION_USER_DATA_SIZE] = {
		0,
	};
	int i;

	/* add nonce on new user_data buffer */
	for (i = 0; i < sizeof(user_data) / sizeof(uint32_t); i++)
		((uint32_t *)user_data)[i] = ((uint32_t *)attestation_report->user_data)[i] ^
					     attestation_report->anonce;

	if (memcmp(hash, user_data,
		   hash_len <= CSV_ATTESTATION_USER_DATA_SIZE ? hash_len :
								CSV_ATTESTATION_USER_DATA_SIZE)) {
		RATS_ERR("unmatched hash value in evidence\n");
		return RATS_VERIFIER_ERR_INVALID;
	}

	assert((sizeof(csv_evidence) + c_evidence->hsk_cek_cert_len) <=
	       sizeof(evidence->csv.report));
	err = verify_cert_chain(c_evidence);
	if (err != RATS_VERIFIER_ERR_NONE) {
		RATS_ERR("failed to verify csv cert chain\n");
		return err;
	}

	err = verify_attestation_report(attestation_report);
	if (err != RATS_VERIFIER_ERR_NONE)
		RATS_ERR("failed to verify csv attestation report\n");

	if (err == RATS_VERIFIER_ERR_NONE) {
		err = convert_quote_to_claims(attestation_report, sizeof(*attestation_report),
					      claims, claims_length);
		if (err != RATS_VERIFIER_ERR_NONE)
			RATS_ERR(
				"failed to convert csv attestation report to builtin claims: %#x\n",
				err);
	}
	return err;
}
