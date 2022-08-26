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
#include "csv_utils.h"

static rats_verifier_err_t verify_cert_chain(csv_evidence *evidence)
{
	rats_verifier_err_t err = RATS_VERIFIER_ERR_INVALID;
	csv_attestation_report *report = &evidence->attestation_report;

	hygon_root_cert_t *hsk_cert = (hygon_root_cert_t *)evidence->hsk_cek_cert;
	csv_cert_t *cek_cert = (csv_cert_t *)(&evidence->hsk_cek_cert[HYGON_CERT_SIZE]);
	csv_cert_t *pek_cert = (csv_cert_t *)report->pek_cert;

	assert(sizeof(hygon_root_cert_t) == HYGON_CERT_SIZE);
	assert(sizeof(csv_cert_t) == HYGON_CSV_CERT_SIZE);

	/* The PEK and ChipId are stored in csv_attestation_report, it's necessary
	 * to check whether PEK and ChipId have been tampered with.
	 */
	hash_block_t hmac;
	uint8_t mnonce[CSV_ATTESTATION_MNONCE_SIZE] = {
		0,
	};
	int i, j;

	/* Retrieve mnonce which is the key of sm3-hmac */
	j = CSV_ATTESTATION_MNONCE_SIZE / sizeof(uint32_t);
	for (i = 0; i < j; i++)
		((uint32_t *)mnonce)[i] = ((uint32_t *)report->mnonce)[i] ^ report->anonce;

	memset((void *)&hmac, 0, sizeof(hash_block_t));
	if (sm3_hmac((const char *)mnonce, CSV_ATTESTATION_MNONCE_SIZE,
		     (const unsigned char *)report + CSV_ATTESTATION_REPORT_HMAC_DATA_OFFSET,
		     CSV_ATTESTATION_REPORT_HMAC_DATA_SIZE, (unsigned char *)&hmac,
		     sizeof(hash_block_t))) {
		RATS_ERR("failed to compute sm3 hmac\n");
		return err;
	}
	if (memcmp(&hmac, &report->hmac, sizeof(hash_block_t))) {
		RATS_ERR("PEK and ChipId may have been tampered with\n");
		return err;
	}
	RATS_DEBUG("check PEK and ChipId successfully\n");

	/* Retrieve PEK cert and ChipId */
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

rats_verifier_err_t csv_verify_evidence(rats_verifier_ctx_t *ctx, attestation_evidence_t *evidence,
					const uint8_t *hash, uint32_t hash_len,
					__attribute__((unused)) claim_t **claims,
					__attribute__((unused)) size_t *claims_length)
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

	return err;
}
