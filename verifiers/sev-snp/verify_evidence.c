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

rats_verifier_err_t sev_snp_verify_evidence(
	rats_verifier_ctx_t *ctx, attestation_evidence_t *evidence, const uint8_t *hash,
	uint32_t hash_len, __attribute__((unused)) attestation_endorsement_t *endorsements,
	__attribute__((unused)) claim_t **claims, __attribute__((unused)) size_t *claims_length)
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
					   &report->platform_version, &evidence->snp);
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
		goto err;
	}
	BIO_puts(bio_mem, ask_pem);
	x509_ask = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
	if (!x509_ask) {
		goto err;
	}
	BIO_reset(bio_mem);
	BIO_puts(bio_mem, ark_pem);
	x509_ark = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
	if (!x509_ark) {
		goto err;
	}
	uint8_t *vcek_ptr = evidence->snp.vcek;
	x509_vcek = d2i_X509(NULL, (const unsigned char **)&(vcek_ptr), evidence->snp.vcek_len);
	if (!x509_vcek) {
		goto err;
	}

	/* Extract the VCEK public key */
	vcek_pub_key = X509_get_pubkey(x509_vcek);
	if (!vcek_pub_key)
		goto err;

	/* Verify the ARK self-signed the ARK */
	ret = x509_validate_signature(x509_ark, NULL, x509_ark);
	if (!ret) {
		RATS_ERR("failed to validate signature of x509_ark cert\n");
		err = RATS_VERIFIER_ERR_INVALID;
		goto err;
	}

	/* Verify the ASK signed by ARK */
	ret = x509_validate_signature(x509_ask, NULL, x509_ark);
	if (!ret) {
		RATS_ERR("failed to validate signature of x509_ask cert\n");
		err = RATS_VERIFIER_ERR_INVALID;
		goto err;
	}

	/* Verify the VCEK signed by ASK */
	ret = x509_validate_signature(x509_vcek, x509_ask, x509_ark);
	if (!ret) {
		RATS_ERR("failed to validate signature of x509_vcek cert\n");
		err = RATS_VERIFIER_ERR_INVALID;
		goto err;
	}

	/* Verify the attestation report signed by VCEK */
	ret = verify_message((sev_sig *)&report->signature, &vcek_pub_key, (const uint8_t *)report,
			     offsetof(snp_attestation_report_t, signature),
			     SEV_SIG_ALGO_ECDSA_SHA384);
	if (!ret) {
		RATS_ERR("failed to verify snp guest report\n");
		err = RATS_VERIFIER_ERR_INVALID;
		goto err;
	}

	err = RATS_VERIFIER_ERR_NONE;

	RATS_INFO("SEV-SNP attestation report validated successfully!\n");

err:
	X509_free(x509_ark);
	X509_free(x509_ask);
	X509_free(x509_vcek);
	BIO_free(bio_mem);
	EVP_PKEY_free(vcek_pub_key);

	return err;
}
