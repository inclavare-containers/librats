/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <librats/log.h>
#include <librats/verifier.h>
#include "sev_utils.h"
#include "amdcert.h"
#include "sevcert.h"
#include "../../attesters/sev/sev.h"

int generate_ark_ask_cert(amd_cert *ask_cert, amd_cert *ark_cert, enum ePSP_DEVICE_TYPE device_type)
{
	char *ark_ask_cert_patch;
	char *default_dir = SEV_DEFAULT_DIR;
	char *url = NULL;
	struct stat st;

	switch (device_type) {
	case PSP_DEVICE_TYPE_NAPLES:
		ark_ask_cert_patch = SEV_DEFAULT_DIR ASK_ARK_NAPLES_FILE;
		url = ASK_ARK_NAPLES_SITE;
		break;
	case PSP_DEVICE_TYPE_ROME:
		ark_ask_cert_patch = SEV_DEFAULT_DIR ASK_ARK_ROME_FILE;
		url = ASK_ARK_ROME_SITE;
		break;
	case PSP_DEVICE_TYPE_MILAN:
		ark_ask_cert_patch = SEV_DEFAULT_DIR ASK_ARK_MILAN_FILE;
		url = ASK_ARK_MILAN_SITE;
		break;
	default:
		RATS_ERR("unsupported device type %d\n", device_type);
		return -1;
	}

	if (stat(default_dir, &st) == -1) {
		if (mkdir(default_dir, S_IRWXU | S_IRWXG | S_IRWXO) != 0)
			RATS_ERR("failed to mkdir %s\n", default_dir);
		return -1;
	}

	/* Don't re-download the ASK/ARK from the KDS server if you already have it */
	if (get_file_size(ark_ask_cert_patch) == 0) {
#ifdef WASM
		RATS_ERR("No ark_ask_cert in %s\n", ark_ask_cert_patch);
		return -1;
#else
		if (download_from_url(url, ark_ask_cert_patch) != 0) {
			RATS_ERR("failed to download %s\n", ark_ask_cert_patch);
			return -1;
		}
#endif
	}

	/* Read in the ask_ark so we can split it into 2 separate cert files */
	uint8_t ask_ark_buf[sizeof(amd_cert) * 2] = { 0 };
	if (read_file(ark_ask_cert_patch, ask_ark_buf, sizeof(ask_ark_buf)) !=
	    sizeof(ask_ark_buf)) {
		RATS_ERR("read %s fail\n", ark_ask_cert_patch);
		return -1;
	}

	/* Initialize the ASK */
	if (amd_cert_init(ask_cert, ask_ark_buf) != 0) {
		RATS_ERR("failed to initialize ASK certificate\n");
		return -1;
	}

	/* Initialize the ARK */
	size_t ask_size = amd_cert_get_size(ask_cert);
	if (amd_cert_init(ark_cert, (uint8_t *)(ask_ark_buf + ask_size)) != 0) {
		RATS_ERR("failed to initialize ASK certificate\n");
		return -1;
	}

	/* Check the usage of the ASK and ARK */
	if (ask_cert->key_usage != AMD_USAGE_ASK || ark_cert->key_usage != AMD_USAGE_ARK) {
		RATS_ERR("certificate Usage %u did not match expected value %d\n",
			 ask_cert->key_usage, AMD_USAGE_ASK);
		return -1;
	}

	return 0;
}

rats_verifier_err_t validate_cert_chain(sev_evidence_t *sev_evidence, amd_cert *ark_cert,
					amd_cert *ask_cert)
{
	rats_verifier_err_t err = RATS_VERIFIER_ERR_INVALID;
	sev_cert *cek = &sev_evidence->cek_cert;
	sev_cert *pek = &sev_evidence->pek_cert;
	sev_cert *oca = &sev_evidence->oca_cert;
	sev_attestation_report *report = &sev_evidence->attestation_report;
	enum ePSP_DEVICE_TYPE device_type = sev_evidence->device_type;

	/* Verify ARK cert with ARK */
	if (!amd_cert_validate_ark(ark_cert, device_type)) {
		RATS_ERR("failed to verify ARK cert\n");
		return err;
	}
	RATS_INFO("verify ARK cert successfully\n");

	/* Verify ASK cert with ARK */
	if (!amd_cert_validate_ask(ask_cert, ark_cert, device_type)) {
		RATS_ERR("failed to verify ASK cert\n");
		return err;
	}
	RATS_INFO("verify ASK cert successfully\n");

	/* Verify CEK cert with ASK */
	sev_cert ask_pubkey;
	if (amd_cert_export_pub_key(ask_cert, &ask_pubkey) != 0) {
		RATS_ERR("failed to export pub key from ask\n");
		return err;
	}

	if (!verify_sev_cert(cek, &ask_pubkey, NULL)) {
		RATS_ERR("failed to verify CEK cert\n");
		return err;
	}
	RATS_INFO("verify CEK cert successfully\n");

	/* Verify PEK cert with CEK and OCA */
	if (!verify_sev_cert(pek, oca, cek)) {
		RATS_ERR("failed to verify PEK cert\n");
		return err;
	}
	RATS_INFO("verify PEK cert successfully\n");

	/* Verify attestation report with PEK */
	if (!validate_attestation(pek, report)) {
		RATS_ERR("failed to verify sev attestation report\n");
		return err;
	}

	RATS_INFO("SEV(-ES) attestation report validated successfully!\n");

	return RATS_VERIFIER_ERR_NONE;
}

rats_verifier_err_t sev_verify_evidence(rats_verifier_ctx_t *ctx, attestation_evidence_t *evidence,
					const uint8_t *hash, uint32_t hash_len,
					__attribute__((unused)) claim_t **claims,
					__attribute__((unused)) size_t *claims_length)
{
	RATS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	rats_verifier_err_t err = RATS_VERIFIER_ERR_UNKNOWN;
	sev_evidence_t *sev_evidence = (sev_evidence_t *)(evidence->sev.report);

	/* SEV(-ES) do NOT support self-defined user_data, therefore we skip the
	 * hash verify.
	 */

	/*  Generate ask and ark cert */
	amd_cert ask_cert;
	amd_cert ark_cert;
	enum ePSP_DEVICE_TYPE device_type = sev_evidence->device_type;
	if (generate_ark_ask_cert(&ask_cert, &ark_cert, device_type) == -1) {
		RATS_ERR("failed to load ASK cert\n");
		return RATS_VERIFIER_ERR_INVALID;
	}

	err = validate_cert_chain(sev_evidence, &ark_cert, &ask_cert);
	if (err != RATS_VERIFIER_ERR_NONE)
		RATS_ERR("failed to verify snp attestation report\n");

	return err;
}