/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <librats/claim.h>
#include <librats/log.h>
#include <librats/verifier.h>
#include <sgx_dcap_quoteverify.h>
#include "tdx-ecdsa.h"

rats_verifier_err_t ecdsa_verify_evidence(__attribute__((unused)) rats_verifier_ctx_t *ctx,
					  const char *name, attestation_evidence_t *evidence,
					  __attribute__((unused)) uint32_t evidence_len,
					  const uint8_t *hash, uint32_t hash_len,
					  attestation_endorsement_t *endorsements)
{
	rats_verifier_err_t err = RATS_VERIFIER_ERR_UNKNOWN;

	/* Verify the hash value */
	if (memcmp(hash, ((tdx_quote_t *)(evidence->tdx.quote))->report_body.report_data,
		   hash_len) != 0) {
		RATS_ERR("unmatched hash value in evidence.\n");
		return RATS_VERIFIER_ERR_INVALID;
	}

	/* Call DCAP quote verify library to get supplemental data size */
	uint32_t supplemental_data_size = 0;
	uint8_t *p_supplemental_data = NULL;
	quote3_error_t dcap_ret = tdx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
	if (dcap_ret == SGX_QL_SUCCESS &&
	    supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t)) {
		RATS_INFO("tdx qv gets quote supplemental data size successfully.\n");
		p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
		if (!p_supplemental_data) {
			RATS_ERR("failed to malloc supplemental data space.\n");
			return RATS_VERIFIER_ERR_NO_MEM;
		}
	} else {
		RATS_ERR("failed to get quote supplemental data size by sgx qv: %04x\n", dcap_ret);
		return (int)dcap_ret;
	}

	/* Call DCAP quote verify library for quote verification */
	time_t current_time = time(NULL);
	sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
	uint32_t collateral_expiration_status = 1;

	if (endorsements) {
		sgx_ql_qve_collateral_t collateral = {
			.version = endorsements->ecdsa.version,
			.tee_type = 0x00000081, /* TDX */
			.pck_crl_issuer_chain = endorsements->ecdsa.pck_crl_issuer_chain,
			.pck_crl_issuer_chain_size = endorsements->ecdsa.pck_crl_issuer_chain_size,
			.root_ca_crl = endorsements->ecdsa.root_ca_crl,
			.root_ca_crl_size = endorsements->ecdsa.root_ca_crl_size,
			.pck_crl = endorsements->ecdsa.pck_crl,
			.pck_crl_size = endorsements->ecdsa.pck_crl_size,
			.tcb_info_issuer_chain = endorsements->ecdsa.tcb_info_issuer_chain,
			.tcb_info_issuer_chain_size =
				endorsements->ecdsa.tcb_info_issuer_chain_size,
			.tcb_info = endorsements->ecdsa.tcb_info,
			.tcb_info_size = endorsements->ecdsa.tcb_info_size,
			.qe_identity_issuer_chain = endorsements->ecdsa.qe_identity_issuer_chain,
			.qe_identity_issuer_chain_size =
				endorsements->ecdsa.qe_identity_issuer_chain_size,
			.qe_identity = endorsements->ecdsa.qe_identity,
			.qe_identity_size = endorsements->ecdsa.qe_identity_size,
		};

		dcap_ret = tdx_qv_verify_quote(evidence->tdx.quote,
					       (uint32_t)(evidence->tdx.quote_len), &collateral,
					       current_time, &collateral_expiration_status,
					       &quote_verification_result, NULL,
					       supplemental_data_size, p_supplemental_data);
	} else {
		dcap_ret = tdx_qv_verify_quote(evidence->tdx.quote,
					       (uint32_t)(evidence->tdx.quote_len), NULL,
					       current_time, &collateral_expiration_status,
					       &quote_verification_result, NULL,
					       supplemental_data_size, p_supplemental_data);
	}
	if (dcap_ret == SGX_QL_SUCCESS) {
		RATS_INFO("tdx qv verifies quote successfully.\n");
	} else {
		RATS_ERR("failed to verify quote by tdx qv: %04x\n", dcap_ret);
		err = (int)quote_verification_result;
		goto errret;
	}

	/* Check verification result */
	switch (quote_verification_result) {
	case SGX_QL_QV_RESULT_OK:
	/* FIXME: currently we deem this as success */
	case SGX_QL_QV_RESULT_OUT_OF_DATE:
		RATS_INFO("verification completed successfully.\n");
		err = RATS_VERIFIER_ERR_NONE;
		break;
	case SGX_QL_QV_RESULT_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
	case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
		RATS_WARN("verification completed with Non-terminal result: %x\n",
			  quote_verification_result);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)quote_verification_result);
		break;
	case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
	case SGX_QL_QV_RESULT_REVOKED:
	case SGX_QL_QV_RESULT_UNSPECIFIED:
	default:
		RATS_WARN("verification completed with Terminal result: %x\n",
			  quote_verification_result);
		err = (int)quote_verification_result;
		break;
	}
errret:
	free(p_supplemental_data);

	return err;
}

#define TDX_CLAIMS_COUNT 4

#define TDX_CLAIM_RTMR0 "rtmr0"
#define TDX_CLAIM_RTMR1 "rtmr1"
#define TDX_CLAIM_RTMR2 "rtmr2"
#define TDX_CLAIM_RTMR3 "rtmr3"

rats_verifier_err_t tdx_parse_claims(tdx_quote_t *quote, claim_t **claims_out,
				     size_t *claims_length_out)
{
	if (!quote || !claims_out || !claims_length_out)
		return RATS_ERR_INVALID_PARAMETER;

	rats_err_t err = RATS_ERR_UNKNOWN;

	size_t claims_index = 0;
	uint64_t claims_size = TDX_CLAIMS_COUNT * sizeof(claim_t);
	claim_t *claims = (claim_t *)malloc(claims_size);
	if (claims == NULL)
		return RATS_ERR_NO_MEM;

	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], TDX_CLAIM_RTMR0,
				      sizeof(TDX_CLAIM_RTMR0), quote->report_body.rtmr[0],
				      sizeof(quote->report_body.rtmr[0])));

	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], TDX_CLAIM_RTMR1,
				      sizeof(TDX_CLAIM_RTMR1), quote->report_body.rtmr[1],
				      sizeof(quote->report_body.rtmr[1])));

	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], TDX_CLAIM_RTMR2,
				      sizeof(TDX_CLAIM_RTMR2), quote->report_body.rtmr[2],
				      sizeof(quote->report_body.rtmr[2])));

	CLAIM_CHECK(librats_add_claim(&claims[claims_index++], TDX_CLAIM_RTMR3,
				      sizeof(TDX_CLAIM_RTMR3), quote->report_body.rtmr[3],
				      sizeof(quote->report_body.rtmr[3])));

	*claims_out = claims;
	*claims_length_out = claims_index;
	claims = NULL;

	err = RATS_VERIFIER_ERR_NONE;

done:
	if (claims)
		free_claims_list(claims, claims_index);

	return err;
}

rats_verifier_err_t tdx_ecdsa_verify_evidence(rats_verifier_ctx_t *ctx,
					      attestation_evidence_t *evidence, const uint8_t *hash,
					      __attribute__((unused)) uint32_t hash_len,
					      __attribute__((unused))
					      attestation_endorsement_t *endorsements,
					      claim_t **claims, size_t *claims_length)
{
	RATS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	rats_verifier_err_t err = RATS_VERIFIER_ERR_UNKNOWN;
	err = ecdsa_verify_evidence(ctx, ctx->opts->name, evidence, sizeof(attestation_evidence_t),
				    hash, hash_len, endorsements);
	if (err != RATS_VERIFIER_ERR_NONE) {
		RATS_ERR("failed to verify ecdsa\n");
		return err;
	}

	err = tdx_parse_claims((tdx_quote_t *)evidence->tdx.quote, claims, claims_length);
	if (err != RATS_VERIFIER_ERR_NONE)
		RATS_ERR("failed to parse tdx claims\n");

	return err;
}
