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
#include <sgx_quote_4.h>
#include <sgx_quote_5.h>
#include <assert.h>

rats_verifier_err_t check_quote_data_integrity(const uint8_t *p_quote, uint32_t quote_len)
{
	if (quote_len < sizeof(sgx_quote4_header_t)) {
		RATS_ERR("invalid quote: data is truncated.\n");
		return RATS_VERIFIER_ERR_INVALID;
	}
	sgx_quote4_header_t *quote_header = &((sgx_quote4_t *)p_quote)->header;

	if (quote_header->version == 4) {
		if (quote_len < sizeof(sgx_quote4_t)) {
			RATS_ERR("invalid quote: data is truncated.\n");
			return RATS_VERIFIER_ERR_INVALID;
		}
	} else if (quote_header->version == 5) {
		if (quote_len < sizeof(sgx_quote5_t)) {
			RATS_ERR("invalid quote: data is truncated.\n");
			return RATS_VERIFIER_ERR_INVALID;
		}
		sgx_quote5_t *quote = (sgx_quote5_t *)p_quote;
		uint16_t tee_report_type = quote->type;
		if (tee_report_type == 2) { /* quote5 with TDX 1.0 */
			if (quote_len < offsetof(sgx_quote5_t, body) + quote->size ||
			    quote->size < sizeof(sgx_report2_body_t)) {
				RATS_ERR("invalid quote: data is truncated.\n");
				return RATS_VERIFIER_ERR_INVALID;
			}
		} else if (tee_report_type == 3) { /* quote5 with TDX 1.5 */
			if (quote_len < offsetof(sgx_quote5_t, body) + quote->size ||
			    quote->size < sizeof(sgx_report2_body_v1_5_t)) {
				RATS_ERR("invalid quote: data is truncated.\n");
				return RATS_VERIFIER_ERR_INVALID;
			}
		} else {
			RATS_ERR("unsupoorted quote body type %d.\n", tee_report_type);
			return RATS_VERIFIER_ERR_INVALID;
		}
	} else {
		RATS_ERR("unsupoorted quote version %d.\n", quote_header->version);
		return RATS_VERIFIER_ERR_INVALID;
	}

	return RATS_VERIFIER_ERR_NONE;
}

rats_verifier_err_t verify_hash_with_report_data(const uint8_t *p_quote, const uint8_t *hash,
						 uint32_t hash_len)
{
	sgx_quote4_header_t *quote_header = &((sgx_quote4_t *)p_quote)->header;

	/* Determine the version of quote for report data offsets */
	uint8_t *p_report_data = NULL;
	if (quote_header->version == 4) {
		p_report_data = ((sgx_quote4_t *)p_quote)->report_body.report_data.d;
	} else if (quote_header->version == 5) {
		sgx_quote5_t *quote = (sgx_quote5_t *)p_quote;
		uint16_t tee_report_type = quote->type;
		if (tee_report_type == 2) { /* quote5 with TDX 1.0 */
			sgx_report2_body_t *report_body = (sgx_report2_body_t *)quote->body;
			p_report_data = report_body->report_data.d;
		} else if (tee_report_type == 3) { /* quote5 with TDX 1.5 */
			sgx_report2_body_v1_5_t *report_body =
				(sgx_report2_body_v1_5_t *)quote->body;
			p_report_data = report_body->report_data.d;
		} else {
			RATS_ERR("unsupoorted quote body type %d.\n", tee_report_type);
			return RATS_VERIFIER_ERR_INVALID;
		}
	} else {
		RATS_ERR("unsupoorted quote version %d.\n", quote_header->version);
		return RATS_VERIFIER_ERR_INVALID;
	}

	/* Compare hash string */
	if (memcmp(hash, p_report_data, hash_len) != 0) {
		RATS_ERR("unmatched hash value in evidence.\n");
		return RATS_VERIFIER_ERR_INVALID;
	}

	return RATS_VERIFIER_ERR_NONE;
}

rats_verifier_err_t ecdsa_verify_evidence(__attribute__((unused)) rats_verifier_ctx_t *ctx,
					  const char *name, attestation_evidence_t *evidence,
					  __attribute__((unused)) uint32_t evidence_len,
					  const uint8_t *hash, uint32_t hash_len,
					  attestation_endorsement_t *endorsements)
{
	rats_verifier_err_t err = RATS_VERIFIER_ERR_UNKNOWN;

	/* The quote may from untrusted source, and we need to check integrity of quote data. */
	err = check_quote_data_integrity(evidence->tdx.quote, evidence->tdx.quote_len);
	if (err != RATS_VERIFIER_ERR_NONE) {
		return err;
	}

	/* Verify the hash value */
	err = verify_hash_with_report_data(evidence->tdx.quote, hash, hash_len);
	if (err != RATS_VERIFIER_ERR_NONE) {
		return err;
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

rats_verifier_err_t convert_quote_to_claims(uint8_t *p_quote, uint32_t quote_size,
					    claim_t **claims_out, size_t *claims_length_out)
{
	if (!claims_out || !claims_length_out)
		return RATS_VERIFIER_ERR_NONE;
	if (!p_quote || !quote_size)
		return RATS_VERIFIER_ERR_INVALID_PARAMETER;

	claim_t *claims = NULL;
	size_t claims_length = 0;
	rats_verifier_err_t err = RATS_VERIFIER_ERR_UNKNOWN;

	/* Determine the version of quote for report data offsets */
	sgx_report2_body_t *report2_body = NULL;
	sgx_report2_body_v1_5_t *report2_body_v1_5 = NULL;

	sgx_quote4_header_t *quote_header = &((sgx_quote4_t *)p_quote)->header;
	if (quote_header->version == 4) {
		report2_body = &((sgx_quote4_t *)p_quote)->report_body;
	} else if (quote_header->version == 5) {
		sgx_quote5_t *quote = (sgx_quote5_t *)p_quote;
		uint16_t tee_report_type = quote->type;
		if (tee_report_type == 2) { /* quote5 with TDX 1.0 */
			report2_body = (sgx_report2_body_t *)quote->body;
		} else if (tee_report_type == 3) { /* quote5 with TDX 1.5 */
			report2_body_v1_5 = (sgx_report2_body_v1_5_t *)quote->body;
		} else {
			RATS_ERR("unsupoorted quote body type %d.\n", tee_report_type);
			return RATS_VERIFIER_ERR_INVALID;
		}
	} else {
		RATS_ERR("unsupoorted quote version %d.\n", quote_header->version);
		return RATS_VERIFIER_ERR_INVALID;
	}

	size_t claims_index = 0;
	if (report2_body != NULL) {
		claims_length = 2 + 14; /* 2 common claims + 14 tdx claims */
		claims = malloc(sizeof(claim_t) * claims_length);
		if (claims == NULL)
			return RATS_VERIFIER_ERR_NO_MEM;

		/* common claims */
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_COMMON_QUOTE,
					      p_quote, quote_size));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++],
					      BUILT_IN_CLAIM_COMMON_QUOTE_TYPE, "tdx_ecdsa",
					      sizeof("tdx_ecdsa")));

		/* tdx claims */
		CLAIM_CHECK(librats_add_claim(
			&claims[claims_index++], BUILT_IN_CLAIM_TDX_TEE_TCB_SVN,
			(uint8_t *)&report2_body->tee_tcb_svn, sizeof(report2_body->tee_tcb_svn)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_TDX_MR_SEAM,
					      (uint8_t *)&report2_body->mr_seam,
					      sizeof(report2_body->mr_seam)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++],
					      BUILT_IN_CLAIM_TDX_MRSIGNER_SEAM,
					      (uint8_t *)&report2_body->mrsigner_seam,
					      sizeof(report2_body->mrsigner_seam)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++],
					      BUILT_IN_CLAIM_TDX_SEAM_ATTRIBUTES,
					      (uint8_t *)&report2_body->seam_attributes,
					      sizeof(report2_body->seam_attributes)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++],
					      BUILT_IN_CLAIM_TDX_TD_ATTRIBUTES,
					      (uint8_t *)&report2_body->td_attributes,
					      sizeof(report2_body->td_attributes)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_TDX_XFAM,
					      (uint8_t *)&report2_body->xfam,
					      sizeof(report2_body->xfam)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_TDX_MR_TD,
					      (uint8_t *)&report2_body->mr_td,
					      sizeof(report2_body->mr_td)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++],
					      BUILT_IN_CLAIM_TDX_MR_CONFIG_ID,
					      (uint8_t *)&report2_body->mr_config_id,
					      sizeof(report2_body->mr_config_id)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_TDX_MR_OWNER,
					      (uint8_t *)&report2_body->mr_owner,
					      sizeof(report2_body->mr_owner)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++],
					      BUILT_IN_CLAIM_TDX_MR_OWNER_CONFIG,
					      (uint8_t *)&report2_body->mr_owner_config,
					      sizeof(report2_body->mr_owner_config)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_TDX_RT_MR0,
					      (uint8_t *)&report2_body->rt_mr[0],
					      sizeof(report2_body->rt_mr[0])));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_TDX_RT_MR1,
					      (uint8_t *)&report2_body->rt_mr[1],
					      sizeof(report2_body->rt_mr[1])));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_TDX_RT_MR2,
					      (uint8_t *)&report2_body->rt_mr[2],
					      sizeof(report2_body->rt_mr[2])));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_TDX_RT_MR3,
					      (uint8_t *)&report2_body->rt_mr[3],
					      sizeof(report2_body->rt_mr[3])));

		assert(claims_index == claims_length && "bug detected");

	} else if (report2_body_v1_5 != NULL) {
		claims_length = 2 + 16; /* 2 common claims + 16 tdx claims */
		claims = malloc(sizeof(claim_t) * claims_length);
		if (claims == NULL)
			return RATS_VERIFIER_ERR_NO_MEM;

		/* common claims */
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_COMMON_QUOTE,
					      p_quote, quote_size));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++],
					      BUILT_IN_CLAIM_COMMON_QUOTE_TYPE, "tdx_ecdsa",
					      sizeof("tdx_ecdsa")));

		/* tdx claims */
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++],
					      BUILT_IN_CLAIM_TDX_TEE_TCB_SVN,
					      (uint8_t *)&report2_body_v1_5->tee_tcb_svn,
					      sizeof(report2_body_v1_5->tee_tcb_svn)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_TDX_MR_SEAM,
					      (uint8_t *)&report2_body_v1_5->mr_seam,
					      sizeof(report2_body_v1_5->mr_seam)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++],
					      BUILT_IN_CLAIM_TDX_MRSIGNER_SEAM,
					      (uint8_t *)&report2_body_v1_5->mrsigner_seam,
					      sizeof(report2_body_v1_5->mrsigner_seam)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++],
					      BUILT_IN_CLAIM_TDX_SEAM_ATTRIBUTES,
					      (uint8_t *)&report2_body_v1_5->seam_attributes,
					      sizeof(report2_body_v1_5->seam_attributes)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++],
					      BUILT_IN_CLAIM_TDX_TD_ATTRIBUTES,
					      (uint8_t *)&report2_body_v1_5->td_attributes,
					      sizeof(report2_body_v1_5->td_attributes)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_TDX_XFAM,
					      (uint8_t *)&report2_body_v1_5->xfam,
					      sizeof(report2_body_v1_5->xfam)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_TDX_MR_TD,
					      (uint8_t *)&report2_body_v1_5->mr_td,
					      sizeof(report2_body_v1_5->mr_td)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++],
					      BUILT_IN_CLAIM_TDX_MR_CONFIG_ID,
					      (uint8_t *)&report2_body_v1_5->mr_config_id,
					      sizeof(report2_body_v1_5->mr_config_id)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_TDX_MR_OWNER,
					      (uint8_t *)&report2_body_v1_5->mr_owner,
					      sizeof(report2_body_v1_5->mr_owner)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++],
					      BUILT_IN_CLAIM_TDX_MR_OWNER_CONFIG,
					      (uint8_t *)&report2_body_v1_5->mr_owner_config,
					      sizeof(report2_body_v1_5->mr_owner_config)));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_TDX_RT_MR0,
					      (uint8_t *)&report2_body_v1_5->rt_mr[0],
					      sizeof(report2_body_v1_5->rt_mr[0])));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_TDX_RT_MR1,
					      (uint8_t *)&report2_body_v1_5->rt_mr[1],
					      sizeof(report2_body_v1_5->rt_mr[1])));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_TDX_RT_MR2,
					      (uint8_t *)&report2_body_v1_5->rt_mr[2],
					      sizeof(report2_body_v1_5->rt_mr[2])));
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++], BUILT_IN_CLAIM_TDX_RT_MR3,
					      (uint8_t *)&report2_body_v1_5->rt_mr[3],
					      sizeof(report2_body_v1_5->rt_mr[3])));
		/* for TDX 1.5 only */
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++],
					      BUILT_IN_CLAIM_TDX_TEE_TCB_SVN2,
					      (uint8_t *)&report2_body_v1_5->tee_tcb_svn2,
					      sizeof(report2_body_v1_5->tee_tcb_svn2)));
		/* for TDX 1.5 only */
		CLAIM_CHECK(librats_add_claim(&claims[claims_index++],
					      BUILT_IN_CLAIM_TDX_MR_SERVICETD,
					      (uint8_t *)&report2_body_v1_5->mr_servicetd,
					      sizeof(report2_body_v1_5->mr_servicetd)));

		assert(claims_index == claims_length && "bug detected");
	} else {
		assert(0 && "This code should not be reached");
	}

	*claims_out = claims;
	*claims_length_out = claims_length;
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

	if (err == RATS_VERIFIER_ERR_NONE) {
		err = convert_quote_to_claims(evidence->tdx.quote, evidence->tdx.quote_len, claims,
					      claims_length);
		if (err != RATS_VERIFIER_ERR_NONE)
			RATS_ERR("failed to convert tdx_ecdsa quote to builtin claims: %#x\n", err);
	}
	return err;
}
