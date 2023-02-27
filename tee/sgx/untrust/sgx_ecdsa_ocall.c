/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <string.h>
#include <librats/log.h>
#include <librats/attester.h>
#include <librats/verifier.h>
#include <sgx_urts.h>
#include <sgx_quote.h>
#include <sgx_quote_3.h>
#include <sgx_ql_quote.h>
#include <sgx_dcap_quoteverify.h>
#include <sgx_dcap_ql_wrapper.h>
#include "sgx_ecdsa.h"
#include "rats_u.h"

rats_log_level_t rats_global_log_level = RATS_LOG_LEVEL_DEFAULT;

static void get_random_nonce(uint8_t *nonce, uint32_t size)
{
	for (uint32_t i = 0; i < size; i++)
		nonce[i] = (uint8_t)((rand() % 255) + 1);
}

void rats_ocall_get_target_info(sgx_target_info_t *qe_target_info)
{
	int qe3_ret = sgx_qe_get_target_info(qe_target_info);
	if (SGX_QL_SUCCESS != qe3_ret)
		RATS_ERR("sgx_qe_get_target_info() with error code 0x%04x\n", qe3_ret);
}

rats_attester_err_t rats_ocall_qe_get_quote_size(uint32_t *quote_size)
{
	quote3_error_t qe3_ret = sgx_qe_get_quote_size(quote_size);
	if (SGX_QL_SUCCESS != qe3_ret) {
		RATS_ERR("sgx_qe_get_quote_size(): 0x%04x\n", qe3_ret);
		return SGX_ECDSA_ATTESTER_ERR_CODE((int)qe3_ret);
	}

	return RATS_ATTESTER_ERR_NONE;
}

rats_attester_err_t rats_ocall_qe_get_quote(sgx_report_t *report, uint32_t quote_size,
					    uint8_t *quote)
{
	quote3_error_t qe3_ret = sgx_qe_get_quote(report, quote_size, quote);
	if (SGX_QL_SUCCESS != qe3_ret) {
		RATS_ERR("sgx_qe_get_quote(): 0x%04x\n", qe3_ret);
		return SGX_ECDSA_ATTESTER_ERR_CODE((int)qe3_ret);
	}

	return RATS_ATTESTER_ERR_NONE;
}

rats_verifier_err_t rats_ocall_ecdsa_verify_evidence(
	__attribute__((unused)) rats_verifier_ctx_t *ctx, sgx_enclave_id_t enclave_id,
	const char *name, sgx_quote3_t *pquote, uint32_t quote_size, uint32_t collateral_version,
	char *collateral_pck_crl_issuer_chain, uint32_t collateral_pck_crl_issuer_chain_size,
	char *collateral_root_ca_crl, uint32_t collateral_root_ca_crl_size,
	char *collateral_pck_crl, uint32_t collateral_pck_crl_size,
	char *collateral_tcb_info_issuer_chain, uint32_t collateral_tcb_info_issuer_chain_size,
	char *collateral_tcb_info, uint32_t collateral_tcb_info_size,
	char *collateral_qe_identity_issuer_chain,
	uint32_t collateral_qe_identity_issuer_chain_size, char *collateral_qe_identity,
	uint32_t collateral_qe_identity_size)
{
	rats_verifier_err_t err = RATS_VERIFIER_ERR_UNKNOWN;
	uint32_t supplemental_data_size = 0;
	uint8_t *p_supplemental_data = NULL;
	sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
	uint32_t collateral_expiration_status = 1;
	time_t current_time = 0;
	sgx_isv_svn_t qve_isvsvn_threshold = 3;
	sgx_status_t sgx_ret = SGX_SUCCESS;
	quote3_error_t verify_qveid_ret = SGX_QL_ERROR_UNEXPECTED;
	quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
	sgx_ql_qe_report_info_t *qve_report_info = NULL;
	uint8_t rand_nonce[16];

	/* sgx_ecdsa_qve instance re-uses this code and thus we need to distinguish
	 * it from sgx_ecdsa instance.
	 */
	if (!strcmp(name, "sgx_ecdsa_qve")) {
		qve_report_info =
			(sgx_ql_qe_report_info_t *)malloc(sizeof(sgx_ql_qe_report_info_t));
		if (!qve_report_info) {
			RATS_ERR("failed to malloc qve report info.\n");
			goto errout;
		}
		get_random_nonce(rand_nonce, sizeof(rand_nonce));
		memcpy(qve_report_info->nonce.rand, rand_nonce, sizeof(rand_nonce));

		sgx_status_t get_target_info_ret;
		sgx_ret = rats_ecall_get_target_info(enclave_id, &get_target_info_ret,
						     &qve_report_info->app_enclave_target_info);
		if (sgx_ret != SGX_SUCCESS || get_target_info_ret != SGX_SUCCESS) {
			RATS_ERR(
				"failed to get target info sgx_ret and get_target_info_ret. %04x, %04x\n",
				sgx_ret, get_target_info_ret);
			err = SGX_ECDSA_VERIFIER_ERR_CODE((int)get_target_info_ret);
			goto errout;
		} else
			RATS_INFO("get target info successfully.\n");

		dcap_ret = sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
		if (dcap_ret == SGX_QL_SUCCESS)
			RATS_INFO("sgx qv setting for enclave load policy succeeds.\n");
		else {
			RATS_ERR("failed to set enclave load policy by sgx qv: %04x\n", dcap_ret);
			err = SGX_ECDSA_VERIFIER_ERR_CODE((int)dcap_ret);
			goto errout;
		}
	}

	dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
	if (dcap_ret == SGX_QL_SUCCESS) {
		RATS_INFO("sgx qv gets quote supplemental data size successfully.\n");
		p_supplemental_data = (uint8_t *)malloc(supplemental_data_size);
		if (!p_supplemental_data) {
			RATS_ERR("failed to malloc supplemental data space.\n");
			err = RATS_VERIFIER_ERR_NO_MEM;
			goto errout;
		}
	} else {
		RATS_ERR("failed to get quote supplemental data size by sgx qv: %04x\n", dcap_ret);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)dcap_ret);
		goto errout;
	}

	current_time = time(NULL);

	if (collateral_pck_crl_issuer_chain && collateral_root_ca_crl && collateral_pck_crl &&
	    collateral_tcb_info_issuer_chain && collateral_tcb_info &&
	    collateral_qe_identity_issuer_chain && collateral_qe_identity) {
		sgx_ql_qve_collateral_t collateral = {
			.version = collateral_version,
			.tee_type = 0x00000000, /* SGX */
			.pck_crl_issuer_chain = collateral_pck_crl_issuer_chain,
			.pck_crl_issuer_chain_size = collateral_pck_crl_issuer_chain_size,
			.root_ca_crl = collateral_root_ca_crl,
			.root_ca_crl_size = collateral_root_ca_crl_size,
			.pck_crl = collateral_pck_crl,
			.pck_crl_size = collateral_pck_crl_size,
			.tcb_info_issuer_chain = collateral_tcb_info_issuer_chain,
			.tcb_info_issuer_chain_size = collateral_tcb_info_issuer_chain_size,
			.tcb_info = collateral_tcb_info,
			.tcb_info_size = collateral_tcb_info_size,
			.qe_identity_issuer_chain = collateral_qe_identity_issuer_chain,
			.qe_identity_issuer_chain_size = collateral_qe_identity_issuer_chain_size,
			.qe_identity = collateral_qe_identity,
			.qe_identity_size = collateral_qe_identity_size,
		};

		dcap_ret = sgx_qv_verify_quote((uint8_t *)pquote, (uint32_t)quote_size, &collateral,
					       current_time, &collateral_expiration_status,
					       &quote_verification_result, qve_report_info,
					       supplemental_data_size, p_supplemental_data);
	} else {
		dcap_ret = sgx_qv_verify_quote((uint8_t *)pquote, (uint32_t)quote_size, NULL,
					       current_time, &collateral_expiration_status,
					       &quote_verification_result, qve_report_info,
					       supplemental_data_size, p_supplemental_data);
	}
	if (dcap_ret == SGX_QL_SUCCESS)
		RATS_INFO("sgx qv verifies quote successfully.\n");
	else {
		RATS_ERR("failed to verify quote by sgx qv: %04x\n", dcap_ret);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)dcap_ret);
		goto errret;
	}

	if (!strcmp(name, "sgx_ecdsa_qve")) {
		sgx_ret = sgx_tvl_verify_qve_report_and_identity(
			enclave_id, &verify_qveid_ret, (uint8_t *)pquote, (uint32_t)quote_size,
			qve_report_info, current_time, collateral_expiration_status,
			quote_verification_result, p_supplemental_data, supplemental_data_size,
			qve_isvsvn_threshold);
		if (sgx_ret != SGX_SUCCESS || verify_qveid_ret != SGX_QL_SUCCESS) {
			RATS_ERR("verify QvE report and identity failed. %04x\n", verify_qveid_ret);
			err = SGX_ECDSA_VERIFIER_ERR_CODE((int)verify_qveid_ret);
			goto errret;
		} else
			RATS_INFO("verify QvE report and identity successfully.\n");

		if (qve_report_info) {
			if (memcmp(qve_report_info->nonce.rand, rand_nonce, sizeof(rand_nonce)) !=
			    0) {
				RATS_ERR(
					"nonce during SGX quote verification has been tampered with.\n");
				err = RATS_VERIFIER_ERR_INVALID;
				goto errret;
			}
		}
	}

	/* Check verification result */
	switch (quote_verification_result) {
	case SGX_QL_QV_RESULT_OK:
		RATS_INFO("verification completed successfully.\n");
		err = RATS_VERIFIER_ERR_NONE;
		break;
	case SGX_QL_QV_RESULT_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_OUT_OF_DATE:
	case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
	case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
	case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
		RATS_ERR("verification completed with Non-terminal result: %x\n",
			 quote_verification_result);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)quote_verification_result);
		break;
	case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
	case SGX_QL_QV_RESULT_REVOKED:
	case SGX_QL_QV_RESULT_UNSPECIFIED:
	default:
		RATS_ERR("verification completed with Terminal result: %x\n",
			 quote_verification_result);
		err = SGX_ECDSA_VERIFIER_ERR_CODE((int)quote_verification_result);
		break;
	}

errret:
	free(p_supplemental_data);
errout:
	free(qve_report_info);

	return err;
}

rats_attester_err_t
rats_ocall_tee_qv_get_collateral(const uint8_t *pquote /* in */, uint32_t quote_size /* in */,
				 uint8_t **pp_quote_collateral_untrusted /* out */)
{
	uint32_t collateral_size;
	quote3_error_t qv_ret = tee_qv_get_collateral(
		pquote, quote_size, pp_quote_collateral_untrusted, &collateral_size);
	if (SGX_QL_SUCCESS != qv_ret) {
		RATS_ERR("tee_qv_get_collateral(): 0x%04x\n", qv_ret);
		return SGX_ECDSA_ATTESTER_ERR_CODE((int)qv_ret);
	}
	return RATS_ATTESTER_ERR_NONE;
}

rats_attester_err_t
rats_ocall_tee_qv_free_collateral(uint8_t *p_quote_collateral_untrusted /* user_check */)
{
	quote3_error_t qv_ret = tee_qv_free_collateral(p_quote_collateral_untrusted);
	if (SGX_QL_SUCCESS != qv_ret) {
		RATS_ERR("tee_qv_free_collateral(): 0x%04x\n", qv_ret);
		return SGX_ECDSA_ATTESTER_ERR_CODE((int)qv_ret);
	}
	return RATS_ATTESTER_ERR_NONE;
}
