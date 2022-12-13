/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <librats/log.h>
#include <librats/attester.h>
#include <string.h>
#include <sgx_error.h>
#include <sgx_report.h>
#include "sgx_la.h"

extern sgx_status_t sgx_generate_evidence(sgx_report_data_t *report_data, sgx_report_t *app_report);

/* The local attestation requires to exchange the target info between ISV
 * ratss as the prerequisite. This is out of scope in librats because it
 * requires to establish a out of band channel to do that. Instead, introduce
 * QE as the intermediator. One ISV rats as attester can request the local
 * reports signed by QE and the opposite end of ISV rats as verifier can
 * check the validation of local report through calling sgx_qe_get_attester()
 * which verifies the signed local report. Once getting attester successfully,
 * it presents ISV rats's local report has been fully verified.
 */
rats_attester_err_t sgx_la_collect_evidence(rats_attester_ctx_t *ctx,
					    attestation_evidence_t *evidence, const uint8_t *hash,
					    uint32_t hash_len)
{
	RATS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	sgx_report_data_t report_data;
	if (sizeof(report_data.d) < hash_len) {
		RATS_ERR("hash_len(%zu) shall be smaller than user-data filed size (%zu)\n",
			 hash_len, sizeof(report_data.d));
		return RATS_ATTESTER_ERR_INVALID;
	}
	memset(&report_data, 0, sizeof(sgx_report_data_t));
	memcpy(report_data.d, hash, hash_len);

	sgx_report_t isv_report;
	sgx_status_t generate_evidence_ret;
	generate_evidence_ret = sgx_generate_evidence(&report_data, &isv_report);
	if (generate_evidence_ret != SGX_SUCCESS) {
		RATS_ERR("failed to generate evidence %#x\n", generate_evidence_ret);
		return SGX_LA_ATTESTER_ERR_CODE((int)generate_evidence_ret);
	}

	memcpy(evidence->la.report, &isv_report, sizeof(isv_report));
	evidence->la.report_len = sizeof(isv_report);

	snprintf(evidence->type, sizeof(evidence->type), "%s", "sgx_la");

	return RATS_ATTESTER_ERR_NONE;
}
