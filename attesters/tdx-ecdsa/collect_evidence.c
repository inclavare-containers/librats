/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <unistd.h>
#include <librats/log.h>
#include <librats/attester.h>
#include <stddef.h>
#include "../../verifiers/tdx-ecdsa/tdx-ecdsa.h"

#define VSOCK

// clang-format off
#ifdef VSOCK
  #include <stdlib.h>
  #include <stdio.h>
  #include <stdint.h>
  #include <time.h>
  #include <tdx_attest.h>
#endif
// clang-format on

static int tdx_get_report(const tdx_report_data_t *report_data, tdx_report_t *tdx_report)
{
	/* Get report by tdcall */
	if (tdx_att_get_report(report_data, tdx_report) != TDX_ATTEST_SUCCESS) {
		RATS_ERR("failed to ioctl get tdx report data.\n");
		return -1;
	}

	return 0;
}

static int tdx_gen_quote(const uint8_t *hash, uint32_t hash_len, uint8_t *quote_buf,
			 uint32_t *quote_size)
{
	if (hash == NULL) {
		RATS_ERR("empty hash pointer.\n");
		return -1;
	}

	tdx_report_t tdx_report = { { 0 } };
	tdx_report_data_t report_data = { { 0 } };
	if (sizeof(report_data.d) < hash_len) {
		RATS_ERR("hash_len(%u) shall be smaller than user-data filed size (%zu)\n",
			 hash_len, sizeof(report_data.d));
		return -1;
	}
	memcpy(report_data.d, hash, hash_len);
	int ret = tdx_get_report(&report_data, &tdx_report);
	if (ret != 0) {
		RATS_ERR("failed to get tdx report.\n");
		return -1;
	}

#ifdef VSOCK
	tdx_uuid_t selected_att_key_id = { { 0 } };
	uint8_t *p_quote = NULL;
	uint32_t p_quote_size = 0;
	if (tdx_att_get_quote(&report_data, NULL, 0, &selected_att_key_id, &p_quote, &p_quote_size,
			      0) != TDX_ATTEST_SUCCESS) {
		RATS_ERR("failed to get tdx quote.\n");
		return -1;
	}

	if (p_quote_size > *quote_size) {
		RATS_ERR("quote buffer is too small.\n");
		tdx_att_free_quote(p_quote);
		return -1;
	}

	memcpy(quote_buf, p_quote, p_quote_size);
	*quote_size = p_quote_size;
	tdx_att_free_quote(p_quote);
#else
	/* This branch is for getting quote size and quote by tdcall,
	 * it depends on the implemetation in qemu.
	 */
	#error "using tdcall to retrieve TD quote is still not supported!"
#endif

	return 0;
}

rats_attester_err_t tdx_ecdsa_collect_evidence(rats_attester_ctx_t *ctx,
					       attestation_evidence_t *evidence,
					       const uint8_t *hash, uint32_t hash_len)
{
	RATS_DEBUG("ctx %p, evidence %p, hash %p, hash_len: %u\n", ctx, evidence, hash, hash_len);

	evidence->tdx.quote_len = sizeof(evidence->tdx.quote);
	if (tdx_gen_quote(hash, hash_len, evidence->tdx.quote, &evidence->tdx.quote_len)) {
		RATS_ERR("failed to generate quote\n");
		return RATS_ATTESTER_ERR_INVALID;
	}

	RATS_DEBUG("Succeed to generate the quote!\n");

	/* Essentially speaking, QGS generates the same
	 * format of quote as sgx_ecdsa.
	 */
	snprintf(evidence->type, sizeof(evidence->type), "tdx_ecdsa");

	RATS_DEBUG("ctx %p, evidence %p, quote_size %u\n", ctx, evidence, evidence->tdx.quote_len);

	return RATS_ATTESTER_ERR_NONE;
}
