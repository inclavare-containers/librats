/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
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

#define TDEL_INFO "/sys/firmware/acpi/tables/TDEL"
#define TDEL_DATA "/sys/firmware/acpi/tables/data/TDEL"

static int tdx_get_report(const tdx_report_data_t *report_data, tdx_report_t *tdx_report)
{
	/* Get report by tdcall */
	if (tdx_att_get_report(report_data, tdx_report) != TDX_ATTEST_SUCCESS) {
		RATS_ERR("failed to ioctl get tdx report data.\n");
		return -1;
	}

	return 0;
}

rats_attester_err_t tdx_get_tdel_info(rats_attester_ctx_t *ctx,
                                      attestation_evidence_t *evidence,
                                      int *tdel_info_len)
{
	RATS_DEBUG("ctx %p, evidence %p\n", ctx, evidence);

	int fd = open(TDEL_INFO, O_RDONLY);
	if (fd < 0) {
	        RATS_INFO("failed to open TDEL info device\n");
	        /* TDEL is optional */
	        return RATS_ATTESTER_ERR_NONE;
	}

	unsigned char tdel_info[TDEL_INFO_SZ];
	int tdel_info_sz = read(fd, tdel_info, sizeof(tdel_info));
	if (tdel_info_sz != sizeof(tdel_info)) {
	        close(fd);
	        RATS_INFO("failed to read TDEL info\n");
	        return -RATS_ATTESTER_ERR_INVALID;
	}

	*tdel_info_len = tdel_info_sz;
	memcpy(&(evidence->tdx.quote[TDX_ECDSA_QUOTE_SZ]), tdel_info, tdel_info_sz);

	close(fd);

	RATS_DEBUG("TDEL info size %d-byte\n", tdel_info_sz);

	return RATS_ATTESTER_ERR_NONE;
}

rats_attester_err_t tdx_get_tdel_data(rats_attester_ctx_t *ctx,
				      attestation_evidence_t *evidence,
                                      int *tdel_data_len)
{
	RATS_DEBUG("ctx %p, evidence %p\n", ctx, evidence);

	int fd = open(TDEL_DATA, O_RDONLY);
	if (fd < 0) {
	        RATS_ERR("failed to open TDEL info device\n");
	        return -RATS_ATTESTER_ERR_INVALID;
	}


	unsigned char tdel_data[TDEL_DATA_SZ];
	int tdel_data_sz = read(fd, tdel_data, sizeof(tdel_data));
	if (tdel_data_sz <= 0) {
	        close(fd);
	        RATS_INFO("failed to read TDEL data\n");
	        return -RATS_ATTESTER_ERR_INVALID;
	}

	if (tdel_data_sz == sizeof(tdel_data))
	        RATS_WARN("TDEL data buffer (%d-byte) may be too small\n", sizeof(tdel_data));

	*tdel_data_len = tdel_data_sz;
	memcpy(&(evidence->tdx.quote[TDX_ECDSA_QUOTE_SZ + TDEL_INFO_SZ]), tdel_data, tdel_data_sz);

	close(fd);

	RATS_DEBUG("TDEL data size %d-byte\n", tdel_data_sz);

	return RATS_ATTESTER_ERR_NONE;
}

static int tdx_gen_quote(const uint8_t *hash, uint8_t *quote_buf, uint32_t *quote_size)
{
	if (hash == NULL) {
		RATS_ERR("empty hash pointer.\n");
		return -1;
	}

	tdx_report_t tdx_report = { { 0 } };
	tdx_report_data_t report_data = { { 0 } };
	assert(sizeof(report_data.d) >= SHA256_HASH_SIZE);
	memcpy(report_data.d, hash, SHA256_HASH_SIZE);
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
					       const uint8_t *hash,
					       __attribute__((unused)) uint32_t hash_len)
{
	RATS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	evidence->tdx.quote_len = sizeof(evidence->tdx.quote);
	if (tdx_gen_quote(hash, evidence->tdx.quote, &evidence->tdx.quote_len)) {
		RATS_ERR("failed to generate quote\n");
		return RATS_ATTESTER_ERR_INVALID;
	}

	RATS_DEBUG("Succeed to generate the quote!\n");

    int tdel_info_len = 0;
    if (tdx_get_tdel_info(ctx, evidence, &tdel_info_len) != RATS_ATTESTER_ERR_NONE)
            return -RATS_ATTESTER_ERR_INVALID;

    /* TDEL information is optional */
    int tdel_data_len = 0;
    if (tdel_info_len && tdx_get_tdel_data(ctx, evidence, &tdel_data_len) != RATS_ATTESTER_ERR_NONE)
            return -RATS_ATTESTER_ERR_INVALID;

	/* Essentially speaking, QGS generates the same
	 * format of quote as sgx_ecdsa.
	 */
	snprintf(evidence->type, sizeof(evidence->type), "tdx_ecdsa");
    evidence->tdx.tdel_info_len = tdel_info_len;
    evidence->tdx.tdel_data_len = tdel_data_len;

	RATS_DEBUG("ctx %p, evidence %p, quote_size %u\n", ctx, evidence, evidence->tdx.quote_len);

	return RATS_ATTESTER_ERR_NONE;
}
