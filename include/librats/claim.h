/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _LIBRATS_CLAIM_H_
#define _LIBRATS_CLAIM_H_

#include <stddef.h>
#include <stdint.h>
#include <librats/err.h>
#include <librats/log.h>

/* Common built-in claims */
#define BUILT_IN_CLAIM_COMMON_QUOTE	 "common_quote"
#define BUILT_IN_CLAIM_COMMON_QUOTE_TYPE "common_quote_type"

/* SGX built-in claims */
/* Refer to: https://github.com/intel/linux-sgx/blob/a1eeccba5a72b3b9b342569d2cc469ece106d3e9/common/inc/sgx_report.h#L93-L111 */
/* Security Version of the CPU */
#define BUILT_IN_CLAIM_SGX_CPU_SVN "sgx_cpu_svn"
/* ISV assigned Extended Product ID */
#define BUILT_IN_CLAIM_SGX_ISV_EXT_PROD_ID "sgx_isv_ext_prod_id"
/* Any special Capabilities the Enclave possess */
#define BUILT_IN_CLAIM_SGX_ATTRIBUTES "sgx_attributes"
/* The value of the enclave's ENCLAVE measurement */
#define BUILT_IN_CLAIM_SGX_MR_ENCLAVE "sgx_mr_enclave"
/* The value of the enclave's SIGNER measurement */
#define BUILT_IN_CLAIM_SGX_MR_SIGNER "sgx_mr_signer"
/* CONFIGID */
#define BUILT_IN_CLAIM_SGX_CONFIG_ID "sgx_config_id"
/* Product ID of the Enclave */
#define BUILT_IN_CLAIM_SGX_ISV_PROD_ID "sgx_isv_prod_id"
/* Security Version of the Enclave */
#define BUILT_IN_CLAIM_SGX_ISV_SVN "sgx_isv_svn"
/* CONFIGSVN */
#define BUILT_IN_CLAIM_SGX_CONFIG_SVN "sgx_config_svn"
/* ISV assigned Family ID */
#define BUILT_IN_CLAIM_SGX_ISV_FAMILY_ID "sgx_isv_family_id"

/* TDX built-in claims */
/* Refer to: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/cd27223301e7c2bc80c9c5084ad6f5c2b9d24f5c/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_4.h#L123-L137 */
/* TEE_TCB_SVN Array */
#define BUILT_IN_CLAIM_TDX_TEE_TCB_SVN "tdx_tee_tcb_svn"
/* Measurement of the SEAM module */
#define BUILT_IN_CLAIM_TDX_MR_SEAM "tdx_mr_seam"
/* Measurement of a 3rd party SEAM module’s signer (SHA384 hash). The value is 0’ed for Intel SEAM module */
#define BUILT_IN_CLAIM_TDX_MRSIGNER_SEAM "tdx_mrsigner_seam"
/* MBZ: TDX 1.0 */
#define BUILT_IN_CLAIM_TDX_SEAM_ATTRIBUTES "tdx_seam_attributes"
/* TD's attributes */
#define BUILT_IN_CLAIM_TDX_TD_ATTRIBUTES "tdx_td_attributes"
/* TD's XFAM */
#define BUILT_IN_CLAIM_TDX_XFAM "tdx_xfam"
/* Measurement of the initial contents of the TD */
#define BUILT_IN_CLAIM_TDX_MR_TD "tdx_mr_td"
/* Software defined ID for non-owner-defined configuration on the guest TD. e.g., runtime or OS configuration */
#define BUILT_IN_CLAIM_TDX_MR_CONFIG_ID "tdx_mr_config_id"
/* Software defined ID for the guest TD's owner */
#define BUILT_IN_CLAIM_TDX_MR_OWNER "tdx_mr_owner"
/* Software defined ID for owner-defined configuration of the guest TD, e.g., specific to the workload rather than the runtime or OS */
#define BUILT_IN_CLAIM_TDX_MR_OWNER_CONFIG "tdx_mr_owner_config"
/* Array of 4(TDX1: NUM_RTMRS is 4) runtime extendable measurement registers */
#define BUILT_IN_CLAIM_TDX_RT_MR0 "tdx_rt_mr0"
#define BUILT_IN_CLAIM_TDX_RT_MR1 "tdx_rt_mr1"
#define BUILT_IN_CLAIM_TDX_RT_MR2 "tdx_rt_mr2"
#define BUILT_IN_CLAIM_TDX_RT_MR3 "tdx_rt_mr3"

/* TDX built-in claims, for TDX 1.5 only */
/* Refer to: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/cd27223301e7c2bc80c9c5084ad6f5c2b9d24f5c/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_5.h#L99-L100 */
/* Array of TEE TCB SVNs (for TD preserving). */
#define BUILT_IN_CLAIM_TDX_TEE_TCB_SVN2 "tdx_tee_tcb_svn2"
/* If is one or more bound or pre-bound service TDs, SERVTD_HASH is the SHA384 hash of the TDINFO_STRUCTs of those service TDs bound. */
#define BUILT_IN_CLAIM_TDX_MR_SERVICETD "tdx_mr_servicetd"


/* sev-snp built-in claims */
#define BUILT_IN_CLAIM_SEV_SNP_GUEST_SVN     "sev_snp_guest_svn" /* 0x004 */
#define BUILT_IN_CLAIM_SEV_SNP_POLICY	     "sev_snp_policy" /* 0x008 */
#define BUILT_IN_CLAIM_SEV_SNP_FAMILY_ID     "sev_snp_family_id" /* 0x010 */
#define BUILT_IN_CLAIM_SEV_SNP_IMAGE_ID	     "sev_snp_image_id" /* 0x020 */
#define BUILT_IN_CLAIM_SEV_SNP_VMPL	     "sev_snp_vmpl" /* 0x030 */
#define BUILT_IN_CLAIM_SEV_SNP_CURRENT_TCB   "sev_snp_current_tcb" /* 0x038 */
#define BUILT_IN_CLAIM_SEV_SNP_PLATFORM_INFO "sev_snp_platform_info" /* 0x040 */
#define BUILT_IN_CLAIM_SEV_SNP_MEASUREMENT   "sev_snp_measurement" /* 0x090 */
#define BUILT_IN_CLAIM_SEV_SNP_HOST_DATA     "sev_snp_host_data" /* 0x0C0 */
#define BUILT_IN_CLAIM_SEV_SNP_ID_KEY_DIGEST "sev_snp_id_key_digest" /* 0x0E0 */
#define BUILT_IN_CLAIM_SEV_SNP_REPORT_ID     "sev_snp_report_id" /* 0x140 */
#define BUILT_IN_CLAIM_SEV_SNP_REPORT_ID_MA  "sev_snp_report_id_ma" /* 0x160 */
#define BUILT_IN_CLAIM_SEV_SNP_REPORTED_TCB  "sev_snp_reported_tcb" /* 0x180 */
#define BUILT_IN_CLAIM_SEV_SNP_CHIP_ID	     "sev_snp_chip_id" /* 0x1A0 */

/* csv built-in claims */
#define BUILT_IN_CLAIM_CSV_USER_PUBKEY_DIGEST "csv_user_pubkey_digest"
#define BUILT_IN_CLAIM_CSV_VM_ID	      "csv_vm_id"
#define BUILT_IN_CLAIM_CSV_VM_VERSION	      "csv_vm_version"
#define BUILT_IN_CLAIM_CSV_USER_DATA	      "csv_user_data"
#define BUILT_IN_CLAIM_CSV_MNONCE	      "csv_mnonce"
#define BUILT_IN_CLAIM_CSV_MEASURE	      "csv_measure"
#define BUILT_IN_CLAIM_CSV_POLICY	      "csv_policy"
#define BUILT_IN_CLAIM_CSV_SIG_USAGE	      "csv_sig_usage"
#define BUILT_IN_CLAIM_CSV_SIG_ALGO	      "csv_sig_algo"
#define BUILT_IN_CLAIM_CSV_CHIP_ID	      "csv_chip_id"

/**
 * Claims struct used for claims parameters.
 */
typedef struct claim claim_t;
struct claim {
	char *name;
	uint8_t *value;
	size_t value_size;
} __attribute__((packed));

void free_claims_list(claim_t *claims, size_t claims_length);
int librats_add_claim(claim_t *claim, const char *name, const void *value, size_t value_size);

/* This macro checks whether the expression argument evaluates to RATS_ERR_NONE */
#define CLAIM_CHECK(EXPRESSION)                           \
	do {                                              \
		rats_err_t _result_ = (EXPRESSION);       \
		if (_result_ != RATS_ERR_NONE) {          \
			RATS_ERR("failed to add claims"); \
			goto done;                        \
		}                                         \
	} while (0)

typedef int (*rats_verify_claims_callback_t)(claim_t *claims, size_t claims_size, void *args);

#endif /* _LIBRATS_CLAIM_H_ */
