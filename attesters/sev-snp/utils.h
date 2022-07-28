/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SEV_SNP_UTILS_H_
#define SEV_SNP_UTILS_H_

#include <librats/api.h>
#include "sev_snp.h"

#define KDS_CERT_SITE	 "https://kdsintf.amd.com"
#define KDS_VCEK	 KDS_CERT_SITE "/vcek/v1/"
#define CURL_RETRY_TIMES 5

rats_attester_err_t sev_snp_get_vcek_der(const uint8_t *chip_id, size_t chip_id_size,
					 const snp_tcb_version_t *tcb,
					 snp_attestation_evidence_t *snp_report);
#endif 
