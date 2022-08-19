/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _LIBRATS_EVIDENCE_H
#define _LIBRATS_EVIDENCE_H

#define VECK_MAX_SIZE 2 * 1024
#define JSON_MAX_SIZE 10 * 1024

typedef struct attestation_evidence attestation_evidence_t;

typedef struct attestation_verification_report {
	uint8_t ias_report[2 * 1024];
	uint32_t ias_report_len;
	uint8_t ias_sign_ca_cert[2 * 1024];
	uint32_t ias_sign_ca_cert_len;
	uint8_t ias_sign_cert[2 * 1024];
	uint32_t ias_sign_cert_len;
	uint8_t ias_report_signature[2 * 1024];
	uint32_t ias_report_signature_len;
} attestation_verification_report_t;

typedef struct ecdsa_attestation_evidence {
	uint8_t quote[8192];
	uint32_t quote_len;
} ecdsa_attestation_evidence_t;

typedef struct la_attestation_evidence {
	uint8_t report[8192];
	uint32_t report_len;
} la_attestation_evidence_t;

typedef struct tdx_attestation_evidence {
	uint8_t quote[8192];
	uint32_t quote_len;
} tdx_attestation_evidence_t;

typedef struct snp_attestation_evidence {
	uint8_t report[8192];
	uint32_t report_len;
	uint8_t vcek[VECK_MAX_SIZE];
	uint32_t vcek_len;
} snp_attestation_evidence_t;

typedef struct sev_attestation_evidence {
	uint8_t report[8192];
	uint32_t report_len;
} sev_attestation_evidence_t;

typedef struct csv_attestation_evidence {
	uint8_t report[8192];
	uint32_t report_len;
} csv_attestation_evidence_t;

struct attestation_evidence {
	char type[32];
	union {
		attestation_verification_report_t epid;
		ecdsa_attestation_evidence_t ecdsa;
		la_attestation_evidence_t la;
		tdx_attestation_evidence_t tdx;
		snp_attestation_evidence_t snp;
		sev_attestation_evidence_t sev;
		csv_attestation_evidence_t csv;
	};
};

#endif
