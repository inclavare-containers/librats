/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _RATS_ATTESTER_H
#define _RATS_ATTESTER_H

#include <stdint.h>
#include <librats/api.h>

#define RATS_ATTESTER_TYPE_MAX	     32
#define RATS_ATTESTER_TYPE_NAME_SIZE 32

#define RATS_ATTESTER_API_VERSION_1	  1
#define RATS_ATTESTER_API_VERSION_MAX	  RATS_ATTESTER_API_VERSION_1
#define RATS_ATTESTER_API_VERSION_DEFAULT RATS_ATTESTER_API_VERSION_1

#define RATS_ATTESTER_OPTS_FLAGS_SGX_ENCLAVE (1 << 0)
#define RATS_ATTESTER_OPTS_FLAGS_TDX_GUEST   (RATS_ATTESTER_OPTS_FLAGS_SGX_ENCLAVE << 1)
#define RATS_ATTESTER_OPTS_FLAGS_SEV_GUEST   (RATS_ATTESTER_OPTS_FLAGS_TDX_GUEST << 1)
#define RATS_ATTESTER_OPTS_FLAGS_SNP_GUEST   (RATS_ATTESTER_OPTS_FLAGS_SEV_GUEST << 1)
#define RATS_ATTESTER_OPTS_FLAGS_CSV_GUEST   (RATS_ATTESTER_OPTS_FLAGS_SNP_GUEST << 1)

#define RATS_ATTESTER_FLAGS_DEFAULT 0

typedef struct rats_core_context rats_core_context_t;
typedef struct rats_attester_ctx rats_attester_ctx_t;

extern rats_attester_err_t rats_attest_init(rats_conf_t *conf, rats_core_context_t *ctx);

typedef struct rats_attester_opts {
	uint8_t api_version;
	unsigned long flags;
	const char name[RATS_ATTESTER_TYPE_NAME_SIZE];
	/* Different attester instances may generate the same format of attester,
	 * e.g, sgx_ecdsa and sgx_ecdsa_qve both generate the format "sgx_ecdsa".
	 * By default, the value of type equals to name.
	 */
	char type[RATS_ATTESTER_TYPE_NAME_SIZE];
	uint8_t priority;

	/* Optional */
	rats_attester_err_t (*pre_init)(void);
	rats_attester_err_t (*init)(rats_attester_ctx_t *ctx);
	rats_attester_err_t (*collect_evidence)(rats_attester_ctx_t *ctx,
						attestation_evidence_t *evidence, const uint8_t *hash,
						uint32_t hash_len);
	rats_attester_err_t (*cleanup)(rats_attester_ctx_t *ctx);
} rats_attester_opts_t;

struct rats_attester_ctx {
	rats_attester_opts_t *opts;
	void *attester_private;
	unsigned long long enclave_id;
	rats_log_level_t log_level;
	void *handle;

	union {
		struct {
			const char name[RATS_ATTESTER_TYPE_NAME_SIZE];
			bool linkable;
		} sgx_epid;

		struct {
			const char name[RATS_ATTESTER_TYPE_NAME_SIZE];
			uint8_t cert_type;
		} sgx_ecdsa;

		struct {
			const char name[RATS_ATTESTER_TYPE_NAME_SIZE];
			uint8_t cert_type;
		} tdx;
	} config;
};

#endif
