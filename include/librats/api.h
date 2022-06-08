/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _LIBRATS_API_H_
#define _LIBRATS_API_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <librats/err.h>
#include <librats/conf.h>
#include <librats/evidence.h>
#include <librats/core.h>

//clang-format off
#define RATS_API_VERSION_1          1
#define RATS_API_VERSION_MAX        RATS_API_VERSION_1
#define RATS_API_VERSION_DEFAULT    RATS_API_VERSION_1

#define SHA256_HASH_SIZE            32
#define SHA384_HASH_SIZE            48
#define RATS_CONF_FLAGS_GLOBAL_MASK_SHIFT   0
#define RATS_CONF_FLAGS_PRIVATE_MASK_SHIFT  32
/* Internal flags */
#define RATS_CONF_FLAGS_ATTESTER_ENFORCED   (1UL << RATS_CONF_FLAGS_PRIVATE_MASK_SHIFT)
#define RATS_CONF_FLAGS_VERIFIER_ENFORCED   (RATS_CONF_FLAGS_ATTESTER_ENFORCED << 1)
//clang-format on

typedef struct rats_core_context rats_core_context_t;
typedef struct rats_attester_ctx rats_attester_ctx_t;
typedef struct rats_verifier_ctx rats_verifier_ctx_t;

typedef struct rats_sgx_evidence {
	uint8_t *mr_enclave;
	uint8_t *mr_signer;
	uint32_t product_id;
	uint32_t security_version;
	uint8_t *attributes;
	size_t collateral_size;
	char *collateral;
} rats_sgx_evidence_t;

typedef struct rats_tdx_evidence {
	/* TODO */
} rats_tdx_evidence_t;

/* The public_key, user_data_size and user_data are needed to include in hash. */
typedef struct ehd {
	void *public_key;
	int user_data_size;
	char *user_data;
	int unhashed_size;
	char *unhashed;
} ehd_t;

typedef enum { SGX_ECDSA = 1, TDX_ECDSA } rats_evidence_type_t;

typedef struct rats_evidence {
	rats_evidence_type_t type;
	ehd_t ehd;
	int quote_size;
	char *quote;
	union {
		rats_sgx_evidence_t sgx;
		rats_tdx_evidence_t tdx;
	};
} rats_evidence_t;

extern rats_err_t librats_init(rats_conf_t *conf, rats_core_context_t *ctx);
extern rats_attester_err_t librats_collect_evidence(rats_attester_ctx_t *ctx,
						    attestation_evidence_t *evidence, uint8_t *hash,
						    uint32_t hash_len);
extern rats_verifier_err_t librats_verify_evidence(rats_verifier_ctx_t *ctx,
						   attestation_evidence_t *evidence, uint8_t *hash,
						   uint32_t hash_len);

#endif
