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
#define RATS_API_VERSION_1	 1
#define RATS_API_VERSION_MAX	 RATS_API_VERSION_1
#define RATS_API_VERSION_DEFAULT RATS_API_VERSION_1

#define SHA256_HASH_SIZE		   32
#define SHA384_HASH_SIZE		   48
#define RATS_CONF_FLAGS_GLOBAL_MASK_SHIFT  0
#define RATS_CONF_FLAGS_PRIVATE_MASK_SHIFT 32
/* Internal flags */
#define RATS_CONF_FLAGS_ATTESTER_ENFORCED (1UL << RATS_CONF_FLAGS_PRIVATE_MASK_SHIFT)
#define RATS_CONF_FLAGS_VERIFIER_ENFORCED (RATS_CONF_FLAGS_ATTESTER_ENFORCED << 1)
//clang-format on

typedef struct rats_core_context rats_core_context_t;
typedef struct rats_attester_ctx rats_attester_ctx_t;
typedef struct rats_verifier_ctx rats_verifier_ctx_t;

#ifdef __cplusplus
extern "C" {
#endif
extern rats_attester_err_t librats_collect_evidence(attestation_evidence_t *evidence,
						    const uint8_t *hash);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern rats_verifier_err_t librats_verify_evidence(attestation_evidence_t *evidence,
						   const uint8_t *hash);
#ifdef __cplusplus
}
#endif

#endif
