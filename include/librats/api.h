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
#include <librats/claim.h>

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
extern rats_attester_err_t
librats_collect_evidence(const claim_t *custom_claims, size_t custom_claims_size,
			 uint8_t **evidence_buffer, size_t *evidence_buffer_size,
			 uint8_t **endorsements_buffer, size_t *endorsements_buffer_size);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern rats_verifier_err_t librats_verify_evidence(uint8_t *evidence_buffer,
						   size_t evidence_buffer_size,
						   uint8_t *endorsements_buffer,
						   size_t endorsements_buffer_size,
						   claim_t **claims, size_t *claims_length);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
int librats_collect_evidence_to_json(const uint8_t *hash, char **evidence_json);
int librats_verify_evidence_from_json(const char *json_string, const uint8_t *hash);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern rats_attester_err_t librats_get_attestation_certificate(
	const char *subject_name, uint8_t *private_key, size_t private_key_size,
	uint8_t *public_key, size_t public_key_size, const claim_t *custom_claims,
	size_t custom_claims_size, uint8_t **output_certificate, size_t *output_certificate_size);

extern rats_verifier_err_t
librats_verify_attestation_certificate(uint8_t *certificate, size_t certificate_size,
				       rats_verify_claims_callback_t verify_claims_callback,
				       void *args);

#ifdef __cplusplus
}
#endif

#endif
