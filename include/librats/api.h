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
#include <librats/claim.h>
#include <librats/conf.h>
#include <librats/evidence.h>
#include <librats/core.h>
#include <librats/cert.h>

// clang-format off
#define RATS_API_VERSION_1	 1
#define RATS_API_VERSION_MAX	 RATS_API_VERSION_1
#define RATS_API_VERSION_DEFAULT RATS_API_VERSION_1

#define RATS_CONF_FLAGS_GLOBAL_MASK_SHIFT  0
#define RATS_CONF_FLAGS_PRIVATE_MASK_SHIFT 32
// clang-format on

typedef struct rats_core_context rats_core_context_t;
typedef struct rats_attester_ctx rats_attester_ctx_t;
typedef struct rats_verifier_ctx rats_verifier_ctx_t;
typedef struct crypto_wrapper_ctx crypto_wrapper_ctx_t;

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
rats_verifier_err_t librats_verify_evidence(attestation_evidence_t *evidence, const uint8_t *hash,
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

extern rats_attester_err_t librats_get_attestation_certificate(rats_conf_t conf, 
	rats_cert_subject_t subject_name, uint8_t **privkey /* PEM format */, size_t *privkey_len,
	const claim_t *custom_claims, size_t custom_claims_length, bool provide_endorsements,
	uint8_t **certificate_out, size_t *certificate_size_out);

extern rats_verifier_err_t
librats_verify_attestation_certificate(rats_conf_t conf, uint8_t *certificate, size_t certificate_size,
				       rats_verify_claims_callback_t verify_claims_callback,
				       void *args);

#ifdef __cplusplus
}
#endif

#endif
