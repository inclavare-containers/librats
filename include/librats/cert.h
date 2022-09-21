/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _LIBRATS_CERT_H
#define _LIBRATS_CERT_H

#include <librats/evidence.h>
#include <openssl/evp.h>

typedef struct {
	EVP_PKEY *private_key;
	EVP_PKEY *public_key;
} cert_key_t;

typedef struct {
	const uint8_t *evidence_buffer;
	size_t evidence_buffer_size;
	const uint8_t *endorsements_buffer;
	size_t endorsements_buffer_size;
} cert_extension_info_t;

typedef struct {
	const char *subject_name;
	cert_key_t key;
	cert_extension_info_t extension_info;
} rats_cert_info_t;

int openssl_calc_pubkey_sha256(EVP_PKEY *pkey, uint8_t *hash);
rats_attester_err_t openssl_gen_cert(rats_cert_info_t *cert_info, uint8_t **output_certificate,
				     size_t *output_certificate_size);
rats_verifier_err_t openssl_parse_cert(const uint8_t *certificate, size_t certificate_size,
				       EVP_PKEY **publickey, uint8_t **evidence_buffer,
				       size_t *evidence_buffer_size, uint8_t **endorsements_buffer,
				       size_t *endorsements_buffer_size);
#endif
