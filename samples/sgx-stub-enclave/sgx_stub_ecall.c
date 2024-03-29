/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <librats/api.h>

#include "sgx_stub_t.h"

#include "../cert-app/common.c"

int ecall_get_attestation_certificate(rats_conf_t conf, bool no_privkey,
				      const claim_t *custom_claims, size_t custom_claims_size,
				      size_t certificate_capacity, uint8_t *certificate_out,
				      size_t *certificate_size_out)
{
	uint8_t *certificate = NULL;
	size_t certificate_size;

	int ret = get_attestation_certificate(conf, no_privkey, custom_claims, custom_claims_size,
					      &certificate, &certificate_size);
	if (ret == 0) {
		if (certificate_size > certificate_capacity) {
			printf("Certificate buffer too small, size: %zu capacity: %zu\n",
			       certificate_size, certificate_capacity);
			ret = -1;
		} else {
			memcpy(certificate_out, certificate, certificate_size);
		}
		*certificate_size_out = certificate_size;
	}

	if (certificate)
		free(certificate);
	return ret;
}

int ecall_verify_attestation_certificate(rats_conf_t conf, uint8_t *certificate,
					 size_t certificate_size, void *args)
{
	return verify_attestation_certificate(conf, certificate, certificate_size, args);
}