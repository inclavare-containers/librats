/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>

#define EXPORT_CERT_FILE_PATH "/tmp/cert.der"

#ifndef OCCLUM
int export_cert(const char *cert_file_path, uint8_t *certificate, size_t certificate_size)
{
	int ret = -1;
	int fd = open(cert_file_path, O_RDWR | O_CREAT, 00755);
	if (fd == -1) {
		printf("Failed to export certificate file: %s\n", strerror(errno));
		return ret;
	}
	size_t count_wirte = 0;
	int t = 0;
	while (count_wirte < certificate_size) {
		t = write(fd, ((uint8_t *)certificate) + count_wirte,
			  certificate_size - count_wirte);
		if (t == -1) {
			printf("Failed to export certificate file: %s\n", strerror(errno));
			close(fd);
			return ret;
		}
		count_wirte += t;
	}
	close(fd);
	printf("Path to the generated certificate: %s\n", cert_file_path);
	ret = 0;
	return ret;
}
#else
int export_cert(const char *cert_file_path, uint8_t *certificate, size_t certificate_size)
{
	/* Exporting certificate to file on Occlum is not supported currently */
	return 0;
}
#endif

// clang-format off
#ifdef OCCLUM
#include <sgx_report.h>
#elif defined(SGX)
#include <sgx_urts.h>
#include <sgx_quote.h>
#include "sgx_stub_u.h"

#define ENCLAVE_FILENAME "sgx_stub_enclave.signed.so"
// clang-format on

static sgx_enclave_id_t load_enclave(bool debug_enclave)
{
	sgx_launch_token_t t;

	memset(t, 0, sizeof(t));

	sgx_enclave_id_t eid;
	int updated = 0;
	int ret = sgx_create_enclave(ENCLAVE_FILENAME, debug_enclave, &t, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		printf("Failed to load enclave %d\n", ret);
		return 0;
	}

	printf("Success to load enclave with enclave id %ld\n", eid);

	return eid;
}

int rats_app_startup(bool debug_enclave, bool no_privkey, const claim_t *custom_claims,
		     size_t custom_claims_size)
{
	uint8_t certificate[8192 * 4];
	size_t certificate_size;
	int ret;

	sgx_enclave_id_t enclave_id = load_enclave(debug_enclave);
	if (enclave_id == 0) {
		printf("Failed to load sgx stub enclave\n");
		goto err;
	}

	int sgx_status = ecall_get_attestation_certificate(enclave_id, &ret, no_privkey,
							   custom_claims, custom_claims_size,
							   sizeof(certificate), certificate,
							   &certificate_size);
	if (sgx_status != SGX_SUCCESS || ret) {
		printf("Failed at ecall_get_attestation_certificate: sgx status %#x return %#x\n",
		       sgx_status, ret);
		printf("Certificate generation:\tFAILED\n");
		goto err;
	}

	if (certificate == NULL || certificate_size == 0) {
		printf("Certificate generation:\tFAILED (empty certificate)\n");
		goto err;
	}

	printf("Certificate generation:\tSUCCESS\n");

	ret = export_cert(EXPORT_CERT_FILE_PATH, certificate, certificate_size);
	if (ret != 0)
		goto err;

	typedef struct {
		const claim_t *custom_claims;
		size_t custom_claims_size;
	} args_t;

	args_t args = { .custom_claims = custom_claims, .custom_claims_size = custom_claims_size };
	sgx_status = ecall_verify_attestation_certificate(enclave_id, &ret, certificate,
							  certificate_size, &args);
	if (sgx_status != SGX_SUCCESS || ret) {
		printf("Failed at ecall_verify_attestation_certificate: sgx status %#x return %#x\n",
		       sgx_status, ret);
		printf("Certificate verification:\tFAILED\n");
		goto err;
	}
	printf("Certificate verification:\tSUCCESS\n");
	ret = 0;
err:
	return ret;
}
#endif

// clang-format off
#ifndef SGX
#include "common.c"
// clang-format on

int rats_app_startup(bool debug_enclave, bool no_privkey, const claim_t *custom_claims,
		     size_t custom_claims_size)
{
	uint8_t *certificate = NULL;
	size_t certificate_size = 0;
	int ret;

	ret = get_attestation_certificate(no_privkey, custom_claims, custom_claims_size,
					  &certificate, &certificate_size);
	if (ret) {
		printf("Certificate generation:\tFAILED\n");
		goto err;
	}
	if (certificate == NULL || certificate_size == 0) {
		printf("Certificate generation:\tFAILED (empty certificate)\n");
		goto err;
	}
	printf("Certificate generation:\tSUCCESS\n");

	ret = export_cert(EXPORT_CERT_FILE_PATH, certificate, certificate_size);
	if (ret != 0)
		goto err;

	typedef struct {
		const claim_t *custom_claims;
		size_t custom_claims_size;
	} args_t;
	args_t args = { .custom_claims = custom_claims, .custom_claims_size = custom_claims_size };
	ret = verify_attestation_certificate(certificate, certificate_size, &args);
	if (ret) {
		printf("Certificate verification:\tFAILED\n");
		goto err;
	}
	printf("Certificate verification:\tSUCCESS\n");

	ret = 0;
err:
	if (certificate)
		free(certificate);
	return ret;
}
#endif

int main(int argc, char **argv)
{
#ifdef SGX
	printf("    - Welcome to librats sample cert-app program for Intel SGX\n");
#elif defined(OCCLUM)
	printf("    - Welcome to librats sample cert-app program for Occlum\n");
#else
	printf("    - Welcome to librats sample cert-app program for Host\n");
#endif

	char *const short_options = "dhkc:";
	// clang-format off
    struct option long_options[] = {
        { "debug-enclave", no_argument, NULL, 'd' },
        { "help", no_argument, NULL, 'h' },
        { "no-privkey", no_argument, NULL, 'k'},
        { "add-claim", required_argument, NULL, 'c' },
        { 0, 0, 0, 0 }
    };
	// clang-format on

	bool debug_enclave = false;
	bool no_privkey = false;
	claim_t claims[64];
	size_t claims_count = 0;
	int opt;

	do {
		opt = getopt_long(argc, argv, short_options, long_options, NULL);
		switch (opt) {
		case 'd':
			debug_enclave = true;
			break;
		case 'k':
			no_privkey = true;
			break;
		case 'c':;
#ifdef HOST
			printf("WARN: user-defined custom claims is not supported in host mode, unless your environment has sev/sev-snp/csv support.\n");
#endif
			const char *divider = strchr(optarg, ':');
			if (!divider) {
				printf("Invalid argment '%s', shall in format: 'key:val'\n",
				       optarg);
				exit(1);
			}
			claims[claims_count].name = malloc(divider - optarg + 1);
			memcpy(claims[claims_count].name, optarg, divider - optarg);
			claims[claims_count].name[divider - optarg] = '\0';
			size_t value_size = strlen(optarg) - (divider - optarg + 1);
			claims[claims_count].value = malloc(value_size);
			memcpy(claims[claims_count].value, divider + 1, value_size);
			claims[claims_count].value_size = value_size;
			claims_count++;
			break;
		case -1:
			break;
		case 'h':
			puts("    Usage:\n\n"
			     "        cert-app <options> [arguments]\n\n"
			     "    Options:\n\n"
			     "        --debug-enclave/-d            set to enable enclave debugging\n"
			     "        --no-privkey/-k               set to enable key pairs generation in librats\n"
			     "        --add-claim/-c key:val        add a user-defined custom claims.\n"
			     "        --help/-h                     show the usage\n");
			exit(1);
		default:
			exit(1);
		}
	} while (opt != -1);

	return rats_app_startup(debug_enclave, no_privkey, claims, claims_count);
}
