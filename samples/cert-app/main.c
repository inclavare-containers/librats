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
#include <librats/log.h>

#define EXPORT_CERT_FILE_PATH "/tmp/cert.der"

#ifndef OCCLUM
int export_cert(const char *cert_file_path, uint8_t *certificate, size_t certificate_size)
{
	int ret = -1;
	int fd = open(cert_file_path, O_RDWR | O_CREAT, 00755);
	if (fd == -1) {
		RATS_ERR("Failed to export certificate file: %s\n", strerror(errno));
		return ret;
	}
	size_t count_wirte = 0;
	int t = 0;
	while (count_wirte < certificate_size) {
		t = write(fd, ((uint8_t *)certificate) + count_wirte,
			  certificate_size - count_wirte);
		if (t == -1) {
			RATS_ERR("Failed to export certificate file: %s\n", strerror(errno));
			close(fd);
			return ret;
		}
		count_wirte += t;
	}
	close(fd);
	RATS_INFO("Exported certificate file path: %s\n", cert_file_path);
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

rats_log_level_t global_log_level = RATS_LOG_LEVEL_DEFAULT;

static sgx_enclave_id_t load_enclave(bool debug_enclave)
{
	sgx_launch_token_t t;

	memset(t, 0, sizeof(t));

	sgx_enclave_id_t eid;
	int updated = 0;
	int ret = sgx_create_enclave(ENCLAVE_FILENAME, debug_enclave, &t, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		RATS_ERR("Failed to load enclave %d\n", ret);
		return 0;
	}

	RATS_INFO("Success to load enclave with enclave id %ld\n", eid);

	return eid;
}

int rats_app_startup(const char *subject_name, bool debug_enclave, const claim_t *custom_claims,
		     size_t custom_claims_size)
{
	uint8_t certificate[8192 * 4];
	size_t certificate_size;
	int ret;

	sgx_enclave_id_t enclave_id = load_enclave(debug_enclave);
	if (enclave_id == 0) {
		RATS_ERR("Failed to load sgx stub enclave\n");
		goto err;
	}

	int sgx_status = ecall_get_attestation_certificate(enclave_id, &ret, subject_name,
							   custom_claims, custom_claims_size,
							   sizeof(certificate), certificate,
							   &certificate_size);
	if (sgx_status != SGX_SUCCESS || ret) {
		RATS_ERR("Failed at ecall_get_attestation_certificate: sgx status %#x return %#x\n",
			 sgx_status, ret);
		RATS_INFO("Certificate generation:\tFAILED\n");
		goto err;
	}
	RATS_INFO("Certificate generation:\tSUCCESS\n");

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
		RATS_ERR(
			"Failed at ecall_verify_attestation_certificate: sgx status %#x return %#x\n",
			sgx_status, ret);
		RATS_INFO("Certificate verification:\tFAILED\n");
		goto err;
	}
	RATS_INFO("Certificate verification:\tSUCCESS\n");
	ret = 0;
err:
	return ret;
}
#endif

#ifndef SGX

	#include "common.c"

int rats_app_startup(const char *subject_name, bool debug_enclave, const claim_t *custom_claims,
		     size_t custom_claims_size)
{
	uint8_t *certificate = NULL;
	size_t certificate_size;
	int ret;

	ret = get_attestation_certificate(subject_name, custom_claims, custom_claims_size,
					  &certificate, &certificate_size);
	if (ret) {
		RATS_INFO("Certificate generation:\tFAILED\n");
		goto err;
	}
	RATS_INFO("Certificate generation:\tSUCCESS\n");

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
		RATS_INFO("Certificate verification:\tFAILED\n");
		goto err;
	}
	RATS_INFO("Certificate verification:\tSUCCESS\n");

	ret = 0;
err:
	if (certificate)
		free(certificate);
	return ret;
}
#endif

rats_log_level_t rats_loglevel_getenv(const char *name)
{
	char *log_level_str = log_level_str = getenv(name);
	if (log_level_str) {
		if (!strcasecmp(log_level_str, "debug"))
			return RATS_LOG_LEVEL_DEBUG;
		else if (!strcasecmp(log_level_str, "info"))
			return RATS_LOG_LEVEL_INFO;
		else if (!strcasecmp(log_level_str, "warn"))
			return RATS_LOG_LEVEL_WARN;
		else if (!strcasecmp(log_level_str, "error"))
			return RATS_LOG_LEVEL_ERROR;
		else if (!strcasecmp(log_level_str, "fatal"))
			return RATS_LOG_LEVEL_FATAL;
		else if (!strcasecmp(log_level_str, "off"))
			return RATS_LOG_LEVEL_NONE;
	}

	return RATS_LOG_LEVEL_DEFAULT;
}

int main(int argc, char **argv)
{
#ifdef SGX
	printf("    - Welcome to librats sample cert-app program for Intel SGX\n");
#elif defined(OCCLUM)
	printf("    - Welcome to librats sample cert-app program for Occlum\n");
#else
	printf("    - Welcome to librats sample cert-app program\n");
#endif

	char *const short_options = "Dhc:";
	// clang-format off
	struct option long_options[] = {
		{ "debug-enclave", no_argument, NULL, 'D' },
		{ "help", no_argument, NULL, 'h' },
		{ "add-claim", required_argument, NULL, 'c' },
		{ 0, 0, 0, 0 }
	};
	// clang-format on

	bool debug_enclave = false;
	claim_t claims[64];
	size_t claims_count = 0;
	int opt;

	const char *subject_name = "O=Inclavare Containers,CN=LIBRATS";

	do {
		opt = getopt_long(argc, argv, short_options, long_options, NULL);
		switch (opt) {
		case 'D':
			debug_enclave = true;
			break;
		case 'c':;
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
			     "        --debug-enclave/-D   		set to enable enclave debugging\n"
			     "        --add-claim/-c key:val	add a user-defined custom claims.\n"
			     "        --help/-h             	show the usage\n");
			exit(1);
		default:
			exit(1);
		}
	} while (opt != -1);

	rats_global_log_level = rats_loglevel_getenv("RATS_GLOBAL_LOG_LEVEL");
	if (rats_global_log_level == (rats_log_level_t)-1) {
		RATS_FATAL("failed to get log level from env\n");
		exit(1);
	}

	return rats_app_startup(subject_name, debug_enclave, claims, claims_count);
}
