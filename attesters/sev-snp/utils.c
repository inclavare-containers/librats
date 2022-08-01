/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <curl/curl.h>
#include <librats/log.h>
#include "utils.h"

static size_t curl_writefunc_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	snp_attestation_evidence_t *snp_report = (snp_attestation_evidence_t *)userp;

	if (snp_report->vcek_len + realsize > VECK_MAX_SIZE) {
		RATS_ERR("vcek size is larger than %d bytes.", VECK_MAX_SIZE);
		return 0;
	}
	memcpy(&(snp_report->vcek[snp_report->vcek_len]), contents, realsize);
	snp_report->vcek_len += realsize;
	snp_report->vcek[snp_report->vcek_len] = 0;

	return realsize;
}

rats_attester_err_t sev_snp_get_vcek_der(const uint8_t *chip_id, size_t chip_id_size,
					 const snp_tcb_version_t *tcb,
					 snp_attestation_evidence_t *snp_report)
{
	/* clear the vcek in snp_report */
	memset(snp_report->vcek, 0, VECK_MAX_SIZE);
	snp_report->vcek_len = 0;

	/* 2 chars per byte +1 for null term */
	char id_buf[chip_id_size * 2 + 1];
	memset(id_buf, 0, sizeof(id_buf));
	for (uint8_t i = 0; i < chip_id_size; i++) {
		sprintf(id_buf + 2 * i * sizeof(uint8_t), "%02x", chip_id[i]);
	}

	int count = 0;
	char url[256] = {
		0,
	};

	count = snprintf(url, sizeof(url), "%sMilan/%s", KDS_VCEK, id_buf);

	char *TCBStringArray[8];
	TCBStringArray[0] = "blSPL=";
	TCBStringArray[1] = "teeSPL=";
	TCBStringArray[2] = "reserved0SPL=";
	TCBStringArray[3] = "reserved1SPL=";
	TCBStringArray[4] = "reserved2SPL=";
	TCBStringArray[5] = "reserved3SPL=";
	TCBStringArray[6] = "snpSPL=";
	TCBStringArray[7] = "ucodeSPL=";

	/* Generate VCEK cert correspond to @chip_id and @tcb */
	count += snprintf((char *)&url[count], sizeof(url) - count, "?%s%02u&%s%02u&%s%02u&%s%02u",
			  TCBStringArray[0], (unsigned)tcb->f.boot_loader, TCBStringArray[1],
			  (unsigned)tcb->f.tee, TCBStringArray[6], (unsigned)tcb->f.snp,
			  TCBStringArray[7], (unsigned)tcb->f.microcode);

	url[count] = '\0';
	// init curl
	CURLcode curl_ret = CURLE_OK;
	CURL *curl = curl_easy_init();
	if (!curl) {
		RATS_ERR("failed to init curl.");
		return RATS_ATTESTER_ERR_NO_TOOL;
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writefunc_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)snp_report);
	for (int i = 0; i < CURL_RETRY_TIMES; i++) {
		if ((curl_ret = curl_easy_perform(curl)) == CURLE_OK) {
			break;
		}
		RATS_DEBUG("failed to download vcek_der, try again.");
	}
	curl_easy_cleanup(curl);
	if (curl_ret != CURLE_OK) {
		RATS_ERR("failed to download vcek_der after %d retries,%s\n", CURL_RETRY_TIMES,
			 curl_easy_strerror(curl_ret));
		return RATS_ATTESTER_ERR_CURL;
	}

	return RATS_ATTESTER_ERR_NONE;
}