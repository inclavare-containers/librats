/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/sev-guest.h>
#include <librats/attester.h>
#include <librats/log.h>
#include <curl/curl.h>
#include "sev_snp.h"

#define SEV_GUEST_DEVICE "/dev/sev-guest"
#define KDS_CERT_SITE	 "https://kdsintf.amd.com"
#define KDS_VCEK	 KDS_CERT_SITE "/vcek/v1/"
#define CURL_RETRY_TIMES 5

static int snp_get_report(const uint8_t *data, size_t data_size, snp_attestation_report_t *report)
{
	struct snp_report_req req;
	struct snp_report_resp resp;
	struct snp_guest_request_ioctl guest_req;
	snp_msg_report_rsp_t *report_resp = (struct snp_msg_report_rsp *)&resp.data;

	if ((data && data_size > sizeof(req.user_data)) || !report)
		return -1;

	/* Initialize data structures */
	memset(&req, 0, sizeof(req));
	req.vmpl = 1;
	if (data && data_size)
		memcpy(&req.user_data, data, data_size);

	memset(&resp, 0, sizeof(resp));

	memset(&guest_req, 0, sizeof(guest_req));
	guest_req.msg_version = 1;
	guest_req.req_data = (__u64)&req;
	guest_req.resp_data = (__u64)&resp;

	/* Open the sev-guest device */
	int fd = open(SEV_GUEST_DEVICE, O_RDWR);
	if (fd == -1) {
		RATS_ERR("failed to open %s\n", SEV_GUEST_DEVICE);
		return -1;
	}

	/* Issue the guest request IOCTL */
	if (ioctl(fd, SNP_GET_REPORT, &guest_req) == -1) {
		RATS_ERR("failed to issue SNP_GET_REPORT ioctl, firmware error %llu\n",
			 guest_req.fw_err);
		goto out_close;
	}

	close(fd);

	/* Check that the report was successfully generated */
	if (report_resp->status != 0) {
		RATS_ERR("firmware error %#x\n", report_resp->status);
		goto out_close;
	}

	if (report_resp->report_size != sizeof(*report)) {
		RATS_ERR("report size is %u bytes (expected %lu)!\n", report_resp->report_size,
			 sizeof(*report));
		goto out_close;
	}

	memcpy(report, &report_resp->report, report_resp->report_size);

	return 0;

out_close:
	close(fd);

	return -1;
}

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

rats_attester_err_t sev_snp_collect_evidence(rats_attester_ctx_t *ctx,
					     attestation_evidence_t *evidence, uint8_t *hash,
					     uint32_t hash_len)
{
	RATS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	snp_attestation_report_t report;
	memset(&report, 0, sizeof(report));

	if (snp_get_report(hash, hash_len, &report)) {
		RATS_ERR("failed to get snp report\n");
		return RATS_ATTESTER_ERR_INVALID;
	}

	snp_attestation_evidence_t *snp_report = &evidence->snp;
	memcpy(snp_report->report, &report, sizeof(report));
	snp_report->report_len = sizeof(report);

	snprintf(evidence->type, sizeof(evidence->type), "sev_snp");

	rats_attester_err_t err = sev_snp_get_vcek_der(report.chip_id, sizeof(report.chip_id),
						       &report.platform_version, snp_report);
	if (err != RATS_ATTESTER_ERR_NONE) {
		return err;
	}

	return RATS_ATTESTER_ERR_NONE;
}
