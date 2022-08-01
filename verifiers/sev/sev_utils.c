/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <librats/log.h>
#include "sev_utils.h"
#include <curl/curl.h>

int get_file_size(char *name)
{
	struct stat statbuf;

	if (stat(name, &statbuf) == 0)
		return statbuf.st_size;

	return 0;
}

int read_file(const char *filename, void *buffer, size_t len)
{
	FILE *fp = NULL;
	size_t count = 0;

	if ((fp = fopen(filename, "r")) == NULL) {
		RATS_ERR("failed to open %s\n", filename);
		return 0;
	}

	if ((count = fread(buffer, 1, len, fp)) != len) {
		fclose(fp);
		RATS_ERR("failed to read %s with count %lu\n", filename, count);
		return 0;
	}

	fclose(fp);
	return count;
}

size_t curl_writefunc_callback(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	size_t written = fwrite(ptr, size, nmemb, stream);
	return written;
}

int download_from_url(const char *url, const char *file_path)
{
	CURL *curl = NULL;
	FILE *fp = NULL;
	int ret = -1;
	CURLcode curl_ret = CURLE_OK;

	fp = fopen(file_path, "wb");
	if (fp == NULL) {
		return -1;
	}

	curl = curl_easy_init();
	if (!curl) {
		RATS_ERR("failed to init curl.");
		goto err;
	}
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writefunc_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
	for (int i = 0; i < CURL_RETRY_TIMES; i++) {
		if ((curl_ret = curl_easy_perform(curl)) == CURLE_OK) {
			break;
		}
		RATS_DEBUG("failed to download ask_ark, try again.");
	}

	if (curl_ret != CURLE_OK) {
		RATS_ERR("failed to download ask_ark after %d retries,%s\n", CURL_RETRY_TIMES,
			 curl_easy_strerror(curl_ret));
		goto err;
	}
	ret = 0;

err:
	if (curl) {
		curl_easy_cleanup(curl);
	}
	if (fp) {
		fclose(fp);
	}
	if (ret == -1) {
		remove(file_path);
	}
	return ret;
}
