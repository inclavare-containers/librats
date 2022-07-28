/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _SEV_UTILS_H
#define _SEV_UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include "../../attesters/sev/sev.h"

#define SEV_DEFAULT_DIR	       "/opt/sev/"

#define AMD_SEV_DEVELOPER_SITE "https://developer.amd.com/sev/"
#define ASK_ARK_PATH_SITE      "https://developer.amd.com/wp-content/resources/"

#define ASK_ARK_NAPLES_FILE "ask_ark_naples.cert"
#define ASK_ARK_ROME_FILE   "ask_ark_rome.cert"
#define ASK_ARK_MILAN_FILE  "ask_ark_milan.cert"

#define ASK_ARK_NAPLES_SITE ASK_ARK_PATH_SITE ASK_ARK_NAPLES_FILE
#define ASK_ARK_ROME_SITE   ASK_ARK_PATH_SITE ASK_ARK_ROME_FILE
#define ASK_ARK_MILAN_SITE  ASK_ARK_PATH_SITE ASK_ARK_MILAN_FILE

#define CURL_RETRY_TIMES 5

bool reverse_bytes(uint8_t *bytes, size_t size);
int get_file_size(char *name);
int read_file(const char *filename, void *buffer, size_t len);
#ifndef WASM
int download_from_url(const char *url, const char *file_path);
#endif

#endif /* _SEV_UTILS_H */