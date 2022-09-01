/* Copyright (c) 2022 Hygon Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <librats/log.h>
#include <librats/attester.h>
#include <librats/csv.h>
#include <curl/curl.h>
#include "csv_utils.h"

#define PAGE_MAP_FILENAME   "/proc/self/pagemap"
#define PAGE_MAP_PFN_MASK   0x007fffffffffffffUL
#define PAGE_MAP_PAGE_SHIFT 12
#define PAGE_MAP_PAGE_SIZE  (1UL << PAGE_MAP_PAGE_SHIFT)
#define PAGE_MAP_ENTRY_SIZE sizeof(uint64_t)
typedef uint64_t page_map_entry_t;

/**
 * Translate the virtual address of app to physical address
 *
 * Params:
 * 	va [in]: virtual address in app address space
 * Return:
 * 	physical address correspond to @va: success
 * 	NULL: fail
 */
static void *gva_to_gpa(void *va)
{
	int fd = -1;
	void *pa = NULL;
	uint64_t paging_entry_offset;
	page_map_entry_t entry;

	fd = open(PAGE_MAP_FILENAME, O_RDONLY);
	if (fd == -1) {
		RATS_ERR("failed to open %s\n", PAGE_MAP_FILENAME);
		return NULL;
	}

	paging_entry_offset = ((uint64_t)va >> PAGE_MAP_PAGE_SHIFT) * PAGE_MAP_ENTRY_SIZE;
	if (lseek(fd, paging_entry_offset, SEEK_SET) == -1) {
		RATS_ERR("failed to seek\n");
		goto err_close_fd;
	}

	if (read(fd, &entry, sizeof(entry)) != sizeof(entry)) {
		RATS_ERR("failed to read pagemap entry\n");
		goto err_close_fd;
	}

	if (!(entry & (1ul << 63))) {
		RATS_ERR("page doesn't present\n");
		goto err_close_fd;
	}

	pa = (void *)((entry & PAGE_MAP_PFN_MASK) << PAGE_MAP_PAGE_SHIFT) +
	     ((uint64_t)va % PAGE_MAP_PAGE_SIZE);

	RATS_DEBUG("offset %#016lx, entry %#016lx, pa %#016lx\n",
		   (unsigned long)paging_entry_offset, (unsigned long)entry, (unsigned long)pa);

err_close_fd:
	close(fd);

	return pa;
}

static int do_hypercall(unsigned int p1, unsigned long p2, unsigned long p3)
{
	long ret = 0;

	asm volatile("vmmcall" : "=a"(ret) : "a"(p1), "b"(p2), "c"(p3) : "memory");

	return (int)ret;
}

static size_t get_csv_evidence_extend_length(void)
{
	return HYGON_HSK_CEK_CERT_SIZE;
}

static size_t curl_writefunc_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	size_t limit_size = get_csv_evidence_extend_length();
	csv_evidence *evidence = (csv_evidence *)userp;

	if (evidence->hsk_cek_cert_len + realsize > limit_size) {
		RATS_ERR("hsk_cek size is large than %lu bytes.", limit_size);
		return 0;
	}
	memcpy(&(evidence->hsk_cek_cert[evidence->hsk_cek_cert_len]), contents, realsize);
	evidence->hsk_cek_cert_len += realsize;

	return realsize;
}

/**
 * Download HSK and CEK cert, and then save them to @hsk_cek_cert.
 *
 * Params:
 * 	hsk_cek_cert [in]: the buffer to save HSK and CEK cert
 * 	chip_id      [in]: platform's ChipId
 * Return:
 * 	0: success
 * 	otherwise error
 */
static int csv_get_hsk_cek_cert(const char *chip_id, csv_evidence *evidence)
{
	/* Download HSK and CEK cert by ChipId */
	char url[200] = {
		0,
	};
	int count = snprintf(url, sizeof(url), "%s%s", HYGON_KDS_SERVER_SITE, chip_id);
	url[count] = '\0';
	// init curl
	CURLcode curl_ret = CURLE_OK;
	CURL *curl = curl_easy_init();
	if (!curl) {
		RATS_ERR("failed to init curl.");
		return -1;
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_writefunc_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)evidence);
	for (int i = 0; i < 5; i++) {
		evidence->hsk_cek_cert_len = 0;
		if ((curl_ret = curl_easy_perform(curl)) == CURLE_OK) {
			break;
		}
		RATS_DEBUG("failed to download hsk_cek, try again.");
	}
	curl_easy_cleanup(curl);
	if (curl_ret != CURLE_OK) {
		RATS_ERR("failed to download hsk_cek after 5 retries, %s\n",
			 curl_easy_strerror(curl_ret));
		return -1;
	}

	return 0;
}

#define CSV_GUEST_MAP_LEN     4096
#define KVM_HC_VM_ATTESTATION 100 /* Specific to HYGON CPU */

typedef struct {
	unsigned char data[CSV_ATTESTATION_USER_DATA_SIZE];
	unsigned char mnonce[CSV_ATTESTATION_MNONCE_SIZE];
	hash_block_t hash;
} csv_attester_user_data_t;

/**
 * Initiate ATTESTATION from guest, and save evidence to @evidence.
 * The report size of csv_attestation_evidence_t is large enough to hold
 * CSV attestation report, CEK cert and HSK cert.
 * 		.----------------------------.
 * 		|   CSV attestation report   |
 * 		|   Platform's CEK cert      |
 * 		|   Vendor's HSK cert        |
 * 		'----------------------------'
 *
 * The components of CSV attestation report are shown below:
 * 		.------------------------------------------.
 * 		|   CSV environment claims and signature   |
 * 		|   Platform's PEK cert                    |
 * 		|   Platform's ChipId                      |
 * 		|   ...                                    |
 * 		|   hmac of PEK cert, ChipId, ...          |
 * 		'------------------------------------------'
 * Params:
 * 	hash     [in]: hash of TLS pubkey
 * 	evidence [in]: address of csv attestation evidence
 * Return:
 * 	0: success
 * 	otherwise error
 */
static int collect_attestation_evidence(const uint8_t *hash, uint32_t hash_len,
					csv_evidence *evidence)
{
	int ret = 0;
	uint64_t user_data_pa;
	csv_attester_user_data_t *user_data = NULL;

	/* Request an private page which is used to communicate with CSV firmware.
	 * When attester want collect claims from CSV firmware, it will set user
	 * data to this private page. If CSV firmware returns successfully, it will
	 * save claims to this private page.
	 *
	 * TODO: pin the mmapped page in this attester.
	 */
	user_data = mmap(NULL, CSV_GUEST_MAP_LEN, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (user_data == MAP_FAILED) {
		RATS_ERR("failed to mmap\n");
		return -1;
	}
	RATS_DEBUG("mmap [%#016lx - %#016lx)\n", (unsigned long)user_data,
		   (unsigned long)user_data + CSV_GUEST_MAP_LEN);
	memset((void *)user_data, 0, CSV_GUEST_MAP_LEN);

	/* Prepare user defined data (challenge and mnonce) */
	memcpy(user_data->data, hash,
	       hash_len <= CSV_ATTESTATION_USER_DATA_SIZE ? hash_len :
								  CSV_ATTESTATION_USER_DATA_SIZE);
	gen_random_bytes(user_data->mnonce, CSV_ATTESTATION_MNONCE_SIZE);

	/* Prepare hash of user defined data */
	ret = sm3_hash((const unsigned char *)user_data,
		       CSV_ATTESTATION_USER_DATA_SIZE + CSV_ATTESTATION_MNONCE_SIZE,
		       (unsigned char *)(&user_data->hash), sizeof(hash_block_t));
	if (ret) {
		RATS_ERR("failed to compute sm3 hash\n");
		goto err_munmap;
	}

	/* Save user_data->mnonce to check the timeliness of attestation report later */
	unsigned char cur_mnonce[CSV_ATTESTATION_MNONCE_SIZE];
	memcpy(cur_mnonce, user_data->mnonce, CSV_ATTESTATION_MNONCE_SIZE);

	/* Request ATTESTATION */
	user_data_pa = (uint64_t)gva_to_gpa(user_data);
	ret = do_hypercall(KVM_HC_VM_ATTESTATION, (unsigned long)user_data_pa, CSV_GUEST_MAP_LEN);
	if (ret) {
		RATS_ERR("failed to save attestation report to %#016lx (ret:%lu)\n",
			 (unsigned long)ret, user_data_pa);
		goto err_munmap;
	}

	/* Check whether the attestation report is fresh */
	unsigned char report_mnonce[CSV_ATTESTATION_MNONCE_SIZE];
	csv_attestation_report *attestation_report = (csv_attestation_report *)user_data;
	int i;

	for (i = 0; i < CSV_ATTESTATION_MNONCE_SIZE / sizeof(uint32_t); i++)
		((uint32_t *)report_mnonce)[i] = ((uint32_t *)attestation_report->mnonce)[i] ^
						 attestation_report->anonce;
	ret = memcmp(cur_mnonce, report_mnonce, CSV_ATTESTATION_MNONCE_SIZE);
	if (ret) {
		RATS_ERR("mnonce is not fresh\n");
		goto err_munmap;
	}

	/* Fill evidence buffer with attestation report */
	assert(sizeof(csv_attestation_report) <= CSV_GUEST_MAP_LEN);

	attestation_report = &evidence->attestation_report;
	memcpy(attestation_report, user_data, sizeof(csv_attestation_report));

	/* Retreive ChipId from attestation report */
	uint8_t chip_id[CSV_ATTESTATION_CHIP_SN_SIZE + 1] = {
		0,
	};

	for (i = 0; i < CSV_ATTESTATION_CHIP_SN_SIZE / sizeof(uint32_t); i++)
		((uint32_t *)chip_id)[i] = ((uint32_t *)attestation_report->chip_id)[i] ^
					   attestation_report->anonce;

	/* Fill in CEK cert and HSK cert */
	if (csv_get_hsk_cek_cert((const char *)chip_id, evidence)) {
		RATS_ERR("failed to load HSK and CEK cert\n");
		ret = -1;
		goto err_munmap;
	}

	ret = 0;

err_munmap:
	munmap(user_data, CSV_GUEST_MAP_LEN);

	return ret;
}

rats_attester_err_t csv_collect_evidence(rats_attester_ctx_t *ctx, attestation_evidence_t *evidence,
					 const uint8_t *hash,
					 __attribute__((unused)) uint32_t hash_len)
{
	RATS_DEBUG("ctx %p, evidence %p, hash %p\n", ctx, evidence, hash);

	/* For csv guest, the hsk_cek certs should be combined with attestation report */
	uint32_t csv_evidence_len = sizeof(csv_evidence) + get_csv_evidence_extend_length();
	csv_evidence *c_evidence = NULL;
	csv_attestation_evidence_t *csv_report = &evidence->csv;

	assert(csv_evidence_len <= sizeof(csv_report->report));

	if (!(c_evidence = (csv_evidence *)malloc(csv_evidence_len))) {
		RATS_ERR("failed to allocate csv evidence buffer\n");
		return RATS_ATTESTER_ERR_NO_MEM;
	}
	memset(c_evidence, 0, csv_evidence_len);

	if (collect_attestation_evidence(hash, hash_len, c_evidence)) {
		RATS_ERR("failed to get attestation_evidence\n");
		free(c_evidence);
		return RATS_ATTESTER_ERR_INVALID;
	}

	memcpy(csv_report->report, c_evidence, csv_evidence_len);
	csv_report->report_len = csv_evidence_len;

	free(c_evidence);

	RATS_DEBUG("Success to generate attestation_evidence\n");

	snprintf(evidence->type, sizeof(evidence->type), "csv");

	RATS_DEBUG("ctx %p, evidence %p, report_len %u\n", ctx, evidence, evidence->csv.report_len);

	return RATS_ATTESTER_ERR_NONE;
}
