#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <fstream>
#include <iostream>
#include <librats/api.h>
#include <librats/err.h>
#include <librats/log.h>
#include <librats/conf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <emscripten/bind.h>

rats_verifier_err_t evidence_verify(std::string evidence_base64, std::string hash_base64);

uint8_t *base64_decode(const char *str, size_t *sz)
{
	size_t len = strlen(str);
	uint8_t *buf = (uint8_t *)malloc(len + 1);
	memset(buf, 0, len + 1);

	BIO *b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	BIO *bmem = BIO_new_mem_buf((void *)str, (int)len);
	BIO_push(b64, bmem);
	*sz = BIO_read(b64, buf, (int)len);

	BIO_free(bmem);
	BIO_free(b64);

	if (*sz == -1) {
		free(buf);
		return NULL;
	}
	return buf;
}

#ifdef WASM_TEST
std::string base64_encode(void *dat, size_t sz)
{
	BIO *b64 = BIO_new(BIO_f_base64());
	BIO *bmem = BIO_new(BIO_s_mem());

	/* Single line output, please */
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(b64, bmem);
	if (BIO_write(b64, dat, (int)sz) == -1) {
		BIO_free(bmem);
		BIO_free(b64);
		return NULL;
	}
	BIO_flush(b64);

	char *bstr;
	int len = BIO_get_mem_data(bmem, &bstr);
	char *dup = (char *)malloc(len + 1);
	memcpy(dup, bstr, len);
	dup[len] = 0;
	std::string res(dup, len);

	BIO_free(bmem);
	BIO_free(b64);
	return res;
}

std::vector<uint8_t> readBinaryContent(const std::string &filePath)
{
	std::ifstream file(filePath, std::ios::binary);
	if (!file.is_open()) {
		RATS_ERR("Error: Unable to open quote file %s\n", filePath.c_str());
		return {};
	}

	file.seekg(0, std::ios_base::end);
	std::streampos fileSize = file.tellg();

	file.seekg(0, std::ios_base::beg);
	std::vector<uint8_t> retVal(fileSize);
	file.read(reinterpret_cast<char *>(retVal.data()), fileSize);
	file.close();
	return retVal;
}

int test(std::string hash)
{
	attestation_evidence_t evidence;
	std::vector<uint8_t> evidence_vec = readBinaryContent("evidence.bin");
	memcpy(&evidence, evidence_vec.data(), evidence_vec.size());

	std::string evidence_base64 = base64_encode((void *)&evidence, sizeof(evidence));
	printf("Base64 evidence is:\n%s\n", evidence_base64.c_str());
	std::string hash_base64 = base64_encode((void *)hash.c_str(), hash.length());
	printf("Base64 hash is:\n%s\n", hash_base64.c_str());
	rats_verifier_err_t err = evidence_verify(evidence_base64, hash_base64);
	if (err != RATS_VERIFIER_ERR_NONE) {
		printf("Failed to verify evidence %#x\n", err);
		return -1;
	}
	printf("Evidence trusted.\n");
	return 0;
}
#endif

rats_verifier_err_t evidence_verify(std::string evidence_base64, std::string hash_base64)
{
	uint8_t *hash = NULL;
	size_t hash_len = 0;
	uint8_t *evidence_bytes = NULL;
	size_t evidence_len = 0;
	rats_verifier_err_t ver_ret = RATS_VERIFIER_ERR_NONE;

	attestation_evidence_t evidence;
	evidence_bytes = base64_decode(evidence_base64.c_str(), &evidence_len);
	memcpy(&evidence, evidence_bytes, evidence_len);

	hash = base64_decode(hash_base64.c_str(), &hash_len);
	ver_ret = librats_verify_evidence(&evidence, hash, NULL, NULL);
	if (ver_ret != RATS_VERIFIER_ERR_NONE) {
		RATS_ERR("Failed to verify evidence %#x\n", ver_ret);
		goto err;
	}
err:
	if (hash) {
		free(hash);
	}
	if (evidence_bytes) {
		free(evidence_bytes);
	}
	return ver_ret;
}

EMSCRIPTEN_BINDINGS(RATS_VERIFIER)
{
	emscripten::enum_<rats_verifier_err_t>("VerifierCode")
		.value("ERR_NONE", RATS_VERIFIER_ERR_NONE)
		.value("ERR_UNKNOWN", RATS_VERIFIER_ERR_UNKNOWN)
		.value("ERR_NO_MEM", RATS_VERIFIER_ERR_NO_MEM)
		.value("ERR_NOT_REGISTERED", RATS_VERIFIER_ERR_NOT_REGISTERED)
		.value("ERR_INVALID", RATS_VERIFIER_ERR_INVALID)
		.value("ERR_DLOPEN", RATS_VERIFIER_ERR_DLOPEN)
		.value("ERR_INIT", RATS_VERIFIER_ERR_INIT)
		.value("ERR_NO_TOOL", RATS_VERIFIER_ERR_NO_TOOL);
#ifdef WASM_TEST
	emscripten::function("test", &test);
#endif
	emscripten::function("evidence_verify", &evidence_verify);
}
