/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <librats/log.h>
#include <librats/cert.h>
#include <internal/dice.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>

#define CERT_SERIAL_NUMBER 1

static bool using_cert_nonce = false;

int openssl_calc_pubkey_sha256(EVP_PKEY *pkey, uint8_t *hash)

{
	uint8_t *pubkey_blob = NULL;
	int pubkey_blob_size;
	int ret;

	ret = -1;
	/* blob in SubjectPublicKeyInfo(SPKI) format */
	pubkey_blob_size = i2d_PUBKEY(pkey, &pubkey_blob);
	if (pubkey_blob_size < 0)
		goto err;

	SHA256(pubkey_blob, pubkey_blob_size, hash);
	RATS_DEBUG(
		"the sha256 of public key [%d] %02x%02x%02x%02x%02x%02x%02x%02x...%02x%02x%02x%02x\n",
		SHA256_DIGEST_LENGTH, hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6],
		hash[7], hash[28], hash[29], hash[30], hash[31]);

	ret = 0;
err:
	if (pubkey_blob)
		free(pubkey_blob);
	return ret;
}

static rats_err_t x509_extension_add(X509 *cert, const char *oid, bool critical, const void *data,
				     size_t data_len)
{
	ASN1_OCTET_STRING *octet = NULL;
	X509_EXTENSION *ext = NULL;
	rats_err_t ret;

	ret = RATS_ERR_INVALID_PARAMETER;
	int nid = OBJ_txt2nid(oid);
	if (nid == NID_undef) {
		nid = OBJ_create(oid, NULL, NULL);
		if (nid == NID_undef) {
			RATS_ERR("failed to create the object %s\n", oid);
			goto err;
		}
	}

	ret = RATS_ERR_NO_MEM;
	octet = ASN1_OCTET_STRING_new();
	if (!octet)
		goto err;

	if (!ASN1_OCTET_STRING_set(octet, data, data_len))
		goto err;

	ext = X509_EXTENSION_create_by_NID(NULL, nid, critical, octet);
	if (!ext) {
		RATS_ERR("failed to create extension\n");
		goto err;
	}

	if (!X509_add_ext(cert, ext, -1)) {
		RATS_ERR("failed to add extension %s\n", oid);
		goto err;
	}

	ret = RATS_ERR_NONE;

err:
	if (ext)
		X509_EXTENSION_free(ext);

	if (octet)
		ASN1_OCTET_STRING_free(octet);

	return ret;
}

static rats_err_t x509_extension_get(X509 *cert, const char *oid, uint8_t **data_out,
				     size_t *data_len_out, bool optional)
{
	ASN1_OCTET_STRING *octet;
	X509_EXTENSION *ext;
	void *data = NULL;
	size_t data_len;
	rats_err_t ret;

	*data_out = NULL;
	*data_len_out = 0;

	ret = RATS_ERR_INVALID_PARAMETER;
	int nid = OBJ_txt2nid(oid);
	if (nid == NID_undef) {
		nid = OBJ_create(oid, NULL, NULL);
		if (nid == NID_undef) {
			RATS_ERR("failed to create the object %s\n", oid);
			goto err;
		}
	}

	ret = RATS_ERR_UNKNOWN;
	int pos = X509_get_ext_by_NID(cert, nid, -1);
	if (pos == -1) {
		if (optional) /* ok if extension is optional */
			ret = RATS_ERR_NONE;
		goto err;
	}

	ext = X509_get_ext(cert, pos);
	if (!ext)
		goto err;

	octet = X509_EXTENSION_get_data(ext);
	data_len = octet->length;

	ret = RATS_ERR_NO_MEM;
	data = malloc(data_len);
	if (!data)
		goto err;

	memcpy(data, octet->data, octet->length);
	*data_out = data;
	*data_len_out = data_len;

	ret = RATS_ERR_NONE;
err:
	return ret;
}

rats_attester_err_t add_cert_extensions(X509 *cert, const cert_extension_info_t *extension_info)
{
	X509V3_CTX ctx;
	X509_EXTENSION *ext = NULL;
	rats_attester_err_t ret;

	/* Add some essential extensions */
	ret = RATS_ATTESTER_ERR_CERT_EXTENSION;
	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

	ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "CA:FALSE");
	if (!ext) {
		RATS_ERR("failed to create basic constraint extension\n");
		goto err;
	}
	if (!X509_add_ext(cert, ext, -1)) {
		RATS_ERR("failed to add basic constraint extension\n");
		goto err;
	}
	X509_EXTENSION_free(ext);

	ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
	if (!ext) {
		RATS_ERR("failed to create subject key identifier extension\n");
		goto err;
	}
	if (!X509_add_ext(cert, ext, -1)) {
		RATS_ERR("failed to add subject key identifier extension\n");
		goto err;
	}
	X509_EXTENSION_free(ext);

	ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier, "keyid:always");
	if (!ext) {
		RATS_ERR("failed to create authority key identifier extension\n");
		goto err;
	}
	if (!X509_add_ext(cert, ext, -1)) {
		RATS_ERR("failed to add authority key identifier extension\n");
		goto err;
	}
	X509_EXTENSION_free(ext);
	ext = NULL;

	/* Add evidence extension */
	if (extension_info->evidence_buffer_size) {
		ret = RATS_ATTESTER_ERR_CERT_EXTENSION;
		/* The DiceTaggedEvidence extension criticality flag SHOULD be marked critical. */
		if (x509_extension_add(cert, TCG_DICE_TAGGED_EVIDENCE_OID, true,
				       extension_info->evidence_buffer,
				       extension_info->evidence_buffer_size) != RATS_ERR_NONE)
			goto err;
	}

	/* Add endorsements extension */
	if (extension_info->endorsements_buffer_size) {
		ret = RATS_ATTESTER_ERR_CERT_EXTENSION;
		if (x509_extension_add(cert, TCG_DICE_ENDORSEMENT_MANIFEST_OID, true,
				       extension_info->endorsements_buffer,
				       extension_info->endorsements_buffer_size) != RATS_ERR_NONE)
			goto err;
	}

	ret = RATS_ATTESTER_ERR_NONE;
err:
	if (ext)
		X509_EXTENSION_free(ext);
	return ret;
}

static bool _rfc2253_is_escape_char(char c)
{
	return c == ',' || c == '=' || c == '+' || c == '<' || c == '>' || c == '#' || c == ';' ||
	       c == '\\';
}

/* Parse RDN in rfc2253 format. For example: "CN=xxx,OU=xxx,ST=xxx,C=FR"
 */
static int parse_x509_name(X509_NAME *name, const char *subject_name)
{
	size_t len;
	char *tmp = NULL;
	char *p;
	char *attr_type;
	char *attr_value;
	int ret = -1;

	len = strlen(subject_name) + 1;
	tmp = malloc(len);
	if (!tmp)
		return -1;
	memcpy(tmp, subject_name, len);

	p = tmp;
	while (*p) {
		{
			/* find '=' */
			char *t = p;
			for (; *t != '\0'; t++) {
				if (*t == '=')
					break;
			}
			if (*t == '\0')
				goto err;

			*t = '\0';
			attr_type = p;
			p = t + 1;
		}

		{
			/* find ',' or '\0' */
			char *t = p;
			for (; *t != '\0'; t++) {
				if (*t == ',')
					break;
				if (*t == '\\' && _rfc2253_is_escape_char(t[1]))
					t++;
			}
			attr_value = p;
			if (*t == '\0') {
				p = t;
			} else {
				*t = '\0';
				p = t + 1;
			}

			/* Remove '\' before escape char */
			char *r = attr_value;
			char *w = attr_value;
			while (r <= t) {
				if (*r == '\\' && _rfc2253_is_escape_char(r[1]))
					r++;
				if (r != w)
					*w = *r;
				r++;
				w++;
			}
			*w = '\0';
		}
		X509_NAME_add_entry_by_txt(name, attr_type, MBSTRING_ASC,
					   (const unsigned char *)attr_value, -1, -1, 0);
	}

	ret = 0;
err:
	if (tmp)
		free(tmp);

	return ret;
}

rats_attester_err_t openssl_gen_cert(rats_cert_info_t *cert_info, uint8_t **output_certificate,
				     size_t *output_certificate_size)
{
	X509 *cert = NULL;
	X509_NAME *name;
	uint8_t *der = NULL;
	rats_attester_err_t ret;

	RATS_DEBUG("cert_info %p\n", cert_info);

	if (!cert_info)
		return RATS_ATTESTER_ERR_INVALID;

	/* Generate certificate */
	ret = RATS_ATTESTER_ERR_NO_MEM;
	cert = X509_new();
	if (!cert)
		goto err;

	X509_set_version(cert, 3);
	ASN1_INTEGER_set(X509_get_serialNumber(cert), CERT_SERIAL_NUMBER);
	if (!using_cert_nonce) {
		/* WORKAROUND: allow 1 hour delay for the systems behind current clock
         */
		X509_gmtime_adj(X509_get_notBefore(cert), -3600);
		/* 1 year */
		X509_gmtime_adj(X509_get_notAfter(cert), (long)3600 * 24 * 365 * 1);
	} else {
		/* WORKAROUND: with nonce mechanism, the validity of cert can be fixed
         * within a larger range. */
		const char timestr_notBefore[] = "19700101000001Z";
		const char timestr_notAfter[] = "20491231235959Z";
		ASN1_TIME_set_string(X509_get_notBefore(cert), timestr_notBefore);
		ASN1_TIME_set_string(X509_get_notAfter(cert), timestr_notAfter);
	}

	ret = RATS_ATTESTER_ERR_CERT_PUB_KEY;
	if (!X509_set_pubkey(cert, cert_info->key.public_key))
		goto err;

	/* subject name */
	name = X509_get_subject_name(cert);
	if (!name)
		goto err;

	ret = RATS_ATTESTER_ERR_CERT_SUBJECT_NAME;
	if (parse_x509_name(name, cert_info->subject_name) != 0)
		goto err;

	/* Set issuer name to the same as subject name */
	if (!X509_set_issuer_name(cert, name))
		goto err;

	ret = add_cert_extensions(cert, &cert_info->extension_info);
	if (ret != RATS_ATTESTER_ERR_NONE)
		goto err;

	ret = RATS_ATTESTER_ERR_CERT_GEN;
	if (!X509_sign(cert, cert_info->key.private_key, EVP_sha256()))
		goto err;

	/* Encode certificate to DER format */
	int len = i2d_X509(cert, &der);
	if (len < 0)
		goto err;

	*output_certificate = der;
	der = NULL;
	*output_certificate_size = len;

	RATS_DEBUG("self-signing certificate generated\n");

	ret = RATS_ATTESTER_ERR_NONE;

err:
	if (ret != RATS_ATTESTER_ERR_NONE)
		RATS_DEBUG("failed to generate certificate %d\n", ret);

	if (der)
		free(der);

	if (cert)
		X509_free(cert);

	return ret;
}

rats_verifier_err_t openssl_parse_cert(const uint8_t *certificate, size_t certificate_size,
				       EVP_PKEY **publickey, uint8_t **evidence_buffer,
				       size_t *evidence_buffer_size, uint8_t **endorsements_buffer,
				       size_t *endorsements_buffer_size)
{
	X509 *cert = NULL;
	rats_verifier_err_t ret;

	/* Initialize pointer parameters */
	*evidence_buffer = NULL;
	*evidence_buffer_size = 0;
	*endorsements_buffer = NULL;
	*endorsements_buffer_size = 0;

	/* Decode certificate as DER format */
	ret = RATS_VERIFIER_ERR_CERT_PARSE;
	if (!d2i_X509(&cert, &certificate, certificate_size)) {
		RATS_ERR("bad certificate format\n");
		goto err;
	}

	{ /* Extract evidence from extension */
		ret = RATS_VERIFIER_ERR_CERT_EXTENSION;
		rats_err_t ext_ret = x509_extension_get(cert, TCG_DICE_TAGGED_EVIDENCE_OID,
							evidence_buffer, evidence_buffer_size,
							true);
		if (ext_ret != RATS_ERR_NONE) {
			RATS_ERR("failed to get evidence extension from cert: %#x\n", ext_ret);
			goto err;
		}
	}
	{ /* Extract endorsements from extension */
		ret = RATS_VERIFIER_ERR_CERT_EXTENSION;
		rats_err_t ext_ret = x509_extension_get(cert, TCG_DICE_ENDORSEMENT_MANIFEST_OID,
							endorsements_buffer,
							endorsements_buffer_size, true);
		if (ext_ret != RATS_ERR_NONE) {
			RATS_ERR("failed to get endorsement extension from cert: %#x\n", ext_ret);
			goto err;
		}
	}

	/* Extract public key of cert */
	*publickey = X509_get_pubkey(cert);

	ret = RATS_VERIFIER_ERR_NONE;
err:
	if (cert)
		X509_free(cert);
	if (ret != RATS_VERIFIER_ERR_NONE && *evidence_buffer) {
		free(*evidence_buffer);
		*evidence_buffer = NULL;
		*evidence_buffer_size = 0;
	}
	if (ret != RATS_VERIFIER_ERR_NONE && *endorsements_buffer) {
		free(*endorsements_buffer);
		*endorsements_buffer = NULL;
		*endorsements_buffer_size = 0;
	}

	return ret;
}