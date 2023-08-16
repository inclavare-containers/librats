/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <librats/log.h>
#include <librats/crypto_wrapper.h>
#include <librats/cert.h>
#include "internal/dice.h"
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>

static int find_extension_from_cert(X509 *cert, const char *oid, uint8_t **data_out,
				    size_t *data_len_out, bool optional)
{
	ASN1_OCTET_STRING *octet;
	X509_EXTENSION *ext;
	void *data = NULL;
	size_t data_len;

	*data_out = NULL;
	*data_len_out = 0;

	int nid = OBJ_txt2nid(oid);
	if (nid == NID_undef) {
		nid = OBJ_create(oid, NULL, NULL);
		if (nid == NID_undef) {
			RATS_ERR("failed to create the object %s\n", oid);
			return 1;
		}
	}

	int pos = X509_get_ext_by_NID(cert, nid, -1);
	if (pos == -1) {
		if (optional) /* ok if extension is optional */
			return 0;
		return 1;
	}

	ext = X509_get_ext(cert, pos);
	if (!ext)
		return 1;

	octet = X509_EXTENSION_get_data(ext);
	data_len = octet->length;

	data = malloc(data_len);
	if (!data)
		return 1;

	memcpy(data, octet->data, octet->length);
	*data_out = data;
	*data_len_out = data_len;

	return 0;
}

/* We use this verify_callback function to customize it to tolerate self-signed certificates. */
static int _cert_verify_callback(int ok, X509_STORE_CTX *ctx)
{
	if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
		return 1;
	}

	return ok;
}

crypto_wrapper_err_t openssl_verify_cert(crypto_wrapper_ctx_t *ctx, const uint8_t *certificate,
					 size_t certificate_size)
{
	RATS_DEBUG("ctx: %p, certificate: %p, certificate_size %zu\n", ctx, certificate,
		   certificate_size);

	crypto_wrapper_err_t ret = CRYPTO_WRAPPER_ERR_NONE;
	X509 *cert = NULL;
	uint8_t *evidence_buffer = NULL;
	size_t evidence_buffer_size = 0;
	uint8_t *endorsements_buffer = NULL;
	size_t endorsements_buffer_size = 0;

	/* Decode certificate as DER format */
	ret = CRYPTO_WRAPPER_ERR_CERT_PARSE;
	const unsigned char *t = (const unsigned char *)certificate;
	if (!d2i_X509(&cert, &t, certificate_size)) {
		RATS_ERR("bad certificate format\n");
		return CRYPTO_WRAPPER_ERR_CERT;
	}

	/* Get pubkey in SubjectPublicKeyInfo format from cert */
	EVP_PKEY *pkey = X509_get_pubkey(cert);
	if (!pkey) {
		RATS_ERR("Unable to decode the public key from certificate\n");
		X509_free(cert);
		return CRYPTO_WRAPPER_ERR_CERT;
	}
	int pubkey_buffer_size = i2d_PUBKEY(pkey, NULL);
	unsigned char pubkey_buffer[pubkey_buffer_size];
	unsigned char *p = pubkey_buffer;
	i2d_PUBKEY(pkey, &p);
	EVP_PKEY_free(pkey);

	/* Check digest of this cert */
	X509_STORE *x509_store = X509_STORE_new();
	X509_STORE_set_flags(x509_store, 0);
	X509_STORE_CTX *x509_store_ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(x509_store_ctx, x509_store, cert, NULL);
	X509_STORE_set_verify_cb(x509_store, _cert_verify_callback);
	X509_STORE_CTX_set_purpose(x509_store_ctx, X509_PURPOSE_ANY);
	ret = X509_verify_cert(x509_store_ctx);

	/* Extract the evidence_buffer(optional for nullverifier) and endorsements_buffer(optional)
	 * from the X.509 certificate extension.
	 */
	ret = CRYPTO_WRAPPER_ERR_CERT_EXTENSION;
	/* Extract evidence from extension */
	int rc = find_extension_from_cert(cert, TCG_DICE_TAGGED_EVIDENCE_OID, &evidence_buffer,
					  &evidence_buffer_size, true);
	if (rc) {
		RATS_ERR("failed to extract the evidence extensions from the certificate\n");
		goto err;
	}

	/* Extract endorsements from extension */
	rc = find_extension_from_cert(cert, TCG_DICE_ENDORSEMENT_MANIFEST_OID, &endorsements_buffer,
				      &endorsements_buffer_size, true);
	if (rc) {
		RATS_ERR("failed to extract the endorsements extensions from the certificate\n");
		goto err;
	}

	/* Verify evidence and endorsements */
	ret = crypto_wrapper_verify_certificate_extension(ctx, pubkey_buffer, pubkey_buffer_size,
							  evidence_buffer, evidence_buffer_size,
							  endorsements_buffer,
							  endorsements_buffer_size);
	if (ret != CRYPTO_WRAPPER_ERR_NONE) {
		RATS_ERR("failed to verify certificate extension: %#x\n", ret);
		goto err;
	}

	ret = CRYPTO_WRAPPER_ERR_NONE;
err:
	if (cert)
		X509_free(cert);
	if (evidence_buffer)
		free(evidence_buffer);
	if (endorsements_buffer)
		free(endorsements_buffer);
	return ret;
}
