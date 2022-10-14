#include <librats/api.h>
#include <librats/log.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <unistd.h>

int generate_key_pairs(uint8_t **private_key_out, size_t *private_key_size_out,
		       uint8_t **public_key_out, size_t *public_key_size_out)
{
	EC_KEY *eckey = NULL;
	EVP_PKEY *pkey = NULL;

	BIO *bio = NULL;
	BUF_MEM *bptr = NULL;

	uint8_t *private_key = NULL;
	long private_key_size;
	uint8_t *public_key = NULL;
	long public_key_size;

	int ret = -1;

	/* Generate private key and public key */
	eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (!eckey)
		goto err;
	EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

	if (!EC_KEY_generate_key(eckey))
		goto err;

	if (!EC_KEY_check_key(eckey))
		goto err;

	pkey = EVP_PKEY_new();
	EVP_PKEY_assign_EC_KEY(pkey, eckey);
	eckey = NULL;

	/* Encode private key */
	bio = BIO_new(BIO_s_mem());
	if (!bio)
		goto err;

	if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, 0, NULL))
		goto err;

	private_key_size = BIO_get_mem_data(bio, &private_key);
	if (private_key_size <= 0)
		goto err;

	BIO_get_mem_ptr(bio, &bptr);
	(void)BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free(bio);
	bio = NULL;
	bptr->data = NULL;
	BUF_MEM_free(bptr);
	bptr = NULL;

	/* Encode public key */
	bio = BIO_new(BIO_s_mem());
	if (!bio)
		goto err;

	if (!PEM_write_bio_PUBKEY(bio, pkey))
		goto err;

	public_key_size = BIO_get_mem_data(bio, &public_key);
	if (public_key_size <= 0)
		goto err;

	BIO_get_mem_ptr(bio, &bptr);
	(void)BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free(bio);
	bio = NULL;
	bptr->data = NULL;
	BUF_MEM_free(bptr);
	bptr = NULL;

	/* Set function output */
	*private_key_out = private_key;
	private_key = NULL;
	*private_key_size_out = private_key_size;
	*public_key_out = public_key;
	public_key = NULL;
	*public_key_size_out = public_key_size;

	ret = 0;
err:
	if (private_key)
		free(private_key);
	if (public_key)
		free(public_key);
	if (bio)
		BIO_free(bio);
	if (bptr)
		BUF_MEM_free(bptr);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (eckey)
		EC_KEY_free(eckey);
	if (ret)
		RATS_ERR("Failed to generate private key\n");
	return ret;
}

rats_err_t verify_callback(claim_t *claims, size_t claims_size, void *args_in)
{
	rats_err_t ret = RATS_ERR_NONE;

	RATS_INFO("verify_callback called, claims %p, claims_size %zu, args %p\n", claims,
		  claims_size, args_in);
	for (size_t i = 0; i < claims_size; ++i) {
		RATS_INFO("claims[%zu] -> name: '%s' value_size: %zu value: '%.*s'\n", i,
			  claims[i].name, claims[i].value_size, (int)claims[i].value_size,
			  claims[i].value);
	}

	/* Let's check all custom claims exits and unchanged */
	typedef struct {
		const claim_t *custom_claims;
		size_t custom_claims_size;
	} args_t;
	args_t *args = (args_t *)args_in;

	RATS_INFO("checking for all %zu user-defined custom claims\n", args->custom_claims_size);

	for (size_t i = 0; i < args->custom_claims_size; ++i) {
		const claim_t *claim = &args->custom_claims[i];
		bool found = false;
		for (size_t j = 0; j < claims_size; ++j) {
			if (!strcmp(claim->name, claims[j].name)) {
				found = true;
				if (claim->value_size != claims[j].value_size) {
					RATS_ERR(
						"different claim detected -> name: '%s' expected value_size: %zu got: %zu\n",
						claim->name, claim->value_size,
						claims[j].value_size);
					ret = RATS_ERR_INVALID;
					break;
				}

				if (memcmp(claim->value, claims[j].value, claim->value_size)) {
					RATS_ERR(
						"different claim detected -> name: '%s' value_size: %zu expected value: '%.*s' got: '%.*s'\n",
						claim->name, claim->value_size,
						(int)claim->value_size, claim->value,
						(int)claim->value_size, claims[j].value);
					ret = RATS_ERR_INVALID;
					break;
				}
				break;
			}
		}
		if (!found) {
			RATS_ERR("different claim detected -> name: '%s' not found\n", claim->name);
			ret = RATS_ERR_INVALID;
		}
	}
	RATS_INFO("verify_callback check result:\t%s\n",
		  ret == RATS_ERR_NONE ? "SUCCESS" : "FAILED");
	return ret;
}

int get_attestation_certificate(const char *subject_name, const claim_t *custom_claims,
				size_t custom_claims_size, uint8_t **certificate_out,
				size_t *certificate_size_out)
{
	uint8_t *private_key = NULL;
	size_t private_key_size;
	uint8_t *public_key = NULL;
	size_t public_key_size;

	int ret = -1;
	rats_attester_err_t rats_ret;

	/* Generate private key and public key */
	if (generate_key_pairs(&private_key, &private_key_size, &public_key, &public_key_size) < 0)
		goto err;

	/* Collect certificate */
	rats_ret = librats_get_attestation_certificate(subject_name, private_key, private_key_size,
						       public_key, public_key_size, custom_claims,
						       custom_claims_size, certificate_out,
						       certificate_size_out);
	if (rats_ret != RATS_ATTESTER_ERR_NONE) {
		RATS_ERR("Failed to generate certificate %#x\n", rats_ret);
		goto err;
	}
	ret = 0;
err:
	if (private_key)
		free(private_key);
	if (public_key)
		free(public_key);
	return ret;
}

int verify_attestation_certificate(uint8_t *certificate, size_t certificate_size, void *args)
{
	int ret = -1;
	rats_verifier_err_t rats_ret;
	/* Verify certificate */
	rats_ret = librats_verify_attestation_certificate(certificate, certificate_size,
							  verify_callback, args);
	if (rats_ret != RATS_VERIFIER_ERR_NONE) {
		RATS_ERR("Failed to verify certificate %#x\n", rats_ret);
		goto err;
	}
	ret = 0;
err:
	return ret;
}