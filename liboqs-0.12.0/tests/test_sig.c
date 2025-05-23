// SPDX-License-Identifier: MIT

#if defined(_WIN32)
#pragma warning(disable : 4244 4293)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#if OQS_USE_PTHREADS
#include <pthread.h>
#endif

#ifdef OQS_ENABLE_TEST_CONSTANT_TIME
#include <valgrind/memcheck.h>
#define OQS_TEST_CT_CLASSIFY(addr, len)  VALGRIND_MAKE_MEM_UNDEFINED(addr, len)
#define OQS_TEST_CT_DECLASSIFY(addr, len)  VALGRIND_MAKE_MEM_DEFINED(addr, len)
#else
#define OQS_TEST_CT_CLASSIFY(addr, len)
#define OQS_TEST_CT_DECLASSIFY(addr, len)
#endif

#include "system_info.c"

typedef struct magic_s {
	uint8_t val[31];
} magic_t;

static OQS_STATUS sig_test_correctness(const char *method_name) {

	OQS_SIG *sig = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *message = NULL;
	size_t message_len = 100;
	uint8_t ctx[257] = { 0 };
	uint8_t *signature = NULL;
	size_t signature_len;
	OQS_STATUS rc, ret = OQS_ERROR;

	//The magic numbers are random values.
	//The length of the magic number was chosen to be 31 to break alignment
	magic_t magic;
	OQS_randombytes(magic.val, sizeof(magic_t));

	sig = OQS_SIG_new(method_name);
	if (sig == NULL) {
		fprintf(stderr, "ERROR: OQS_SIG_new failed\n");
		goto err;
	}

	printf("================================================================================\n");
	printf("Sample computation for signature %s\n", sig->method_name);
	printf("================================================================================\n");

	public_key = OQS_MEM_malloc(sig->length_public_key + 2 * sizeof(magic_t));
	secret_key = OQS_MEM_malloc(sig->length_secret_key + 2 * sizeof(magic_t));
	message = OQS_MEM_malloc(message_len + 2 * sizeof(magic_t));
	signature = OQS_MEM_malloc(sig->length_signature + 2 * sizeof(magic_t));

	if ((public_key == NULL) || (secret_key == NULL) || (message == NULL) || (signature == NULL)) {
		fprintf(stderr, "ERROR: OQS_MEM_malloc failed\n");
		goto err;
	}

	//Set the magic numbers before
	memcpy(public_key, magic.val, sizeof(magic_t));
	memcpy(secret_key, magic.val, sizeof(magic_t));
	memcpy(message, magic.val, sizeof(magic_t));
	memcpy(signature, magic.val, sizeof(magic_t));

	public_key += sizeof(magic_t);
	secret_key += sizeof(magic_t);
	message += sizeof(magic_t);
	signature += sizeof(magic_t);

	// and after
	memcpy(public_key + sig->length_public_key, magic.val, sizeof(magic_t));
	memcpy(secret_key + sig->length_secret_key, magic.val, sizeof(magic_t));
	memcpy(message + message_len, magic.val, sizeof(magic_t));
	memcpy(signature + sig->length_signature, magic.val, sizeof(magic_t));

	OQS_randombytes(message, message_len);
	OQS_TEST_CT_DECLASSIFY(message, message_len);

	rc = OQS_SIG_keypair(sig, public_key, secret_key);
	OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_keypair failed\n");
		goto err;
	}

	rc = OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key);
	OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_sign failed\n");
		goto err;
	}

	OQS_TEST_CT_DECLASSIFY(public_key, sig->length_public_key);
	OQS_TEST_CT_DECLASSIFY(signature, signature_len);
	rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
	OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_verify failed\n");
		goto err;
	}

	/* modify the signature to invalidate it */
	OQS_randombytes(signature, signature_len);
	OQS_TEST_CT_DECLASSIFY(signature, signature_len);
	rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
	OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
	if (rc != OQS_ERROR) {
		fprintf(stderr, "ERROR: OQS_SIG_verify should have failed!\n");
		goto err;
	}

	/* testing signing with context, if supported */
	OQS_randombytes(ctx, 257);
	if (sig->sig_with_ctx_support) {
		for (size_t i = 0; i < 256; ++i) {
			rc = OQS_SIG_sign_with_ctx_str(sig, signature, &signature_len, message, message_len, ctx, i, secret_key);
			OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
			if (rc != OQS_SUCCESS) {
				fprintf(stderr, "ERROR: OQS_SIG_sign_with_ctx_str failed\n");
				goto err;
			}

			OQS_TEST_CT_DECLASSIFY(public_key, sig->length_public_key);
			OQS_TEST_CT_DECLASSIFY(signature, signature_len);
			rc = OQS_SIG_verify_with_ctx_str(sig, message, message_len, signature, signature_len, ctx, i, public_key);
			OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
			if (rc != OQS_SUCCESS) {
				fprintf(stderr, "ERROR: OQS_SIG_verify_with_ctx_str failed\n");
				goto err;
			}

			/* modify the signature to invalidate it */
			OQS_randombytes(signature, signature_len);
			OQS_TEST_CT_DECLASSIFY(signature, signature_len);
			rc = OQS_SIG_verify_with_ctx_str(sig, message, message_len, signature, signature_len, ctx, i, public_key);
			OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
			if (rc != OQS_ERROR) {
				fprintf(stderr, "ERROR: OQS_SIG_verify_with_ctx_str should have failed!\n");
				goto err;
			}
		}

		rc = OQS_SIG_sign_with_ctx_str(sig, signature, &signature_len, message, message_len, ctx, 257, secret_key);
		OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
		if (rc != OQS_ERROR) {
			fprintf(stderr, "ERROR: OQS_SIG_sign_with_ctx_str should only support up to 256 byte contexts\n");
			goto err;
		}
	} else {
		rc = OQS_SIG_sign_with_ctx_str(sig, signature, &signature_len, message, message_len, ctx, 1, secret_key);
		if (rc != OQS_ERROR) {
			fprintf(stderr, "ERROR: OQS_SIG_sign_with_ctx_str should fail without support for context strings\n");
			goto err;
		}
	}

	rc = OQS_SIG_sign_with_ctx_str(sig, signature, &signature_len, message, message_len, NULL, 0, secret_key);
	OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_sign_with_ctx_str should always succeed when providing a NULL context string\n");
		goto err;
	}
	OQS_TEST_CT_DECLASSIFY(public_key, sig->length_public_key);
	OQS_TEST_CT_DECLASSIFY(signature, signature_len);
	rc = OQS_SIG_verify_with_ctx_str(sig, message, message_len, signature, signature_len, NULL, 0, public_key);
	OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_verify_with_ctx_str failed\n");
		goto err;
	}

	/* modify the signature to invalidate it */
	OQS_randombytes(signature, signature_len);
	OQS_TEST_CT_DECLASSIFY(signature, signature_len);
	rc = OQS_SIG_verify_with_ctx_str(sig, message, message_len, signature, signature_len, NULL, 0, public_key);
	OQS_TEST_CT_DECLASSIFY(&rc, sizeof rc);
	if (rc != OQS_ERROR) {
		fprintf(stderr, "ERROR: OQS_SIG_verify_with_ctx_str should have failed!\n");
		goto err;
	}

#ifndef OQS_ENABLE_TEST_CONSTANT_TIME
	/* check magic values */
	int rv = memcmp(public_key + sig->length_public_key, magic.val, sizeof(magic_t));
	rv |= memcmp(secret_key + sig->length_secret_key, magic.val, sizeof(magic_t));
	rv |= memcmp(message + message_len, magic.val, sizeof(magic_t));
	rv |= memcmp(signature + sig->length_signature, magic.val, sizeof(magic_t));
	rv |= memcmp(public_key - sizeof(magic_t), magic.val, sizeof(magic_t));
	rv |= memcmp(secret_key - sizeof(magic_t), magic.val, sizeof(magic_t));
	rv |= memcmp(message - sizeof(magic_t), magic.val, sizeof(magic_t));
	rv |= memcmp(signature - sizeof(magic_t), magic.val, sizeof(magic_t));
	if (rv) {
		fprintf(stderr, "ERROR: Magic numbers do not match\n");
		goto err;
	}
#endif

	printf("verification passes as expected\n");
	ret = OQS_SUCCESS;
	goto cleanup;

err:
	ret = OQS_ERROR;

cleanup:
	if (secret_key) {
		OQS_MEM_secure_free(secret_key - sizeof(magic_t), sig->length_secret_key + 2 * sizeof(magic_t));
	}
	if (public_key) {
		OQS_MEM_insecure_free(public_key - sizeof(magic_t));
	}
	if (message) {
		OQS_MEM_insecure_free(message - sizeof(magic_t));
	}
	if (signature) {
		OQS_MEM_insecure_free(signature - sizeof(magic_t));
	}
	OQS_SIG_free(sig);

	return ret;
}

#ifdef OQS_ENABLE_TEST_CONSTANT_TIME
static void TEST_SIG_randombytes(uint8_t *random_array, size_t bytes_to_read) {
	// We can't make direct calls to the system randombytes on some platforms,
	// so we have to swap out the OQS_randombytes provider.
	OQS_randombytes_switch_algorithm("system");
	OQS_randombytes(random_array, bytes_to_read);
	OQS_randombytes_custom_algorithm(&TEST_SIG_randombytes);

	// OQS_TEST_CT_CLASSIFY tells Valgrind's memcheck tool to issue a warning if
	// the program branches on any byte that depends on random_array. This helps us
	// identify timing side-channels, as these bytes often contain secret data.
	OQS_TEST_CT_CLASSIFY(random_array, bytes_to_read);
}
#endif

#if OQS_USE_PTHREADS
struct thread_data {
	char *alg_name;
	OQS_STATUS rc;
};

void *test_wrapper(void *arg) {
	struct thread_data *td = arg;
	td->rc = sig_test_correctness(td->alg_name);
	OQS_thread_stop();
	return NULL;
}
#endif

int main(int argc, char **argv) {
	OQS_init();

	printf("Testing signature algorithms using liboqs version %s\n", OQS_version());

	if (argc != 2) {
		fprintf(stderr, "Usage: test_sig algname\n");
		fprintf(stderr, "  algname: ");
		for (size_t i = 0; i < OQS_SIG_algs_length; i++) {
			if (i > 0) {
				fprintf(stderr, ", ");
			}
			fprintf(stderr, "%s", OQS_SIG_alg_identifier(i));
		}
		fprintf(stderr, "\n");
		OQS_destroy();
		return EXIT_FAILURE;
	}

	print_system_info();

	char *alg_name = argv[1];
	if (!OQS_SIG_alg_is_enabled(alg_name)) {
		printf("Signature algorithm %s not enabled!\n", alg_name);
		OQS_destroy();
		return EXIT_FAILURE;
	}

#ifdef OQS_ENABLE_TEST_CONSTANT_TIME
	OQS_randombytes_custom_algorithm(&TEST_SIG_randombytes);
#else
	OQS_randombytes_switch_algorithm("system");
#endif

	OQS_STATUS rc;
#if OQS_USE_PTHREADS
#define MAX_LEN_SIG_NAME_ 64
	// don't run algorithms with large stack usage in threads
	char no_thread_sig_patterns[][MAX_LEN_SIG_NAME_]  = {"MAYO-5", "cross-rsdp-128-small", "cross-rsdp-192-small", "cross-rsdp-256-balanced", "cross-rsdp-256-small", "cross-rsdpg-192-small", "cross-rsdpg-256-small"};
	int test_in_thread = 1;
	for (size_t i = 0 ; i < sizeof(no_thread_sig_patterns) / MAX_LEN_SIG_NAME_; ++i) {
		if (strstr(alg_name, no_thread_sig_patterns[i]) != NULL) {
			test_in_thread = 0;
			break;
		}
	}
	if (test_in_thread) {
		pthread_t thread;
		struct thread_data td;
		td.alg_name = alg_name;
		int trc = pthread_create(&thread, NULL, test_wrapper, &td);
		if (trc) {
			fprintf(stderr, "ERROR: Creating pthread\n");
			OQS_destroy();
			return EXIT_FAILURE;
		}
		pthread_join(thread, NULL);
		rc = td.rc;
	} else {
		rc = sig_test_correctness(alg_name);
	}
#else
	rc = sig_test_correctness(alg_name);
#endif
	if (rc != OQS_SUCCESS) {
		OQS_destroy();
		return EXIT_FAILURE;
	}
	OQS_destroy();
	return EXIT_SUCCESS;
}
