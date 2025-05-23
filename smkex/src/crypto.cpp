
#include "crypto.h"
//#include "pkt.h" 

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

unsigned char __SYMBOLS[] = "0123456789ABCDEF";



EC_KEY* __new_key_pair(void) {
    // Initialize new curve
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ec_key == NULL) {
        fprintf(stderr, "Error: Could not create EC key.\n");
        return NULL;
    }

    // Generate local key pair
    int rc = EC_KEY_generate_key(ec_key);
    if (rc == 0) {
        fprintf(stderr, "Error: Could not generate ECDH key.\n");
        EC_KEY_free(ec_key);
        return NULL;
    }

    return ec_key;
}

unsigned int compute_sha256(unsigned char dest[], const unsigned char src[], int dlen)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L // OpenSSL 1.0.2
    unsigned int len = 0;
    const EVP_MD *md = EVP_sha256();

    EVP_MD_CTX mdctx;
    EVP_MD_CTX_init(&mdctx);

    EVP_DigestInit_ex(&mdctx, md, NULL);
    EVP_DigestUpdate(&mdctx, src, dlen);
    EVP_DigestFinal_ex(&mdctx, dest, &len);
    EVP_MD_CTX_cleanup(&mdctx);

    return len;

#else // OpenSSL 1.1.1
    unsigned int len = 0;
    const EVP_MD *md = EVP_sha256();

    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, src, dlen);
    EVP_DigestFinal_ex(mdctx, dest, &len);
    EVP_MD_CTX_free(mdctx);

    return len;
#endif

}


void hexdump(unsigned char * string, int length) {
    int i;
    unsigned char c;
    for (i = 0; i < length; i++) {
        c = string[i];
        printf("%c%c", __SYMBOLS[c / 16], __SYMBOLS[c % 16]);
    }
}

void sha1dump(unsigned char * string, int length) {
    unsigned char md[20];
    SHA_CTX context;
    SHA1_Init(&context);
    SHA1_Update(&context, string, length);
    SHA1_Final(md, &context);

    hexdump(md, 20);
}

/*
 * Encrypts ptext with AES-256 in GCM mode and appends the authentication tag
 * length(ctext) = length(ptext) + length(authtag)
 */
int mp_aesgcm_encrypt(const unsigned char * ptext,
        size_t plen,
        const unsigned char * key,
        const unsigned char * iv,
        unsigned char * ctext,
        size_t * clen) {
            
    // Uncomment the following to disable encryption
    //memcpy(ctext, ptext, plen);
    //*clen = plen;
    //return 1;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    OPENSSL_assert(ctx != NULL);

    EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL, 1);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == SESSION_KEY_LENGTH);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == SESSION_IV_LENGTH);
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, -1);

    *clen = 0;

    int out_len;
    if (!EVP_CipherUpdate(ctx, ctext, &out_len, ptext, plen)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    *clen += out_len;

    if (!EVP_CipherFinal_ex(ctx, ctext + *clen, &out_len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    *clen += out_len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SESSION_TAG_LENGTH, ctext + *clen)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    *clen += SESSION_TAG_LENGTH;

    EVP_CIPHER_CTX_free(ctx);

    return 1;
}


/*
 * Decrypts ctext using AES-256 in GCM
 * ctext format must be [ ciphertext bytes | authtag ]
 */
int mp_aesgcm_decrypt(const unsigned char * ctext,
        size_t clen,
        const unsigned char * key,
        const unsigned char * iv,
        unsigned char * ptext,
        size_t * plen) {
            
    // Uncomment the following to disable encryption
    //memcpy(ptext, ctext, clen);
    //*plen = clen;
    //return 1;

    EVP_CIPHER_CTX * ctx;
    int out_len;

    ctx = EVP_CIPHER_CTX_new();
    OPENSSL_assert(ctx != NULL);

    EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL, 0);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == SESSION_KEY_LENGTH);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == SESSION_IV_LENGTH);
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, -1);

    /* ctext + clen - 16 gives the last 16 bytes of the ciphertext, which contain the tag */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SESSION_TAG_LENGTH,
        (unsigned char *)ctext + clen - SESSION_TAG_LENGTH);

    *plen = 0;

    /* total ciphertext length is clen - 16 (we omit the GMAC tag) */
    if (!EVP_CipherUpdate(ctx, ptext, &out_len, ctext, clen - SESSION_TAG_LENGTH)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    *plen += out_len;

    if (!EVP_CipherFinal_ex(ctx, ptext + out_len, &out_len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    *plen += out_len;

    EVP_CIPHER_CTX_free(ctx);

    return 1;
}

int mp_randomize(unsigned char *buffer, int len)
{
    if (!buffer || len <= 0)
        return -1;
    
    return RAND_bytes(buffer, len);
}

void * nist_800_kdf(const void * in, unsigned int inlen, void * out, unsigned int * outlen)
{
    int offset = 0;
    int counter = 0;

    HMAC(EVP_sha256(), in, inlen, (unsigned char *)&counter, sizeof(counter), (unsigned char *)out + offset, NULL);
    offset += 32;
    counter++;

    HMAC(EVP_sha256(), in, inlen, (unsigned char *)&counter, sizeof(counter),(unsigned char *) out + offset, NULL);
    offset += 32;
    counter++;

    *outlen = offset;

    return out;
}

