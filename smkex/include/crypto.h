        #ifndef CRYPTO_H
        #define CRYPTO_H

        #include <openssl/evp.h>
        #include <openssl/err.h>
        #include <openssl/ec.h>
        #include <openssl/hmac.h>

        #define KDF_KEY_LENGTH 64
        #define SESSION_KEY_LENGTH 32
        #define SESSION_IV_LENGTH 12
        #define SESSION_TAG_LENGTH 16
        #define SESSION_NONCE_LENGTH 8

        #define KYBER_PUBLIC_KEY_LENGTH 1184  // Kyber-768
        #define KYBER_PRIVATE_KEY_LENGTH 2400 // Kyber-768
        #define KYBER_CIPHERTEXT_LENGTH 1088  // Kyber-768
        #define KYBER_SHARED_SECRET_LENGTH 32 // Kyber-768
        
        /*
        * @brief: computes SHA256 of given input
        *
        * @param[in] dest[]: preallocated buffer long enough to store result of SHA256 (32 bytes)
        * @param[in] src[]: source buffer containing data to be hashed
        * @param[in] dlen: length of data in src buffer
        * @returns: length of computed sha256 function (should be 32 if all ok).
        */
        unsigned int compute_sha256(unsigned char dest[], const unsigned char src[], int dlen);

        void hexdump(unsigned char * string, int length);
        void sha1dump(unsigned char * string, int length);

        int mp_aesgcm_encrypt(const unsigned char * ptext,
                size_t plen,
                const unsigned char * key,
                const unsigned char * iv,
                unsigned char * ctext,
                size_t * clen);

        int mp_aesgcm_decrypt(const unsigned char * ctext,
                size_t clen,
                const unsigned char * key,
                const unsigned char * iv,
                unsigned char * ptext,
                size_t * plen);

        int mp_randomize(unsigned char *buffer, int len);

        /* KDF based of NIST SP 800-108 (HMAC + Counter)
        * Generates 64 pseudorandom bytes using HMAC-SHA-256
        * Basically out = HMAC(k, 0) || HMAC(k, 1)
        *
        * @param[in] in: input key
        * @parma[in] inlen: input key length
        * @param[in] out: buffer for hmac output
        * @param[in] outlen: length of resulting pseudorandom stream (should be 64)
        * @returns the output buffer, same as out
        */
        void * nist_800_kdf(const void * in, unsigned int inlen, void * out, unsigned int * outlen);

        EC_KEY* __new_key_pair(void);

        // Adaugă funcții pentru Kyber
        /**
         * @brief Generează o pereche de chei Kyber (simulare)
         * @param[out] pk Buffer pentru cheia publică (trebuie alocat în prealabil)
         * @param[out] sk Buffer pentru cheia privată (trebuie alocat în prealabil)
         * @return 0 dacă generarea a reușit, o valoare negativă în caz contrar
         */
        int mp_kyber_keygen(unsigned char *pk, unsigned char *sk);

        /**
         * @brief Encapsulează o cheie folosind Kyber (simulare)
         * @param[in] pk Cheia publică Kyber a destinatarului
         * @param[out] ct Ciphertext-ul rezultat (trebuie alocat în prealabil)
         * @param[out] ss Secretul partajat rezultat (trebuie alocat în prealabil)
         * @return 0 dacă encapsularea a reușit, o valoare negativă în caz contrar
         */
        int mp_kyber_encapsulate(const unsigned char *pk, unsigned char *ct, unsigned char *ss);

        /**
         * @brief Decapsulează o cheie folosind Kyber (simulare)
         * @param[in] ct Ciphertext-ul primit
         * @param[in] sk Cheia privată Kyber proprie
         * @param[out] ss Secretul partajat rezultat (trebuie alocat în prealabil)
         * @return 0 dacă decapsularea a reușit, o valoare negativă în caz contrar
         */
        int mp_kyber_decapsulate(const unsigned char *ct, const unsigned char *sk, unsigned char *ss);

        /**
         * @brief Combină secretul DH cu secretul Kyber pentru a deriva o cheie hibridă
         * @param[in] dh_secret Secretul Diffie-Hellman
         * @param[in] dh_len Lungimea secretului Diffie-Hellman
         * @param[in] kyber_secret Secretul Kyber
         * @param[in] kyber_len Lungimea secretului Kyber
         * @param[out] combined_key Buffer pentru cheia combinată (trebuie alocat în prealabil)
         * @param[in] key_len Lungimea dorită pentru cheia combinată
         * @return Lungimea cheii combinate sau 0 în caz de eroare
         */
        int mp_combine_secrets(const unsigned char *dh_secret, int dh_len, 
        const unsigned char *kyber_secret, int kyber_len,
        unsigned char *combined_key, int key_len);

        #endif
