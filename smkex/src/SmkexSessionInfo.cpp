/** \file
 *  \brief  SmkexSessionInfo.c source file
 *
 *  This file implements the core methods for a SMKEX Session 
 *
 *  Authors:
 *    Liliana Grigoriu (liliana.grigoriu@upb.ro)
 *    Marios O. Choudary (marios.choudary@cs.pub.ro)
 *
 *  Last update: August 2021
 */

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include<stdio.h>
#include "Smkex.h"
#include "SmkexSessionInfo.h"
#include <oqs/kem.h>  

// functie de verificare din curs criptografie 
#define CHECK(assertion, call_description)  \
  do {                                      \
    if (!(assertion)) {                     \
      fprintf(stderr, "(%s, %d): ",         \
        __FILE__, __LINE__);                \
      perror(call_description);             \
      exit(EXIT_FAILURE);                   \
    }                                       \
  } while(0)

#define DEBUG 1
#define THIS_TAG "Smkex"

#ifndef __ANDROID__
#include "MpBaseService.h"
#include "MpLogger.h"
#define LOGMSG(x) MpService::instance()->getLogger()->print(THIS_TAG, __FUNCTION__, (x))
#else
#define LOGMSG(x)
#endif

int SmkexSessionInfo::_nextID = 0; 


// TODO: replace all the DH stuff into some function or place somewhere else
SmkexSessionInfo::SmkexSessionInfo(){

    // get unique ID
    _nextID++;
    _uniqueID = _nextID;
    _sessionID = _nextID;

#if DEBUG
    printf("In SmkexSessionInfo::Constructor with uniqueID=%d\n", _uniqueID);
#endif

    // Initialise protocol data
    memset(_session_key, 0, SMKEX_SESSION_KEY_LEN);
    _session_key_len = 0;
    memset(local_priv_key, 0, SMKEX_PRIV_KEY_LEN);
    local_priv_key_length = 0;
    memset(local_nonce, 0, SMKEX_NONCE_LEN);
    local_nonce_length = 0;
    memset(local_pub_key, 0, SMKEX_PUB_KEY_LEN);
    local_pub_key_length = 0;
    memset(remote_nonce, 0, SMKEX_NONCE_LEN);
    remote_nonce_length = 0;
    memset(remote_pub_key, 0, SMKEX_PUB_KEY_LEN);
    remote_pub_key_length = 0;

    // initialise DH structure 
#if DEBUG
    printf("Init DH parameters from file\n") ;
#endif
    //  currently computed and stored in _dh from "../smkex/dhparam.pem"
    // TODO: use EC instead
    __read_pg_from_file(SMKEX_DH_PARAMETER_FILENAME);

#if DEBUG
    printf("SmkexSessionInfo::Constructor ending here\n");
#endif

  // VERTICAL RATCHETING - Initialize new members
    _vertical_ratchet_counter = 0;
    _last_vertical_ratchet_at_counter = 0;
    _vertical_ratchet_pending = false;
    _awaiting_vertical_ratchet_response = false;
    _stored_keys_count = 0;
    _current_dh_secret_len = 0;
    
    // Initialize stored keys array
    for(int i = 0; i < MAX_STORED_KEYS; i++) {
        _stored_dh_keys[i].is_valid = false;
        _stored_dh_keys[i].counter_from = 0;
        _stored_dh_keys[i].counter_to = 0;
        _stored_dh_keys[i].dh_secret_len = 0;
    }
    
    // Initialize temp keys
    memset(_temp_local_pub_key, 0, SMKEX_PUB_KEY_LEN);
    memset(_temp_local_priv_key, 0, SMKEX_PRIV_KEY_LEN);
    _temp_local_pub_key_length = 0;
    _temp_local_priv_key_length = 0;
    
    memset(_current_dh_secret, 0, SMKEX_DH_KEY_LEN);
    
    #if DEBUG
    printf("SmkexSessionInfo::Constructor - Vertical Ratchet initialized\n");
    #endif
}

SmkexSessionInfo::~SmkexSessionInfo(){
#if DEBUG
    printf("In SmkexSessionInfo::Destructor with uniqueID=%d\n", _uniqueID);
#endif
    if (_dh!=0) free(_dh);
#if DEBUG
    printf("SmkexSessionInfo::Destructor ending here\n");
#endif
}

SmkexSessionInfo& SmkexSessionInfo::operator=(const SmkexSessionInfo& other)
{
#if DEBUG
  printf("We are in the copy constructor of SmkexSessionInfo\n");
#endif

  if (this == &other)
     return *this;

#if DEBUG
  printf("and in SmkexSessionInfo(&other) we are not called by *this.... \n");
#endif

  _iAmSessionInitiator = other.isInitiator();
  _state = other.getState();
  _sessionID = other.getSessionID();
  _buddy = other.getBuddy();
  _buddy2 = other.getBuddy2();
  __read_pg_from_file(SMKEX_DH_PARAMETER_FILENAME);
  if(initKeysfromDH())
    LOGMSG("Error initialising DH keys\n");
  // overwrite key values from given object
  local_priv_key_length = other.getLocalPrivKey(local_priv_key);
  local_pub_key_length = other.getLocalPubKey(local_pub_key);
  local_nonce_length = other.getLocalNonce(local_nonce);
  remote_pub_key_length = other.getRemotePubKey(remote_pub_key);
  remote_nonce_length = other.getRemoteNonce(remote_nonce);
  _session_key_len = other.getSessionKey(_session_key);

  return *this;
}

int SmkexSessionInfo::initKeysfromDH(void)
{

  if(_dh_initialised)
    LOGMSG("Warning: re-initialising DH keys\n");

  int _i= DH_generate_key(_dh);  // computes key values dh->priv_key and dh->pub_key

  if (_i!=1){
      printf("ERROR in  DH_generate_key\n exiting.\n") ;
      return -1;
  }
  LOGMSG("successfully generated local keys\n");

  BIGNUM *local_pub_key_num, *local_priv_key_num;
  
#if OPENSSL_VERSION_NUMBER < 0x10100000L // OpenSSL 1.0.2
  if (local_pub_key_num != NULL)
    local_pub_key_num = _dh->pub_key;
  if (local_priv_key_num != NULL)
    local_priv_key_num = _dh->priv_key;

#else // OpenSSL 1.1.1
  DH_get0_key(_dh, (const BIGNUM**) &local_pub_key_num,
      (const BIGNUM**) &local_priv_key_num);
#endif

  local_pub_key_length =  BN_num_bytes(local_pub_key_num);
  local_priv_key_length =  BN_num_bytes(local_priv_key_num);

  printf("Pub key has %d bytes\n", local_pub_key_length);    
  CHECK(SMKEX_PUB_KEY_LEN == local_pub_key_length, "DH PUB KEY LEN");    
  CHECK(SMKEX_PRIV_KEY_LEN == local_priv_key_length, "DH PRIV KEY LEN");

  BN_bn2bin(local_pub_key_num, local_pub_key);
  BN_bn2bin(local_priv_key_num, local_priv_key);

  _dh_initialised = true;

#if DEBUG
    printf("DH keys initialised.\n\nPublic key is: ");
    for(unsigned int k=0; k<local_pub_key_length; k++)
        printf("%02X", local_pub_key[k]);
    printf("\n");
    printf("Private key is: ");
    for(unsigned int k=0; k<local_priv_key_length; k++)
        printf("%02X", local_priv_key[k]);
    printf("\n\n");
#endif

  return 0;
}

int SmkexSessionInfo::initKeysFromKyber() {
  if (_kyber_initialised)
    LOGMSG("Warning: re-initialising Kyber keys\n");

  // initializare kyber
  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
  if (kem == NULL) {
    LOGMSG("Error creating Kyber KEM object\n");
    return -1;
  }

  // aloc memorie pentru chei
  local_kyber_pub_key_length = kem->length_public_key;
  local_kyber_priv_key_length = kem->length_secret_key;

  // verific daca lungimile cheilor se potrivesc cu spatiul alocat
  if (local_kyber_pub_key_length > SMKEX_KYBER_PUB_KEY_LEN ||
      local_kyber_priv_key_length > SMKEX_KYBER_PRIV_KEY_LEN) {
    LOGMSG("Kyber key lengths exceed allocated buffer sizes\n");
    OQS_KEM_free(kem);
    return -1;
  }

  // generez perechea de chei
  OQS_STATUS rc = OQS_KEM_keypair(kem, local_kyber_pub_key, local_kyber_priv_key);
  if (rc != OQS_SUCCESS) {
    LOGMSG("Error generating Kyber key pair\n");
    OQS_KEM_free(kem);
    return -1;
  }

  _kyber_initialised = true;

#if DEBUG
  printf("Kyber keys initialised with liboqs.\n\nKyber Public key (first 32 bytes): ");
  for (unsigned int k = 0; k < 32; k++)
    printf("%02X", local_kyber_pub_key[k]);
  printf("...\n");
#endif

  // eliberez resursele
  OQS_KEM_free(kem);

  return 0;
}

int SmkexSessionInfo::encapsulateKyberKey() {
  if (!_kyber_initialised) {
    printf("Error encapsulating Kyber key: keys not initialised\n");
    return -1;
  }

  if (remote_kyber_pub_key_length == 0) {
    printf("Error encapsulating Kyber key: remote public key not set\n");
    return -1;
  }

  // Initializarea Kyber KEM

  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
  if (kem == NULL) {
    LOGMSG("Error creating Kyber KEM object\n");
    return -1;
  }

  remote_kyber_ciphertext_length = kem->length_ciphertext;
  _kyber_shared_secret_len = kem->length_shared_secret;

  // Verific daca lungimile cheilor se potrivesc cu spatiul alocat
  if (remote_kyber_ciphertext_length > SMKEX_KYBER_CIPHERTEXT_LEN ||
      _kyber_shared_secret_len > SMKEX_KYBER_SHARED_SECRET_LEN) {
    LOGMSG("Kyber key lengths exceed allocated buffer sizes\n");
    OQS_KEM_free(kem);
    return -1;
  }

  // ecapsulez cheia folosind cheia publica a partenerului
  OQS_STATUS rc = OQS_KEM_encaps(kem, remote_kyber_ciphertext, _kyber_shared_secret, remote_kyber_pub_key);
  if (rc != OQS_SUCCESS) {
    LOGMSG("Error encapsulating Kyber key\n");
    OQS_KEM_free(kem);
    return -1;
  }

#if DEBUG
  printf("Kyber encapsulation complete using liboqs.\n\nShared Secret (first 16 bytes): ");
  for(unsigned int k=0; k<16 && k<_kyber_shared_secret_len; k++)
      printf("%02X", _kyber_shared_secret[k]);
  printf("...\n");
#endif
  
  OQS_KEM_free(kem);
  return 0;
}

// Implementarea decapsulării Kyber
int SmkexSessionInfo::decapsulateKyberKey() {
  if (!_kyber_initialised) {
      printf("Error: Kyber not initialised before decapsulation\n");
      return -1;
  }
  
  if (remote_kyber_ciphertext_length == 0) {
      printf("Error: Remote Kyber ciphertext not received\n");
      return -1;
  }
  
  // Inițializare Kyber
  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
  if (kem == NULL) {
      printf("Error creating Kyber KEM instance\n");
      return -1;
  }
  
  // Alocă memorie pentru secretul partajat
  _kyber_shared_secret_len = kem->length_shared_secret;
  
  if (_kyber_shared_secret_len > SMKEX_KYBER_SHARED_SECRET_LEN) {
      printf("Error: Kyber shared secret buffer too small\n");
      OQS_KEM_free(kem);
      return -1;
  }
  
  // Decapsulează cheia folosind cheia privată proprie
  OQS_STATUS rc = OQS_KEM_decaps(kem, _kyber_shared_secret, remote_kyber_ciphertext, local_kyber_priv_key);
  if (rc != OQS_SUCCESS) {
      printf("Error decapsulating Kyber key\n");
      OQS_KEM_free(kem);
      return -1;
  }
  
#if DEBUG
  printf("Kyber decapsulation complete using liboqs.\n\nShared Secret (first 16 bytes): ");
  for(unsigned int k=0; k<16 && k<_kyber_shared_secret_len; k++)
      printf("%02X", _kyber_shared_secret[k]);
  printf("...\n");
#endif
  
  OQS_KEM_free(kem);
  return 0;
}

// Metoda pentru obtinerea secretului Kyber
int SmkexSessionInfo::getKyberSharedSecret(unsigned char kbuf[]) const {
  if (kbuf != NULL && _kyber_shared_secret_len > 0) {
    memcpy(kbuf, _kyber_shared_secret, _kyber_shared_secret_len);
  }

  return _kyber_shared_secret_len;
}

// Metodă pentru obținerea cheii publice Kyber locale
int SmkexSessionInfo::getLocalKyberPubKey(unsigned char kbuf[]) const {
  if (kbuf != NULL && local_kyber_pub_key_length > 0) {
      memcpy(kbuf, local_kyber_pub_key, local_kyber_pub_key_length);
  }
  
  return local_kyber_pub_key_length;
}

// Metodă pentru obținerea cheii private Kyber locale
int SmkexSessionInfo::getLocalKyberPrivKey(unsigned char kbuf[]) const {
  if (kbuf != NULL && local_kyber_priv_key_length > 0) {
      memcpy(kbuf, local_kyber_priv_key, local_kyber_priv_key_length);
  }
  
  return local_kyber_priv_key_length;
}

int SmkexSessionInfo::getRemoteKyberPubKey(unsigned char kbuf[]) const {
  if (kbuf != NULL && remote_kyber_pub_key_length > 0) {
      memcpy(kbuf, remote_kyber_pub_key, remote_kyber_pub_key_length);
  }
  
  return remote_kyber_pub_key_length;
}

// Metodă pentru obținerea ciphertext-ului Kyber remote
int SmkexSessionInfo::getRemoteKyberCiphertext(unsigned char kbuf[]) const {
  if (kbuf != NULL && remote_kyber_ciphertext_length > 0) {
      memcpy(kbuf, remote_kyber_ciphertext, remote_kyber_ciphertext_length);
  }
  
  return remote_kyber_ciphertext_length;
}

/**
 * Open file <filename>, read public Diffie-Hellman parameters P and G and store them in <pdhm>
 * in dh (Diffie-Hellman key exchange context)
 * @param filename file from which to read P and G
 */
void SmkexSessionInfo::__read_pg_from_file(const char * filename) {
    BIO * pbio;
    /* Get DH modulus and generator (P and G) */
    pbio = BIO_new_file(filename, "r");

    CHECK(pbio != NULL, "BIO_new_file");

    /* Read P and G from f  and store in the attribute of this object */
    _dh = PEM_read_bio_DHparams(pbio, NULL, NULL, NULL);
    CHECK(_dh != NULL, "PEM_read_bio_DHparams");
    BIO_free(pbio);
}

int SmkexSessionInfo::generateLocalNonce(unsigned char nbuf[])
{
  // create nonce for this message
  if(RAND_bytes(local_nonce,SMKEX_NONCE_LEN)==0){
    printf("Error creating nonce...............\nExiting\n");
    return 0;
  }
  local_nonce_length=SMKEX_NONCE_LEN;

  if(nbuf != NULL)
    memcpy(nbuf, local_nonce, local_nonce_length);

  return local_nonce_length;
}

int SmkexSessionInfo::getLocalNonce(unsigned char nbuf[]) const
{
  if(nbuf != NULL)
    memcpy(nbuf, local_nonce, local_nonce_length);

  return local_nonce_length;
}

unsigned int SmkexSessionInfo::computeHash(unsigned char dest[])
{
  unsigned int len, hlen;
  // Măresc buffer-ul pentru a include și cheile Kyber
  unsigned char buf[2*SMKEX_NONCE_LEN + 2*SMKEX_PUB_KEY_LEN + 2*SMKEX_KYBER_PUB_KEY_LEN];
  len = 0;
  
  // Adaug datele în aceeași ordine ca înainte, dar includem și cheile Kyber
  memcpy(buf, remote_nonce, remote_nonce_length); 
  len += remote_nonce_length;
  
  memcpy(&buf[len], remote_pub_key, remote_pub_key_length); 
  len += remote_pub_key_length;
  
  // Adaug cheia publică Kyber remotă dacă există
  if (_kyber_initialised && remote_kyber_pub_key_length > 0) {
    memcpy(&buf[len], remote_kyber_pub_key, remote_kyber_pub_key_length);
    len += remote_kyber_pub_key_length;
  }
  
  memcpy(&buf[len], local_nonce, local_nonce_length); 
  len += local_nonce_length;
  
  memcpy(&buf[len], local_pub_key, local_pub_key_length); 
  len += local_pub_key_length;
  
  // Adaug cheia publică Kyber locală dacă există
  if (_kyber_initialised && local_kyber_pub_key_length > 0) {
    memcpy(&buf[len], local_kyber_pub_key, local_kyber_pub_key_length);
    len += local_kyber_pub_key_length;
  }
  
  hlen = compute_sha256(dest, buf, len);

#if DEBUG
  printf("In SmkexSessionInfo::computeHash, computed hash has %d bytes: \n", hlen);
  for(unsigned int k=0; k<hlen; k++)
    printf("%02X", dest[k]);
  printf("\n");
  printf("\nRemote nonce: \n");
  for(unsigned int k=0; k<remote_nonce_length; k++)
    printf("%02X", remote_nonce[k]);
  printf("\nRemote pub key (DH): \n");
  for(unsigned int k=0; k<remote_pub_key_length; k++)
    printf("%02X", remote_pub_key[k]);
  if (_kyber_initialised && remote_kyber_pub_key_length > 0) {
    printf("\nRemote pub key (Kyber): \n");
    for(unsigned int k=0; k<remote_kyber_pub_key_length; k++)
      printf("%02X", remote_kyber_pub_key[k]);
  }
  printf("\nLocal nonce: \n");
  for(unsigned int k=0; k<local_nonce_length; k++)
    printf("%02X", local_nonce[k]);
  printf("\nLocal pub key (DH): \n");
  for(unsigned int k=0; k<local_pub_key_length; k++)
    printf("%02X", local_pub_key[k]);
  if (_kyber_initialised && local_kyber_pub_key_length > 0) {
    printf("\nLocal pub key (Kyber): \n");
    for(unsigned int k=0; k<local_kyber_pub_key_length; k++)
      printf("%02X", local_kyber_pub_key[k]);
  }
  printf("\n");
#endif

  return hlen;
}

bool SmkexSessionInfo::verifyHash(const unsigned char hbuf[], unsigned int hlen)
{
#if DEBUG
  printf("In SmkexSessionInfo::verifyHash\n");
  printf("Received hash has %d bytes: \n", hlen);
  for(unsigned int k=0; k<hlen; k++)
    printf("%02X", hbuf[k]);
  printf("\n"); 
#endif
  
  unsigned int len, hhlen;
  unsigned char hh[SMKEX_HASH_LEN];
  // Măresc buffer-ul pentru a include și cheile Kyber
  unsigned char buf[2*SMKEX_NONCE_LEN + 2*SMKEX_PUB_KEY_LEN + 2*SMKEX_KYBER_PUB_KEY_LEN];
  len = 0;
  
  // Ordinea este oglindită față de computeHash
  memcpy(buf, local_nonce, local_nonce_length); 
  len += local_nonce_length;
  
  memcpy(&buf[len], local_pub_key, local_pub_key_length); 
  len += local_pub_key_length;
  
  // Adăug cheia publică Kyber locală dacă există
  if (_kyber_initialised && local_kyber_pub_key_length > 0) {
    memcpy(&buf[len], local_kyber_pub_key, local_kyber_pub_key_length);
    len += local_kyber_pub_key_length;
  }
  
  memcpy(&buf[len], remote_nonce, remote_nonce_length); 
  len += remote_nonce_length;
  
  memcpy(&buf[len], remote_pub_key, remote_pub_key_length); 
  len += remote_pub_key_length;
  
  // Adăug cheia publică Kyber remotă dacă există
  if (_kyber_initialised && remote_kyber_pub_key_length > 0) {
    memcpy(&buf[len], remote_kyber_pub_key, remote_kyber_pub_key_length);
    len += remote_kyber_pub_key_length;
  }
  
  hhlen = compute_sha256(hh, buf, len);
  
#if DEBUG
  printf("Locally computed hash has %d bytes: \n", hhlen);
  for(unsigned int k=0; k<hhlen; k++)
    printf("%02X", hh[k]);
  printf("\n");
  printf("\nLocal nonce: \n");
  for(unsigned int k=0; k<local_nonce_length; k++)
    printf("%02X", local_nonce[k]);
  printf("\nLocal pub key (DH): \n");
  for(unsigned int k=0; k<local_pub_key_length; k++)
    printf("%02X", local_pub_key[k]);
  if (_kyber_initialised && local_kyber_pub_key_length > 0) {
    printf("\nLocal pub key (Kyber): \n");
    for(unsigned int k=0; k<local_kyber_pub_key_length; k++)
      printf("%02X", local_kyber_pub_key[k]);
  }
  printf("\nRemote nonce: \n");
  for(unsigned int k=0; k<remote_nonce_length; k++)
    printf("%02X", remote_nonce[k]);
  printf("\nRemote pub key (DH): \n");
  for(unsigned int k=0; k<remote_pub_key_length; k++)
    printf("%02X", remote_pub_key[k]);
  if (_kyber_initialised && remote_kyber_pub_key_length > 0) {
    printf("\nRemote pub key (Kyber): \n");
    for(unsigned int k=0; k<remote_kyber_pub_key_length; k++)
      printf("%02X", remote_kyber_pub_key[k]);
  }
  printf("\n");
#endif

  if ((hhlen != hlen) || (strncmp((char*)hh, (char*)hbuf, hhlen) != 0))
    return false;

  return true;
}

// TODO: update with EC keys
int SmkexSessionInfo::computeSessionKey(unsigned char kbuf[])
{
  int dklen;
  unsigned char dhkey[SMKEX_DH_KEY_LEN];
  BIGNUM *pub_key_buddy = BN_bin2bn(remote_pub_key, SMKEX_PUB_KEY_LEN, NULL);
  dklen = DH_compute_key(dhkey, pub_key_buddy, _dh);
  BN_free(pub_key_buddy);
  if (dklen == 0)
    return 0;

  // Stochează secretul DH curent pentru vertical ratcheting
  memcpy(_current_dh_secret, dhkey, dklen);
  _current_dh_secret_len = dklen;
  
  if (_kyber_initialised && _kyber_shared_secret_len > 0) {
    // Combinăm cheile Diffie-Hellman și Kyber pentru a crea o cheie finală hibridă
    unsigned char combined_key[SMKEX_DH_KEY_LEN + SMKEX_KYBER_SHARED_SECRET_LEN];
    memset(combined_key, 0, sizeof(combined_key)); // Asigurăm un comportament predictibil
    
    // Combinăm cheile în același mod pe ambii participanți
    memcpy(combined_key, dhkey, dklen);
    memcpy(combined_key + dklen, _kyber_shared_secret, _kyber_shared_secret_len);
    
    // Derivăm cheia finală
    unsigned int combined_len = dklen + _kyber_shared_secret_len;
    nist_800_kdf(combined_key, combined_len, _session_key, &_session_key_len);

    #if DEBUG
    printf("Combined DH and Kyber secrets for key derivation.\n");
    #endif
  } else {
    // Folosim doar cheia Diffie-Hellman dacă Kyber nu este disponibil
    nist_800_kdf(dhkey, dklen, _session_key, &_session_key_len);
    
    #if DEBUG
    printf("Used only DH secret for key derivation (Kyber not available).\n");
    #endif
  }

  if (kbuf != NULL)
    memcpy(kbuf, _session_key, _session_key_len);

  return _session_key_len;
}

int SmkexSessionInfo::getSessionKey(unsigned char kbuf[]) const
{
  if(kbuf != NULL)
    memcpy(kbuf, _session_key, _session_key_len);
  
  return _session_key_len;
}

int SmkexSessionInfo::getLocalPrivKey(unsigned char kbuf[]) const
{
  if(kbuf != NULL)
    memcpy(kbuf, local_priv_key, local_priv_key_length);
  
  return local_priv_key_length;
}

int SmkexSessionInfo::getLocalPubKey(unsigned char kbuf[]) const
{
  if(kbuf != NULL)
    memcpy(kbuf, local_pub_key, local_pub_key_length);
  
  return local_pub_key_length;
}

int SmkexSessionInfo::getRemotePubKey(unsigned char kbuf[]) const
{
  if(kbuf != NULL)
    memcpy(kbuf, remote_pub_key, remote_pub_key_length);
  
  return remote_pub_key_length;
}

int SmkexSessionInfo::getRemoteNonce(unsigned char nbuf[]) const
{
  if(nbuf != NULL)
    memcpy(nbuf, remote_nonce, remote_nonce_length);
  
  return remote_nonce_length;
}

void SmkexSessionInfo::printSessionInfo() const
{
    cout << "In SmkexSessionInfo::printSessionInfo() we have this data: " << endl;
    cout << "Unieque ID: " << _uniqueID << endl;
    cout << "Is Initiator: " << _iAmSessionInitiator << endl;
    cout << "Session ID: " << _sessionID << endl;
    cout << "Buddy ID: " << _buddy << endl;
    cout << "Buddy ID2: " << _buddy2 << endl;
    cout << "DH Initialised: " << _dh_initialised << endl;
    cout << "Kyber Initialised: " << _kyber_initialised << endl;
    cout << "Session key len: " << _session_key_len << endl;
    cout << "Session key bytes: " << endl;
    for(int k=0; k < _session_key_len; k++)
      printf("%02X", _session_key[k]);
    cout << endl;

    if (_kyber_initialised && _kyber_shared_secret_len > 0) {
      cout << "Kyber shared secret len: " << _kyber_shared_secret_len << endl;
      cout << "Kyber shared secret bytes: " << endl;
      for(int k=0; k < _kyber_shared_secret_len; k++)
          printf("%02X", _kyber_shared_secret[k]);
      cout << endl;
  }
}

void SmkexSessionInfo::initializeRatchet() {
    printf("=== CALLING INITIALIZE RATCHET ===\n");
    printf("Role: %s\n", _iAmSessionInitiator ? "INITIATOR" : "RESPONDER");
    printf("Previous ratchet state: initialized=%s, sending=%u, receiving=%u\n",
           _ratchet_initialized ? "YES" : "NO", _sending_counter, _receiving_counter);
    
    if (_session_key_len == 0) {
        LOGMSG("Error: Cannot initialize ratchet without session key\n");
        return;
    }
    
    // DEBUG: Verify buffer sizes
    printf("SMKEX_SESSION_KEY_LEN = %d\n", SMKEX_SESSION_KEY_LEN);
    printf("_session_key_len = %u\n", _session_key_len);
    printf("sizeof(_sending_chain_key) = %zu\n", sizeof(_sending_chain_key));
    printf("sizeof(_receiving_chain_key) = %zu\n", sizeof(_receiving_chain_key));
    printf("sizeof(_session_key) = %zu\n", sizeof(_session_key));
    
    // Reset the ratchet completely
    _ratchet_initialized = false;
    
    // FIXED: Clear chain key buffers completely before use
    memset(_sending_chain_key, 0, sizeof(_sending_chain_key));
    memset(_receiving_chain_key, 0, sizeof(_receiving_chain_key));
    
    // Initialize counters based on role
    _sending_counter = 0;
    _receiving_counter = 0;

    // Derive initial chain keys from session key using KDF
    printf("Session key (%u bytes): ", _session_key_len);
    for(int i = 0; i < (int)_session_key_len && i < 32; i++)
        printf("%02X", _session_key[i]);
    if (_session_key_len > 32) printf("...");
    printf("\n");
    
    printf("INITRATCHET DEBUG: Role=%s, SessionID=%d, Buddy=%s\n", 
           _iAmSessionInitiator ? "INITIATOR" : "RESPONDER", 
           _sessionID, _buddy.c_str());
    
    // Use a proper KDF to derive chain keys from session key
    // For sending chain: HMAC-SHA256(session_key, "SENDING_CHAIN" || role)
    // For receiving chain: HMAC-SHA256(session_key, "RECEIVING_CHAIN" || role)
    
    unsigned int hmac_len;
    
    if (_iAmSessionInitiator) {
        // Initiator: sending = "INIT_SEND", receiving = "RESP_SEND" 
        const char* send_label = "INIT_SEND";
        const char* recv_label = "RESP_SEND";
        
        HMAC(EVP_sha256(), _session_key, _session_key_len,
             (unsigned char*)send_label, strlen(send_label), 
             _sending_chain_key, &hmac_len);
             
        HMAC(EVP_sha256(), _session_key, _session_key_len,
             (unsigned char*)recv_label, strlen(recv_label), 
             _receiving_chain_key, &hmac_len);
             
        printf("INITRATCHET DEBUG: INITIATOR - sending=INIT_SEND, receiving=RESP_SEND\n");
    } else {
        // Responder: sending = "RESP_SEND", receiving = "INIT_SEND"
        const char* send_label = "RESP_SEND";
        const char* recv_label = "INIT_SEND";
        
        HMAC(EVP_sha256(), _session_key, _session_key_len,
             (unsigned char*)send_label, strlen(send_label), 
             _sending_chain_key, &hmac_len);
             
        HMAC(EVP_sha256(), _session_key, _session_key_len,
             (unsigned char*)recv_label, strlen(recv_label), 
             _receiving_chain_key, &hmac_len);
             
        printf("INITRATCHET DEBUG: RESPONDER - sending=RESP_SEND, receiving=INIT_SEND\n");
    }
    
    printf("HMAC output length: %u\n", hmac_len);
    
    _ratchet_initialized = true;
    
    // VERTICAL RATCHETING - Reset vertical ratchet info când se re-inițializează ratchet-ul
    if(_vertical_ratchet_counter == 0) {
        // Prima inițializare
        _last_vertical_ratchet_at_counter = 0;
    }
    // Altfel păstrează valorile existente pentru vertical ratchet
    
    LOGMSG("Symmetric ratchet initialized successfully\n");

#if DEBUG
    printf("Ratchet initialized with role: %s\n", 
           _iAmSessionInitiator ? "INITIATOR" : "RESPONDER");
    printf("Initial sending counter: %u\n", _sending_counter);
    printf("Initial receiving counter: %u\n", _receiving_counter);
    
    // Show first 32 bytes of each chain key (SHA256 output is 32 bytes)
    printf("Sending chain key (32 bytes): ");
    for(int i = 0; i < 32; i++)
        printf("%02X", _sending_chain_key[i]);
    printf("\n");
    
    printf("Receiving chain key (32 bytes): ");
    for(int i = 0; i < 32; i++)
        printf("%02X", _receiving_chain_key[i]);
    printf("\n");
    
    // VERTICAL RATCHETING DEBUG
    printf("Vertical ratchet counter: %u\n", _vertical_ratchet_counter);
    printf("Last vertical ratchet at counter: %u\n", _last_vertical_ratchet_at_counter);
#endif
}

bool SmkexSessionInfo::ratchetSendingChain(unsigned char message_key[SMKEX_SESSION_KEY_LEN]) {
    if (!_ratchet_initialized) {
        LOGMSG("Error: Ratchet not initialized\n");
        return false;
    }

    printf("=== RATCHET SENDING DEBUG ===\n");
    printf("Buddy: %s, Role: %s\n", _buddy.c_str(), _iAmSessionInitiator ? "INITIATOR" : "RESPONDER");
    printf("Using sending counter: %u (will increment to %u after)\n", _sending_counter, _sending_counter + 1);
    
    // Show only first 32 bytes (actual HMAC output)
    printf("Current sending chain key (32 bytes): ");
    for(int i = 0; i < 32; i++)
        printf("%02X", _sending_chain_key[i]);
    printf("\n");
    
    // Counter bytes for HMAC input
    unsigned char counter_bytes[4];
    counter_bytes[0] = (_sending_counter >> 24) & 0xFF;
    counter_bytes[1] = (_sending_counter >> 16) & 0xFF;
    counter_bytes[2] = (_sending_counter >> 8) & 0xFF;
    counter_bytes[3] = _sending_counter & 0xFF;
    
    printf("Counter bytes: %02X%02X%02X%02X (decimal: %u)\n",
           counter_bytes[0], counter_bytes[1], counter_bytes[2], counter_bytes[3], _sending_counter);
    
    // Message key = HMAC(chain_key, counter || "MSG")
    unsigned char hmac_input[7];
    memcpy(hmac_input, counter_bytes, 4);
    memcpy(hmac_input + 4, "MSG", 3);
    
    printf("HMAC input: ");
    for(int i = 0; i < 7; i++)
        printf("%02X", hmac_input[i]);
    printf("\n");
    
    unsigned int hmac_len;
    // FIXED: Use only 32 bytes of chain key for HMAC (SHA256 output size)
    HMAC(EVP_sha256(), _sending_chain_key, 32, 
         hmac_input, 7, message_key, &hmac_len);
    
    // Update chain key: new_chain_key = HMAC(chain_key, "CHAIN")
    unsigned char new_chain_key[32]; // SHA256 output is 32 bytes
    HMAC(EVP_sha256(), _sending_chain_key, 32,
         (unsigned char*)"CHAIN", 5, new_chain_key, &hmac_len);
    
    // Clear the full buffer and copy new key
    memset(_sending_chain_key, 0, SMKEX_SESSION_KEY_LEN);
    memcpy(_sending_chain_key, new_chain_key, 32);
    
    _sending_counter++;
    
    printf("Message key (first 16 bytes): ");
    for(int i = 0; i < 16; i++)
        printf("%02X", message_key[i]);
    printf("...\n");
    printf("=============================\n");
    
    return true;
}

bool SmkexSessionInfo::ratchetReceivingChain(unsigned char message_key[SMKEX_SESSION_KEY_LEN]) {
    if (!_ratchet_initialized) {
        LOGMSG("Error: Ratchet not initialized\n");
        return false;
    }

    printf("=== RATCHET RECEIVING DEBUG ===\n");
    printf("Buddy: %s, Role: %s\n", _buddy.c_str(), _iAmSessionInitiator ? "INITIATOR" : "RESPONDER");
    printf("Using receiving counter: %u (will increment to %u after)\n", _receiving_counter, _receiving_counter + 1);
    
    // Show only first 32 bytes (actual HMAC output)
    printf("Current receiving chain key (32 bytes): ");
    for(int i = 0; i < 32; i++)
        printf("%02X", _receiving_chain_key[i]);
    printf("\n");
    
    // Counter bytes for HMAC input
    unsigned char counter_bytes[4];
    counter_bytes[0] = (_receiving_counter >> 24) & 0xFF;
    counter_bytes[1] = (_receiving_counter >> 16) & 0xFF;
    counter_bytes[2] = (_receiving_counter >> 8) & 0xFF;
    counter_bytes[3] = _receiving_counter & 0xFF;
    
    printf("Counter bytes: %02X%02X%02X%02X (decimal: %u)\n",
           counter_bytes[0], counter_bytes[1], counter_bytes[2], counter_bytes[3], _receiving_counter);
    
    unsigned char hmac_input[7];
    memcpy(hmac_input, counter_bytes, 4);
    memcpy(hmac_input + 4, "MSG", 3);
    
    printf("HMAC input: ");
    for(int i = 0; i < 7; i++)
        printf("%02X", hmac_input[i]);
    printf("\n");
    
    unsigned int hmac_len;
    // FIXED: Use only 32 bytes of chain key for HMAC (SHA256 output size)
    HMAC(EVP_sha256(), _receiving_chain_key, 32,
         hmac_input, 7, message_key, &hmac_len);
    
    // Update chain key
    unsigned char new_chain_key[32]; // SHA256 output is 32 bytes
    HMAC(EVP_sha256(), _receiving_chain_key, 32,
         (unsigned char*)"CHAIN", 5, new_chain_key, &hmac_len);
    
    // Clear the full buffer and copy new key
    memset(_receiving_chain_key, 0, SMKEX_SESSION_KEY_LEN);
    memcpy(_receiving_chain_key, new_chain_key, 32);
    
    _receiving_counter++;
    
    printf("Message key (first 16 bytes): ");
    for(int i = 0; i < 16; i++)
        printf("%02X", message_key[i]);
    printf("...\n");
    printf("===============================\n");
    
    return true;
}

void SmkexSessionInfo::printRatchetState() const {
    printf("=== Ratchet State ===\n");
    printf("Initialized: %s\n", _ratchet_initialized ? "YES" : "NO");
    printf("Sending counter: %u\n", _sending_counter);
    printf("Receiving counter: %u\n", _receiving_counter);
    
    if (_ratchet_initialized) {
        printf("Sending chain key (first 8 bytes): ");
        for(int i = 0; i < 8; i++)
            printf("%02X", _sending_chain_key[i]);
        printf("...\n");
        
        printf("Receiving chain key (first 8 bytes): ");
        for(int i = 0; i < 8; i++)
            printf("%02X", _receiving_chain_key[i]);
        printf("...\n");
    }
    printf("==================\n");
}

bool SmkexSessionInfo::shouldPerformVerticalRatchet() const {
    if (!_ratchet_initialized) {
        return false;
    }
    
    // Verifică dacă am trimis suficiente mesaje pentru un vertical ratchet
    unsigned int messages_since_last_ratchet = _sending_counter - _last_vertical_ratchet_at_counter;
    
    #if DEBUG
    printf("VERTICAL_RATCHET_CHECK: sending_counter=%u, last_ratchet_at=%u, messages_since=%u\n",
           _sending_counter, _last_vertical_ratchet_at_counter, messages_since_last_ratchet);
    #endif
    
    return (messages_since_last_ratchet >= VERTICAL_RATCHET_INTERVAL) && !_awaiting_vertical_ratchet_response;
}

int SmkexSessionInfo::initiateVerticalRatchet() {
    if (!_dh_initialised) {
        printf("Error: DH not initialized for vertical ratchet\n");
        return -1;
    }
    
    printf("=== INITIATING VERTICAL RATCHET ===\n");
    printf("Current sending counter: %u\n", _sending_counter);
    printf("Last vertical ratchet at: %u\n", _last_vertical_ratchet_at_counter);
    
    // Păstrează cheia DH curentă pentru mesajele out-of-order
    storePreviousDHKey();
    
    // Generează noi chei DH temporare
    if(DH_generate_key(_dh) != 1) {
        printf("Error generating new DH keys for vertical ratchet\n");
        return -1;
    }
    
    BIGNUM *new_pub_key_num, *new_priv_key_num;
    
    #if OPENSSL_VERSION_NUMBER < 0x10100000L // OpenSSL 1.0.2
    new_pub_key_num = _dh->pub_key;
    new_priv_key_num = _dh->priv_key;
    #else // OpenSSL 1.1.1
    DH_get0_key(_dh, (const BIGNUM**) &new_pub_key_num, (const BIGNUM**) &new_priv_key_num);
    #endif
    
    _temp_local_pub_key_length = BN_num_bytes(new_pub_key_num);
    _temp_local_priv_key_length = BN_num_bytes(new_priv_key_num);
    
    if(_temp_local_pub_key_length != SMKEX_PUB_KEY_LEN || 
       _temp_local_priv_key_length != SMKEX_PRIV_KEY_LEN) {
        printf("Error: Generated DH key lengths don't match expected lengths\n");
        return -1;
    }
    
    BN_bn2bin(new_pub_key_num, _temp_local_pub_key);
    BN_bn2bin(new_priv_key_num, _temp_local_priv_key);
    
    // ACTUALIZEAZĂ imediat cheile locale cu cele noi generate
    memcpy(local_pub_key, _temp_local_pub_key, _temp_local_pub_key_length);
    memcpy(local_priv_key, _temp_local_priv_key, _temp_local_priv_key_length);
    local_pub_key_length = _temp_local_pub_key_length;
    local_priv_key_length = _temp_local_priv_key_length;
    
    // Calculează și actualizează IMEDIAT noul DH secret (parțial - cu cheia veche remote)
    // Aceasta va fi o stare temporară până primim cheia nouă de la partner
    if(remote_pub_key_length > 0) {
        BIGNUM *pub_key_buddy = BN_bin2bn(remote_pub_key, remote_pub_key_length, NULL);
        _current_dh_secret_len = DH_compute_key(_current_dh_secret, pub_key_buddy, _dh);
        BN_free(pub_key_buddy);
        
        printf("Updated current DH secret with new local key (temporary state)\n");
        printf("New temporary DH secret (first 8 bytes): ");
        for(int i = 0; i < 8; i++)
            printf("%02X", _current_dh_secret[i]);
        printf("...\n");
    }
    
    _awaiting_vertical_ratchet_response = true;
    _vertical_ratchet_pending = true;
    
    printf("Generated new DH keys for vertical ratchet\n");
    printf("New public key (first 8 bytes): ");
    for(int i = 0; i < 8; i++)
        printf("%02X", _temp_local_pub_key[i]);
    printf("...\n");
    printf("====================================\n");
    
    return 0;
}

int SmkexSessionInfo::processVerticalRatchetKey(const unsigned char* received_pub_key, unsigned int key_len) {
    if(key_len != SMKEX_PUB_KEY_LEN) {
        printf("Error: Received DH key length mismatch in vertical ratchet\n");
        return -1;
    }
    
    printf("=== PROCESSING VERTICAL RATCHET KEY ===\n");
    printf("Received public key (first 8 bytes): ");
    for(int i = 0; i < 8; i++)
        printf("%02X", received_pub_key[i]);
    printf("...\n");
    
    // Dacă nu suntem inițiatori, generăm și noi noi chei DH
    if(!_awaiting_vertical_ratchet_response) {
        printf("Not initiator - generating new DH keys in response\n");
        
        // Păstrează cheia DH curentă
        storePreviousDHKey();
        
        // Generează noi chei DH
        if(DH_generate_key(_dh) != 1) {
            printf("Error generating new DH keys in response to vertical ratchet\n");
            return -1;
        }
        
        BIGNUM *new_pub_key_num, *new_priv_key_num;
        
        #if OPENSSL_VERSION_NUMBER < 0x10100000L // OpenSSL 1.0.2
        new_pub_key_num = _dh->pub_key;
        new_priv_key_num = _dh->priv_key;
        #else // OpenSSL 1.1.1
        DH_get0_key(_dh, (const BIGNUM**) &new_pub_key_num, (const BIGNUM**) &new_priv_key_num);
        #endif
        
        _temp_local_pub_key_length = BN_num_bytes(new_pub_key_num);
        _temp_local_priv_key_length = BN_num_bytes(new_priv_key_num);
        
        BN_bn2bin(new_pub_key_num, _temp_local_pub_key);
        BN_bn2bin(new_priv_key_num, _temp_local_priv_key);
        
        printf("Generated response DH keys\n");
    }
    
    // Actualizează cheia publică remotă cu cea primită
    memcpy(remote_pub_key, received_pub_key, key_len);
    remote_pub_key_length = key_len;
    
    // Finalizează vertical ratchet
    if(finalizeVerticalRatchet() != 0) {
        printf("Error finalizing vertical ratchet\n");
        return -1;
    }
    
    printf("=====================================\n");
    return 0;
}

int SmkexSessionInfo::finalizeVerticalRatchet() {
    printf("=== FINALIZING VERTICAL RATCHET ===\n");
    
    // Calculează noul secret DH folosind cheile temporare
    unsigned char new_dh_secret[SMKEX_DH_KEY_LEN];
    BIGNUM *pub_key_buddy = BN_bin2bn(remote_pub_key, remote_pub_key_length, NULL);
    
    // Folosește cheia privată temporară pentru calculul secretului
    BIGNUM *temp_priv_bn = BN_bin2bn(_temp_local_priv_key, _temp_local_priv_key_length, NULL);
    
    // Creează un DH temporar cu cheia privată nouă
    DH* temp_dh = DH_new();
    #if OPENSSL_VERSION_NUMBER < 0x10100000L // OpenSSL 1.0.2
    const BIGNUM *p, *g;
    DH_get0_pqg(_dh, &p, NULL, &g);
    DH_set0_pqg(temp_dh, BN_dup(p), NULL, BN_dup(g));
    temp_dh->priv_key = temp_priv_bn;
    temp_dh->pub_key = BN_bin2bn(_temp_local_pub_key, _temp_local_pub_key_length, NULL);
    #else // OpenSSL 1.1.1
    const BIGNUM *p, *g;
    DH_get0_pqg(_dh, &p, NULL, &g);
    DH_set0_pqg(temp_dh, BN_dup(p), NULL, BN_dup(g));
    BIGNUM *temp_pub_bn = BN_bin2bn(_temp_local_pub_key, _temp_local_pub_key_length, NULL);
    DH_set0_key(temp_dh, temp_pub_bn, temp_priv_bn);
    #endif
    
    int dh_secret_len = DH_compute_key(new_dh_secret, pub_key_buddy, temp_dh);
    
    BN_free(pub_key_buddy);
    DH_free(temp_dh);
    
    if(dh_secret_len <= 0) {
        printf("Error computing new DH secret in vertical ratchet\n");
        return -1;
    }
    
    // Actualizează secretul DH curent
    memcpy(_current_dh_secret, new_dh_secret, dh_secret_len);
    _current_dh_secret_len = dh_secret_len;
    
    // Actualizează cheile locale cu cele temporare
    memcpy(local_pub_key, _temp_local_pub_key, _temp_local_pub_key_length);
    memcpy(local_priv_key, _temp_local_priv_key, _temp_local_priv_key_length);
    local_pub_key_length = _temp_local_pub_key_length;
    local_priv_key_length = _temp_local_priv_key_length;
    
    // Re-derivă cheia de sesiune folosind noul secret DH + Kyber (dacă există)
    if (_kyber_initialised && _kyber_shared_secret_len > 0) {
        // Combinăm noul secret DH cu secretul Kyber existent
        unsigned char combined_key[SMKEX_DH_KEY_LEN + SMKEX_KYBER_SHARED_SECRET_LEN];
        memcpy(combined_key, new_dh_secret, dh_secret_len);
        memcpy(combined_key + dh_secret_len, _kyber_shared_secret, _kyber_shared_secret_len);
        
        unsigned int combined_len = dh_secret_len + _kyber_shared_secret_len;
        nist_800_kdf(combined_key, combined_len, _session_key, &_session_key_len);
        
        printf("Re-derived session key using new DH + existing Kyber secret\n");
    } else {
        // Folosim doar noul secret DH
        nist_800_kdf(new_dh_secret, dh_secret_len, _session_key, &_session_key_len);
        printf("Re-derived session key using new DH secret only\n");
    }
    
    // Re-inițializează symmetric ratchet cu noua cheie de sesiune
    initializeRatchet();
    
    // Actualizează contoarele de vertical ratchet
    _last_vertical_ratchet_at_counter = _sending_counter;
    _vertical_ratchet_counter++;
    _vertical_ratchet_pending = false;
    _awaiting_vertical_ratchet_response = false;
    
    // Curăță cheile temporare
    memset(_temp_local_pub_key, 0, SMKEX_PUB_KEY_LEN);
    memset(_temp_local_priv_key, 0, SMKEX_PRIV_KEY_LEN);
    _temp_local_pub_key_length = 0;
    _temp_local_priv_key_length = 0;
    
    printf("Vertical ratchet completed successfully\n");
    printf("New session key (first 16 bytes): ");
    for(int i = 0; i < 16; i++)
        printf("%02X", _session_key[i]);
    printf("...\n");
    printf("Vertical ratchet counter: %u\n", _vertical_ratchet_counter);
    printf("==================================\n");
    
    return 0;
}

void SmkexSessionInfo::storePreviousDHKey() {
    if(_current_dh_secret_len == 0) {
        // Prima dată când păstrăm o cheie - calculează secretul curent
        if(remote_pub_key_length > 0) {
            BIGNUM *pub_key_buddy = BN_bin2bn(remote_pub_key, remote_pub_key_length, NULL);
            _current_dh_secret_len = DH_compute_key(_current_dh_secret, pub_key_buddy, _dh);
            BN_free(pub_key_buddy);
        }
    }
    
    if(_current_dh_secret_len == 0) {
        printf("Warning: No current DH secret to store\n");
        return;
    }
    
    // Găsește un slot liber sau cel mai vechi
    int slot_to_use = -1;
    unsigned int oldest_counter = UINT_MAX;
    
    for(int i = 0; i < MAX_STORED_KEYS; i++) {
        if(!_stored_dh_keys[i].is_valid) {
            slot_to_use = i;
            break;
        }
        if(_stored_dh_keys[i].counter_from < oldest_counter) {
            oldest_counter = _stored_dh_keys[i].counter_from;
            slot_to_use = i;
        }
    }
    
    if(slot_to_use >= 0) {
        _stored_dh_keys[slot_to_use].is_valid = true;
        memcpy(_stored_dh_keys[slot_to_use].dh_secret, _current_dh_secret, _current_dh_secret_len);
        _stored_dh_keys[slot_to_use].dh_secret_len = _current_dh_secret_len;
        _stored_dh_keys[slot_to_use].counter_from = _last_vertical_ratchet_at_counter;
        _stored_dh_keys[slot_to_use].counter_to = _sending_counter - 1;
        
        if(slot_to_use >= _stored_keys_count) {
            _stored_keys_count = slot_to_use + 1;
        }
        
        printf("Stored previous DH key in slot %d (counters %u-%u)\n", 
               slot_to_use, _stored_dh_keys[slot_to_use].counter_from, 
               _stored_dh_keys[slot_to_use].counter_to);
    }
}

bool SmkexSessionInfo::findDHSecretForCounter(unsigned int counter, unsigned char* dh_secret, unsigned int* secret_len) {
    // Verifică secretul curent
    if(counter >= _last_vertical_ratchet_at_counter && _current_dh_secret_len > 0) {
        memcpy(dh_secret, _current_dh_secret, _current_dh_secret_len);
        *secret_len = _current_dh_secret_len;
        printf("Using current DH secret for counter %u\n", counter);
        return true;
    }
    
    // Caută în cheile stocate
    for(int i = 0; i < _stored_keys_count; i++) {
        if(_stored_dh_keys[i].is_valid && 
           counter >= _stored_dh_keys[i].counter_from && 
           counter <= _stored_dh_keys[i].counter_to) {
            memcpy(dh_secret, _stored_dh_keys[i].dh_secret, _stored_dh_keys[i].dh_secret_len);
            *secret_len = _stored_dh_keys[i].dh_secret_len;
            printf("Using stored DH secret from slot %d for counter %u (range %u-%u)\n", 
                   i, counter, _stored_dh_keys[i].counter_from, _stored_dh_keys[i].counter_to);
            return true;
        }
    }
    
    printf("Warning: No DH secret found for counter %u\n", counter);
    return false;
}

void SmkexSessionInfo::cleanupOldDHKeys() {
    unsigned int current_counter = _receiving_counter;
    int cleaned_count = 0;
    
    for(int i = 0; i < MAX_STORED_KEYS; i++) {
        if(_stored_dh_keys[i].is_valid) {
            // Păstrează cheile pentru ultimele 2 * VERTICAL_RATCHET_INTERVAL mesaje
            if(_stored_dh_keys[i].counter_to < current_counter - (2 * VERTICAL_RATCHET_INTERVAL)) {
                _stored_dh_keys[i].is_valid = false;
                _stored_dh_keys[i].counter_from = 0;
                _stored_dh_keys[i].counter_to = 0;
                _stored_dh_keys[i].dh_secret_len = 0;
                cleaned_count++;
                
                printf("Cleaned up old DH key from slot %d\n", i);
            }
        }
    }
    
    if(cleaned_count > 0) {
        printf("Cleaned up %d old DH keys\n", cleaned_count);
    }
}

void SmkexSessionInfo::printVerticalRatchetState() const {
    printf("=== Vertical Ratchet State ===\n");
    printf("Vertical ratchet counter: %u\n", _vertical_ratchet_counter);
    printf("Last vertical ratchet at counter: %u\n", _last_vertical_ratchet_at_counter);
    printf("Pending vertical ratchet: %s\n", _vertical_ratchet_pending ? "YES" : "NO");
    printf("Awaiting response: %s\n", _awaiting_vertical_ratchet_response ? "YES" : "NO");
    
    // Afișează starea corectă în funcție de faza vertical ratchet
    if(_awaiting_vertical_ratchet_response) {
        printf("STATUS: Waiting for partner's response to complete vertical ratchet\n");
        printf("Current DH secret: INTERMEDIATE STATE (using new local + old remote key)\n");
    } else if(_vertical_ratchet_pending) {
        printf("STATUS: Processing incoming vertical ratchet request\n");  
        printf("Current DH secret: INTERMEDIATE STATE\n");
    } else {
        printf("STATUS: Vertical ratchet complete - using finalized keys\n");
        printf("Current DH secret: FINAL STATE\n");
    }
    
    printf("Current DH secret length: %u\n", _current_dh_secret_len);
    printf("Stored keys count: %u\n", _stored_keys_count);
    
    if(_current_dh_secret_len > 0) {
        printf("Current DH secret (first 8 bytes): ");
        for(int i = 0; i < 8 && i < (int)_current_dh_secret_len; i++)
            printf("%02X", _current_dh_secret[i]);
        printf("...\n");
    }
    
    printf("Stored DH keys:\n");
    for(int i = 0; i < MAX_STORED_KEYS; i++) {
        if(_stored_dh_keys[i].is_valid) {
            printf("  Slot %d: counters %u-%u, secret_len=%u (first 4 bytes: ",
                   i, _stored_dh_keys[i].counter_from, _stored_dh_keys[i].counter_to,
                   _stored_dh_keys[i].dh_secret_len);
            for(int j = 0; j < 4 && j < (int)_stored_dh_keys[i].dh_secret_len; j++)
                printf("%02X", _stored_dh_keys[i].dh_secret[j]);
            printf("...)\n");
        }
    }
    
    unsigned int messages_since_last = _sending_counter - _last_vertical_ratchet_at_counter;
    printf("Messages since last vertical ratchet: %u / %d\n", 
           messages_since_last, VERTICAL_RATCHET_INTERVAL);
    printf("Should perform vertical ratchet: %s\n", 
           shouldPerformVerticalRatchet() ? "YES" : "NO");
    printf("=============================\n");
}


