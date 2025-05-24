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
    
    // Check if there's unwanted data beyond 32 bytes
    bool has_extra_data = false;
    for(int i = 32; i < SMKEX_SESSION_KEY_LEN; i++) {
        if (_sending_chain_key[i] != 0 || _receiving_chain_key[i] != 0) {
            has_extra_data = true;
            break;
        }
    }
    if (has_extra_data) {
        printf("WARNING: Extra data found beyond 32 bytes in chain keys!\n");
        printf("Sending chain key (full %d bytes): ", SMKEX_SESSION_KEY_LEN);
        for(int i = 0; i < SMKEX_SESSION_KEY_LEN; i++)
            printf("%02X", _sending_chain_key[i]);
        printf("\n");
        
        printf("Receiving chain key (full %d bytes): ", SMKEX_SESSION_KEY_LEN);
        for(int i = 0; i < SMKEX_SESSION_KEY_LEN; i++)
            printf("%02X", _receiving_chain_key[i]);
        printf("\n");
    }
#endif

    // Inițializează vertical ratchet
    initializeVerticalRatchet();
    
    printf("Both symmetric and vertical ratchets initialized\n");
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

// Verical Ratcheting implementation
void SmkexSessionInfo::initializeVerticalRatchet() {
  printf("===INITIALIZING VERTICAL RATCHET ===\n");

  if (_session_key_len == 0) {
    LOGMSG("Error: Cannot initialize vertical ratchet without session key\n");
    return;
  }

  // Using session key as root key
  memcpy(_root_key, _session_key, SMKEX_SESSION_KEY_LEN);

  // initializing state
  _vertical_ratchet_initialized = true;
  _vertical_ratchet_initialized = true;
  _local_dh_priv_ratchet_length = 0;
  _local_dh_pub_ratchet_length = 0;
  _remote_dh_pub_ratchet_length = 0;
  _previous_sending_counter = 0;
  _skipped_message_keys.clear();

  generateNewDHRatchetKeys();

      printf("Vertical ratchet initialized successfully\n");
    printf("Root key (first 16 bytes): ");
    for(int i = 0; i < 16; i++)
        printf("%02X", _root_key[i]);
    printf("...\n");
    printf("=====================================\n");

}

bool SmkexSessionInfo::generateNewDHRatchetKeys() {
    if (!_dh) {
        printf("Error: DH context not initialized\n");
        return false;
    }
    
    printf("=== GENERATING NEW DH RATCHET KEYS ===\n");
    
    // Generează o nouă pereche de chei DH pentru ratchet
    if (DH_generate_key(_dh) != 1) {
        printf("Error generating new DH ratchet keys\n");
        return false;
    }
    
    // Extrage cheile generate
    BIGNUM *local_pub_key_num, *local_priv_key_num;
    
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    local_pub_key_num = _dh->pub_key;
    local_priv_key_num = _dh->priv_key;
#else
    DH_get0_key(_dh, (const BIGNUM**)&local_pub_key_num, (const BIGNUM**)&local_priv_key_num);
#endif

    if (local_pub_key_num != NULL) {
        _local_dh_pub_ratchet_length = BN_bn2bin(local_pub_key_num, _local_dh_pub_ratchet);
    }

    if (local_priv_key_num != NULL) {
        _local_dh_priv_ratchet_length = BN_bn2bin(local_priv_key_num, _local_dh_priv_ratchet);
    }
    
    printf("Generated new DH ratchet keys:\n");
    printf("Public key length: %u\n", _local_dh_pub_ratchet_length);
    printf("Private key length: %u\n", _local_dh_priv_ratchet_length);
    printf("=====================================\n");
    
    return true;
}

bool SmkexSessionInfo::performVerticalRatchetStep(const unsigned char *new_dh_pub_key, unsigned int key_length) {
    if (!_vertical_ratchet_initialized) {
        printf("Error: Vertical ratchet not initialized\n");
        return false;
    }
    
    if (new_dh_pub_key == NULL || key_length == 0) {
        printf("Error: Invalid DH key parameters\n");
        return false;
    }
    
    printf("Performing vertical ratchet step with new DH key (length=%u)\n", key_length);
    
    // Setează cheia DH remotă
    setRemoteDHRatchetPubKey(new_dh_pub_key, key_length);
    
    // Calculează noul shared secret DH
    unsigned char new_dh_shared_secret[SMKEX_SESSION_KEY_LEN];
    if (computeDHSharedSecret(_local_dh_priv_ratchet, new_dh_pub_key, key_length, new_dh_shared_secret) != 0) {
        printf("Error computing new DH shared secret\n");
        return false;
    }
    
    printf("Computed new DH shared secret (first 16 bytes): ");
    for(int i = 0; i < 16; i++)
        printf("%02X", new_dh_shared_secret[i]);
    printf("...\n");
    
    // Salvează root key-ul vechi pentru comparație
    unsigned char old_root_key[SMKEX_SESSION_KEY_LEN];
    memcpy(old_root_key, _root_key, SMKEX_SESSION_KEY_LEN);
    
    // Actualizează root key și chain keys folosind KDF
    unsigned char new_root_key[SMKEX_SESSION_KEY_LEN];
    unsigned char new_sending_chain_key[SMKEX_SESSION_KEY_LEN];
    unsigned char new_receiving_chain_key[SMKEX_SESSION_KEY_LEN];
    
    // KDF(root_key || dh_shared_secret) -> new_root_key || new_chain_keys
    if (performKDF(_root_key, new_dh_shared_secret, new_root_key, new_sending_chain_key, new_receiving_chain_key) != 0) {
        printf("Error performing KDF for vertical ratchet\n");
        return false;
    }
    
    // Actualizează cheile
    memcpy(_root_key, new_root_key, SMKEX_SESSION_KEY_LEN);
    memcpy(_sending_chain_key, new_sending_chain_key, SMKEX_SESSION_KEY_LEN);
    memcpy(_receiving_chain_key, new_receiving_chain_key, SMKEX_SESSION_KEY_LEN);
    
    // Resetează contoarele pentru noua epocă
    _previous_sending_counter = _sending_counter;
    _sending_counter = 0;
    _receiving_counter = 0;
    
    // Generează o nouă pereche de chei DH pentru următorul ratchet
    if (generateNewDHRatchetKeyPair() != 0) {
        printf("Warning: Could not generate new DH ratchet key pair\n");
    }
    
    printf("Vertical ratchet step completed successfully!\n");
    printf("Root key changed from: ");
    for(int i = 0; i < 16; i++) printf("%02X", old_root_key[i]);
    printf("...\n");
    printf("                   to: ");
    for(int i = 0; i < 16; i++) printf("%02X", _root_key[i]);
    printf("...\n");
    
    return true;
}

void SmkexSessionInfo::setRemoteDHRatchetPubKey(const unsigned char *key, unsigned int length) {
    if (key == NULL || length == 0 || length > SMKEX_PUB_KEY_LEN) {
        printf("Error: Invalid remote DH ratchet key parameters\n");
        return;
    }
    
    memcpy(_remote_dh_pub_ratchet, key, length);
    _remote_dh_pub_ratchet_length = length;
    
    printf("Set remote DH ratchet key (length=%u, first 16 bytes): ", length);
    for(int i = 0; i < 16 && i < length; i++)
        printf("%02X", key[i]);
    printf("...\n");
}

int SmkexSessionInfo::getLocalDHRatchetPubKey(unsigned char kbuf[]) const {
    if (!_vertical_ratchet_initialized || _local_dh_pub_ratchet_length == 0) {
        return 0;
    }
    
    if (kbuf != NULL) {
        memcpy(kbuf, _local_dh_pub_ratchet, _local_dh_pub_ratchet_length);
    }
    
    return _local_dh_pub_ratchet_length;
}

bool SmkexSessionInfo::trySkippedMessageKey(unsigned int counter, unsigned char message_key[SMKEX_SESSION_KEY_LEN]) {
    auto it = _skipped_message_keys.find(counter);
    if (it != _skipped_message_keys.end()) {
        memcpy(message_key, it->second, SMKEX_SESSION_KEY_LEN);
        _skipped_message_keys.erase(it);
        printf("Using skipped message key for counter %u\n", counter);
        return true;
    }
    return false;
}

void SmkexSessionInfo::skipMessageKeys(unsigned int until_counter) {
    if (_sending_counter + MAX_SKIP < until_counter) {
        printf("Error: Too many skipped messages (%u)\n", until_counter - _sending_counter);
        return;
    }
    
    printf("Skipping message keys from %u to %u\n", _sending_counter, until_counter - 1);
    
    // Salvează cheile pentru mesajele sărite
    while (_sending_counter < until_counter) {
        unsigned char message_key[SMKEX_SESSION_KEY_LEN];
        
        // Generează cheia pentru mesajul sărit
        unsigned char counter_bytes[4];
        counter_bytes[0] = (_sending_counter >> 24) & 0xFF;
        counter_bytes[1] = (_sending_counter >> 16) & 0xFF;
        counter_bytes[2] = (_sending_counter >> 8) & 0xFF;
        counter_bytes[3] = _sending_counter & 0xFF;
        
        unsigned char hmac_input[7];
        memcpy(hmac_input, counter_bytes, 4);
        memcpy(hmac_input + 4, "MSG", 3);
        
        unsigned int hmac_len;
        HMAC(EVP_sha256(), _sending_chain_key, SMKEX_SESSION_KEY_LEN,
             hmac_input, 7, message_key, &hmac_len);
        
        // Salvează cheia
        memcpy(_skipped_message_keys[_sending_counter], message_key, SMKEX_SESSION_KEY_LEN);
        
        // Avansează chain key
        unsigned char new_chain_key[SMKEX_SESSION_KEY_LEN];
        HMAC(EVP_sha256(), _sending_chain_key, SMKEX_SESSION_KEY_LEN,
             (unsigned char*)"CHAIN", 5, new_chain_key, &hmac_len);
        memcpy(_sending_chain_key, new_chain_key, SMKEX_SESSION_KEY_LEN);
        
        _sending_counter++;
    }
}

void SmkexSessionInfo::resetVerticalRatchet() {
    printf("=== RESETTING VERTICAL RATCHET ===\n");
    
    _vertical_ratchet_initialized = false;
    memset(_root_key, 0, sizeof(_root_key));
    memset(_local_dh_priv_ratchet, 0, sizeof(_local_dh_priv_ratchet));
    memset(_local_dh_pub_ratchet, 0, sizeof(_local_dh_pub_ratchet));
    memset(_remote_dh_pub_ratchet, 0, sizeof(_remote_dh_pub_ratchet));
    
    _local_dh_priv_ratchet_length = 0;
    _local_dh_pub_ratchet_length = 0;
    _remote_dh_pub_ratchet_length = 0;
    _previous_sending_counter = 0;
    
    _skipped_message_keys.clear();
    
    printf("Vertical ratchet reset completed\n");
    printf("==================================\n");
}

void SmkexSessionInfo::debugVerticalRatchetState() const {
    printf("\n=== VERTICAL RATCHET DEBUG STATE ===\n");
    printf("Vertical ratchet initialized: %s\n", _vertical_ratchet_initialized ? "YES" : "NO");
    printf("Sending counter: %u\n", _sending_counter);
    printf("Receiving counter: %u\n", _receiving_counter);
    printf("Previous sending counter: %u\n", _previous_sending_counter);
    
    if (_vertical_ratchet_initialized) {
        printf("Root key (first 16 bytes): ");
        for(int i = 0; i < 16; i++)
            printf("%02X", _root_key[i]);
        printf("...\n");
        
        printf("Local DH pub key length: %u\n", _local_dh_pub_ratchet_length);
        if (_local_dh_pub_ratchet_length > 0) {
            printf("Local DH pub key (first 16 bytes): ");
            for(int i = 0; i < 16 && i < _local_dh_pub_ratchet_length; i++)
                printf("%02X", _local_dh_pub_ratchet[i]);
            printf("...\n");
        }
        
        printf("Remote DH pub key length: %u\n", _remote_dh_pub_ratchet_length);
        if (_remote_dh_pub_ratchet_length > 0) {
            printf("Remote DH pub key (first 16 bytes): ");
            for(int i = 0; i < 16 && i < _remote_dh_pub_ratchet_length; i++)
                printf("%02X", _remote_dh_pub_ratchet[i]);
            printf("...\n");
        }
        
        printf("Skipped message keys count: %zu\n", _skipped_message_keys.size());
    }
    printf("====================================\n\n");
}

void SmkexSessionInfo::testVerticalRatchetTrigger(unsigned int message_count) {
    printf("\n=== TESTING VERTICAL RATCHET TRIGGER ===\n");
    printf("Simulating %u messages...\n", message_count);
    
    // Salvează starea inițială
    unsigned char old_root_key[SMKEX_SESSION_KEY_LEN];
    unsigned char old_sending_key[SMKEX_SESSION_KEY_LEN];
    unsigned char old_receiving_key[SMKEX_SESSION_KEY_LEN];
    
    memcpy(old_root_key, _root_key, SMKEX_SESSION_KEY_LEN);
    memcpy(old_sending_key, _sending_chain_key, SMKEX_SESSION_KEY_LEN);
    memcpy(old_receiving_key, _receiving_chain_key, SMKEX_SESSION_KEY_LEN);
    
    // Simulează trimiterea de mesaje
    for (unsigned int i = 0; i < message_count; i++) {
        unsigned char dummy_key[SMKEX_SESSION_KEY_LEN];
        ratchetSendingChain(dummy_key);
        printf("Message %u: sending counter = %u\n", i+1, _sending_counter);
    }
    
    printf("Final sending counter: %u\n", _sending_counter);
    printf("Should trigger vertical ratchet at: %u messages\n", VERTICAL_RATCHET_INTERVAL);
    
    // Verifică dacă s-ar trebui să se declanșeze vertical ratchet
    if (_sending_counter > 0 && _sending_counter % VERTICAL_RATCHET_INTERVAL == 0) {
        printf("*** VERTICAL RATCHET SHOULD BE TRIGGERED NOW ***\n");
    }
    
    printf("=========================================\n\n");
}

bool SmkexSessionInfo::verifyRatchetKeyChange(const unsigned char* old_root_key, 
                                            const unsigned char* old_sending_key,
                                            const unsigned char* old_receiving_key) {
    printf("\n=== VERIFYING RATCHET KEY CHANGES ===\n");
    
    bool root_changed = (memcmp(_root_key, old_root_key, SMKEX_SESSION_KEY_LEN) != 0);
    bool sending_changed = (memcmp(_sending_chain_key, old_sending_key, SMKEX_SESSION_KEY_LEN) != 0);
    bool receiving_changed = (memcmp(_receiving_chain_key, old_receiving_key, SMKEX_SESSION_KEY_LEN) != 0);
    
    printf("Root key changed: %s\n", root_changed ? "YES" : "NO");
    printf("Sending chain key changed: %s\n", sending_changed ? "YES" : "NO");
    printf("Receiving chain key changed: %s\n", receiving_changed ? "YES" : "NO");
    
    if (root_changed) {
        printf("Old root key (first 16 bytes): ");
        for(int i = 0; i < 16; i++) printf("%02X", old_root_key[i]);
        printf("...\n");
        printf("New root key (first 16 bytes): ");
        for(int i = 0; i < 16; i++) printf("%02X", _root_key[i]);
        printf("...\n");
    }
    
    printf("====================================\n\n");
    return root_changed && sending_changed && receiving_changed;
}

int SmkexSessionInfo::performKDF(const unsigned char *root_key, const unsigned char *dh_secret,
                                unsigned char *new_root_key, unsigned char *new_sending_key,
                                unsigned char *new_receiving_key) {
    // Folosește HKDF pentru a deriva noile chei
    unsigned char combined_input[SMKEX_SESSION_KEY_LEN * 2];
    memcpy(combined_input, root_key, SMKEX_SESSION_KEY_LEN);
    memcpy(combined_input + SMKEX_SESSION_KEY_LEN, dh_secret, SMKEX_SESSION_KEY_LEN);
    
    unsigned char output[SMKEX_SESSION_KEY_LEN * 3];
    
    // Folosește SHA-256 pentru KDF
    if (EVP_Digest(combined_input, SMKEX_SESSION_KEY_LEN * 2, output, NULL, EVP_sha256(), NULL) != 1) {
        printf("Error in EVP_Digest for KDF\n");
        return -1;
    }
    
    // Extinde output-ul pentru a obține toate cheile necesare
    unsigned char extended_output[SMKEX_SESSION_KEY_LEN * 3];
    for (int i = 0; i < 3; i++) {
        unsigned char counter = i + 1;
        unsigned char input_with_counter[SMKEX_SESSION_KEY_LEN + 1];
        memcpy(input_with_counter, output, SMKEX_SESSION_KEY_LEN);
        input_with_counter[SMKEX_SESSION_KEY_LEN] = counter;
        
        if (EVP_Digest(input_with_counter, SMKEX_SESSION_KEY_LEN + 1, 
                      extended_output + (i * SMKEX_SESSION_KEY_LEN), NULL, EVP_sha256(), NULL) != 1) {
            printf("Error in EVP_Digest for key derivation step %d\n", i);
            return -1;
        }
    }
    
    // Copiază cheile derivate
    memcpy(new_root_key, extended_output, SMKEX_SESSION_KEY_LEN);
    memcpy(new_sending_key, extended_output + SMKEX_SESSION_KEY_LEN, SMKEX_SESSION_KEY_LEN);
    memcpy(new_receiving_key, extended_output + (2 * SMKEX_SESSION_KEY_LEN), SMKEX_SESSION_KEY_LEN);
    
    return 0;
}

int SmkexSessionInfo::generateDHKeyPair(unsigned char *private_key, unsigned char *public_key, unsigned int *public_key_length) {
    if (!_dh) {
        printf("Error: DH context not initialized\n");
        return -1;
    }
    
    // Creează un nou context DH pentru această generare
    DH *temp_dh = DH_new();
    if (!temp_dh) {
        printf("Error creating temporary DH context\n");
        return -1;
    }
    
    // Copiază parametrii P și G din contextul principal
    BIGNUM *p, *g;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    p = BN_dup(_dh->p);
    g = BN_dup(_dh->g);
    temp_dh->p = p;
    temp_dh->g = g;
#else
    const BIGNUM *orig_p, *orig_g;
    DH_get0_pqg(_dh, &orig_p, NULL, &orig_g);
    p = BN_dup(orig_p);
    g = BN_dup(orig_g);
    DH_set0_pqg(temp_dh, p, NULL, g);
#endif
    
    // Generează noua pereche de chei
    if (DH_generate_key(temp_dh) != 1) {
        printf("Error generating DH key pair\n");
        DH_free(temp_dh);
        return -1;
    }
    
    // Extrage cheile generate
    BIGNUM *pub_key_num, *priv_key_num;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    pub_key_num = temp_dh->pub_key;
    priv_key_num = temp_dh->priv_key;
#else
    DH_get0_key(temp_dh, (const BIGNUM**)&pub_key_num, (const BIGNUM**)&priv_key_num);
#endif
    
    if (!pub_key_num || !priv_key_num) {
        printf("Error: Generated keys are NULL\n");
        DH_free(temp_dh);
        return -1;
    }
    
    // Convertește cheile în format binar
    unsigned int priv_length = BN_num_bytes(priv_key_num);
    *public_key_length = BN_num_bytes(pub_key_num);
    
    if (priv_length > SMKEX_PRIV_KEY_LEN || *public_key_length > SMKEX_PUB_KEY_LEN) {
        printf("Error: Generated keys too large (priv: %u, pub: %u)\n", priv_length, *public_key_length);
        DH_free(temp_dh);
        return -1;
    }
    
    // Copiază cheile în buffer-ele de output
    BN_bn2bin(priv_key_num, private_key);
    BN_bn2bin(pub_key_num, public_key);
    
    printf("Generated DH key pair: priv_len=%u, pub_len=%u\n", priv_length, *public_key_length);
    
    DH_free(temp_dh);
    return 0;
}

int SmkexSessionInfo::computeDHSharedSecret(const unsigned char *local_private_key, 
                                          const unsigned char *remote_public_key,
                                          unsigned int remote_key_length,
                                          unsigned char *shared_secret) {
    if (!_dh) {
        printf("Error: DH context not initialized\n");
        return -1;
    }
    
    if (!local_private_key || !remote_public_key || !shared_secret) {
        printf("Error: NULL parameters in computeDHSharedSecret\n");
        return -1;
    }
    
    // Convertește cheia publică remotă în BIGNUM
    BIGNUM *remote_pub_bn = BN_bin2bn(remote_public_key, remote_key_length, NULL);
    if (!remote_pub_bn) {
        printf("Error converting remote public key to BIGNUM\n");
        return -1;
    }
    
    // Creează un context DH temporar cu cheia privată locală
    DH *temp_dh = DH_new();
    if (!temp_dh) {
        printf("Error creating temporary DH context\n");
        BN_free(remote_pub_bn);
        return -1;
    }
    
    // Copiază parametrii P și G
    BIGNUM *p, *g;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    p = BN_dup(_dh->p);
    g = BN_dup(_dh->g);
    temp_dh->p = p;
    temp_dh->g = g;
    
    // Setează cheia privată locală
    temp_dh->priv_key = BN_bin2bn(local_private_key, SMKEX_PRIV_KEY_LEN, NULL);
#else
    const BIGNUM *orig_p, *orig_g;
    DH_get0_pqg(_dh, &orig_p, NULL, &orig_g);
    p = BN_dup(orig_p);
    g = BN_dup(orig_g);
    DH_set0_pqg(temp_dh, p, NULL, g);
    
    // Setează cheia privată locală
    BIGNUM *priv_key_bn = BN_bin2bn(local_private_key, SMKEX_PRIV_KEY_LEN, NULL);
    DH_set0_key(temp_dh, NULL, priv_key_bn);
#endif
    
    // Calculează shared secret-ul
    int shared_secret_len = DH_compute_key(shared_secret, remote_pub_bn, temp_dh);
    
    if (shared_secret_len <= 0) {
        printf("Error computing DH shared secret\n");
        BN_free(remote_pub_bn);
        DH_free(temp_dh);
        return -1;
    }
    
    // Dacă shared secret-ul este mai scurt decât buffer-ul, completează cu zero-uri
    if (shared_secret_len < SMKEX_SESSION_KEY_LEN) {
        memset(shared_secret + shared_secret_len, 0, SMKEX_SESSION_KEY_LEN - shared_secret_len);
    }
    
    printf("Computed DH shared secret: length=%d bytes\n", shared_secret_len);
    
    BN_free(remote_pub_bn);
    DH_free(temp_dh);
    return 0;
}

int SmkexSessionInfo::generateNewDHRatchetKeyPair() {
    // Generează o nouă pereche de chei DH pentru ratchet
    if (generateDHKeyPair(_local_dh_priv_ratchet, _local_dh_pub_ratchet, &_local_dh_pub_ratchet_length) != 0) {
        printf("Error generating new DH ratchet key pair\n");
        return -1;
    }
    
    printf("Generated new DH ratchet key pair (pub key first 16 bytes): ");
    for(int i = 0; i < 16 && i < _local_dh_pub_ratchet_length; i++)
        printf("%02X", _local_dh_pub_ratchet[i]);
    printf("...\n");
    
    return 0;
}
