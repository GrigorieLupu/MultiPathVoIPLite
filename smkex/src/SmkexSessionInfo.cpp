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
    if (_dh != 0) {
        DH_free(_dh);
        _dh = nullptr;
    }
    if (_vertical_dh != 0) {
        DH_free(_vertical_dh);
        _vertical_dh = nullptr;
    }
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
    
    bool is_first_init = !_ratchet_initialized;
    
    // Reset the ratchet completely
    _ratchet_initialized = false;
    
    // Clear chain key buffers completely before use
    memset(_sending_chain_key, 0, sizeof(_sending_chain_key));
    memset(_receiving_chain_key, 0, sizeof(_receiving_chain_key));
    
    // Only reset counters on first initialization, not on vertical ratchet
    if (is_first_init) {
        _sending_counter = 0;
        _receiving_counter = 0;
        printf("First ratchet init - counters reset to 0\n");
    } else {
        printf("Vertical ratchet re-init - keeping counters at S:%u R:%u\n", 
               _sending_counter, _receiving_counter);
    }
    

    printf("Session key (%u bytes): ", _session_key_len);
    for(int i = 0; i < (int)_session_key_len && i < 32; i++)
        printf("%02X", _session_key[i]);
    if (_session_key_len > 32) printf("...");
    printf("\n");
    
    printf("INITRATCHET DEBUG: Role=%s, SessionID=%d, Buddy=%s\n", 
           _iAmSessionInitiator ? "INITIATOR" : "RESPONDER", 
           _sessionID, _buddy.c_str());
    
    // 🔥 CRUCIAL FIX: Use consistent labels regardless of who is calling
    // The key insight: we need to ensure that:
    // - What INITIATOR calls "sending" should match what RESPONDER calls "receiving"
    // - What INITIATOR calls "receiving" should match what RESPONDER calls "sending"
    
    unsigned int hmac_len;
    
    if (_iAmSessionInitiator) {
        // Initiator: I send with "ALICE_SEND", I receive from "BOB_SEND"
        const char* my_send_label = "ALICE_SEND";
        const char* their_send_label = "BOB_SEND";
        
        HMAC(EVP_sha256(), _session_key, _session_key_len,
             (unsigned char*)my_send_label, strlen(my_send_label), 
             _sending_chain_key, &hmac_len);
             
        HMAC(EVP_sha256(), _session_key, _session_key_len,
             (unsigned char*)their_send_label, strlen(their_send_label), 
             _receiving_chain_key, &hmac_len);
             
        printf("INITRATCHET DEBUG: INITIATOR - my_sending=ALICE_SEND, my_receiving=BOB_SEND\n");
    } else {
        // Responder: I send with "BOB_SEND", I receive from "ALICE_SEND"
        const char* my_send_label = "BOB_SEND";
        const char* their_send_label = "ALICE_SEND";
        
        HMAC(EVP_sha256(), _session_key, _session_key_len,
             (unsigned char*)my_send_label, strlen(my_send_label), 
             _sending_chain_key, &hmac_len);
             
        HMAC(EVP_sha256(), _session_key, _session_key_len,
             (unsigned char*)their_send_label, strlen(their_send_label), 
             _receiving_chain_key, &hmac_len);
             
        printf("INITRATCHET DEBUG: RESPONDER - my_sending=BOB_SEND, my_receiving=ALICE_SEND\n");
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
    printf("Symmetric Ratchet:\n");
    printf("  Initialized: %s\n", _ratchet_initialized ? "YES" : "NO");
    printf("  Sending counter: %u\n", _sending_counter);
    printf("  Receiving counter: %u\n", _receiving_counter);
    
    if (_ratchet_initialized) {
        printf("  Sending chain key (first 8 bytes): ");
        for(int i = 0; i < 8; i++)
            printf("%02X", _sending_chain_key[i]);
        printf("...\n");
        
        printf("  Receiving chain key (first 8 bytes): ");
        for(int i = 0; i < 8; i++)
            printf("%02X", _receiving_chain_key[i]);
        printf("...\n");
    }
    
    printf("Vertical Ratchet:\n");
    printf("  Initialized: %s\n", _vertical_ratchet_initialized ? "YES" : "NO");
    printf("  Counter: %u\n", _vertical_ratchet_counter);
    printf("  Pending: %s\n", _pending_vertical_ratchet ? "YES" : "NO");
    printf("  Total messages: %u\n", _sending_counter + _receiving_counter);
    printf("  Next vertical ratchet at: %u messages\n", 
           ((_sending_counter + _receiving_counter) / VERTICAL_RATCHET_INTERVAL + 1) * VERTICAL_RATCHET_INTERVAL);
    
    if (_vertical_ratchet_initialized && _vertical_local_pub_key_length > 0) {
        printf("  Current vertical key (first 8 bytes): ");
        for(int i = 0; i < 8; i++)
            printf("%02X", _vertical_local_pub_key[i]);
        printf("...\n");
    }
    
    printf("==================\n");
}

bool SmkexSessionInfo::initVerticalRatchet() {
    printf("=== INITIALIZING VERTICAL RATCHET ===\n");
    
    // Creează un nou context DH pentru vertical ratchet
    if (_vertical_dh) {
        DH_free(_vertical_dh);
    }
    
    // Citește parametrii DH din fișier
    BIO* pbio = BIO_new_file(SMKEX_DH_PARAMETER_FILENAME, "r");
    if (!pbio) {
        printf("Error: Cannot open DH parameter file for vertical ratchet\n");
        return false;
    }
    
    _vertical_dh = PEM_read_bio_DHparams(pbio, NULL, NULL, NULL);
    BIO_free(pbio);
    
    if (!_vertical_dh) {
        printf("Error: Cannot read DH parameters for vertical ratchet\n");
        return false;
    }
    
    // Generează noile chei DH pentru vertical ratchet
    if (DH_generate_key(_vertical_dh) != 1) {
        printf("Error: Cannot generate DH keys for vertical ratchet\n");
        DH_free(_vertical_dh);
        _vertical_dh = nullptr;
        return false;
    }
    
    // Extrage cheia publică
    BIGNUM *local_pub_key_num, *local_priv_key_num;
    
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    local_pub_key_num = _vertical_dh->pub_key;
    local_priv_key_num = _vertical_dh->priv_key;
#else
    DH_get0_key(_vertical_dh, (const BIGNUM**)&local_pub_key_num,
                (const BIGNUM**)&local_priv_key_num);
#endif
    
    _vertical_local_pub_key_length = BN_num_bytes(local_pub_key_num);
    if (_vertical_local_pub_key_length != SMKEX_PUB_KEY_LEN) {
        printf("Error: Vertical ratchet DH key length mismatch\n");
        DH_free(_vertical_dh);
        _vertical_dh = nullptr;
        return false;
    }
    
    BN_bn2bin(local_pub_key_num, _vertical_local_pub_key);
    
    _vertical_ratchet_initialized = true;
    
    printf("Vertical ratchet initialized successfully\n");
    printf("New vertical DH public key (first 16 bytes): ");
    for(int i = 0; i < 16; i++) {
        printf("%02X", _vertical_local_pub_key[i]);
    }
    printf("...\n");
    
    return true;
}

// In SmkexSessionInfo.cpp - Fix the shouldPerformVerticalRatchet method

bool SmkexSessionInfo::shouldPerformVerticalRatchet() const {
    unsigned int total_messages = _sending_counter + _receiving_counter;
    
    // Verificare: dacă am ajuns la multiplu de VERTICAL_RATCHET_INTERVAL
    bool meets_count_requirement = (total_messages > 0) && 
                                  (total_messages % VERTICAL_RATCHET_INTERVAL == 0);
    
    printf("=== VERTICAL RATCHET AUTO-CHECK ===\n");
    printf("Buddy: %s\n", _buddy.c_str());
    printf("Role: %s\n", _iAmSessionInitiator ? "INITIATOR" : "RESPONDER");
    printf("Sending: %u, Receiving: %u, Total: %u\n", 
           _sending_counter, _receiving_counter, total_messages);
    printf("Interval: %d, Modulo: %u\n", VERTICAL_RATCHET_INTERVAL, total_messages % VERTICAL_RATCHET_INTERVAL);
    printf("Meets count requirement: %s\n", meets_count_requirement ? "YES" : "NO");
    printf("Pending: %s\n", _pending_vertical_ratchet ? "YES" : "NO");
    
    // 🔥 CRUCIAL FIX: Only the INITIATOR should trigger vertical ratchet automatically
    // The RESPONDER should only respond to received vertical ratchet messages
    if (meets_count_requirement && !_pending_vertical_ratchet) {
        if (_iAmSessionInitiator) {
            printf("✅ INITIATOR will trigger vertical ratchet\n");
            printf("Final decision: YES\n");
            printf("=====================================\n");
            return true;
        } else {
            printf("⏳ RESPONDER waits for INITIATOR to trigger vertical ratchet\n");
            printf("Final decision: NO (waiting for initiator)\n");
            printf("=====================================\n");
            return false;
        }
    }
    
    // Clear stuck pending state if needed
    if (meets_count_requirement && _pending_vertical_ratchet) {
        printf("🔧 CLEARING stuck pending vertical ratchet to retry\n");
        const_cast<SmkexSessionInfo*>(this)->_pending_vertical_ratchet = false;
        
        // Only initiator retries
        if (_iAmSessionInitiator) {
            printf("✅ INITIATOR retries vertical ratchet\n");
            printf("Final decision: YES (retry)\n");
            printf("=====================================\n");
            return true;
        }
    }
    
    printf("Final decision: NO\n");
    printf("=====================================\n");
    return false;
}

bool SmkexSessionInfo::performVerticalRatchet() {
    if (!_ratchet_initialized) {
        printf("ERROR: Cannot perform vertical ratchet without initialized symmetric ratchet\n");
        return false;
    }
    
    printf("\n");
    printf("██████████████████████████████████████████████████████████\n");
    printf("█               VERTICAL RATCHET STARTED                █\n");
    printf("██████████████████████████████████████████████████████████\n");
    printf("Buddy: %s\n", _buddy.c_str());
    printf("Current message count: %u (sending) + %u (receiving) = %u\n",
           _sending_counter, _receiving_counter, _sending_counter + _receiving_counter);
    
    // Afișează cheia de sesiune ÎNAINTE de vertical ratchet
    printf("\n=== BEFORE VERTICAL RATCHET ===\n");
    printf("Current session key (first 32 bytes): ");
    for(int i = 0; i < 32 && i < (int)_session_key_len; i++) {
        printf("%02X", _session_key[i]);
    }
    printf("\n");
    printf("Current sending chain key (first 16 bytes): ");
    for(int i = 0; i < 16; i++) {
        printf("%02X", _sending_chain_key[i]);
    }
    printf("\n");
    printf("Current receiving chain key (first 16 bytes): ");
    for(int i = 0; i < 16; i++) {
        printf("%02X", _receiving_chain_key[i]);
    }
    printf("\n");
    
    // Inițializează vertical ratchet dacă nu este deja inițializat
    if (!_vertical_ratchet_initialized) {
        if (!initVerticalRatchet()) {
            printf("ERROR: Failed to initialize vertical ratchet\n");
            return false;
        }
    }
    
    _pending_vertical_ratchet = true;
    _vertical_ratchet_counter++;
    
    printf("Vertical ratchet initiated (counter: %u)\n", _vertical_ratchet_counter);
    printf("Waiting for partner's response...\n");
    
    return true;
}

bool SmkexSessionInfo::processVerticalRatchetMessage(const unsigned char* data, uint32_t dataLen) {
    printf("\n");
    printf("██████████████████████████████████████████████████████████\n");
    printf("█           PROCESSING VERTICAL RATCHET MESSAGE         █\n");
    printf("██████████████████████████████████████████████████████████\n");
    
    if (dataLen < SMKEX_PUB_KEY_LEN) {
        printf("ERROR: Insufficient data for vertical ratchet message\n");
        return false;
    }
    
    // Salvează cheia publică primită
    _vertical_remote_pub_key_length = SMKEX_PUB_KEY_LEN;
    memcpy(_vertical_remote_pub_key, data, SMKEX_PUB_KEY_LEN);
    
    printf("Received vertical ratchet public key:\n");
    for(int i = 0; i < (int)_vertical_remote_pub_key_length; i++) {
        printf("%02X", _vertical_remote_pub_key[i]);
        if ((i + 1) % 32 == 0) printf("\n");
    }
    if (_vertical_remote_pub_key_length % 32 != 0) printf("\n");
    
    // Inițializează propriile chei pentru vertical ratchet dacă nu sunt inițializate
    if (!_vertical_ratchet_initialized) {
        if (!initVerticalRatchet()) {
            printf("ERROR: Failed to initialize vertical ratchet\n");
            return false;
        }
    }
    
    printf("Our vertical ratchet public key:\n");
    for(int i = 0; i < (int)_vertical_local_pub_key_length; i++) {
        printf("%02X", _vertical_local_pub_key[i]);
        if ((i + 1) % 32 == 0) printf("\n");
    }
    if (_vertical_local_pub_key_length % 32 != 0) printf("\n");
    
    // Calculează noul secret partajat DH
    unsigned char new_dh_secret[SMKEX_DH_KEY_LEN];
    BIGNUM *remote_pub_key_bn = BN_bin2bn(_vertical_remote_pub_key, 
                                          _vertical_remote_pub_key_length, NULL);
    
    int new_dh_len = DH_compute_key(new_dh_secret, remote_pub_key_bn, _vertical_dh);
    BN_free(remote_pub_key_bn);
    
    if (new_dh_len <= 0) {
        printf("ERROR: Cannot compute new DH secret for vertical ratchet\n");
        return false;
    }
    
    printf("Computed NEW DH secret (%d bytes):\n", new_dh_len);
    for(int i = 0; i < new_dh_len; i++) {
        printf("%02X", new_dh_secret[i]);
        if ((i + 1) % 32 == 0) printf("\n");
    }
    if (new_dh_len % 32 != 0) printf("\n");
    
    // Salvează cheia de sesiune VECHE pentru comparație
    unsigned char old_session_key[SMKEX_SESSION_KEY_LEN];
    memcpy(old_session_key, _session_key, _session_key_len);
    
    // 🔥 CRUCIAL FIX: Asigură ordinea DETERMINISTĂ pentru combinare
    // Folosim buddy names pentru a determina ordinea consistentă
    
    std::string alice = _iAmSessionInitiator ? _buddy : getBuddy();  // buddy-ul inițiatorului
    std::string bob = _iAmSessionInitiator ? getBuddy() : _buddy;    // buddy-ul responder-ului
    
    // Sortăm alphabetic pentru ordine deterministă
    bool alice_first = (alice.compare(bob) < 0);
    
    printf("Deterministic ordering: alice='%s', bob='%s', alice_first=%s\n", 
           alice.c_str(), bob.c_str(), alice_first ? "YES" : "NO");
    
    // Combină în ordine deterministă: vechea cheie + noul secret DH
    unsigned char combined_input[SMKEX_SESSION_KEY_LEN + SMKEX_DH_KEY_LEN];
    
    if (alice_first) {
        // Alice data first, then Bob data
        memcpy(combined_input, _session_key, _session_key_len);
        memcpy(combined_input + _session_key_len, new_dh_secret, new_dh_len);
        printf("Using ALICE_FIRST ordering: old_session_key + new_dh_secret\n");
    } else {
        // Bob data first, then Alice data  
        memcpy(combined_input, new_dh_secret, new_dh_len);
        memcpy(combined_input + new_dh_len, _session_key, _session_key_len);
        printf("Using BOB_FIRST ordering: new_dh_secret + old_session_key\n");
    }
    
    // Derivă noua cheie de sesiune
    unsigned char new_session_key[SMKEX_SESSION_KEY_LEN];
    unsigned int new_session_key_len;
    nist_800_kdf(combined_input, _session_key_len + new_dh_len, 
                 new_session_key, &new_session_key_len);
    
    printf("\n=== KEY TRANSFORMATION ===\n");
    printf("OLD session key (first 32 bytes): ");
    for(int i = 0; i < 32 && i < (int)_session_key_len; i++) {
        printf("%02X", old_session_key[i]);
    }
    printf("\n");
    
    printf("NEW session key (first 32 bytes): ");
    for(int i = 0; i < 32 && i < (int)new_session_key_len; i++) {
        printf("%02X", new_session_key[i]);
    }
    printf("\n");
    
    // Verifică dacă cheia s-a schimbat efectiv
    bool key_changed = (memcmp(old_session_key, new_session_key, 32) != 0);
    printf("Key actually changed: %s\n", key_changed ? "YES ✓" : "NO ✗");
    
    // Actualizează cheia de sesiune
    memcpy(_session_key, new_session_key, new_session_key_len);
    _session_key_len = new_session_key_len;
    
    // Salvează cheile de lanț VECHI pentru comparație
    unsigned char old_sending_chain[32], old_receiving_chain[32];
    memcpy(old_sending_chain, _sending_chain_key, 32);
    memcpy(old_receiving_chain, _receiving_chain_key, 32);
    
    // 🔥 CRUCIAL FIX: Reset counters to 0 after vertical ratchet
    printf("\n=== RESETTING COUNTERS FOR VERTICAL RATCHET ===\n");
    printf("OLD counters: Sending=%u, Receiving=%u\n", _sending_counter, _receiving_counter);
    _sending_counter = 0;
    _receiving_counter = 0;
    printf("NEW counters: Sending=%u, Receiving=%u\n", _sending_counter, _receiving_counter);
    
    // Re-inițializează symmetric ratchet cu noua cheie de sesiune
    printf("\n=== REINITIALIZING SYMMETRIC RATCHET ===\n");
    initializeRatchet();
    
    printf("OLD sending chain key (first 16 bytes): ");
    for(int i = 0; i < 16; i++) {
        printf("%02X", old_sending_chain[i]);
    }
    printf("\n");
    
    printf("NEW sending chain key (first 16 bytes): ");
    for(int i = 0; i < 16; i++) {
        printf("%02X", _sending_chain_key[i]);
    }
    printf("\n");
    
    printf("OLD receiving chain key (first 16 bytes): ");
    for(int i = 0; i < 16; i++) {
        printf("%02X", old_receiving_chain[i]);
    }
    printf("\n");
    
    printf("NEW receiving chain key (first 16 bytes): ");
    for(int i = 0; i < 16; i++) {
        printf("%02X", _receiving_chain_key[i]);
    }
    printf("\n");
    
    _pending_vertical_ratchet = false;
    _vertical_ratchet_counter++;
    
    printf("\n");
    printf("██████████████████████████████████████████████████████████\n");
    printf("█          VERTICAL RATCHET COMPLETED SUCCESSFULLY      █\n");
    printf("█                   Counter: %3u                        █\n", _vertical_ratchet_counter);
    printf("█         Deterministic order: %-24s █\n", alice_first ? "ALICE_FIRST" : "BOB_FIRST");
    printf("█         Counters reset to: S:0 R:0                   █\n");
    printf("██████████████████████████████████████████████████████████\n");
    printf("\n");
    
    return true;
}

void SmkexSessionInfo::resetVerticalRatchetCounters() {
    printf("=== RESETTING VERTICAL RATCHET COUNTERS ===\n");
    
    _vertical_ratchet_counter = 0;
    _pending_vertical_ratchet = false;
    
    if (_vertical_dh) {
        DH_free(_vertical_dh);
        _vertical_dh = nullptr;
    }
    
    _vertical_ratchet_initialized = false;
    memset(_vertical_local_pub_key, 0, sizeof(_vertical_local_pub_key));
    memset(_vertical_remote_pub_key, 0, sizeof(_vertical_remote_pub_key));
    _vertical_local_pub_key_length = 0;
    _vertical_remote_pub_key_length = 0;
    
    printf("Vertical ratchet state reset\n");
}

int SmkexSessionInfo::getVerticalLocalPubKey(unsigned char kbuf[]) const {
    if (kbuf != NULL && _vertical_local_pub_key_length > 0) {
        memcpy(kbuf, _vertical_local_pub_key, _vertical_local_pub_key_length);
    }
    
    return _vertical_local_pub_key_length;
}


