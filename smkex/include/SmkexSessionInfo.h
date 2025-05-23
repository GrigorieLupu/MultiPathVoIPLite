#ifndef __SMKEX_SESSION_INFO_H__
#define __SMKEX_SESSION_INFO_H__
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include "crypto.h"
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
#include <stdio.h>
#include "Smkex.h"
#include "SmkexState.h"
#include <oqs/kem.h>

// PQ
#define SMKEX_KYBER_PUB_KEY_LEN 1184     // Dimensiunea cheii publice Kyber-768
#define SMKEX_KYBER_PRIV_KEY_LEN 2400    // Dimensiunea cheii private Kyber-768
#define SMKEX_KYBER_CIPHERTEXT_LEN 1088  // Dimensiunea textului cifrat Kyber-768
#define SMKEX_KYBER_SHARED_SECRET_LEN 32 // Dimensiunea secretului Kyber-768
// PQ

#define SMKEX_PUB_KEY_LEN 256
#define SMKEX_PRIV_KEY_LEN 256
#define SMKEX_NONCE_LEN 8
#define SMKEX_HASH_LEN 32
#if ANDROID == 1
#define SMKEX_DH_PARAMETER_FILENAME "/storage/self/primary/dhparam.pem"
#else
#define SMKEX_DH_PARAMETER_FILENAME "../smkex/dhparam.pem"
#endif
#define SMKEX_DH_KEY_LEN 256
#define SMKEX_SESSION_KEY_LEN 64

class SmkexSessionInfo
{
private:
  static int _nextID;

  int _uniqueID;
  bool _iAmSessionInitiator = false;
  int _state = SmkexState::STATENotConnected;
  int _sessionID;
  std::string _buddy = "None";
  std::string _buddy2 = "None";
  DH *_dh;
  bool _dh_initialised = false;

  unsigned char _session_key[SMKEX_SESSION_KEY_LEN];
  unsigned int _session_key_len;

  // PQ

  bool _kyber_initialised = false;
  unsigned char _kyber_shared_secret[SMKEX_KYBER_SHARED_SECRET_LEN];
  unsigned int _kyber_shared_secret_len = 0;

  // Symmetric Ratchet
  unsigned char _sending_chain_key[SMKEX_SESSION_KEY_LEN];
  unsigned char _receiving_chain_key[SMKEX_SESSION_KEY_LEN];
  unsigned int _sending_counter;
  unsigned int _receiving_counter;
  bool _ratchet_initialized;

public:
  unsigned char local_priv_key[SMKEX_PRIV_KEY_LEN];
  unsigned int local_priv_key_length;
  unsigned char local_pub_key[SMKEX_PUB_KEY_LEN];
  unsigned int local_pub_key_length;
  unsigned char local_nonce[SMKEX_NONCE_LEN];
  unsigned int local_nonce_length;
  unsigned char remote_pub_key[SMKEX_PUB_KEY_LEN];
  unsigned int remote_pub_key_length;
  unsigned char remote_nonce[SMKEX_NONCE_LEN];
  unsigned int remote_nonce_length;
  // EC_POINT *localPubKey;
  // EC_KEY *localPrivKey;
  // EC_GROUP *ecgroup;

  // PQ

  unsigned char local_kyber_pub_key[SMKEX_KYBER_PUB_KEY_LEN];
  unsigned int local_kyber_pub_key_length;
  unsigned char local_kyber_priv_key[SMKEX_KYBER_PRIV_KEY_LEN];
  unsigned int local_kyber_priv_key_length;
  unsigned char remote_kyber_pub_key[SMKEX_KYBER_PUB_KEY_LEN];
  unsigned int remote_kyber_pub_key_length;
  unsigned char remote_kyber_ciphertext[SMKEX_KYBER_CIPHERTEXT_LEN];
  unsigned int remote_kyber_ciphertext_length;

  // Constructor
  SmkexSessionInfo();

  // Destructor
  ~SmkexSessionInfo();

  // copy operator
  SmkexSessionInfo &operator=(const SmkexSessionInfo &other);

  // Getters/Setters
  // void setStatus(int);
  // int getStatus();
  inline bool isInitiator(void) const
  {
    return _iAmSessionInitiator;
  }

  inline int getSessionID() const { return _sessionID; }

  inline int getState(void) const
  {
    return _state;
  }

  inline std::string getBuddy(void) const
  {
    return _buddy;
  }

  inline std::string getBuddy2(void) const
  {
    return _buddy2;
  }

  inline DH *getDH(void) const
  {
    return _dh;
  }

  inline bool isDHInitialised(void) const
  {
    return _dh_initialised;
  }

  inline void SetInitiator(void)
  {
    _iAmSessionInitiator = true;
  }

  inline void setSessionID(int sessionID) { _sessionID = sessionID; }

  inline void setState(int state)
  {
    _state = state;
  }

  inline void setBuddy(std::string buddy)
  {
    _buddy = buddy;
  }

  inline void setBuddy2(std::string buddy)
  {
    _buddy2 = buddy;
  }

  // SYMMETRIC RATCHET
  /**
   * Initialize symmetric ratcheting from the session key
   */
  void initializeRatchet();

  /**
   * Ratchet the sending chain forward
   * @param[out] message_key Buffer to store the derived message key
   * @return true if successful
   */
  bool ratchetSendingChain(unsigned char message_key[SMKEX_SESSION_KEY_LEN]);

  /**
   * Ratchet the receiving chain forward
   * @param[out] message_key Buffer to store the derived message key
   * @return true if successful
   */
  bool ratchetReceivingChain(unsigned char message_key[SMKEX_SESSION_KEY_LEN]);

  /**
   * Get current sending counter
   */
  unsigned int getSendingCounter() const { return _sending_counter; }

  /**
   * Get current receiving counter
   */
  unsigned int getReceivingCounter() const { return _receiving_counter; }

  /**
   * Check if ratchet is initialized
   */
  bool isRatchetInitialized() const { return _ratchet_initialized; }

  /**
   * Print ratchet state for debugging
   */
  void printRatchetState() const;

  /**
   * Initialise private and public DH values.
   * Currently done from parameters already available in internal _dh structure.
   *
   * @returns 0 if successful, non-zero otherwise.
   */
  int initKeysfromDH(void);

  /**
   * Open file <filename>, read public Diffie-Hellman parameters P and G and store them in <pdhm>
   * in dh (Diffie-Hellman key exchange context)
   * @param filename file from which to read P and G
   */
  void __read_pg_from_file(const char *filename);

  /**
   * Generates a new nonce and stores it as local nonce.
   *
   * Parameters:
   *  @param[in] nbuf: pre-allocated buffer with enough capacity for the nonce.
   *  Pass NULL if nonce is not needed on return;
   *  @returns: the length of the nonce if successful, zero otherwise.
   */
  int generateLocalNonce(unsigned char nbuf[]);

  /**
   * Returns the local nonce.
   *
   * Parameters:
   *  @param[in] nbuf: pre-allocated buffer with enough capacity for the nonce.
   *  Pass NULL to retrieve only the nonce length.
   *
   *  @returns: the length of the nonce if successful, zero otherwise.
   */
  int getLocalNonce(unsigned char nbuf[]) const;

  /**
   * Computes the Hash of nonce_buddy|pubkey_buddy|nonce_ours|pubkey_ours.
   * Currently using SHA256.
   *
   * Parameters:
   *  @param[in] dest: pre-allocated buffer with enough capacity for resulting hash.
   *  @returns: the Hash length (zero if something failed).
   */
  unsigned int computeHash(unsigned char dest[]);

  /**
   * Verifies given H with hash of session's parameters.
   *
   * @param[in] hbuf: the hash value to check against the hash of this session info.
   * @param[in] hlen: the length of the hash value given.
   * @returns: true if verification successful, false otherwise.
   */
  bool verifyHash(const unsigned char hbuf[], unsigned int hlen);

  /**
   * Computes the session key based on the key exchange
   *
   * @param[in] kbuf: pre-allocated buffer with enough capacity for the key.
   * Pass NULL if key is not needed on return.
   * @returns: the key length (zero if something failed).
   */
  int computeSessionKey(unsigned char kbuf[]);

  /**
   * Retrieves the session key
   *
   * @param[in] kbuf: pre-allocated buffer with enough capacity for the key.
   * Pass NULL to retrieve only the length of the session key.
   *
   * @returns: the key length (zero if something failed).
   */
  int getSessionKey(unsigned char kbuf[]) const;

  /**
   * Retrieves the local private DH key
   *
   * @param[in] kbuf: pre-allocated buffer with enough capacity for the key.
   * Pass NULL to retrieve only the key length.
   *
   * @returns: the key length (zero if something failed).
   */
  int getLocalPrivKey(unsigned char kbuf[]) const;

  /**
   * Retrieves the local public DH key
   *
   * @param[in] kbuf: pre-allocated buffer with enough capacity for the key.
   * Pass NULL to retrieve only the key length.
   *
   * @returns: the key length (zero if something failed).
   */
  int getLocalPubKey(unsigned char kbuf[]) const;

  /**
   * Retrieves the remote public DH key
   *
   * @param[in] kbuf: pre-allocated buffer with enough capacity for the key.
   * Pass NULL to retrieve only the key length.
   *
   * @returns: the key length (zero if something failed).
   */
  int getRemotePubKey(unsigned char kbuf[]) const;

  /**
   * Retrieves the remote nonce
   *
   * @param[in] nbuf: pre-allocated buffer with enough capacity for the nonce.
   * Pass NULL to retrieve only the nonce length.
   *
   * @returns: the nonce length (zero if something failed).
   */
  int getRemoteNonce(unsigned char nbuf[]) const;

  /**
   * Prints information about this SessionInfo object
   */
  void printSessionInfo() const;

  // PQ
  int initKeysFromKyber();
  int encapsulateKyberKey();
  int decapsulateKyberKey();

  int getLocalKyberPubKey(unsigned char kbuf[]) const;
  int getLocalKyberPrivKey(unsigned char kbuf[]) const;
  int getRemoteKyberPubKey(unsigned char kbuf[]) const;
  int getRemoteKyberCiphertext(unsigned char kbuf[]) const;

  inline bool isKyberInitialised(void) const
  {
    return _kyber_initialised;
  }

  int getKyberSharedSecret(unsigned char kbuf[]) const;
};
#endif