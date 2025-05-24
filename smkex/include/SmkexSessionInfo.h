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
#include <map>

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

#define VERTICAL_RATCHET_INTERVAL 5


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

  // Vertical ratchet state
  bool _vertical_ratchet_initialized;
  unsigned char _root_key[SMKEX_SESSION_KEY_LEN];
  unsigned char _local_dh_priv_ratchet[SMKEX_PRIV_KEY_LEN];
  unsigned char _local_dh_pub_ratchet[SMKEX_PUB_KEY_LEN];
  unsigned char _remote_dh_pub_ratchet[SMKEX_PUB_KEY_LEN];
  unsigned int _local_dh_priv_ratchet_length;
  unsigned int _local_dh_pub_ratchet_length;
  unsigned int _remote_dh_pub_ratchet_length;

  // skip list for out-of-order message handling
  static const int MAX_SKIP = 1000;
  std::map<unsigned int, unsigned char[SMKEX_SESSION_KEY_LEN]> _skipped_message_keys;
  unsigned int _previous_sending_counter;

  /**
     * @brief Generează o pereche de chei DH (privată/publică)
     * @param private_key Buffer pentru cheia privată
     * @param public_key Buffer pentru cheia publică  
     * @param public_key_length Pointer către lungimea cheii publice (output)
     * @return 0 dacă generarea a reușit, -1 în caz de eroare
     */
    int generateDHKeyPair(unsigned char *private_key, unsigned char *public_key, unsigned int *public_key_length);

    /**
     * @brief Calculează shared secret-ul DH
     * @param local_private_key Cheia privată locală
     * @param remote_public_key Cheia publică remotă
     * @param remote_key_length Lungimea cheii publice remote
     * @param shared_secret Buffer pentru shared secret (output)
     * @return 0 dacă calculul a reușit, -1 în caz de eroare
     */
    int computeDHSharedSecret(const unsigned char *local_private_key, 
                             const unsigned char *remote_public_key,
                             unsigned int remote_key_length,
                             unsigned char *shared_secret);

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

  // Vertical Ratcheting
  /**
   * @brief Inițializează vertical ratchet-ul cu cheia root
   */
  void initializeVerticalRatchet();

  /**
   * @brief Verifică și afișează starea detaliată a vertical ratchet-ului
   */
  void debugVerticalRatchetState() const;
  
  /**
   * @brief Simulează trimiterea unui număr de mesaje pentru a testa ratchet-ul
   */
  void testVerticalRatchetTrigger(unsigned int message_count);
  
  /**
   * @brief Verifică dacă cheile s-au schimbat după vertical ratchet
   */
  bool verifyRatchetKeyChange(const unsigned char* old_root_key, 
                             const unsigned char* old_sending_key,
                             const unsigned char* old_receiving_key);

  /**
   * @brief Efectuează un pas de vertical ratchet când primim o nouă cheie publică DH
   * @param new_remote_dh_pub Noua cheie publică DH de la peer
   * @param length Lungimea cheii publice
   * @return true dacă operația a reușit
   */
  bool performVerticalRatchetStep(const unsigned char *new_remote_dh_pub, unsigned int length);

  /**
   * @brief Generează o nouă pereche de chei DH pentru vertical ratchet
   * @return true dacă operația a reușit
   */
  bool generateNewDHRatchetKeys();

  /**
   * @brief Obține cheia publică DH locală pentru ratchet
   */
  int getLocalDHRatchetPubKey(unsigned char kbuf[]) const;

  /**
   * @brief Setează cheia publică DH remotă pentru ratchet
   */
    void setRemoteDHRatchetPubKey(const unsigned char *key, unsigned int length);

    /**
     * @brief Efectuează KDF pentru derivarea noilor chei în vertical ratchet
     */
    int performKDF(const unsigned char *root_key, const unsigned char *dh_secret,
                   unsigned char *new_root_key, unsigned char *new_sending_key,
                   unsigned char *new_receiving_key);
    
    /**
     * @brief Generează o nouă pereche de chei DH pentru ratchet
     */
    int generateNewDHRatchetKeyPair();

  /**
   * @brief Verifică dacă avem o cheie salvată pentru un anumit counter
   */
  bool trySkippedMessageKey(unsigned int counter, unsigned char message_key[SMKEX_SESSION_KEY_LEN]);

  /**
   * @brief Salvează cheile pentru mesajele sărite (skip)
   */
  void skipMessageKeys(unsigned int until_counter);

  /**
   * @brief Verifică dacă vertical ratchet este inițializat
   */
  bool isVerticalRatchetInitialized() const { return _vertical_ratchet_initialized; }

  /**
   * @brief Resetează vertical ratchet-ul
   */
  void resetVerticalRatchet();

  int initKeysfromDH(void);

  /**
   * @brief Resetează contoarele ratchet la valorile inițiale
   *
   * Această metodă re-derivă cheile de lanț din cheia de sesiune
   * și resetează contoarele pentru a resincroniza comunicarea.
   */
  void resetRatchetCounters();

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