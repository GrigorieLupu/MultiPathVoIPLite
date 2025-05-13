#ifndef __MP_SMKEX_H__
#define __MP_SMKEX_H__

#include "IOobKeySetup.h"
#include "SmkexRecord.h"  
#include "SmkexSessionInfo.h"  
#include "ISmkexTransportCallback.h"
#include "ISmkexTransport.h"
#include "crypto.h"
#include <stdint.h>
#include <iostream>
#include <cstring>
#include <stdint.h>
#include <string>
#include <map>

using namespace std;

#define SMKEX_CHANNEL_0 0
#define SMKEX_CHANNEL_1 1

// PQ

#define SMKEX_KYBER_ENABLED 1
#define SMKEX_COMBINED_KEY_EXCHANGE 1

const int SMKEX_CHANNELS[2] = { SMKEX_CHANNEL_0, SMKEX_CHANNEL_1 };

/**
 * Class used to implement the SMKEX protocol for a given client.
 * Its main tasks are to implement the FSM of the protocol and to handle
 * sessions with different users.
 */
class Smkex: public ISmkexTransportCallback, public IOobKeySetup {

private:
	std::string _clientID, _clientID2;
  	ISmkexTransport *_smkexTransport;
  	bool _key_established;
  	std::string _lastEstablishedBuddyID;

  /** 
	*  Storage of sessions
   */
  	map<int, SmkexSessionInfo> smkexSessionsMap;

  /**
   * Used to link connections to same session, by linking
   * all the clientID's of a buddy to the same Session ID
   */
  	map<std::string, int> sessionLinkMap;

public:
	int keyLength;

	/**
	 * @brief Ctor
	 * @return NONE
	 */
	Smkex();

	/**
	 * @brief Dtor
	 * @return NONE
	 */
	~Smkex();

  // setters and getters
	void setClientID(const std::string &clientId);
	void setClientID2(const std::string &clientId);
	std::string getClientID();
	std::string getClientID2();

  inline int getNumberOfSessions() { return smkexSessionsMap.size(); }
  inline int getNumberOfLinks() { return sessionLinkMap.size(); }

  inline bool isKeyEstablished() { return _key_established; }
  inline std::string getLastEstablishedBuddyID() { return _lastEstablishedBuddyID; }

  /**
   * Makes a link between a buddy ID and a session ID.
   * This is necessary for mapping multiple clientID's
   * (e.g. for different connections) to same session.
   *
   * Note: this function replaces existing session link for the given buddy.
   *
   * @param buddy the buddy (client) ID to be mapped
   * @param sessionID the session ID to map with
   */
  void makeSessionLink(const std::string &buddy, int sessionID);
   
	/**
   * @brief creates a new session with the specified buddy
   *
	 * @param buddy ID of buddy for the desired session.
   *
	 * @returns session information in case it exists or creates a new one otherwise
	*/
	//static SmkexSessionInfo& createSessionInfo(const std::string &buddy);

	/**
   * @brief retrieves the session information for the session with the
   * specified buddy. This method will
   * retrieve the existing session if it exists, otherwise creates a new one.
   *
	 * @param buddy ID of buddy for the desired session.
   *
	 * @returns session information in case it exists or creates a new one otherwise
	*/
	SmkexSessionInfo& getSessionInfo(const std::string &buddy);


	/** 
   * @brief adds the given sessionInfo to the list of SessionInfo if no SessionInfo with buddy is available.
   * In case a SessionInfo with buddy exists, this function returns error.
   * If you want to replace existing sessions, use replaceSessionInfo instead.
   *
	 * @param buddy with whom the session is being established 
	 * @param sessionInfo pointer to the SessionInfo  
   *
	 * @returns true if successful, false otherwise
	*/	
	bool addSessionInfo(std::string& buddy,SmkexSessionInfo &sessionInfo); 

	/** 
   * @brief replaces the sessionInfo for the given buddy in the list of sessions
   * or inserts a new session if none exists
   *
	 * @param buddy with whom the session is being replaced 
	 * @param sessionInfo pointer to the new SessionInfo data
   *
	 * @returns true if successful, false otherwise
	*/	
	bool replaceSessionInfo(std::string& buddy,SmkexSessionInfo &sessionInfo);

	/**
     * @brief tells whether there is SessionInfo for this buddy
	 * @param[in] buddy the buddy in the current inquiry
	 * @return true if there is a session, false if there is no session
	*/
	bool hasSessionInfo(const std::string &buddy);

	/**
     * @brief saves the SessionInfo for this buddy aftre a change has been made to it 
	 * (not necessary if we are working directly on the SessionInfo of the buddy in the program memory)
   *
	 * @param buddy the buddy whom the Sessioninfo concerns
   *
	 * @returns 1 if the SessionInfo was stored successfully, 0 otherwise
	*/
	int saveSessionInfo(std::string buddy);


	/**
	 * @brief Creates a new session with given buddy and starts SMKEX-T4M protocol.
   *
   * Note: this method will also make an internal connection betwen the
   * different buddy IDs, so we can track the IDs of same connections.
   *
	 * @param buddy the buddy ID for the first channel
	 * @param buddy2 the buddy ID for the second channel.
   *
	 * @returns a reference to the SessionInfo object associated with buddy
	 */
	SmkexSessionInfo& initSession(const std::string &buddy, const std::string &buddy2);

	/**
	 * @brief sends an SMKEX record to buddy over the WebSocket server 
	 * @param rec: the SmkexT4mRecord to be sent
	 * @param buddy the URI for the buddy to which the key or nonce is being sent
	 * @param chan the channel (1 or 2) on which it is supposed to be sent 
   *
	 * @returns 0 if the sending seemed successful and non-zero otherwise
	 */
	int sendRecord(const SmkexT4mRecord& rec, std::string buddy, int chan);


	/**
	 * @brief allocates memory for the key or nonce to be stored, 
	 * writes/copies the key or nonce into the allocated memory
	 * @param pointer to the key or nonce to be stored
	 * @param length  the length of the key or nonce  
	 * @return a pointer to the newly reserved memory where the nonce is stored
	 */
	unsigned char * storeKeyOrNonce(unsigned char *pointer, unsigned int length);

	/**
	 * @brief sends nonce and hash on second channel for given session
	 * @param session: the session from which to send the nonce and H.
	 * @param buddy: the URI for the buddy to which the key or nonce is being sent
   *
	 * @returns zero if successful, non-zero otherwise
	 */
	int sendNonceH(SmkexSessionInfo &session, std::string buddy);

  /**
   * @brief Check for new SMKEX messages received
   *
   * @returns zero if all goes well, non-zero otherwise.
   */
  inline int checkNewMessages()
  {
    if (_smkexTransport)
      return _smkexTransport->updateMessagesFromServer();

	return -1;
  }
  	
	/**
	 * @brief process a given Smkex message received buddy in channel
   *
	 * @param rec the SmkexT4mRecord record to be processed
	 * @param buddy the buddy where the message comes from
   * @param channel the channel on which this message came from
   *
	 * @returns 0 if all is good, non-zero otherwise.
	*/
	int processSmkexMessage(
      const uint8_t* msg, uint32_t msgLen, int channel);

	// TODO function to encrypt and send a message to buddy
	unsigned char *encriptAndSendMsg(unsigned char *message, uint32_t msgLen, std::string buddy);

	// TODO function to decrypt and output a message from buddy	
	unsigned char *decryptMessage(unsigned char *message, uint32_t msgLen, std::string buddy);


	/**
	 * @brief Websocket message received callback
   *
	 * @param buddy Message sender
	 * @param msg Message
	 * @param msgLen Message length
   * @param channel the channel on which the message came
   *
	 * @return NONE
	 */
  void onMsgReceived(std::string const& buddy, const uint8_t* msg, uint32_t msgLen, int channel);

	/**
	* @brief outputs a key or nonce (method used for debug purposes)
	* @param[in] key: pointer to the first character of the key or nonce
	* @param[in] key_length: the length of the key
	 * @return NONE`
	 */
	void print_buf(unsigned char *buf, int len);

	/**
   	* Print elements in smkexSessionsMap
   	*/
 	void printSessionMap(void);

  /**
   * Print elements in sessionLinkMap
   */
  	void printLinkMap(void);

	/**
	 * @brief sends alert to buddy (means that the connection attempt has failed) 
	 * @param[in] buddy 
	 * @return NONE
	 * 
	*/
	void sendAlert(std::string const& buddy);  //TODO now implement

	void testCryptography();

  /**
   * @brief Get out-of-band key for ID
   * @param[in] buddy Buddy identity
   * @param[out] key Crypto key
   * @param[in] key_len Crypto key length
   * 
   * @return TRUE on success, FALSE otherwise  
   */
  virtual bool getKeyForBuddy(const std::string &buddy, char *key, int keyLen);

  void setSmkexTransport(ISmkexTransport *smkexTransport);


  	// PQ
	/**
     * @brief Trimite ciphertext-ul Kyber către buddy
     * @param session Informații despre sesiune
     * @param buddy Destinatarul mesajului
     * @return 0 dacă mesajul a fost trimis cu succes, altfel o valoare negativă
     */
    int sendKyberCiphertext(SmkexSessionInfo &session, std::string buddy);

	/**
     * @brief Procesează mesajul Kyber primit
     * @param session Informații despre sesiune
     * @param data Datele primite
     * @param dataLen Lungimea datelor
     * @return 0 dacă procesarea a reușit, altfel o valoare negativă
     */
    int processKyberMessage(SmkexSessionInfo &session, const unsigned char *data, uint32_t dataLen);

	/**
     * @brief Verifică dacă Kyber este activat pentru sesiunea curentă
     * @return true dacă Kyber este activat, false în caz contrar
     */
    inline bool isKyberEnabled() const { return SMKEX_KYBER_ENABLED; }
};

int sendKyberCiphertext(SmkexSessionInfo &session, std::string buddy);

#endif /* __MP_SMKEX_H__*/