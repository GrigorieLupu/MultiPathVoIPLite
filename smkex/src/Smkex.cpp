/** \file
 *  \brief  Smkex.c source file
 *
 *  This file implements the core of the SMKEX protocol
 *
 *  Authors:
 * 	  Liliana Grigoriu (liliana.grigoriu@upb.ro)
 *    Marios O. Choudary (marios.choudary@cs.pub.ro)
 *
 * 	Last update: August 2021
 *
 */

#include <iostream>
#include <string.h>
#include <cstring>
#include <vector>
#include <map>
#include <algorithm>			
#include <openssl/ecdh.h>   //de exemplu pentru create common key
#include <time.h>
#include "Smkex.h"
#include "SmkexRecord.h"
#include "SmkexSessionInfo.h"  
#include "SmkexState.h"
#include "crypto.h"
#include "logging.hpp"


using namespace std;

Smkex::Smkex(){
  MP_LOG1("Smkex::Ctor");

  _key_established = false;
}

Smkex::~Smkex() {
  MP_LOG1("Smkex::Dtor");
}

void Smkex::makeSessionLink(const std::string &buddy, int sessionID)
{
  sessionLinkMap[buddy] = sessionID;
#if DEBUG
  printf("In Smkex::makeSessionLink with sessionID=%d for buddy %s\n",
      sessionID, buddy.c_str());
  printf("Now we have %lu elements in sessionLinkMap\n", sessionLinkMap.size());
  printLinkMap();
#endif
}


SmkexSessionInfo& Smkex::getSessionInfo(const std::string &buddy)
{
#if DEBUG
  printf("In Smkex::getSessionInfo, before any processing\n");
  printSessionMap();
#endif

  int sessionID = sessionLinkMap[buddy];
  SmkexSessionInfo &si = smkexSessionsMap[sessionID];

#if DEBUG
  printf("In Smkex::getSessionInfo, after retrieving sessionMap for sessionID=%d\n",
         sessionID);
  printSessionMap();
#endif

  if(sessionID == 0)
  {
    // Creating a new session for this buddy
    // Need to create a new element in the map with correct ID maping
    // We do it this way (perhaps complicated) so we can use references with
    // getSessionInfo (as returned by map's [] operator)
    sessionID = si.getSessionID(); // retrieve the generated/next sessionID
    SmkexSessionInfo &sii = smkexSessionsMap[sessionID]; // make new obj & map at sessionID
    if(sii.initKeysfromDH())
      MP_LOG1("Error initialising DH keys\n");

    sii.setSessionID(sessionID); // set the correct sessionID
    if (sii.getBuddy() == "None")
      sii.setBuddy(buddy);

#if DEBUG
    printf("In Smkex::getSessionInfo, created new sessionMap for ID=%d\n",
         sessionID);
    printSessionMap();
#endif

    // remove previous entry in sessionmap
    smkexSessionsMap.erase(0);

    // update ID-session link with buddy
    sessionLinkMap[buddy] = sessionID;

#if DEBUG
    printf("In Smkex::getSessionInfo, after removing sessionmap for ID=0.\n");
    printSessionMap();
#endif

    return sii;
  }
  else{
    // Using retrieved session
    if (si.getBuddy() == "None")
      si.setBuddy(buddy);

    return si;
  }
}

bool Smkex::addSessionInfo(std::string &buddy,SmkexSessionInfo &sessionInfo){
  if (hasSessionInfo(buddy))
    return false;

  std::pair<std::map<int, SmkexSessionInfo>::iterator, bool> ret;
  int sessionID = sessionLinkMap[buddy];
  ret = smkexSessionsMap.insert(std::pair<int,SmkexSessionInfo>(sessionID,sessionInfo));
  return ret.second;
}

bool Smkex::replaceSessionInfo(std::string &buddy,SmkexSessionInfo &sessionInfo)
{
  int sessionID = sessionLinkMap[buddy];
  if (hasSessionInfo(buddy))
  {
    smkexSessionsMap[sessionID] = sessionInfo;
    sessionInfo.setBuddy(buddy);
    return true;
  }
  else
  {
    std::pair<std::map<int, SmkexSessionInfo>::iterator, bool> ret;
		ret = smkexSessionsMap.insert(std::pair<int,SmkexSessionInfo>(sessionID,sessionInfo));
    sessionInfo.setBuddy(buddy);
    return ret.second;
  }
}


bool Smkex::hasSessionInfo(const std::string &buddy){
  int sessionID = sessionLinkMap[buddy];
#if DEBUG
  printf("In Smkex::hasSessionInfo\n");
  printSessionMap();
  printf("In Smkex::hasSessionInfo, sessionID=%d for buddy %s\n",
      sessionID, buddy.c_str());
#endif
  if(Smkex::smkexSessionsMap.find(sessionID)==Smkex::smkexSessionsMap.end())
		return false;

  return true;
}

unsigned char *Smkex::storeKeyOrNonce(unsigned char *pointer, unsigned int length){
	unsigned char *ptr=(unsigned char *) malloc(length);
	memcpy(ptr,pointer,length); // copy the key or nonce into the allocated memory region
	cout<<"Smkex::storeKeyOrNonce: stored the following key or nonce: returning a pointer to it: \n";
	print_buf(ptr,length);
	return ptr;
}

int Smkex::sendRecord(const SmkexT4mRecord& rec, std::string buddy, int chan)
{
  if (_smkexTransport == NULL)
  {
    MP_LOG1("Error: WebSocket not initalised\n");
    return -1;
  }

  /* Serialize record */
  int len = rec.getLength();
  
  unsigned char *data = new unsigned char[len];
  len = rec.serializeRecord(data);
  if (!len || !data)
  {
    if(data)
      delete[] data;
		
    return -1;
	}


  if(_smkexTransport->sendMessageToBuddy(buddy, data, len, chan))
  {
    MP_LOG1("Error sending message through ws\n");
    return -1;
  }

	return 0;
}

int Smkex::sendNonceH(SmkexSessionInfo &session, std::string buddy)
{
  unsigned char nonce[SMKEX_NONCE_LEN];
  unsigned char hm[SMKEX_HASH_LEN];
  unsigned int len_nonce, len_hm;
  unsigned char bufm[SMKEX_NONCE_LEN+SMKEX_HASH_LEN];

  len_nonce = session.generateLocalNonce(nonce);
  if (len_nonce == 0)
  {
    MP_LOG1("Error generating local nonce\n");
    return -1;
  }
  MP_LOG1("\nSuccessfully created local nonce\n");
#if DEBUG
  printf("Local nonce has %d bytes: \n", len_nonce);
  print_buf(nonce, len_nonce);
#endif

  len_hm = session.computeHash(hm);
  if (len_hm == 0 || len_hm > SMKEX_HASH_LEN)
  {
    MP_LOG1("\nError creating hash of data\n");
    return -1;
  }
  MP_LOG1("\nSuccessfully created hash of data\n");

  // create full buffer and send it
  memcpy(bufm, session.local_nonce, SMKEX_NONCE_LEN);
  memcpy(bufm+SMKEX_NONCE_LEN, hm, len_hm);
  MP_LOG1("\nSending nonce+hash to buddy (on channel 1)\n");
  SmkexT4mRecord sr(0, buddy, getClientID2(), handshakeNonceH,
      SMKEX_T4M_PROTOCOL_VERSION, SMKEX_NONCE_LEN+SMKEX_HASH_LEN, bufm);
  MP_LOG1("printRecord from sendNonceH\n");
  sr.printRecord();
  sendRecord(sr,buddy,SMKEX_CHANNEL_1);

  return 0;
}

SmkexSessionInfo& Smkex::initSession(const std::string &buddy, const std::string &buddy2){
  // Create new session (or retrieve if existing...)
  SmkexSessionInfo &session = getSessionInfo(buddy);

  // Make link for second buddy(client) ID to same session
  session.setBuddy2(buddy2);
  makeSessionLink(buddy2, session.getSessionID());

  // Set this client as the initiator of the protocol
  session.SetInitiator();

  if(session.getState() != SmkexState::STATENotConnected)
    MP_LOG1("Warning: Reinitiating a session that was not in NotConnected state\n");

  // Inițializează cheile DH
  if(session.initKeysfromDH())
    MP_LOG1("Error initialising DH keys\n");
  
  // Inițializează cheile Kyber
  if(session.initKeysFromKyber())
    MP_LOG1("Error initialising Kyber keys\n");

  MP_LOG1("Initiating SMKEX session: sending DH and Kyber public keys to buddy (on channel 0)\n");
  
  // Creează un buffer combinat pentru ambele chei publice
  unsigned char combined_key[SMKEX_PUB_KEY_LEN + SMKEX_KYBER_PUB_KEY_LEN];
  memcpy(combined_key, session.local_pub_key, session.local_pub_key_length);
  memcpy(combined_key + session.local_pub_key_length, 
         session.local_kyber_pub_key, session.local_kyber_pub_key_length);
  
  // Trimite cheile combinate
  SmkexT4mRecord rec(0, buddy, getClientID(), handshakeKey,
      SMKEX_T4M_PROTOCOL_VERSION, 
      session.local_pub_key_length + session.local_kyber_pub_key_length,
      combined_key);
  
  rec.printRecord();
  sendRecord(rec, buddy, SMKEX_CHANNEL_0);
  
  session.setState(SmkexState::STATEWaitKey);

  cout<<"Smkex.cpp::initSession:with buddy "<< buddy <<" finished\n";

  return session;
}

int Smkex::processSmkexMessage(
  const uint8_t* msg, uint32_t msgLen, int channel)
{
SmkexT4mRecord rec((char *)(msg), msgLen);
std::string buddy = rec.getSrc();
unsigned char buf[SMKEX_NONCE_LEN+SMKEX_HASH_LEN];
unsigned char skey[SMKEX_SESSION_KEY_LEN];
int klen;
string buddy_c2;

MP_LOG1("Received new message in processSmkexMessage\n");
#if DEBUG
printf("Message on channel %d from %s\n",
        channel, buddy.c_str());
#endif

rec.printRecord();

if (channel < 0)
{
  MP_LOG1("Incorrect received channel (negative value)\n");
  return -1;
}

// Retrieve session for buddy
MP_LOG1("Getting session info for buddy\n");
SmkexSessionInfo &session = getSessionInfo(buddy);
session.printSessionInfo();

#if DEBUG
printf("Our current state with buddy %s is: %d\n", buddy.c_str(), session.getState());
#endif

// Note: for now we use the handshakeKey message also as client hello message,
// i.e. to start a new session for the sending buddy
switch((int)rec.getType()){
  case handshakeKey:
    MP_LOG1("received handshakeKey\n");

    if (SMKEX_CHANNEL_0 == channel && !session.isInitiator() && 
        (session.getState() == SmkexState::STATENotConnected))
    {
      // Make/update link with second ID on second channel for buddy
      buddy_c2 = buddy + "2";
      session.setBuddy2(buddy_c2);
      Smkex::makeSessionLink(buddy_c2, session.getSessionID());

      // Verifică dacă mesajul conține suficiente date pentru ambele chei
      uint32_t total_length = rec.getData(NULL);
      if(total_length < SMKEX_PUB_KEY_LEN)
      {
        MP_LOG1("Not enough data for DH key\n");
        return -1;
      }

      // Extrage datele primite
      unsigned char *combined_key = new unsigned char[total_length];
      rec.getData(combined_key);

      // Copiază cheia publică DH
      session.remote_pub_key_length = SMKEX_PUB_KEY_LEN;
      memcpy(session.remote_pub_key, combined_key, session.remote_pub_key_length);

      // Dacă avem date suficiente, copiază și cheia publică Kyber
      if(total_length >= SMKEX_PUB_KEY_LEN + SMKEX_KYBER_PUB_KEY_LEN) {
        session.remote_kyber_pub_key_length = SMKEX_KYBER_PUB_KEY_LEN;
        memcpy(session.remote_kyber_pub_key, 
              combined_key + session.remote_pub_key_length,
              session.remote_kyber_pub_key_length);
      }

      delete[] combined_key;

      // Inițializează cheile noastre
      if(session.initKeysfromDH())
        MP_LOG1("Error initialising DH keys\n");
      
      if(session.remote_kyber_pub_key_length > 0) {
        if(session.initKeysFromKyber())
          MP_LOG1("Error initialising Kyber keys\n");

        // Encapsulează cheia Kyber
        if(session.encapsulateKyberKey())
          MP_LOG1("Error encapsulating Kyber key\n");
      }

      // Trimite cheile publice DH + Kyber (dacă sunt disponibile)
      unsigned int response_length = session.local_pub_key_length;
      unsigned char *our_combined_key = NULL;
      
      if(session.isKyberInitialised()) {
        response_length += session.local_kyber_pub_key_length;
        our_combined_key = new unsigned char[response_length];
        
        memcpy(our_combined_key, session.local_pub_key, session.local_pub_key_length);
        memcpy(our_combined_key + session.local_pub_key_length, 
              session.local_kyber_pub_key, session.local_kyber_pub_key_length);
      } else {
        our_combined_key = new unsigned char[response_length];
        memcpy(our_combined_key, session.local_pub_key, session.local_pub_key_length);
      }
      
      SmkexT4mRecord sr(0, buddy, getClientID(), handshakeKey,
          SMKEX_T4M_PROTOCOL_VERSION, response_length, our_combined_key);
      
      sr.printRecord();
      sendRecord(sr, buddy, SMKEX_CHANNEL_0);
      
      delete[] our_combined_key;

      session.setState(SmkexState::STATEWaitNonce);
    }
    else if(SMKEX_CHANNEL_0 == channel && session.isInitiator() &&
        (session.getState() == SmkexState::STATEWaitKey))
    {
      // Verifică dacă mesajul conține suficiente date pentru cel puțin cheia DH
      uint32_t total_length = rec.getData(NULL);
      if(total_length < SMKEX_PUB_KEY_LEN)
      {
        MP_LOG1("Not enough data for DH key\n");
        return -1;
      }

      // Extrage datele primite
      unsigned char *combined_key = new unsigned char[total_length];
      rec.getData(combined_key);

      // Copiază cheia publică DH
      session.remote_pub_key_length = SMKEX_PUB_KEY_LEN;
      memcpy(session.remote_pub_key, combined_key, session.remote_pub_key_length);

      // Dacă avem date suficiente, copiază și cheia publică Kyber
      if(total_length >= SMKEX_PUB_KEY_LEN + SMKEX_KYBER_PUB_KEY_LEN) {
        session.remote_kyber_pub_key_length = SMKEX_KYBER_PUB_KEY_LEN;
        memcpy(session.remote_kyber_pub_key, 
              combined_key + session.remote_pub_key_length,
              session.remote_kyber_pub_key_length);
        
        // Encapsulează cheia Kyber dacă am primit o cheie publică Kyber validă
        if(session.encapsulateKyberKey())
          MP_LOG1("Error encapsulating Kyber key\n");
      }

      delete[] combined_key;

      // Generează nonce și continuă protocolul
      if(RAND_bytes(session.local_nonce, SMKEX_NONCE_LEN) == 0){
        MP_LOG1("Error creating nonce...............\nExiting\n");
        exit(1);
      }
      MP_LOG1("\nSuccessfully created local nonce\n");
      session.local_nonce_length = SMKEX_NONCE_LEN;

      MP_LOG1("\nNow sending nonce 1 to buddy (on channel 1)\n");
      SmkexT4mRecord sr(0, session.getBuddy2(), getClientID2(), handshakeNonce,
          SMKEX_T4M_PROTOCOL_VERSION, session.local_nonce_length, session.local_nonce);
      
      sr.printRecord();
      sendRecord(sr, session.getBuddy2(), SMKEX_CHANNEL_1);

      session.setState(SmkexState::STATEWaitNonceH);
    }
    else
    {
      // TODO: implement functionality on bad message/state as desired.
      MP_LOG1("\nError: wrong message/state. Ignoring this message for now.\n");
    }

    break;

  case handshakeNonce:
    MP_LOG1("received handshakeNonce\n");

    if (SMKEX_CHANNEL_1 == channel && !session.isInitiator() &&
        (session.getState() == SmkexState::STATEWaitNonce))
    {
      if(SMKEX_NONCE_LEN < rec.getData(NULL))
      {
        MP_LOG1("Not enough memory to store data as nonce\n");
        exit(1);
      }
      session.remote_nonce_length = rec.getData(session.remote_nonce);

      // send nonce + hash on second channel
      // note: the sendNonceH method generates a fresh local nonce before sending it
      sendNonceH(session, session.getBuddy2());

      session.setState(SmkexState::STATEWaitNonceH);
    }
    else
    {
      // TODO: implement functionality on bad message/state as desired.
      MP_LOG1("\nError: wrong message/state. Ignoring this message for now.\n");
    }

    break;

  case handshakeNonceH:
    MP_LOG1("received handshakeNonceH\n");

    // Works (almost) the same for both initiator and receiver
    if (SMKEX_CHANNEL_1 == channel && session.getState() == SmkexState::STATEWaitNonceH)
    {
      if((SMKEX_NONCE_LEN + SMKEX_HASH_LEN) < rec.getData(NULL))
      {
        MP_LOG1("Not enough memory to store nonce and hash\n");
        exit(1);
      }
      rec.getData(buf);

      // Get nonce
      memcpy(session.remote_nonce, buf, SMKEX_NONCE_LEN);
      session.remote_nonce_length = SMKEX_NONCE_LEN;

      // Check match of hash
#if DEBUG
      printf("About to verify hash\n");
      printf("Received nonce is: \n");
      print_buf(session.remote_nonce, SMKEX_NONCE_LEN);
      printf("Received hash is: \n");
      print_buf(&buf[SMKEX_NONCE_LEN], SMKEX_HASH_LEN);
#endif
      if(!session.verifyHash(&buf[SMKEX_NONCE_LEN], SMKEX_HASH_LEN))
      {
        MP_LOG1("\nError verifying hash\n");
        return 0;
      }
      MP_LOG1("Hash verification successful\n");

      // Dacă nu suntem inițiatori și avem Kyber inițializat, decapsulează cheia
      // if(!session.isInitiator() && session.isKyberInitialised() && 
      //    session.remote_kyber_pub_key_length > 0) {
      //   if(session.decapsulateKyberKey()) {
      //     MP_LOG1("\nError decapsulating Kyber key\n");
      //     return -1;
      //   }
      // }

      // Compute key (now includes Kyber secret if available)
      klen = session.computeSessionKey(skey);
      if (klen == 0)
      {
        MP_LOG1("\nError computing secret key\n");
        return 0;
      }
      MP_LOG1("computed session key successfully\n");
#if DEBUG
      printf("Session key has %d bytes:\n", klen);
      print_buf(skey,klen);
#endif
      
      // Go in connected state
      session.setState(SmkexState::STATEConnected);
      
      // Send last nonce+hash (only for initiator) 
      if (session.isInitiator() && session.isKyberInitialised() && 
        session.remote_kyber_pub_key_length > 0) {
        // Trimite ciphertextul Kyber după verificarea hash-ului
        sendKyberCiphertext(session, session.getBuddy2());
      }

      // Signal the key establishment
      _key_established = true;
      _lastEstablishedBuddyID = buddy;
    }
    else
    {
      // TODO: implement functionality on bad message/state as desired.
      MP_LOG1("\nError: wrong message/state. Ignoring this message for now.\n");
    }

    break;

  case alert:
    // TODO: check/update this
    session.setState(SmkexState::STATENotConnected);
    if (session.isInitiator())
      Smkex::initSession(buddy, session.getBuddy2());

    break;

    case handshakeKyberCiphertext:
    MP_LOG1("received handshakeKyberCiphertext\n");
    
    if (SMKEX_CHANNEL_1 == channel && !session.isInitiator() && 
        session.isKyberInitialised()) {
        
        if(SMKEX_KYBER_CIPHERTEXT_LEN < rec.getData(NULL)) {
            MP_LOG1("Not enough memory for Kyber ciphertext\n");
            return -1;
        }
        
        // Copiază ciphertextul primit
        session.remote_kyber_ciphertext_length = rec.getData(session.remote_kyber_ciphertext);
        
        // Decapsulează cheia Kyber folosind ciphertextul primit
        if(session.decapsulateKyberKey()) {
            MP_LOG1("\nError decapsulating Kyber key\n");
            return -1;
        }
        
        // Recalculează cheia de sesiune finală care va include acum secretul Kyber corect
        unsigned char skey[SMKEX_SESSION_KEY_LEN];
        int klen = session.computeSessionKey(skey);
        if (klen == 0) {
            MP_LOG1("\nError computing secret key\n");
            return -1;
        }

        _key_established = true;
        _lastEstablishedBuddyID = buddy;
        
        // Debug output pentru cheia finală
        MP_LOG1("Computed final session key with correct Kyber shared secret\n");
        #if DEBUG
        printf("Final session key has %d bytes:\n", klen);
        print_buf(skey, klen);
        #endif
    }
    break;

  default:
    MP_LOG1("\nWarning: unknown case for received message. Not processing.\n\n");
}

MP_LOG1("returning\n\n");
return 0;
}

void Smkex::sendAlert(std::string const& buddy){
	MP_LOG1("sending alert, connection with buddy could not be established \n");
	unsigned char a[2]="a"; // dummy data included (esle functions would need updating)
	SmkexT4mRecord rec(0,buddy, getClientID(), alert, SMKEX_T4M_PROTOCOL_VERSION,2,a); 
	cout<<"printRecord from sendAlert\n";
  rec.printRecord();
  sendRecord(rec,buddy,SMKEX_CHANNEL_0);
}


void Smkex::onMsgReceived(std::string const& buddy,
    const uint8_t* msg, uint32_t msgLen, int channel) { 
	
	MP_LOG1("SMKEX Message received...\n");
#if DEBUG
  printf("Message on channel %d from %s with length %d\n",
          channel, buddy.c_str(), msgLen);
#endif

	// SmkexT4mRecord rec((char *)(msg), msgLen);
	// rec.printRecord();
	Smkex::processSmkexMessage(msg, msgLen, channel);

	cout<<"returning from function onMsgReceived\n\n\n";	
}


void Smkex::print_buf(unsigned char *buf, int len){
   for(int k=0; k<len; k++)
        printf("%02X", buf[k]);
   printf("\n");	
}

void Smkex::printSessionMap()
{
  std::map<int,SmkexSessionInfo>::iterator it;
  int idx = 0;
  printf("smkexSessionMap has %d elements\n",
      Smkex::getNumberOfSessions());
  printf("Elements in smkexSessionsMap are:\n");
  for (it=smkexSessionsMap.begin(); it!=smkexSessionsMap.end(); ++it)
  {
    printf("At index=%d, we have sessionID=%d for buddy %s with internal sessionID=%d\n",
        idx, it->first, it->second.getBuddy().c_str(),
        it->second.getSessionID());
    idx++;
  }
}

void Smkex::printLinkMap()
{
  std::map<std::string,int>::iterator it;
  int idx = 0;
  printf("sessionLinkMap has %d elements\n",
      Smkex::getNumberOfLinks());
  printf("Elements in sessionLinkMap are:\n");
  for (it=sessionLinkMap.begin(); it!=sessionLinkMap.end(); ++it)
  {
    printf("At index=%d, we have buddy=%s with sessionID=%d\n",
        idx, it->first.c_str(), it->second);
    idx++;
  }
}


void Smkex::setClientID(const std::string &clientId){
	_clientID = std::string(clientId);
}

void Smkex::setClientID2(const std::string &clientId){
	_clientID2 = std::string(clientId);
}
	
	
std::string  Smkex::getClientID(){
	return _clientID;
};

std::string  Smkex::getClientID2(){
	return _clientID2;
};


void Smkex::testCryptography(){
	// make two keys a,d 


}

int Smkex::sendKyberCiphertext(SmkexSessionInfo &session, std::string buddy) {
  MP_LOG1("Sending Kyber ciphertext to buddy\n");
  
  // Trimite ciphertextul Kyber
  SmkexT4mRecord sr(0, buddy, getClientID2(), handshakeKyberCiphertext,
      SMKEX_T4M_PROTOCOL_VERSION, session.remote_kyber_ciphertext_length, 
      session.remote_kyber_ciphertext);
  
  sr.printRecord();
  return sendRecord(sr, buddy, SMKEX_CHANNEL_1);
}

bool Smkex::getKeyForBuddy(const std::string &buddy, char *key, int keyLen) {
  int klen;
  unsigned char kbuf[256];


#if DEBUG
  printf("In Smkex::getKeyForBuddy\n");
  printf("Requested keyLen: %d\n", keyLen);
  SmkexSessionInfo &sess = getSessionInfo(buddy);
  printf("After retrieving session info\n");
  sess.printSessionInfo();
  klen = sess.getSessionKey(kbuf);
  printf("Session key has %d bytes: \n\n\n", klen);
  print_buf((unsigned char*)kbuf, klen);
  printf("After debugging messages in Smkex::getKeyForBuddy\n");
#endif


  /* Get key from session */
  memset(key, 0, keyLen);
  SmkexSessionInfo &session = getSessionInfo(buddy);
  klen = session.getSessionKey(kbuf);
  memcpy(key, kbuf, keyLen);

  return true;
}

void Smkex::setSmkexTransport(ISmkexTransport *smkexTransport)
{
  _smkexTransport = smkexTransport;
}