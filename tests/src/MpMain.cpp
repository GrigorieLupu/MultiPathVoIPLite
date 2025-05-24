#include "MpBaseService.h"
#include "MpSingleton.h"
#include "MpLogger.h"
#include "MpLock.h"
#include "MpBuffer.h"
#include "MpAccSettings.h"
#include "MpRegistration.h"
#include "MpIRegistration.h"
#include "MpBuddy.h"
#include "MpPresence.h"
#include "MpICall.h"
#include "MpCall.h"
#include "MpMsg.h"
#include "MpTests.h"
#include "MpLinuxOutputStream.h"
#include "MpSIPStack.h"
#include "MpBaseService.h"
#include "MpStatus.h"
#include "Smkex.h"
#include "SmkexSessionInfo.h"
#include "WebSockets.h"
#include <algorithm>
#include <stdint.h>
#include <iostream>
#include <cstring>

#ifdef _WIN32
#include <windows.h>

void mssleep(unsigned milliseconds)
{
  Sleep(milliseconds);
}
#else
#include <unistd.h>

void mssleep(unsigned milliseconds)
{
  usleep(milliseconds * 1000); // takes microseconds
}
#endif

#define THIS_TAG "MpMain"
#define LOGMSG(x) MpService::instance()->getLogger()->print(THIS_TAG, __FUNCTION__, (x))
#define DEBUG 1

void print_usage(const std::string &buddy);

namespace MpMainMenuPrinter
{
  std::string g_last_buddy;

  void setLastBuddy(const std::string &buddy)
  {
    g_last_buddy = buddy;
  }

  void printMenu()
  {
    print_usage(g_last_buddy);
  }
}

void print_usage(const std::string &buddy) {
  std::cout << std::endl << "++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
  std::cout << "Buddy: " << buddy << std::endl;
  std::cout << "c - Call buddy " << buddy << std::endl;
  std::cout << "a - Answer call with " << buddy << std::endl;
  std::cout << "e - End call with " << buddy << std::endl;
  std::cout << "m - Send message to buddy " << buddy << std::endl;
  std::cout << "r - Show ratchet state" << std::endl;
  std::cout << "v - Force vertical ratchet" << std::endl;
  std::cout << "p - Clear pending vertical ratchet" << std::endl;
  std::cout << "s - Show session states" << std::endl;  // NOU!
  std::cout << "d - Debug session info" << std::endl;
  std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
}

using namespace std;

int main(int argc, char *argv[])
{
  unsigned char kbuf[SMKEX_SESSION_KEY_LEN] = {0};
  unsigned int klen;
  char clientID[256] = {0};
  char clientID2[256] = {0};
  char buddyID[256] = {0};
  char buddyID2[256] = {0};
  char server_ip[256] = {0};
  char server_ip2[256] = {0};
  char sipCertPath[256] = {0};
  char sipPrivKeyPath[256] = {0};
  int sip_port;
  int smkex_port;
  int smkex_port2;

  for (int i = 1; i < argc; i++)
  {
    if (strcmp(argv[i], "--run-tests") == 0)
    {
      // Creează și rulează testele
      MpTests tests;
      tests.Run();
      // Ieși din aplicație după finalizarea testelor
      return 0;
    }
  }

  if (argc < 12)
  {
    std::cout << "Too few arguments. Usage: " << argv[0] << " clientID buddyID server_ip1 sip_server_port1 smkex_server_port1 clientID2 buddyID2 server_ip2 smkex_server_port2 sip_cert_path sip_private_key_path [verbose]" << std::endl;
    return 1;
  }

  MpLinuxOutputStream linuxOutStream;

  if ((argc > 13 && !strcmp(argv[13], "verbose")) ||
      (argc > 12 && !strcmp(argv[12], "verbose")))
    MpService::instance()->getLogger()->setOutputStream(&linuxOutStream);

  /* Initialise params */
  strcpy(clientID, argv[1]);
  strcpy(buddyID, argv[2]);
  strcpy(server_ip, argv[3]);
  sip_port = atoi(argv[4]);
  smkex_port = atoi(argv[5]);
  strcpy(clientID2, argv[6]);
  strcpy(buddyID2, argv[7]);
  strcpy(server_ip2, argv[8]);
  smkex_port2 = atoi(argv[9]);
  strcpy(sipCertPath, argv[10]);
  strcpy(sipPrivKeyPath, argv[11]);

  MpMainMenuPrinter::setLastBuddy(buddyID);

  printf("ClientID1 = %s\nClientID2 = %s\n", clientID, clientID2);

  Smkex smkex;
  smkex.setClientID(std::string(clientID));
  smkex.setClientID2(std::string(clientID2));

  std::string serverips[] = {server_ip, server_ip2};
  int ports[] = {smkex_port, smkex_port2};
  std::string clientids[] = {std::string(clientID), std::string(clientID2)};

  WebSockets &webSocketTransport = WebSockets::getInstance();
  webSocketTransport.init(serverips, ports, clientids, 2);
  webSocketTransport.addMsgCb(&smkex);

  smkex.setSmkexTransport(&webSocketTransport);

  if (argc > 12 && strncmp(argv[12], "init", 4) == 0)
  {
    // Initiator, so send the public key
    SmkexSessionInfo &session = smkex.initSession(std::string(buddyID), std::string(buddyID2));
    LOGMSG("Session initiated\n");
#if DEBUG
    printf("Session ID = %d\n", session.getSessionID());
#endif

    // wait until session is established
    while (session.getState() != SmkexState::STATEConnected)
    {
      LOGMSG("Waiting for session to be established\n");
#if DEBUG
      printf("Current state is: %d\n", session.getState());
#endif
      mssleep(10);

      // Read SMKEX messages if available
      LOGMSG("Checking for new messages from web socket\n");
      if (smkex.checkNewMessages())
        LOGMSG("Error retrieving SMKEX messages\n");
    }

    LOGMSG("\nSession with buddy established!\n");
    klen = session.getSessionKey(kbuf);
#if DEBUG
    printf("Session key has %d bytes: \n\n\n", klen);
    smkex.print_buf(kbuf, klen);
#endif

    // Now send messages with key as needed...
  }
  else
  {
    LOGMSG("We are not initiator, so listening for connections.\n");
    // Not initiator, wait for session from any possible buddy
    while (!smkex.isKeyEstablished())
    {
      LOGMSG("Waiting for a new session to be established\n");
      mssleep(10);

      // Read SMKEX messages if available
      LOGMSG("Checking for new messages from web socket\n");
      if (smkex.checkNewMessages())
        LOGMSG("Error retrieving SMKEX messages\n");
    }

    // Get information on last established session
    std::string lastBuddy = smkex.getLastEstablishedBuddyID();
    SmkexSessionInfo &session = smkex.getSessionInfo(lastBuddy);
#if DEBUG
    printf("A new session was established with buddy %s\n", lastBuddy.c_str());
#endif

    LOGMSG("\nSession with buddy established!\n");
    klen = session.getSessionKey(kbuf);
#if DEBUG
    printf("Session key has %d bytes: \n\n\n", klen);
    smkex.print_buf(kbuf, klen);
#endif
  }

  /* Registration */
  MpRegistration regCb;
  MpUserAccount *uc = MpService::instance()->getUserAccount();
  uc->addRegCallback((MpIRegistration *)&regCb);

  MpAccSettings accSettings(std::string(server_ip), // std::string("195.95.167.231"),
                            sip_port,               // 8890,
                            std::string(clientID),
                            10 /* PJSIP log level */,
                            MP_NETWORK_WIFI,
                            false,
                            sipCertPath,
                            sipPrivKeyPath);
  uc->login(accSettings);

  /* Add SMKEX class as callback for OOB key setup functions */
  MpService::instance()->getSIPStack()->addOobKeySetup(&smkex);

  /* Add buddy and subscribe to presence */
  MpPresence pres;
  MpService::instance()->getBuddyList()->addPresenceCb(&pres);

  MpBuddy buddy(buddyID);
  std::string buddySerial = buddy.getBuddySerial();
  MpService::instance()->getBuddyList()->addBuddy(buddy);

  /* Configure receive message for MpMsg */
  MpMsg msgRcv;
  MpService::instance()->getDataMsg()->addMsgCb(&msgRcv);

  /* Configure receive call */
  MpCall callRcv;
  MpService::instance()->getCallManager()->addCallCb(&callRcv);

  char opt;
  while (true)
  {
    print_usage(buddyID);

    opt = getchar();
    switch (opt)
    {
    case 'c':
      /* Call buddy */
      std::cout << std::endl
                << "Action: Calling buddy!" << std::endl;
      MpService::instance()->getCallManager()->callBuddy(buddyID);
      break;
    case 'a':
      /* Answer call */
      std::cout << std::endl
                << "Action: Answer call!" << std::endl;
      MpService::instance()->getCallManager()->answerCall(MP_ANSWER_CALL);
      break;
    case 'e':
    {
      /* Disconnect call */
      std::cout << std::endl
                << "Action: End call!" << std::endl;

      // Închide apelul local
      mp_status_t result = MpService::instance()->getCallManager()->endCall();

      if (result == MP_SUCCESS)
      {
        std::cout << "Apel încheiat cu succes." << std::endl;
      }
      else
      {
        std::cout << "Eroare la încheierea apelului! Forțez închiderea..." << std::endl;
        // În caz de eroare, forțează închiderea tuturor apelurilor
        pjsua_call_hangup_all();
      }
      break;
    }
    case 's':
{
    /* Show all session states */
    std::cout << std::endl << "Action: Show session states!" << std::endl;
    SmkexSessionInfo &session = smkex.getSessionInfo(buddyID);
    
    printf("=== SESSION STATES DEBUG ===\n");
    printf("Current session state: %d\n", session.getState());
    printf("SmkexState::STATENotConnected: %d\n", SmkexState::STATENotConnected);
    printf("SmkexState::STATEWaitKey: %d\n", SmkexState::STATEWaitKey);
    printf("SmkexState::STATEWaitNonce: %d\n", SmkexState::STATEWaitNonce);
    printf("SmkexState::STATEWaitNonceH: %d\n", SmkexState::STATEWaitNonceH);
    printf("SmkexState::STATEConnected: %d\n", SmkexState::STATEConnected);
    printf("============================\n");
    
    // Testează și compatibilitatea pentru vertical ratchet
    bool ready_strict = (session.getState() == SmkexState::STATEConnected);
    bool ready_relaxed = (session.getState() == SmkexState::STATEConnected) || (session.getState() == 3);
    
    printf("Ready for vertical ratchet (strict): %s\n", ready_strict ? "YES" : "NO");
    printf("Ready for vertical ratchet (relaxed): %s\n", ready_relaxed ? "YES" : "NO");
    
    break;
}
    case 'm':
    {
      /* Send message */
      std::cout << std::endl
                << "Action: Send message!" << std::endl;
      char msg[256] = {0};
      std::cout << "Enter message: " << std::endl;
      std::cin.clear();
      std::cin.ignore();
      std::cin.getline(msg, sizeof(msg) - 1, '\n');

      // DEBUGGING: Arată starea ÎNAINTE de trimiterea mesajului
      SmkexSessionInfo &session = smkex.getSessionInfo(buddyID);
      printf("📊 BEFORE sending message:\n");
      printf("   Sending counter: %u\n", session.getSendingCounter());
      printf("   Receiving counter: %u\n", session.getReceivingCounter());
      printf("   Total: %u\n", session.getSendingCounter() + session.getReceivingCounter());
      printf("   Next vertical ratchet at: %u messages\n",
             ((session.getSendingCounter() + session.getReceivingCounter()) / VERTICAL_RATCHET_INTERVAL + 1) * VERTICAL_RATCHET_INTERVAL);

      // Resetează starea SIP dacă e necesar
      try
      {
        pjsua_acc_id acc_id = pjsua_acc_get_default();
        if (acc_id != PJSUA_INVALID_ID)
        {
          pjsua_acc_info acc_info;
          if (pjsua_acc_get_info(acc_id, &acc_info) == PJ_SUCCESS)
          {
            if (acc_info.status != 200)
            {
              std::cout << "Resetez conexiunea SIP înainte de a trimite mesajul..." << std::endl;
              pjsua_acc_set_registration(acc_id, PJ_FALSE);
              pj_thread_sleep(100);
              pjsua_acc_set_registration(acc_id, PJ_TRUE);
              pj_thread_sleep(300);
            }
          }
        }
      }
      catch (...)
      {
        std::cout << "Warning: Exception during SIP status check" << std::endl;
      }

      // Trimite mesajul
      MpBuffer payload((uint8_t *)msg, strlen(msg));
      MpMsgPayload message(buddyID, payload, 1, 5, 1, MP_TYPE_MESSAGE, false);
      MpService::instance()->getAutoResend()->addMessage(message);

      std::cout << std::endl
                << "✅ Message sent!" << std::endl;

      // DEBUGGING: Arată starea DUPĂ trimiterea mesajului
      printf("📊 AFTER sending message:\n");
      printf("   Sending counter: %u\n", session.getSendingCounter());
      printf("   Receiving counter: %u\n", session.getReceivingCounter());
      printf("   Total: %u\n", session.getSendingCounter() + session.getReceivingCounter());

      break;
    }

    case 'r':
    {
      /* Show ratchet state */
      std::cout << std::endl
                << "Action: Show ratchet state!" << std::endl;
      SmkexSessionInfo &session = smkex.getSessionInfo(buddyID);
      session.printRatchetState();

      // Also print current session key for comparison
      unsigned char current_key[SMKEX_SESSION_KEY_LEN];
      int klen = session.getSessionKey(current_key);
      if (klen > 0)
      {
        std::cout << "Base session key (first 16 bytes): ";
        for (int i = 0; i < 16 && i < klen; i++)
          printf("%02X", current_key[i]);
        std::cout << "..." << std::endl;
      }
      break;
    }

    case 'v':
    {
      /* Force vertical ratchet */
      std::cout << std::endl
                << "Action: Force vertical ratchet!" << std::endl;
      SmkexSessionInfo &session = smkex.getSessionInfo(buddyID);
      if (session.getState() == SmkexState::STATEConnected)
      {
        if (smkex.checkAndPerformVerticalRatchet(buddyID) == 0)
        {
          std::cout << "Vertical ratchet initiated successfully!" << std::endl;
        }
        else
        {
          std::cout << "Failed to initiate vertical ratchet!" << std::endl;
        }
      }
      else
      {
        std::cout << "Session not connected - cannot perform vertical ratchet!" << std::endl;
      }
      break;
    }

    case 'p':
{
    /* Clear pending vertical ratchet */
    std::cout << std::endl << "Action: Clear pending vertical ratchet!" << std::endl;
    SmkexSessionInfo &session = smkex.getSessionInfo(buddyID);
    
    if (session.hasPendingVerticalRatchet()) {
        // Hack pentru a curăța starea pending (pentru debugging)
        session.resetVerticalRatchetCounters();
        std::cout << "✅ Pending vertical ratchet cleared!" << std::endl;
    } else {
        std::cout << "ℹ️  No pending vertical ratchet to clear" << std::endl;
    }
    
    session.printRatchetState();
    break;
}
    }
  }

  return 0;
}