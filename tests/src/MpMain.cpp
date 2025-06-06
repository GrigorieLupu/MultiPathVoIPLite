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
    std::cout << "v - Force Signal-style vertical ratchet" << std::endl;
    std::cout << "p - Clear pending vertical ratchet" << std::endl;
    std::cout << "s - Show session states" << std::endl;
    std::cout << "w - Manual WebSocket check" << std::endl;
    std::cout << "z - Restart WebSocket listener" << std::endl;  // ✅ NEW
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

  // ✅ INITIALIZE WEBSOCKET WITH MULTITHREADING
  printf("🌐 Initializing WebSocket with multithreading support...\n");
  WebSockets &webSocketTransport = WebSockets::getInstance();
  webSocketTransport.init(serverips, ports, clientids, 2);
  webSocketTransport.addMsgCb(&smkex);

  smkex.setSmkexTransport(&webSocketTransport);

  // ✅ SHOW WEBSOCKET STATUS
  printf("🌐 WebSocket listener status: %s\n", 
         webSocketTransport.isListenerRunning() ? "🟢 RUNNING" : "🔴 STOPPED");

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

      // ✅ NOTE: No need for manual WebSocket checks - background thread handles it!
      // The background WebSocket listener will automatically receive messages
    }

    LOGMSG("\nSession with buddy established!\n");
    klen = session.getSessionKey(kbuf);
#if DEBUG
    printf("Session key has %d bytes: \n\n\n", klen);
    smkex.print_buf(kbuf, klen);
#endif
  }
  else
  {
    LOGMSG("We are not initiator, so listening for connections.\n");
    // Not initiator, wait for session from any possible buddy
    while (!smkex.isKeyEstablished())
    {
      LOGMSG("Waiting for a new session to be established\n");
      mssleep(10);

      // ✅ NOTE: Background WebSocket thread handles message reception automatically
      // No need for manual checkNewMessages() calls
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

  MpAccSettings accSettings(std::string(server_ip),
                            sip_port,
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
  SmkexSessionInfo &session = smkex.getSessionInfo(buddyID);

  printf("\n🎯 Application ready! Background WebSocket listener is active.\n");
  printf("🔄 Signal-style vertical ratchet enabled - will trigger on role reversals\n\n");

  while (true)
  {
    // ✅ SHOW WEBSOCKET STATUS IN MENU
    printf("\n🌐 WebSocket Listener: %s | ", 
           webSocketTransport.isListenerRunning() ? "🟢 ACTIVE" : "🔴 STOPPED");
    printf("Session State: %d | ", session.getState());
    printf("Messages: S:%u R:%u\n", 
           session.getSendingCounter(), session.getReceivingCounter());

    print_usage(buddyID);
    opt = getchar();
    
    switch (opt)
    {
    case 'c':
        std::cout << std::endl << "Action: Calling buddy!" << std::endl;
        MpService::instance()->getCallManager()->callBuddy(buddyID);
        break;
        
    case 'a':
        std::cout << std::endl << "Action: Answer call!" << std::endl;
        MpService::instance()->getCallManager()->answerCall(MP_ANSWER_CALL);
        break;
        
    case 'e':
    {
        std::cout << std::endl << "Action: End call!" << std::endl;
        mp_status_t result = MpService::instance()->getCallManager()->endCall();
        if (result == MP_SUCCESS) {
            std::cout << "✅ Call ended successfully." << std::endl;
        } else {
            std::cout << "❌ Error ending call! Forcing termination..." << std::endl;
            pjsua_call_hangup_all();
        }
        break;
    }
    
    case 's':
    {
        std::cout << std::endl << "Action: Show session states!" << std::endl;
        
        printf("=== SESSION STATES DEBUG ===\n");
        printf("Current session state: %d\n", session.getState());
        printf("Role: %s\n", session.isInitiator() ? "INITIATOR" : "RESPONDER");
        printf("Messages: %u (S:%u + R:%u)\n", 
               session.getSendingCounter() + session.getReceivingCounter(),
               session.getSendingCounter(), session.getReceivingCounter());
        printf("Vertical pending: %s\n", session.hasPendingVerticalRatchet() ? "YES" : "NO");
        
        printf("--- WebSocket Info ---\n");
        printf("Background listener: %s\n", 
               webSocketTransport.isListenerRunning() ? "ACTIVE" : "STOPPED");
        printf("=======================\n");
        break;
    }
    
    case 'm':
    {
        std::cout << std::endl << "Action: Send message!" << std::endl;
        char msg[256] = {0};
        std::cout << "Enter message: ";
        std::cin.clear();
        std::cin.ignore();
        std::cin.getline(msg, sizeof(msg) - 1, '\n');

        // Show state BEFORE sending
        printf("📊 BEFORE: S:%u + R:%u = %u\n", 
               session.getSendingCounter(), session.getReceivingCounter(),
               session.getSendingCounter() + session.getReceivingCounter());

        MpBuffer payload((uint8_t *)msg, strlen(msg));
        MpMsgPayload message(buddyID, payload, 1, 5, 1, MP_TYPE_MESSAGE, false);
        MpService::instance()->getAutoResend()->addMessage(message);

        std::cout << "✅ Message sent!" << std::endl;
        
        // Show state AFTER sending
        printf("📊 AFTER: S:%u + R:%u = %u\n", 
               session.getSendingCounter(), session.getReceivingCounter(),
               session.getSendingCounter() + session.getReceivingCounter());
        break;
    }
    
    case 'r':
    {
        std::cout << std::endl << "Action: Show ratchet state!" << std::endl;
        session.printRatchetState();
        break;
    }
    
    case 'v':
    {
        std::cout << std::endl << "Action: Force Signal-style vertical ratchet!" << std::endl;
        if (session.getState() == SmkexState::STATEConnected || 
            session.getState() == SmkexState::STATEWaitNonceH) {
            // Use the new Signal-style method
            if (smkex.checkAndPerformVerticalRatchetOnFallback(buddyID) == 0) {
                std::cout << "✅ Signal-style vertical ratchet initiated!" << std::endl;
            } else {
                std::cout << "❌ Failed to initiate Signal-style vertical ratchet!" << std::endl;
            }
        } else {
            std::cout << "❌ Session not ready! State: " << session.getState() << std::endl;
        }
        break;
    }
    
    case 'p':
    {
        std::cout << std::endl << "Action: Clear pending vertical ratchet!" << std::endl;
        if (session.hasPendingVerticalRatchet()) {
            session.resetVerticalRatchetCounters();
            std::cout << "✅ Pending cleared!" << std::endl;
        } else {
            std::cout << "ℹ️  No pending to clear" << std::endl;
        }
        break;
    }
    
    case 'w':
    {
        std::cout << std::endl << "Action: Manual WebSocket check!" << std::endl;
        smkex.checkNewMessages();
        std::cout << "✅ Manual check completed!" << std::endl;
        std::cout << "ℹ️  Background listener is: " << 
                    (webSocketTransport.isListenerRunning() ? "🟢 ACTIVE" : "🔴 STOPPED") << std::endl;
        break;
    }
    
    case 'z':
    {
        std::cout << std::endl << "Action: Restart WebSocket listener!" << std::endl;
        webSocketTransport.stopWebSocketListener();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        webSocketTransport.startWebSocketListener();
        std::cout << "✅ WebSocket listener restarted!" << std::endl;
        break;
    }
    
    case 't':
    {
        std::cout << std::endl << "Action: Test Signal-style ratchet detection!" << std::endl;
        printf("🧪 Testing role reversal detection:\n");
        printf("   Current: last_was_sent = %s\n", "Unknown"); // Add getter if needed
        printf("   Send a message, then have the other side respond\n");
        printf("   You should see: 🔄 ROLE REVERSAL DETECTED!\n");
        break;
    }
    
    case 'd':
    {
        std::cout << std::endl << "Action: Debug session info!" << std::endl;
        session.printSessionInfo();
        
        printf("\n--- WebSocket Debug ---\n");
        printf("Listener running: %s\n", 
               webSocketTransport.isListenerRunning() ? "YES" : "NO");
        printf("Background thread receives messages automatically\n");
        printf("No manual polling needed!\n");
        break;
    }
    
    case 'q':
    {
        std::cout << std::endl << "Action: Quit application!" << std::endl;
        
        // ✅ CLEAN SHUTDOWN
        printf("🛑 Stopping WebSocket listener...\n");
        webSocketTransport.stopWebSocketListener();
        
        printf("✅ Application shutting down cleanly\n");
        return 0;
    }
    
    default:
        if (opt != '\n') {  // Ignore empty input
            std::cout << "❓ Unknown option: " << opt << std::endl;
        }
        break;
    }
  }

  return 0;
}