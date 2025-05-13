#include "MpTestAutoResendEngine.h"
#include "MpMsgPayload.h"
#include "MpDBConnectorMock.h"
#include "MpAutoResendEngine.h"
#include "MpMsgTransportMock.h"
#include "MpPresenceListMock.h"
#include "MpSIPStackMock.h"
#include <iostream>

MpTestAutoResendEngine::MpTestAutoResendEngine() {
	testSuite = new MpTestSuiteData();

	testSuite->testSuiteName = "TEST Auto Resend Engine";
	MpTestsUtils::addTest(*testSuite, "DB sync with connectors 1",
			testSyncWithDBConnectors1);
	MpTestsUtils::addTest(*testSuite, "DB sync with connectors 2",
			testSyncWithDBConnectors2);
	MpTestsUtils::addTest(*testSuite, "DB sync with connectors 3",
			testSyncWithDBConnectors3);
	MpTestsUtils::addTest(*testSuite, "DB sync with connectors 4",
			testSyncWithDBConnectors4);
	MpTestsUtils::addTest(*testSuite, "DB sync with connectors 5",
			testSyncWithDBConnectors5);
	MpTestsUtils::addTest(*testSuite, "DB sync with connectors 6",
			testSyncWithDBConnectors6);
	MpTestsUtils::addTest(*testSuite, "DB sync with connectors 7",
			testSyncWithDBConnectors7);
}

int MpTestAutoResendEngine::testSyncWithDBConnectors1() {
	MpDBConnectorMock dbConn;
	MpMsgTransportMock transport;
	MpBuddy buddy0("User0");
	MpBuddy buddy1("User1");
	MpBuddy buddy2("User2");
	MpBuddy buddy3("User3");
	MpBuddy buddy4("User4");
	MpPresenceListMock presList;

	for (int i = 0; i < 4; i++) {
		std::string user = "";
		if (i % 4 == 0) {
			user = "User0";
		} else if (i % 4 == 1) {
			user = "User1";
		} else if (i % 4 == 2) {
			user = "User2";
		} else if (i % 4 == 3) {
			user = "User3";
		}
		char msgPayload[] = "Content";
		MpBuffer msgPayloadBuf((uint8_t*) msgPayload, strlen(msgPayload));
		dbConn.pushMessage(user,
				MpMsgPayload(user, msgPayloadBuf, i, 3, i, MP_TYPE_MESSAGE,
						false));

	}
	MpAutoResendEngine arEngine;
	MpSIPStackMock sipStackMock;
	arEngine.setSIPStack(&sipStackMock);
	arEngine.setAutoResendEnabled(true);
	arEngine.setMsgTransport(&transport);
	arEngine.addDBConnector(&dbConn);
	arEngine.setPresList(&presList);
	arEngine.syncWithDBConnectors();

	/*========================================*/

	/*========================================*/
	buddy4.setState(MP_BUDDY_ONLINE);
	presList.insertUser("User4");
	arEngine.buddy_state2(buddy4);

	/*========================================*/
	buddy3.setState(MP_BUDDY_ONLINE);
	presList.insertUser("User3");
	arEngine.buddy_state2(buddy3);
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "User3");

	/*========================================*/
	buddy2.setState(MP_BUDDY_ONLINE);
	presList.insertUser("User2");
	arEngine.buddy_state2(buddy2);
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "User3");

	/*========================================*/
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_NOT_SENT); // User3 removed
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "User2");

	/*========================================*/
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_NOT_SENT); // User2 removed

	/*========================================*/
	arEngine.buddy_state2(buddy3);
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "User0");

	/*========================================*/
	buddy1.setState(MP_BUDDY_ONLINE);
	presList.insertUser("User1");
	arEngine.buddy_state2(buddy1);
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "User0");

	/*========================================*/
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_NOT_SENT); // User0 removed
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "User1");

	/*========================================*/
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_NOT_SENT); // User1 removed
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "User3");

	/*========================================*/
	arEngine.buddy_state2(buddy2);
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "User3");

	/*========================================*/
	arEngine.buddy_state2(buddy1);
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_NOT_SENT); //User2 removed
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "User1");

	/*========================================*/
	arEngine.buddy_state2(buddy3);
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_NOT_SENT); //User1 removed
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "User2");

	/*========================================*/
	buddy0.setState(MP_BUDDY_ONLINE);
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_NOT_SENT);
	presList.insertUser("User0");
	arEngine.buddy_state2(buddy0);
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_NOT_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "User0");

	return 0;
}

int MpTestAutoResendEngine::testSyncWithDBConnectors2() {
	MpDBConnectorMock dbConn;
	MpMsgTransportMock transport;
	MpPresenceListMock presList;
	MpBuddy buddy0("User0");
	MpBuddy buddy1("User1");
	char msgPayload[] = "Content";
	MpBuffer msgPayloadBuf((uint8_t*) msgPayload, strlen(msgPayload));
	dbConn.pushMessage("User0",
			MpMsgPayload(std::string("User0"), msgPayloadBuf, 0, 3, 10,
					MP_TYPE_MESSAGE, true));
	dbConn.pushMessage("User1",
			MpMsgPayload(std::string("User1"), msgPayloadBuf, 1, 3, 10,
					MP_TYPE_MESSAGE, true));

	MpAutoResendEngine arEngine;
	MpSIPStackMock sipStackMock;
	arEngine.setSIPStack(&sipStackMock);
	arEngine.setAutoResendEnabled(true);
	arEngine.setMsgTransport(&transport);
	arEngine.addDBConnector(&dbConn);
	arEngine.setPresList(&presList);
	arEngine.syncWithDBConnectors();

	buddy0.setState(MP_BUDDY_ONLINE);
	presList.insertUser("User0");
	arEngine.buddy_state2(buddy0);
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "User0");

	/*========================================*/
	buddy1.setState(MP_BUDDY_ONLINE);
	presList.insertUser("User1");
	arEngine.buddy_state2(buddy1);
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_NOT_SENT); //User0 removed
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "User1");

	/*========================================*/
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT); // Message for User1 deleted
	arEngine.buddy_state2(buddy0);
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "User0");

	/*========================================*/
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_NOT_SENT); // User0 removed
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "User0");

	return 0;
}

int MpTestAutoResendEngine::testSyncWithDBConnectors3() {

	MpDBConnectorMock dbConn;
	MpMsgTransportMock transport;
	MpPresenceListMock presList;

	MpBuddy buddy0("User0");

	MpMsgPayload* messages[2000];

	for (int i = 0; i < 1000; i++) {
		char msgPayload[100];
		sprintf(msgPayload, "Msg %d", i);
		MpBuffer msgPayloadBuf((uint8_t*) msgPayload, strlen(msgPayload));
		messages[i] = new MpMsgPayload(std::string("User0"), msgPayloadBuf, i, 3,
				10, MP_TYPE_MESSAGE, true);
		dbConn.pushMessage("User 0", *(messages[i]));
	}
	MpAutoResendEngine arEngine;
	MpSIPStackMock sipStackMock;
	arEngine.setSIPStack(&sipStackMock);
	arEngine.setAutoResendEnabled(true);
	arEngine.setMsgTransport(&transport);
	arEngine.addDBConnector(&dbConn);
	arEngine.setPresList(&presList);
	/*Load messages into engine*/
	arEngine.syncWithDBConnectors();

	/*Send some messages*/
	presList.insertUser("User0");
	buddy0.setState(MP_BUDDY_ONLINE);

	arEngine.buddy_state2(buddy0);
	MP_ASSERT_EQ(transport.lastMsg_.getUID(), 0);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[0]->getPayload());
	/*Confirm first message*/
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[1]->getPayload());
	/*Confirm second message*/
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[2]->getPayload());
	/*Confirm third message*/
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[3]->getPayload());

	/*Put the user online again*/
	buddy0.setState(MP_BUDDY_ONLINE);
	arEngine.buddy_state2(buddy0);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[3]->getPayload());

	/*Put the user offline*/
	buddy0.setState(MP_BUDDY_OFFLINE);
	arEngine.buddy_state2(buddy0);
	/*Wait and send some messages*/
	for (int i = 0; i < 1000; i++) {
		char msgPayload[100];
		sprintf(msgPayload, "Msg %d", i + 1000);
		MpBuffer msgPayloadBuf((uint8_t*) msgPayload, strlen(msgPayload));
		messages[i + 1000] = new MpMsgPayload(std::string("User0"),
				msgPayloadBuf, 0, 3, 10, MP_TYPE_MESSAGE, true);
		arEngine.addMessage(*(messages[i + 1000]));
	}
	/*Put the user online again*/
	buddy0.setState(MP_BUDDY_ONLINE);
	arEngine.buddy_state2(buddy0);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[3]->getPayload());

	for (int i = 4; i < 2000; i++) {
		/*Confirm last message*/
		arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
		MP_ASSERT_EQ(transport.lastMsg_.getPayload(),
				messages[i]->getPayload());
	}

	return 0;
}

int MpTestAutoResendEngine::testSyncWithDBConnectors4() {

	MpDBConnectorMock dbConn;
	MpMsgTransportMock transport;
	MpPresenceListMock presList;

	MpBuddy buddy0("user0");
	MpBuddy buddy1("user1");

	MpMsgPayload* messages[20];

	for (int i = 0; i < 10; i++) {
		char msgPayload[100];
		sprintf(msgPayload, "Msg %d", i);
		MpBuffer msgPayloadBuf((uint8_t*) msgPayload, strlen(msgPayload));
		messages[i] = new MpMsgPayload(std::string("user0"), msgPayloadBuf, i, 3,
				10, MP_TYPE_MESSAGE, true);
		dbConn.pushMessage("user0", *(messages[i]));
	}

	for (int i = 10; i < 20; i++) {
		char msgPayload[100];
		sprintf(msgPayload, "Msg %d", i);
		MpBuffer msgPayloadBuf((uint8_t*) msgPayload, strlen(msgPayload));
		messages[i] = new MpMsgPayload(std::string("user1"), msgPayloadBuf, i, 3,
				10, MP_TYPE_MESSAGE, true);
		dbConn.pushMessage("user1", *(messages[i]));
	}

	MpAutoResendEngine arEngine;
	MpSIPStackMock sipStackMock;
	arEngine.setSIPStack(&sipStackMock);
	arEngine.setAutoResendEnabled(true);
	arEngine.setMsgTransport(&transport);
	arEngine.addDBConnector(&dbConn);
	arEngine.setPresList(&presList);
	/*Load messages into engine*/
	arEngine.syncWithDBConnectors();

	/*Send some messages*/
	presList.insertUser("user0");
	buddy0.setState(MP_BUDDY_OFFLINE);

	presList.insertUser("user1");
	buddy1.setState(MP_BUDDY_ONLINE);

	arEngine.buddy_state2(buddy0);
	arEngine.buddy_state2(buddy1);

	MP_ASSERT_EQ(transport.lastMsg_.getUID(), 10);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[10]->getPayload());
	/*Confirm message*/
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[11]->getPayload());
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[0]->getPayload());
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[1]->getPayload());
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[12]->getPayload());

	buddy0.setState(MP_BUDDY_ONLINE);
	arEngine.buddy_state2(buddy0);
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getUID(), 2);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[2]->getPayload());
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[3]->getPayload());
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[4]->getPayload());
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[5]->getPayload());
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[13]->getPayload());

	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[14]->getPayload());

	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[6]->getPayload());

	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[7]->getPayload());

	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[15]->getPayload());

	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[16]->getPayload());

	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[8]->getPayload());

	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[9]->getPayload());

	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[17]->getPayload());

	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[18]->getPayload());

	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getPayload(), messages[19]->getPayload());

	return 0;
}

int MpTestAutoResendEngine::testSyncWithDBConnectors5() {

	MpDBConnectorMock dbConn;
	MpMsgTransportMock transport;
	MpPresenceListMock presList;

	MpBuddy buddy0("user0");
	MpBuddy buddy1("user1");

	char msgPayload[100];
	sprintf(msgPayload, "Msg %d", 1);
	MpBuffer msgPayloadBuf((uint8_t*) msgPayload, strlen(msgPayload));
	dbConn.pushMessage("user0",
			MpMsgPayload(std::string("user0"), msgPayloadBuf, 999, 3, 10,
					MP_TYPE_MESSAGE, true));

	MpAutoResendEngine arEngine;
	MpSIPStackMock sipStackMock;
	arEngine.setSIPStack(&sipStackMock);
	arEngine.setAutoResendEnabled(true);
	arEngine.setMsgTransport(&transport);
	arEngine.addDBConnector(&dbConn);
	arEngine.setPresList(&presList);
	/*Load messages into engine*/
	arEngine.syncWithDBConnectors();

	/*Send some messages*/
	presList.insertUser("user0");
	buddy0.setState(MP_BUDDY_OFFLINE);

	presList.insertUser("user1");
	buddy1.setState(MP_BUDDY_ONLINE);

	arEngine.buddy_state2(buddy0);
	arEngine.buddy_state2(buddy1);

	buddy0.setState(MP_BUDDY_ONLINE);
	arEngine.buddy_state2(buddy0);

	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "user0");
	MP_ASSERT_EQ(arEngine.isMessageProcessing("user5", 1), false);
	MP_ASSERT_EQ(arEngine.isMessageProcessing("user5", 999), false);
	MP_ASSERT_EQ(arEngine.isMessageProcessing("user0", 1), true);
	MP_ASSERT_EQ(arEngine.isMessageProcessing("user0", 999), true);

	return 0;
}

int MpTestAutoResendEngine::testSyncWithDBConnectors6() {

	MpDBConnectorMock dbConn;
	MpMsgTransportMock transport;
	MpPresenceListMock presList;

	MpBuddy buddy0("user0");
	MpBuddy buddy1("user1");
	MpBuddy buddy2("user2");

	char msgPayload[100];
	sprintf(msgPayload, "Msg %d", 1);
	MpBuffer msgPayloadBuf((uint8_t*) msgPayload, strlen(msgPayload));
	dbConn.pushMessage("user0",
			MpMsgPayload(std::string("user0"), msgPayloadBuf, 999, 3, 10,
					MP_TYPE_MESSAGE, true));
	dbConn.pushMessage("user1",
			MpMsgPayload(std::string("user1"), msgPayloadBuf, 1000, 3, 10,
					MP_TYPE_MESSAGE, true));
	dbConn.pushMessage("user2",
			MpMsgPayload(std::string("user2"), msgPayloadBuf, 1001, 3, 10,
					MP_TYPE_MESSAGE, true));
	MpAutoResendEngine arEngine;
	MpSIPStackMock sipStackMock;
	arEngine.setSIPStack(&sipStackMock);
	arEngine.setAutoResendEnabled(true);
	arEngine.setMsgTransport(&transport);
	arEngine.addDBConnector(&dbConn);
	arEngine.setPresList(&presList);
	/*Load messages into engine*/
	arEngine.syncWithDBConnectors();

	/*Send some messages*/
	presList.insertUser("user0");
	buddy0.setState(MP_BUDDY_OFFLINE);

	presList.insertUser("user1");
	buddy1.setState(MP_BUDDY_ONLINE);

	presList.insertUser("user2");
	buddy2.setState(MP_BUDDY_ONLINE);

	arEngine.buddy_state2(buddy0);
	arEngine.buddy_state2(buddy1);

	buddy0.setState(MP_BUDDY_ONLINE);
	arEngine.buddy_state2(buddy0);

	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "user1");

	arEngine.removeMessagesForSerial("user99");
	arEngine.removeMessagesForSerial("user1");
	arEngine.removeMessagesForSerial("user0");
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);

	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "user2");

	return 0;
}

int MpTestAutoResendEngine::testSyncWithDBConnectors7() {

	MpDBConnectorMock dbConn;
	MpMsgTransportMock transport;
	MpPresenceListMock presList;

	MpBuddy buddy0("user0");
	MpBuddy buddy1("user1");

	char msgPayload[100];
	sprintf(msgPayload, "Msg %d", 1);
	MpBuffer msgPayloadBuf((uint8_t*) msgPayload, strlen(msgPayload));
	dbConn.pushMessage("user0",
			MpMsgPayload(std::string("user0"), msgPayloadBuf, 1, 3, 10,
					MP_TYPE_MESSAGE, true));
	dbConn.pushMessage("user0",
			MpMsgPayload(std::string("user0"), msgPayloadBuf, 999, 3, 10,
					MP_TYPE_MESSAGE, true));
	dbConn.pushMessage("user0",
			MpMsgPayload(std::string("user0"), msgPayloadBuf, 1000, 3, 10,
					MP_TYPE_MESSAGE, true));
	dbConn.pushMessage("user1",
			MpMsgPayload(std::string("user1"), msgPayloadBuf, 1001, 3, 10,
					MP_TYPE_MESSAGE, true));
	dbConn.pushMessage("user1",
			MpMsgPayload(std::string("user1"), msgPayloadBuf, 1002, 3, 10,
					MP_TYPE_MESSAGE, true));
	dbConn.pushMessage("user1",
			MpMsgPayload(std::string("user1"), msgPayloadBuf, 1003, 3, 10,
					MP_TYPE_MESSAGE, true));
	MpAutoResendEngine arEngine;
	MpSIPStackMock sipStackMock;
	arEngine.setSIPStack(&sipStackMock);
	arEngine.setAutoResendEnabled(true);
	arEngine.setMsgTransport(&transport);
	arEngine.addDBConnector(&dbConn);
	arEngine.setPresList(&presList);
	/*Load messages into engine*/
	arEngine.syncWithDBConnectors();

	/*Send some messages*/
	presList.insertUser("user0");
	buddy0.setState(MP_BUDDY_ONLINE);

	presList.insertUser("user1");
	buddy1.setState(MP_BUDDY_ONLINE);

	arEngine.buddy_state2(buddy0);
	arEngine.buddy_state2(buddy1);

	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "user0");
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_NOT_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "user1");
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "user1");
	arEngine.resendMessage("user0", 999);
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "user0");
	arEngine.messageStatus(transport.lastMsg_, MP_MESSAGE_SENT);
	MP_ASSERT_EQ(transport.lastMsg_.getUserSerial(), "user0");

	return 0;
}
