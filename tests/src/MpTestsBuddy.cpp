#include "MpTestsBuddy.h"
#include "MpSIPStackMock.h"
#include "MpPresenceMock.h"
#include "MpStatus.h"
#include <stdlib.h>
#include <iostream>

#define DEFAULT_SERIAL "200605167004011430BC1AD1F34DB5DA69"

MpTestsBuddy::MpTestsBuddy() {
	testSuite = new MpTestSuiteData();

	testSuite->testSuiteName = "Test Buddy";
	MpTestsUtils::addTest(*testSuite, "Add and remove buddy test",
			AddAndRemoveBuddyTest);
	MpTestsUtils::addTest(*testSuite, "Duplicate buddy test",
			AddDuplicateBuddyTest);
	MpTestsUtils::addTest(*testSuite, "Add buddy invalid serials test",
			AddBuddyInvalidSerialsTest);
	MpTestsUtils::addTest(*testSuite, "Add buddy valid serials test",
			AddBuddyValidSerialsTest);
	MpTestsUtils::addTest(*testSuite, "Delete unexisting buddy test",
			DeleteUnexistingBuddyTest);
	MpTestsUtils::addTest(*testSuite, "Reset buddy list", ResetListBuddyTest);
	MpTestsUtils::addTest(*testSuite, "Presence buddy list",
			PresenceListBuddyTest);
}

MpTestsBuddy::~MpTestsBuddy() {
	delete testSuite;
	testSuite = NULL;
}

int MpTestsBuddy::AddAndRemoveBuddyTest() {

	MpBuddy buddy(DEFAULT_SERIAL);
	MpSIPStackMock sipStackMock;
	MpService::instance()->getBuddyList()->setSIPStack(&sipStackMock);
	sipStackMock.setSubscribeStatus(MP_SUCCESS);
	sipStackMock.setUnsubscribeStatus(MP_SUCCESS);

	MP_CHECK_INPUT(
			MP_SUCCESS
					== MpService::instance()->getBuddyList()->addBuddy(buddy),
			1);
	MpBuddy b = MpService::instance()->getBuddyList()->getBuddy(
			buddy.getBuddySerial());
	MP_CHECK_INPUT(b.getBuddySerial() == buddy.getBuddySerial(), 1);

	MpBuddy b1 = MpService::instance()->getBuddyList()->getBuddy("dddd");
	MP_CHECK_INPUT(b1.getBuddySerial() == "", 1);

	MP_CHECK_INPUT(
			MP_SUCCESS == MpService::instance()->getBuddyList()->rmBuddy(DEFAULT_SERIAL),
			1);

	MpService::instance()->getBuddyList()->reset();

	sipStackMock.setSubscribeStatus(MP_GENERAL_ERR);
	MP_CHECK_INPUT(
			MP_GENERAL_ERR
					== MpService::instance()->getBuddyList()->addBuddy(buddy),
			1);
	MpService::instance()->getBuddyList()->reset();
	MpService::instance()->getBuddyList()->setSIPStack(0);

	return 0;
}

int MpTestsBuddy::AddDuplicateBuddyTest() {

	MpBuddy buddy(DEFAULT_SERIAL);
	MpSIPStackMock sipStackMock;
	MpService::instance()->getBuddyList()->setSIPStack(&sipStackMock);
	sipStackMock.setSubscribeStatus(MP_SUCCESS);
	sipStackMock.setUnsubscribeStatus(MP_SUCCESS);

	MP_CHECK_INPUT(
			MP_SUCCESS
					== MpService::instance()->getBuddyList()->addBuddy(buddy),
			1);
	MP_CHECK_INPUT(
			MP_GENERAL_ERR
					== MpService::instance()->getBuddyList()->addBuddy(buddy),
			1);
	MP_CHECK_INPUT(
			MP_SUCCESS == MpService::instance()->getBuddyList()->rmBuddy(DEFAULT_SERIAL),
			1);

	MpService::instance()->getBuddyList()->setSIPStack(0);

	return 0;
}

int MpTestsBuddy::AddBuddyInvalidSerialsTest() {

	MpSIPStackMock sipStackMock;
	MpService::instance()->getBuddyList()->setSIPStack(&sipStackMock);
	sipStackMock.setSubscribeStatus(MP_SUCCESS);
	sipStackMock.setUnsubscribeStatus(MP_SUCCESS);

	const char *serials[] = { "()()()", "%^&1a2b3c", "@#asadasdasda#$sdas",
			"111!@#$%333", "!@#$%!@#$%", "Σ123ξϢϨ", "abcЩЖЊϿփcba", "是的请是的请" };

	for (unsigned int i = 0; i < sizeof(serials) / sizeof(serials[0]); i++) {
		MpBuddy buddy(serials[i]);
		MP_CHECK_INPUT(
				MP_GENERAL_ERR
						== MpService::instance()->getBuddyList()->addBuddy(
								buddy), 1);
	}

	MpService::instance()->getBuddyList()->setSIPStack(0);

	return 0;
}

int MpTestsBuddy::AddBuddyValidSerialsTest() {

	const char *serials[] = { "123", "123abcd", "123abcd456fdsd",
			"aasdhefuasdnadeua", "1a2b3c4d5e" };
	MpSIPStackMock sipStackMock;
	MpService::instance()->getBuddyList()->setSIPStack(&sipStackMock);
	sipStackMock.setSubscribeStatus(MP_SUCCESS);
	sipStackMock.setUnsubscribeStatus(MP_SUCCESS);

	for (unsigned int i = 0; i < sizeof(serials) / sizeof(serials[0]); i++) {
		MpBuddy buddy(serials[i]);
		MP_CHECK_INPUT(
				MP_SUCCESS
						== MpService::instance()->getBuddyList()->addBuddy(
								buddy), 1);
		MP_CHECK_INPUT(
				MP_SUCCESS
						== MpService::instance()->getBuddyList()->rmBuddy(
								serials[i]), 1);
	}

	MpService::instance()->getBuddyList()->setSIPStack(0);

	return 0;
}

int MpTestsBuddy::DeleteUnexistingBuddyTest() {

	MpBuddy buddy("blablabla");
	MpSIPStackMock sipStackMock;
	MpService::instance()->getBuddyList()->setSIPStack(&sipStackMock);
	sipStackMock.setSubscribeStatus(MP_SUCCESS);
	sipStackMock.setUnsubscribeStatus(MP_SUCCESS);

	MP_CHECK_INPUT(
			MP_SUCCESS == MpService::instance()->getBuddyList()->rmBuddy(DEFAULT_SERIAL),
			1);

	MpService::instance()->getBuddyList()->setSIPStack(0);

	return 0;
}

int MpTestsBuddy::ResetListBuddyTest() {

	MpBuddy buddy("blablabla");
	MpSIPStackMock sipStackMock;
	MpService::instance()->getBuddyList()->setSIPStack(&sipStackMock);
	sipStackMock.setSubscribeStatus(MP_SUCCESS);
	sipStackMock.setUnsubscribeStatus(MP_SUCCESS);

	buddy.setState(MP_BUDDY_ONLINE);
	MpService::instance()->getBuddyList()->addBuddy(buddy);

	bool online = MpService::instance()->getBuddyList()->isUserOnline(
			buddy.getBuddySerial());
	MP_CHECK_INPUT(true == online, 1);

	MpService::instance()->getBuddyList()->reset();
	online = MpService::instance()->getBuddyList()->isUserOnline(
			buddy.getBuddySerial());
	MP_CHECK_INPUT(false == online, 1);

	MpService::instance()->getBuddyList()->setSIPStack(0);
	return 0;
}

int MpTestsBuddy::PresenceListBuddyTest() {

	MpBuddy buddy("blablabla");
	MpSIPStackMock sipStackMock;
	MpService::instance()->getBuddyList()->setSIPStack(&sipStackMock);
	sipStackMock.setSubscribeStatus(MP_SUCCESS);
	sipStackMock.setUnsubscribeStatus(MP_SUCCESS);
	MpPresenceMock pmock;
	pmock.buddyStateCalled = pmock.buddyState2Called = false;

	MpService::instance()->getBuddyList()->addPresenceCb(&pmock);

	buddy.setState(MP_BUDDY_ONLINE);
	MpService::instance()->getBuddyList()->addBuddy(buddy);

	MP_CHECK_INPUT(false == pmock.buddyStateCalled, 1);
	MP_CHECK_INPUT(false == pmock.buddyState2Called, 1);

	buddy.setState(MP_BUDDY_OFFLINE);
	MpService::instance()->getBuddyList()->buddy_state(buddy.getBuddyID());

	MP_CHECK_INPUT(true == pmock.buddyStateCalled, 1);
	MP_CHECK_INPUT(true == pmock.buddyState2Called, 1);

	pmock.buddyStateCalled = pmock.buddyState2Called = false;

	MpService::instance()->getBuddyList()->buddy_state(-1000);

	MP_CHECK_INPUT(false == pmock.buddyStateCalled, 1);
	MP_CHECK_INPUT(false == pmock.buddyState2Called, 1);

	MpService::instance()->getBuddyList()->rmPresenceCb(&pmock);
	MpService::instance()->getBuddyList()->buddy_state(buddy.getBuddyID());

	MP_CHECK_INPUT(false == pmock.buddyStateCalled, 1);
	MP_CHECK_INPUT(false == pmock.buddyState2Called, 1);

	return 0;
}
