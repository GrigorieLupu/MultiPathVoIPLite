#ifndef __MP_TESTSBUDDY_H__
#define __MP_TESTSBUDDY_H__

#include "MpTestsUtils.h"

class MpTestsBuddy
{
private:

	static int AddAndRemoveBuddyTest();
	static int AddDuplicateBuddyTest();
	static int AddBuddyInvalidSerialsTest();
	static int AddBuddyValidSerialsTest();
	static int DeleteUnexistingBuddyTest();
	static int ResetListBuddyTest();
	static int PresenceListBuddyTest();

public:
	MpTestsBuddy();
	~MpTestsBuddy();

	MpTestSuiteData *testSuite;

};

#endif /* __MP_TESTSBUDDY_H__ */
