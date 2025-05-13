#ifndef __MP_TESTS_H__
#define __MP_TESTS_H__

#include "MpTestsUtils.h"
#include "MpTestsBuddy.h"
#include "MpTestAutoResendEngine.h"

#include <stdint.h>
#include <iostream>
#include <unistd.h>

class MpTests {

private:
	MpAccSettings *accSettings;
	MpUserAccount *userAccount;

	std::vector<MpTestSuiteData*> testSuiteList;

	MpTestsBuddy *testBuddy;
	MpTestAutoResendEngine* testAutoResendEngine;
	
public:
	MpTests();
	~MpTests();

	void Run();
};

#endif /* __MP_TESTS_H__ */
