#ifndef __MP_TESTSUTILS_H__
#define __MP_TESTSUTILS_H__

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

#include "MpUtils.h"
#include <vector>

typedef int (*TestFunc)(void); /**< Signature for a testing function */

typedef struct MpTestData {
	/**
	 * @brief Name of the test
	 */
	std::string testName;

	/**
	 * @brief The function that will be called for the given test
	 */
	TestFunc testFunction;
} MpTestData;

typedef struct MpTestSuiteData {
	/**
	 * @brief Name of the test suite
	 */
	std::string testSuiteName;

	/**
	 * @brief Tests table
	 */
	std::vector<MpTestData> testsList;
} MpTestSuiteData;

class MpTestsUtils {
public:
	static void addTest(MpTestSuiteData &testSuite, const char *testName, TestFunc testFunc);

};

#endif /* __MP_TESTSUTILS_H__ */
