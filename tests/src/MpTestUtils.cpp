#include "MpTestsUtils.h"

void MpTestsUtils::addTest(MpTestSuiteData &testSuite, const char *testName,
		TestFunc testFunc) {

	MpTestData testData;
	std::string tmpString(testName);
	testData.testName = tmpString;
	testData.testFunction = testFunc;

	testSuite.testsList.push_back(testData);
}

