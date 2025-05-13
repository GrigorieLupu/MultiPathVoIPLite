#ifndef __MP_TESTAUTORESENDENGINE_H__
#define __MP_TESTAUTORESENDENGINE_H__

#include "MpTestsUtils.h"

class MpTestAutoResendEngine {
private:
	static int testSyncWithDBConnectors1();
	static int testSyncWithDBConnectors2();
	static int testSyncWithDBConnectors3();
	static int testSyncWithDBConnectors4();
	static int testSyncWithDBConnectors5();
	static int testSyncWithDBConnectors6();
	static int testSyncWithDBConnectors7();
	/*FIXME add more test scenarios*/
public:
	MpTestSuiteData* testSuite;
	MpTestAutoResendEngine();
};

#endif /* __MP_TESTAUTORESENDENGINE_H__ */
