#include <stdio.h>
#include "MpBaseService.h"
#include "MpUtils.h"

MpBaseService::MpBaseService() {
	MpLoggerSingleton::instance()->print("MpBaseService", __FUNCTION__, "Ctor");

	/*Setup*/
	MpAutoResendSingl::instance()->setMsgTransport(MpMTranSingl::instance());
	MpAutoResendSingl::instance()->setPresList(MpBLSingleton::instance());
	MpBLSingleton::instance()->setSIPStack(MpSIPStackSingleton::instance());
	MpAutoResendSingl::instance()->setSIPStack(MpSIPStackSingleton::instance());
}

MpBaseService::~MpBaseService() {
	MpLoggerSingleton::instance()->print("MpBaseService", __FUNCTION__, "Dtor");

	MpUserAccountSingleton::release();
	MpBLSingleton::release();
	MpDMSingleton::release();
	MpSIPStackSingleton::release();
	MpCMSingleton::release();
	MpMTranSingl::release();
	MpAutoResendSingl::release();
	MpLoggerSingleton::release();
}

