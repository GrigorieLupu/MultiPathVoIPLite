#include "MpMsg.h"
#include "MpBaseService.h"
#include "MpStatus.h"
#include <iostream>
#include <string.h>
#include <cstring>
#include "Smkex.h"
#include "SmkexSessionInfo.h"
#define THIS_TAG "MpMsg"

MpMsg::MpMsg() {
	MpService::instance()->getLogger()->print(THIS_TAG, __FUNCTION__,
			"Ctor");
}

MpMsg::~MpMsg() {
	MpService::instance()->getLogger()->print(THIS_TAG, __FUNCTION__,
			"Dtor");
}

void MpMsg::onSendMsgDone(void* msgId, mp_status_t xferStatus) {
	MpService::instance()->getLogger()->print(THIS_TAG, __FUNCTION__,
			"Message xfer done...");
}

void MpMsg::onMsgReceived(std::string const& serial, const uint8_t* msg, uint32_t msgLen) {

	MpService::instance()->getLogger()->print(THIS_TAG, __FUNCTION__,
											  "Message received...");

#ifndef ANDROID
	std::string message(reinterpret_cast<const char*>(msg), msgLen);

	std::cout << "Event: Message received from " << serial << std::endl << message << std::endl;
#endif
}
