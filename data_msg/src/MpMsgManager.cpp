#include "MpMsgManager.h"
#include "MpBaseService.h"
#include "MpErrors.h"
#include <iostream>

MpMsgManager::MpMsgManager() :
		msgCb_("MpMsgManager_MSG_LOCK"), invCb_("MpMsgManager_INV_LOCK") {
	MP_LOG1("Ctor");
}

MpMsgManager::~MpMsgManager() {
	MP_LOG1("Dtor");
}

mp_status_t MpMsgManager::addMsgCb(MpIMsg* mcb) {
	MP_LOG1("Add msg callback...");
	MP_CHECK_INPUT(mcb != MP_NULL, MP_GENERAL_ERR);
	msgCb_.addPoolData(mcb);

	return MP_SUCCESS;
}
mp_status_t MpMsgManager::rmMsgCb(MpIMsg* mcb) {
	MP_LOG1("Remove msg callback...");
	MP_CHECK_INPUT(mcb != MP_NULL, MP_GENERAL_ERR);
	msgCb_.rmPoolData(mcb);
	return MP_SUCCESS;
}

mp_status_t MpMsgManager::addInvCb(MpIInvitationCallback* icb) {
	MP_LOG1("Add invitation callback...");
	MP_CHECK_INPUT(icb != MP_NULL, MP_GENERAL_ERR);
	invCb_.addPoolData(icb);

	return MP_SUCCESS;
}

mp_status_t MpMsgManager::rmInvCb(MpIInvitationCallback* icb) {
	MP_LOG1("Remove invitation callback...");
	MP_CHECK_INPUT(icb != MP_NULL, MP_GENERAL_ERR);
	invCb_.rmPoolData(icb);

	return MP_SUCCESS;
}

void MpMsgManager::onMsgReceived(const char* fromUri, uint8_t* msgBody,
		uint32_t msgBodyLen) {
	
	std::cout << "MpMsgManager::onMsgReceived:  Received message from: " << fromUri << std::endl;
	std::string message((char *)msgBody,msgBodyLen);
   
	MpBuffer msg(msgBody, msgBodyLen);
	
	std::string serial(MpUtils::getSerialFromUri(fromUri));

	/*If SMS message*/
	msgCb_.usePool();
	vector<MpIMsg*> msgCbPool = msgCb_.getPool();
	vector<MpIMsg*>::iterator it = msgCbPool.begin();
		
	for (; it < msgCbPool.end(); ++it) {
		(*it)->onMsgReceived(serial, msg.getPayload(), msg.getLen());
	}
	
	msgCb_.endUsePool();
}