#include "MpMsgTransportMock.h"

MpMsgTransportMock::MpMsgTransportMock() :
		lastMsg_("null", MpBuffer(), 0, 0, 0, MP_TYPE_MESSAGE, false) {
	msgNotif_ = MP_NULL;
}

void MpMsgTransportMock::sendMessage(const MpMsgPayload& message) {
	this->lastMsg_ = message;
}

void MpMsgTransportMock::setMsgTransportNotif(
		MpIMsgTransportNotif* msgNotif) {
	this->msgNotif_ = msgNotif;
}

bool MpMsgTransportMock::isMessageProcessing(int uid_) {
	/*FIXME not implemented*/
	return false;
}
void MpMsgTransportMock::removeMessageForSerial(
		std::string const& receiverSerial) {
	/*FIXME not implemented*/
}
