#include "MpMsgPayload.h"

void MpMsgPayload::copyMsgPayload(MpMsgPayload const& msgPayload) {
	// Copy Msg payload struct
	setUserSerial(msgPayload.getUserSerial());
	setMessageType(msgPayload.getMessageType());
	payload_ = msgPayload.getPayload();
	setXferStatus(msgPayload.getXferStatus());
	setUID(msgPayload.getUID());
	setNumberOfRetries(msgPayload.getNumberOfRetries());
	setAccID(msgPayload.getAccID());
	if (msgPayload.isMessageProcessed())
		markAsProcessed();
	else
		markAsUnProcessed();
}

MpMsgPayload::MpMsgPayload(MpMsgPayload const& msgPayload) {
	copyMsgPayload(msgPayload);
}

MpMsgPayload::MpMsgPayload(std::string const& userSerial,
		MpBuffer const& payload, int uid, int numberOfRetries, long accID, /*int creationDate,*/
		mp_msg_type_t messageType, bool processed) {
	setUserSerial(userSerial);
	setMessageType(messageType);
	setPayload(payload);
	setXferStatus(0);
	setUID(uid);
	setNumberOfRetries(numberOfRetries);
	setAccID(accID);
	if (processed)
		markAsProcessed();
	else
		markAsUnProcessed();
}

MpMsgPayload& MpMsgPayload::operator =(MpMsgPayload const& msgPayload) {
	if (this != &msgPayload)
		copyMsgPayload(msgPayload);
	return *this;
}

void MpMsgPayload::setPayload(MpBuffer const& payload) {
	const uint8_t* msgPayload = payload.getPayload();
	uint32_t msgPayloadLen = payload.getLen() + 1;
	/*Alloc new payload*/
	uint8_t* msgTransportPayload = new uint8_t[(sizeof(uint8_t)
			* (msgPayloadLen))];
	/*Append transport message type.*/
	msgTransportPayload[0] = (
			messageType_ == MP_TYPE_MESSAGE ?
					MP_TYPE_MESSAGE : MP_TYPE_INVITATION);
	memcpy(msgTransportPayload + sizeof(uint8_t), msgPayload, payload.getLen());
	/*Set transport payload*/
	payload_.setPayload(msgTransportPayload, msgPayloadLen);
	MP_FREE_CHAR_ARRAY(msgTransportPayload);
}

MpBuffer MpMsgPayload::getTransportPayload() const {
	return payload_;
}

void MpMsgPayload::dump() const {
	payload_.dump();
}
