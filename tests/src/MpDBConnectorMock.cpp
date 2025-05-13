#include "MpDBConnectorMock.h"
#include "MpBaseService.h"

const std::vector<MpMsgPayload>& MpDBConnectorMock::getMessages() {
	MP_LOG1("Get messages");
	return messages_;
}
void MpDBConnectorMock::pushMessage(std::string const& userSerial,
		MpMsgPayload const& message) {
	MP_LOG1("Push message into message queue");
	messages_.push_back(message);
}

void MpDBConnectorMock::messageStatus(const MpMsgPayload& message,
		mp_status_t status) {

}

mp_msg_type_t MpDBConnectorMock::getMessageType() {
	return MP_TYPE_MESSAGE;
}
