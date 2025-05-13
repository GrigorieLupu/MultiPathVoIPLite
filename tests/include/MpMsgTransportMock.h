#ifndef __MP_MSGTRANSPORTMOCK_H__
#define __MP_MSGTRANSPORTMOCK_H__

#include "MpIMsgTransport.h"

class MpMsgTransportMock: public MpIMsgTransport {
private:
	MpIMsgTransportNotif* msgNotif_;
public:
	MpMsgPayload lastMsg_;
	void sendMessage(const MpMsgPayload& message);
	void setMsgTransportNotif(MpIMsgTransportNotif* msgNotif);
	bool isMessageProcessing(int uid_);
	void removeMessageForSerial(std::string const& receiverSerial);
	MpMsgTransportMock();
};

#endif /* __MP_MSGTRANSPORTMOCK_H__ */
