#ifndef __MP_DBCONNECTORMOCK_H__
#define __MP_DBCONNECTORMOCK_H__

#include "MpIDBConnector.h"
#include "MpMsgPayload.h"
#include <deque>

class MpDBConnectorMock: public MpIDBConnector {
private:
	std::vector<MpMsgPayload> messages_; ///< Message queue
public:
	void messageStatus(const MpMsgPayload& message, mp_status_t status);
	/**
	 * @brief Get messages
	 * @return A queue with messages collected from the DB
	 */
	const std::vector<MpMsgPayload>& getMessages();
	/**
	 * @brief Push messages into connector
	 * @param[in] messages Message which will be copied into the `message queue`
	 * @return NONE
	 */
	void pushMessage(std::string const& userSerial, MpMsgPayload const& message);
	/**
	 * @brief Return DB connector message type
	 * @return Message type
	 */
	mp_msg_type_t getMessageType();
};

#endif /* __MP_DBCONNECTORMOCK_H__ */
