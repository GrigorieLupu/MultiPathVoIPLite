

#ifndef __MP_IDBCONNECTOR_H__
#define __MP_IDBCONNECTOR_H__

#include "MpMsgPayload.h"
#include "MpIMsgTransportNotif.h"
#include "MpLock.h"
#include <vector>

class MpIDBConnector : public MpIMsgTransportNotif {
public:
	/**
	 * @brief Get messages
	 * @return A queue with messages collected from the DB
	 */
	virtual const std::vector<MpMsgPayload>& getMessages() = 0;
	/**
	 * @brief Return DB connector message type
	 * @return Message type
	 */
	virtual mp_msg_type_t getMessageType() = 0;
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	virtual ~MpIDBConnector() {
	}
};

#endif /* __MP_IDBCONNECTOR_H__ */
