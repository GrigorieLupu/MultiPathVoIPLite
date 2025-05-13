

#ifndef __MP_IMSGTRANSPORT_H__
#define __MP_IMSGTRANSPORT_H__

#include "MpMsgPayload.h"
#include "MpIMsgTransportNotif.h"

class MpIMsgTransport {
public:
	/**
	 * @brief Send a message
	 * @param[in] message Pointer to the message which will be sent.
	 * @return none
	 */
	virtual void sendMessage(const MpMsgPayload& message) = 0;
	/**
	 * @brief Set message transport notifier callback
	 * @param[in] msgNotif Pointer to the message transport notifier
	 * @return none
	 */
	virtual void setMsgTransportNotif(MpIMsgTransportNotif* msgNotif) = 0;
	/**
	 * @brief Test if an SMS message is processing (for manual retry UI)
	 * @param[in] msgObject Message DB Object
	 * @return TRUE if message is in the engine's queue
	 */
	//virtual bool isMessageProcessing(int uid_) = 0;
	/**
	 * @brief Remove current message if receiver serial is a given one
	 * @param[in] receiverSerial contact serial to remove message for
	 * @return none
	 */
	virtual void removeMessageForSerial(std::string const& receiverSerial) = 0;
	/**
	 * @brief Dtor
	 * @return none
	 */
	virtual ~MpIMsgTransport() {
	}
};

#endif /* __MP_IMSGTRANSPORT_H__ */
