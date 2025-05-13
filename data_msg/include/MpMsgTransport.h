#ifndef __MP_MSGTRANSPORT_H__
#define __MP_MSGTRANSPORT_H__

#include "MpSingleton.h"
#include "MpIMsgTransport.h"
#include "MpIMsg.h"
#include "MpLock.h"

#define MP_MSG_TRANSPORT_SLEEP 1800 /*ms*/

class MpMsgTransport: public MpIMsgTransport {
	friend class MpSingleton<MpMsgTransport> ;
private:
	MpLock msgLock_; /*Message lock*/
	MpIMsgTransportNotif* msgNotif_; /*Message sent callback object*/
	MpMsgPayload msg_; /*Pointer to current message*/
	int counter_; /*Counts the number of message sending attempts*/
public:
	/**
	 * @brief Ctor
	 * @return none
	 */
	MpMsgTransport();
	/**
	 * @brief Dtor
	 * @return none
	 */
	~MpMsgTransport();
	/**
	 * @brief Send a message
	 * @param[in] message Message to be sent
	 * @return none
	 */
	void sendMessage(const MpMsgPayload& message);
	/**
	 * @brief Set message transport notifier callback
	 * @param[in] msgNotif Pointer to the message transport notifier
	 * @return none
	 */
	void setMsgTransportNotif(MpIMsgTransportNotif* msgNotif);
	/**
	 * @brief Message received callback
	 * @param[in] buddy Message sender
	 * @param[in] msg Message
	 * @param[in] msgLen Message length
	 * @return NONE
	 */
	void onMsgReceived(MpBuddy const& buddy, const uint8_t* msg,
			uint32_t msgLen);
	/**
	 * @brief Message xfer done callback
	 * @param[in] xferStatus SIP xfer status
	 * @return NONE`
	 */
	void onSendMsgDone(mp_status_t xferStatus);

	/**
	 * @brief Remove current message if receiver serial is given
	 * @param[in] receiverSerial contact serial to remove message for
	 * @return none
	 */
	void removeMessageForSerial(std::string const& receiverSerial);
};

typedef MpSingleton<MpMsgTransport> MpMTranSingl;

#endif /* __MP_MSGTRANSPORT_H__ */
