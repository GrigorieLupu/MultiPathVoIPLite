#ifndef __MP_MSG_H__
#define __MP_MSG_H__

#include "MpIMsg.h"
#include <stdint.h>
#include "Smkex.h"

class MpMsg: public MpIMsg {
public:
	/**
	 * @brief Ctor
	 * @return NONE
	 */
	MpMsg();
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	~MpMsg();
	/**
	 * @brief Message received callback
	 * @param[in] buddy Message sender
	 * @param[in] msg Message
     * @param[in] msgLen Message length
	 * @return NONE
	 */
	void onMsgReceived(std::string const& buddy,  const uint8_t* msg, uint32_t msgLen);
	/**
	 * @brief Message xfer done callback
	 * @param[in] msgId Message id
	 * @param[in] xferStatus SIP xfer status
	 * @return NONE`
	 */
	void onSendMsgDone(void* msgId, mp_status_t xferStatus);
};

#endif /* __MP_MSG_H__ */
