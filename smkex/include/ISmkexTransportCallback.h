#ifndef __ISMKEX_TRANSPORT_CALLBACK_H__
#define __ISMKEX_TRANSPORT_CALLBACK_H__
#include <stdint.h>
#include "MpUtils.h"

class ISmkexTransportCallback {

public:
	/**
	 * @brief Message received callback
	 * @param serial Sender serial
	 * @param msg Message
	 * @param msgLen Message length
	 * @param channel the channel on which the message came
	 * @return NONE
	 */
	virtual void onMsgReceived(std::string const &serial, const uint8_t* msg, uint32_t msgLen, int channel) = 0;
	
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	virtual ~ISmkexTransportCallback() {
	}
};

#endif /* __ISMKEX_TRANSPORT_CALLBACK_H__ */
