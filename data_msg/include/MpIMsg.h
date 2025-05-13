#ifndef __MP_IMSG_H__
#define __MP_IMSG_H__
#include <stdint.h>
#include "MpStatus.h"
#include "MpBuddy.h"

class MpIMsg {

public:
	/**
	 * @brief Message received callback
	 * @param[in] serial Sender serial
	 * @param[in] msg Message
     * @param[in] msgLen Message length
	 * @return NONE
	 */
	virtual void onMsgReceived(std::string const &serial, const uint8_t* msg, uint32_t msgLen) = 0;
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	virtual ~MpIMsg() {

	}
};

#endif /* __MP_IMSG_H__ */
