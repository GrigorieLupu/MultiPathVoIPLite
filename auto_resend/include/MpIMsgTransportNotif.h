

#ifndef __MP_IMSGTRANSPORTNOTIF_H__
#define __MP_IMSGTRANSPORTNOTIF_H__

#include "MpStatus.h"

class MpIMsgTransportNotif {
public:
	/**
	 * @brief Message SIP xfer status
	 * @param[in] message Transmitted message
	 * @param[in] status SIP xfer status
	 * @return none
	 */
	virtual void messageStatus(const MpMsgPayload& message,
			mp_status_t status) = 0;
	/**
	 * @brief Dtor
	 * @return none
	 */
	virtual ~MpIMsgTransportNotif() {
	}
};

#endif /* __MP_IMSGTRANSPORTNOTIF_H__ */
