#ifndef __MP_IREGISTRATION_H__
#define __MP_IREGISTRATION_H__

#include "MpStatus.h"

typedef enum mp_online_state {
	MP_ONLINE, MP_OFFLINE
} mp_online_state_t;

class MpIRegistration {
public:
	/**
	 * @brief Registration state callback
	 * * @param[in] status Can be MP_STATUS_ONLINE, MP_STATUS_OFFLINE or MP_STATUS_ERR
	 * @return NONE
	 */
	virtual void registration_state(mp_online_state_t status) = 0;
	/**
	 * @bried Dtor
	 * @return NONE
	 */
	virtual ~MpIRegistration() {
	}
};

#endif /* __MP_IREGISTRATION_H__ */
