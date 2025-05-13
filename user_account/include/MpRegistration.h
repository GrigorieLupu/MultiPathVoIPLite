#ifndef __MP_REGISTRATION_H__
#define __MP_REGISTRATION_H__

#include "MpIRegistration.h"
#include "MpStatus.h"

class MpRegistration: MpIRegistration {
private:
	/**
	 * @brief Registration state callback
	  * @param[in] status Can be MP_STATUS_ONLINE, MP_STATUS_OFFLINE or MP_STATUS_ERR
	 * @return NONE
	 */
	void registration_state(mp_online_state_t status);
public:
	/**
	 * @brief Ctor
	 * @return NONE
	 */
	MpRegistration();
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	~MpRegistration();

};

#endif /* __MP_REGISTRATION_H__ */
