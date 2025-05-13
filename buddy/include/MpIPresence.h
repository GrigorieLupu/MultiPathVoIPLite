#ifndef __MP_IPRESENCE_H__
#define __MP_IPRESENCE_H__

#include "pjsua.h"
#include "MpBuddy.h"

class MpIPresence {
public:
	/**
	 * @brief Buddy presence changed callback
	 * @param[in] buddy_id Buddy id
	 * @return NONE
	 */
	virtual void buddy_state(pjsua_buddy_id buddy_id) = 0;
	/**
	 * @brief Buddy presence changed callback
	 * @param[in] buddy Buddy
	 * @return NONE
	 */
	virtual void buddy_state2(const MpBuddy& buddy) = 0;
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	virtual ~MpIPresence() {

	}
};

#endif /* __MP_IPRESENCE_H__ */
