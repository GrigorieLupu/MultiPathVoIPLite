#ifndef __MP_PRESENCE_H__
#define __MP_PRESENCE_H__

#include "MpIPresence.h"

class MpPresence: public MpIPresence {
public:
	/**
	 * @brief Ctor
	 * @return NONE
	 */
	MpPresence();
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	~MpPresence();
	/**
	 * @brief Buddy presence changed callback
	 * @param[in] buddy_id Buddy id
	 * @return NONE
	 */
	void buddy_state(pjsua_buddy_id buddy_id);
	/**
	 * @brief Buddy presence changed callback
	 * @param[in] buddy Buddy
	 * @return NONE
	 */
	void buddy_state2(const MpBuddy& buddy);
};

#endif /* __MP_PRESENCE_H__ */
