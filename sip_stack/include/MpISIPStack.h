#ifndef __MP_ISIPSTACK1_H__
#define __MP_ISIPSTACK1_H__

#include "MpBuddy.h"
#include "MpStatus.h"

#define MP_SIP_STACK_LOCK "MP_SIP_STACK_LOCK"
#define MP_APP "Multi-Path (SMKEX) VoIP"

class MpISIPStack {
public:
	/**
	 * @brief Subscribe presence for buddy
	 * @param[in] buddy Buddy
	 * @return STATUS
	 */
	virtual mp_status_t subscribe(MpBuddy& buddy) = 0;
	/**
	 * @brief Unsubscribe presence for buddy
	 * @param[in] buddy_id Pjsua buddy id
	 * @return STATUS
	 */
	virtual mp_status_t unsubscribe(pjsua_buddy_id buddy_id) = 0;
	/**
	 * @brief Check if sip stack is started
	 * @return started
	 */
	virtual bool isSipStackStarted() = 0;
	virtual ~MpISIPStack() {
	}

	/**
	* @brief Resetează starea SIP după terminarea unui apel
	* @return STATUS
	*/
	mp_status_t resetSIPState();
};
#endif /* __MP_ISIPSTACK1_H__ */
