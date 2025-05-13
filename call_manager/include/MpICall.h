#ifndef __MP_ICALL_H__
#define __MP_ICALL_H__

#include <pjsip/sip_msg.h>

/**
 * @brief Call callback function. Methods use the following notation call_x_method (x can u - Caller and Callee,caller or callee)
 */

class MpICall {
public:
	/**
	 * @brief Callback function after invitation call is sent
	 * @return NONE
	 */
	virtual void call_caller_calling(pjsip_status_code last_call_status) = 0;
	/**
	 * @brief Callback function after invitation call is received
	 * @param[in] caller_serial Caller serial
	 * @return NONE
	 */
	virtual void call_callee_incoming(const char* caller_serial) = 0;
	/**
	 * @brief Callback function after the callee has answer with a provisional response (the callee side is `ringing`)
	 * @return NONE
	 */
	virtual void call_caller_early(pjsip_status_code last_call_status) = 0;
	/**
	 * @brief Callback function after invitation call was accepted (200 OK was received) or after response was sent (call was accepted or not)
	 * @return NONE
	 */
	virtual void call_u_connecting(pjsip_status_code last_call_status) = 0;
	/**
	 * @brief Callback after call is confirmed [established] (after ACK is sent or received)
	 * @return NONE
	 */
	virtual void call_u_confirmed(pjsip_status_code last_call_status) = 0;
	/**
	 * @brief Callback after call is terminated
	 * @return NONE
	 */
	virtual void call_u_disconnected(pjsip_status_code last_call_status) = 0;

	/**
	 * @brief Dtor
	 * @return NONE
	 */
	virtual ~MpICall() {
	}
};

#endif /* __MP_ICALL_H__ */
