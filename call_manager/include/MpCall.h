#ifndef __MP_CALL_H__
#define __MP_CALL_H__

#include "MpICall.h"

class MpCall: public MpICall {
public:
	/**
	 * @brief Ctor
	 * @return NONE
	 */
	MpCall();
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	~MpCall();
	/**
	 * @brief Callback function after invitation call is sent
	 * @return NONE
	 */
	void call_caller_calling(pjsip_status_code last_call_status);
	/**
	 * @brief Callback function after invitation call is received
	 * @param[in] caller_serial Caller serial
	 * @return NONE
	 */
	void call_callee_incoming(const char* caller_serial);
	/**
	 * @brief Callback function after the callee has answer with a provisional response (the callee side is `ringing`)
	 * @return NONE
	 */
	void call_caller_early(pjsip_status_code last_call_status);
	/**
	 * @brief Callback function after invitation call was accepted (200 OK was received) or after response was sent (call was accepted or not)
	 * @return NONE
	 */
	void call_u_connecting(pjsip_status_code last_call_status);
	/**
	 * @brief Callback after call is confirmed [established] (after ACK is sent or received)
	 * @return NONE
	 */
	void call_u_confirmed(pjsip_status_code last_call_status);
	/**
	 * @brief Callback after call is terminated
	 * @return NONE
	 */
	void call_u_disconnected(pjsip_status_code last_call_status);
};

#endif /* __MP_CALL_H__ */
