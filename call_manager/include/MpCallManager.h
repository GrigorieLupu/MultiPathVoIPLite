#ifndef __MP_MANAGERCALL_H__
#define __MP_MANAGERCALL_H__

#include "MpSingleton.h"
#include "MpStatus.h"
#include "MpBuffer.h"
#include "MpICall.h"
#include "MpRWLock.h"
#include "MpPool.h"
#include "MpICallTimer.h"
#include "MpIKeyExchange.h"
#include "MpICallTimeout.h"
#include <pjsua-lib/pjsua.h>
#include <vector>
using namespace std;

#define MP_CALL_TIMEOUT			30 /*seconds*/

class MpCallManager: public MpICallTimeout {
	friend class MpSingleton<MpCallManager> ;
	friend class MpSIPStack;
private:
	pjsua_call_id call_id_; ///< Most recent call id
    int lastAnswerMode_; ///< Most recent answer mode
	MpPool<MpICall> callCb_; ///< Call callbacks
	MpICallTimer *timer_; ///< Call timer
	bool enaWatchdog; ///< Indicates if watchdog is enabled
	std::string lastCallBuddy; ///< Most recent buddy engaged in a call

	/**
	 * @brief Ctor
	 * @return NONE
	 */
	MpCallManager();
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	~MpCallManager();
	/**
	 * @brief Copy Ctor
	 * @param[in] cm Call Manager
	 * @return NONE
	 */
	MpCallManager(MpCallManager const& cm);
	/**
	 * @brief Operator =
	 * @param[in] cm Call Manager
	 * @return NONE
	 */
	MpCallManager& operator=(MpCallManager const& cm);

	/**
	 * @brief Callback called by SIPStack when a change in the CALL FSM occured
	 * @param[in] call_id Call id
	 * @param[in] call_state Call state
	 * @param[in] last_status_code Last status code heard, which can be used as cause code
	 * @param[in] remote_contact_uri Remote contact uri
	 * @return NONE
	 */
	void onCallState(pjsua_call_id call_id, pjsip_inv_state call_state, pjsip_status_code last_status_code, char* remote_contact_uri);
	/**
	 * @brief Callback called by SIPStack when ac incoming call arrives
	 * @param[in] call_id Call id
	 * @param[in] caller_serial Caller serial
	 * @return NONE
	 */
	void onIncomingCall(pjsua_call_id call_id, const char* caller_serial);
	/**
	 * @brief Call timer test existence, stop, start and reinitialize convenience functions
	 * @return NONE
	 */
	bool isTimerAvailable();
	void executeStopTimer();
	void executeStartTimer();
	void reinitializeTimer();
public:
	/**
	 * @brief Call a buddy
	 * @param[in] name Buddy name
	 * @return STATUS
	 */
	mp_status_t callBuddy(std::string const& name);
	/**
	 * @brief Add call callback
	 * @return STATUS
	 */
	void addCallCb(MpICall* call);
	/**
	 * @brief Remove call callback
	 * @return
	 */
	void rmCallCb(MpICall* call);
	/**
	 * @brief Answer call
	 * @param[in] call_answer_mode Call answer mode (Accept/Reject call,must be MP_ACCEPT_CALL or MP_REJECT_CALL)
	 * @return STATUS
	 */
	mp_status_t answerCall(mp_status_t call_answer_mode);

	/**
	 * @brief End call
	 * @return STATUS
	 */
	mp_status_t endCall();
    /**
     * @brief Reject an active call
     @return STATUS
     */
    void rejectCall();
	/**
	 * @brief Mute call
	 * @return STATUS
	 */
	mp_status_t muteCall();
	/**
	 * @brief Mute call
	 * @return STATUS
	 */
	mp_status_t unMuteCall();
	/**
	 * @brief Hold call
	 * @return STATUS
	 */
	mp_status_t holdCall();
	/**
	 * @brief Unhold call
	 * @return STATUS
	 */
	mp_status_t unHoldCall();
	/**
	 * @brief Set call timer
	 * @param[in] timer Call timer
	 * @return none
	 */
	void setCallTimer(MpICallTimer *timer);
	/**
	 * @brief Set key exchange
	 * @param[in] keyExchange Key exchange
	 * @return none
	 */
	void setKeyExchange(MpIKeyExchange * keyExchange);
	/**
	 * @brief End call (RTP watchdog inactivity)
	 * @return none
	 */
	void endWatchdogCall();
	/**
	 * @brief Set call timeout to do callback (avoid repeated callbacks)
	 * @return none
	 */
	void setDoCallback();

	/**
	 * @brief Enable RTP watchdog
	 * @return none
	 */
	void setRTPWatchdog();
    
    /**
     * @brief Get last answer mode
     * @return Last answer mode
     */
    int getLastAnswerMode() const { return lastAnswerMode_; }
    
    /**
     * @brief Get the number of active calls
     * @return Number of active calls
     */
    unsigned int getActiveCallCount();

	/**
	 * @brief Get last call buddy
	 * @return Last call buddy
	 */ 
	std::string getLastCallBuddy() const;

	/**
	 * @brief Set last call buddy
	 * @param[in] serial Last call serial
	 * @return none
	 */
	void setLastCallBuddy(const std::string& serial);
};

typedef MpSingleton<MpCallManager> MpCMSingleton;
#endif /* __MP_MANAGERCALL_H__ */
