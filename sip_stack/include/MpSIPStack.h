#ifndef __MP_SIPSTACK_H__
#define __MP_SIPSTACK_H__

#include "MpLock.h"
#include "MpSingleton.h"
#include "MpStatus.h"
#include "MpAccSettings.h"
#include "MpBuffer.h"
#include "MpBuddyList.h"
#include "MpCallManager.h"
#include "MpISIPStack.h"
#include "IOobKeySetup.h"
#include <pjsua-lib/pjsua.h>

class MpSIPStack: public MpISIPStack {
	friend class MpSingleton<MpSIPStack> ;
	friend class MpUserAccount;
	friend class MpBuddyList;
	friend class MpCallManager;
	friend class MpMsgManager;
private:
	MpLock lock_;
	bool started_; ///< SIP started or not
	pjsua_acc_id acc_id_; ///< pjsip accound ID
	/*Properties needed for the hold process*/
	int captureDevice;
	int playbackDevice;
	static MpPool<IOobKeySetup> oobKeyCb_;
	/**
	 * @brief Ctor
	 * @return NONE
	 */
	MpSIPStack();
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	~MpSIPStack();
	/**
	 * @brief PJSIP callback (registration state)
	 * @param[in] acc_id Account ID
	 * @return NONE
	 */
	static void on_reg_state(pjsua_acc_id acc_id);

	/**
	 * @brief PJSIP callback (buddy presence state)
	 * @param[in] buddy_id Buddy id
	 * @return NONE
	 */
	static void on_buddy_state(pjsua_buddy_id buddy_id);
	/**
	 * @brief PJSIP callback (call media state)
	 * @param[in] call_id Call id
	 * @return NONE
	 */
	static void on_call_media_state(pjsua_call_id call_id);
	/**
	 * @brief PJSIP callback (call state)
	 * @param[in] call_id Call id
	 * @param[in] e PJSIP event
	 * @return NONE
	 */
	static void on_call_state(pjsua_call_id call_id, pjsip_event *e);

	/**
	 * @brief PJSIP callback (incoming call)
	 * @param[in] acc_id Account id
	 * @param[in] call_id Call id
	 * @param[in] rdata Request data
	 * @return NONE
	 */
	static void on_incoming_call(pjsua_acc_id acc_id, pjsua_call_id call_id,
			pjsip_rx_data *rdata);

	/**
	 * @brief PJSIP callback (on new message received)
	 * @param[in] call_id Call id
	 * @param[in] from Message sender URI
	 * @param[in] to Message receiver URI
	 * @param[in] contact SIP contact
	 * @param[in] mime_type SIP MIME type
	 * @param[in] body Message body
	 * @return NONE
	 */
	static void on_pager(pjsua_call_id call_id, const pj_str_t *from,
			const pj_str_t *to, const pj_str_t *contact,
			const pj_str_t *mime_type, const pj_str_t *body);
	/**
	 * @brief PJSIP callback (on message sent status)
	 * @param[in] call_id Call id
	 * @param[in] to Receiver URI
	 * @param[in] body Message buddy
	 * @param[in] user_data Custom user data (message UID)
	 * @param[in] status SIP xfer status
	 * @param[in] reason SIP reason
	 */
	static void on_pager_status(pjsua_call_id call_id, const pj_str_t *to,
			const pj_str_t *body, void *user_data, pjsip_status_code status,
			const pj_str_t *reason);

	static int on_srtp_oob_key_and_id(char *key, int key_len, char *id, int max_id_len);
	static int on_srtp_oob_key_from_id(const char *id, int id_len, char *key, int key_len);
    
    static void on_log(int level, const char *data, int len);
    
	/**
	 * @brief Get SIP Account ID
	 * @return SIP Account ID
	 */
	pjsua_acc_id getAccountID() const {
		return acc_id_;
	}
	/**
	 * @brief Subscribe presence for buddy
	 * @param[in] buddy Buddy
	 * @return STATUS
	 */
	mp_status_t subscribe(MpBuddy& buddy);
	/**
	 * @brief Unsubscribe presence for buddy
	 * @param[in] buddy_id Pjsua buddy id
	 * @return STATUS
	 */
	mp_status_t unsubscribe(pjsua_buddy_id buddy_id);
	/**
	 * @brief Make a call
	 * @param[in] uri Uri
	 * @return STATUS
	 */
	mp_status_t call(char* uri);
	/**
	 * @brief Answer a call
	 * @param[in] call_id Call id
	 * @param[in] call_answer_mode Accept or reject call (values must be MP_ANSWER_CALL or MP_REJECT_CALL)
	 * @return STATUS
	 */
	mp_status_t answerCall(pjsua_call_id call_id,
			mp_status_t call_answer_mode);
	/**
	 * @brief End call
	 * @return STATUS
	 */
	mp_status_t endCall();
	/**
	 * @brief Reject call
	 * @param[in] call_id Call ID
	 * @return none
	 */
	void rejectCall(pjsua_call_id call_id);
	/**
	 * @brief Set TX call level
	 * @param[in] mute If true the call will be set on `mute` mode
	 * @return STATUS
	 */
	mp_status_t setRxCallLevel(bool mute);
	/**
	 * @brief Hold/unhold call
	 * @param[in] callId Call ID
	 * @param[in] hold If true call will be holded
	 * @return STATUS
	 */
	mp_status_t setHoldCall(pjsua_call_id callId, bool hold);
	/**
	 * @brief Sets SIP general configuration
	 * @param[in] logLevel Console log level
	 * @return STATUS
	 */
	pj_status_t setSIPGeneralConfig(uint32_t logLevel);

	/**
	 * @brief Sets SIP transport configuration
	 * @param[in] port port
	 * @param[in] certPath Certificate path
	 * @param[in] privPath Private key path
	 * @return STATUS
	 */
	pj_status_t setSIPTransportConfig(uint32_t port, std::string const& certPath,
			std::string const& privPath, bool verifyServer);

	/**
	 * @brief Sets SIP account configuration
	 * @param[in] accSettings Account settings object
	 * @return STATUS
	 */
	pj_status_t setSIPAccountConfig(MpAccSettings const& accSettings);
	
	/**
	 * @brief Set the codec priority in pjsip stack layer based on network state
	 * @param[in] networkState Network state
	 * @return STATUS
	 */
	pj_status_t setCodecsPriorities(mp_network_state_t networkState);

	/**
	 * @brief Get OOB key for buddy
	 * @param[in] buddy Buddy identity
	 * @param[out] key OOB key
	 * @param[in] keyLen Desired key length
	 * @return status
	 */
	static bool getOobKey(const std::string &buddy, char *key, int keyLen);
public:
    /**
	 * @brief Getter and Setter methods needed for the hold process
	 */
    static int onHold;
    int getCaptureDevice();
	int getPlaybackDevice();
	void setCaptureAndPlaybackDevices(int capture_dev, int playback_dev);
	/**
	 * @brief Turn on and off the sound devices stored
	 */
	void turnOffSoundDevices();
	void turnOnSoundDevices();
	/**
	 * @brief Start sip stack (THREAD SAFE)
	 * @return STATUS
	 */
	mp_status_t startSIPStack(MpAccSettings const& accSettingsf);
	/**
	 * @brief Stop SIP stack (THREAD SAFE)
	 * @return STATUS
	 */
	mp_status_t stopSIPStack();
	/**
	 * @bried Send message (this function is message type agnostic)
	 * @param[in] uri Receiver serial
	 * @param[in] msg Message data
	 * @param[in] msgLen Message data length
	 * @param[in] msgId Message id (database primary key recommended)
	 * @return STATUS
	 */
	mp_status_t sendMsg(const char* serial, const uint8_t* msg,
			uint32_t msgLen, void* msgId);
	
	/**
	 * @brief Check if sip stack is started
	 * @return started
	 */
	bool isSipStackStarted();
    
    /**
     * @brief Set user online/offline status (this method will send a SIP PUBLISH request)
     * @param[in] online TRUE if user will be online, FALSE otherwise
     * @return status
     */
    mp_status_t setOnline(bool online);

	/**
	 * @brief Add out-of-band key setup
	 * @param[in] oobKeySetup OOB key setup interface
	 * @return none 
	 */
	void addOobKeySetup(IOobKeySetup *oobKeySetup);
		
	/**
	 * @brief Delete out-of-band key setup
	 * @param[in] oobKeySetup OOB key setup interface
	 * @return none 
	 */
	void rmOobKeySetup(IOobKeySetup *oobKeySetup);

	mp_status_t resetSIPState();
};

typedef MpSingleton<MpSIPStack> MpSIPStackSingleton;

#endif /* __MP_SIPSTACK_H__ */
