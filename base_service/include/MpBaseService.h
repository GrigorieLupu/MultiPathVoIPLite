#ifndef __MP_BS_H__
#define __MP_BS_H__

#include "MpSIPStack.h"
#include "MpSingleton.h"
#include "MpLogger.h"
#include "MpStatus.h"
#include "MpUserAccount.h"
#include "MpBuddyList.h"
#include "MpMsgManager.h"
#include "MpMsgTransport.h"
#include "MpAutoResendEngine.h"

#if MP_DEBUG == 1
#define MP_LOG1(msg) \
	(MpLoggerSingleton::instance()->print(MP_FILE_NAME, __FUNCTION__, msg))
#define MP_LOG1_INT(msg) \
	do { \
		char message[MP_BUFF_SIZE] = {0}; \
		snprintf(message, sizeof(message),"%d", msg); \
		MP_LOG1(message); \
	} while(0)
#define MP_LOG2(msg1, msg2) \
	do { \
	char message[MP_BUFF_SIZE] = {0}; \
	snprintf(message, sizeof(message),"%s %s", msg1, msg2); \
	MP_LOG1(message); \
	} while(0)
#define MP_LOG2_INT(msg1, msg2) \
	do { \
		char message[MP_BUFF_SIZE] = {0}; \
		snprintf(message, sizeof(message),"%s %d", msg1, msg2); \
		MP_LOG1(message); \
	} while(0)
#define MP_LOG2_ADDR(msg1, msg2) \
	do { \
		char message[MP_BUFF_SIZE] = {0}; \
		snprintf(message, sizeof(message),"%s %p", msg1, &msg2); \
		MP_LOG1(message); \
	} while(0)
#define MP_LOG2_HEX(msg1, msg2, msg2Len) \
	do { \
		char message[MP_BUFF_SIZE] = {0}; \
		snprintf(message, sizeof(message),"%s", msg1); \
		for(int i = 0; i < msg2Len; ++i) { \
			snprintf(message + strlen(message), sizeof(message) - strlen(message), "%02X", msg2[i]); \
		} \
		MP_LOG1(message); \
	} while(0)
#define MP_LOG3(msg1, msg2, msg3) \
	do { \
	char message[MP_BUFF_SIZE] = {0}; \
	snprintf(message, sizeof(message),"%s %s %s", msg1, msg2, msg3); \
	MP_LOG1(message); \
	} while(0)
#else
#define MP_LOG1(msg)
#define MP_LOG1_INT(msg)
#define MP_LOG2(msg1, msg2)
#define MP_LOG2_INT(msg1, msg2)
#define MP_LOG2_ADDR(msg1, msg2)
#define MP_LOG2_HEX(msg1, msg2, msg2Len)
#define MP_LOG3(msg1, msg2, msg3)
#endif

class MpBaseService {
	friend class MpSingleton<MpBaseService> ;
private:
	/**
	 * @brief Ctor
	 * @return NONE
	 */
	MpBaseService();
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	~MpBaseService();
public:
	/**
	 * @brief Get logger
	 * @return Logger
	 */
	MpLogger* getLogger() {
		return MpLoggerSingleton::instance();
	}
	/**
	 * @brief Get SIP stack
	 * @return SIP stack
	 */
	MpSIPStack* getSIPStack() {
		return MpSIPStackSingleton::instance();
	}
	/**
	 * @brief Get User account
	 * @return User account
	 */
	MpUserAccount* getUserAccount() {
		return MpUserAccountSingleton::instance();
	}
	/**
	 * @brief Get Buddy list
	 * @return Buddy list
	 */
	MpBuddyList* getBuddyList() {
		return MpBLSingleton::instance();
	}
	/**
	 * @brief Get Call manager
	 * @return Call manager
	 */
	MpCallManager* getCallManager() {
		return MpCMSingleton::instance();
	}

	/**
	 * @brief Get Data msg
	 * @return Data msg
	 */
	MpMsgManager* getDataMsg() {
		return MpDMSingleton::instance();
	}
	/**
	 * @brief Get Message transport manager
	 * @return Transport manager
	 */
	MpMsgTransport* getMsgTransport() {
		return MpMTranSingl::instance();
	}
	/**
	 * @brief Get Auto resend engine
	 * @return Auto resend engine
	 */
	MpAutoResendEngine* getAutoResend() {
		return MpAutoResendSingl::instance();
	}
};

typedef MpSingleton<MpBaseService> MpService;

#endif /* __MP_BS_H__ */
