#ifndef __MP_AUTORESENDENGINE_H__
#define __MP_AUTORESENDENGINE_H__

#include "MpSingleton.h"
#include "MpMsgPayload.h"
#include "MpRWLock.h"
#include "MpIDBConnector.h"
#include "MpMsgPool.h"
#include "MpIMsgTransport.h"
#include "MpIMsgTransportNotif.h"
#include "MpBuddy.h"
#include "MpIPresence.h"
#include "MpIPresenceList.h"
#include "MpISIPStack.h"
#include <deque>
#include <algorithm>
#include <map>

class MpAutoResendEngine: public MpIMsgTransportNotif, public MpIPresence {
	friend class MpSingleton<MpAutoResendEngine> ;
private:
	MpIMsgTransport* msgTransport_; /*Message transport*/
	MpISIPStack* sipStack_; /*SIP stack*/
	MpIPresenceList* presList_; /*Presence list*/
	std::deque<MpIDBConnector*> dbConnectors_; /*Database connectors*/
	std::map<std::string, MpMsgPool> userPool_; /*Users pool*/
	std::vector<std::string> priority_; /*A vector which gives the message sending priority*/
	MpLock dbConnLock_; /*Database connector list lock*/
	MpRWLock userPoolLock_; /*Messages pool lock*/
	bool started_; /*Engine is started*/
	MpLock startedLock_; /*Started lock*/
	bool autoResendEnabled_; /*auto resend messages flag; this is available only for ARM_TYPE_MESSAGE*/
	/**
	 * @brief Sort messages pool (by user weight)
	 * @return none
	 */
	void sortMessages();
	/**
	 * @brief Weight sort comparator
	 * @param[in] p1 Serial 1
	 * @param[in] p2 Serial 2
	 * @return Comparison status
	 *
	 */
	bool weightSortCmp(const std::string& p1, const std::string& p2);
	/**
	 * @brief Send message from pool
	 * @return none
	 */
	void sendMessage();
	/**
	 * @brief Add a message
	 * @param[in] message Message
	 * @return none
	 */
	void addMessageInternal(MpMsgPayload const& message);
	/**
	 * @brief Starts engine if necessary
	 * @return none
	 */
	void startEngine();
	/**
	 * @brief Mark a user pool as processed
	 * @param[in] userPool User pool
	 * return none
	 */
	void markUserPoolProcessed(MpMsgPool& userPool);
	/**
	 * @brief Mark a user pool as clean
	 * @param[in] userPool User pool
	 * @return none
	 */
	void markUserPoolAsClean(MpMsgPool& userPool);
public:
	/**
	 * @brief Ctor
	 * @param[in] presList Presence list
	 * @return none
	 */
	MpAutoResendEngine();
	/**
	 * @brief Dtor
	 * @return none
	 */
	~MpAutoResendEngine();
	/**
	 * @brief Set message transport
	 * @return none
	 */
	inline void setMsgTransport(MpIMsgTransport* msgTransport) {
		msgTransport_ = msgTransport;
		/*Set message notifier callback*/
		msgTransport_->setMsgTransportNotif(this);
	}
	/**
	 * @brief Get message transport
	 * @return Message transport
	 */
	MpIMsgTransport* getMsgTransport() const {
		return msgTransport_;
	}
	/**
	 * @brief Set presence List
	 * @param[in] presList Presence list
	 * @return none
	 */
	void setPresList(MpIPresenceList* presList) {
		presList_ = presList;
	}
	/**
	 * @brief Get presence list
	 * @return Presence list
	 */
	MpIPresenceList* getPresList() const {
		return presList_;
	}
	/**
	 * @brief Add a database connector
	 * @param[in] dbConn Database connector
	 * @return none
	 */
	void addDBConnector(MpIDBConnector* dbConn);
	/**
	 * @brief Sync the engine with the database info (provided by the connectors).
	 * @return none
	 */
	void syncWithDBConnectors();
	/**
	 * @brief Add a message. This function adds a message and starts the engine if necessary.
	 * @param[in] message Message
	 * @return none
	 */
	void addMessage(MpMsgPayload const& message);
	/**
	 * @brief Message SIP xfer status
	 * @param[in] message Pointer to the transmitted message
	 * @param[in] status SIP xfer status
	 * @return none
	 */
	void messageStatus(const MpMsgPayload& message, mp_status_t status);
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
	/**
	 * @brief Test if an SMS message is processing (for manual retry UI)
	 * @param[in] serial Message receiver serial (FIXME should be available in the UI)
	 * @param[in] msgObject Message DB Object
	 * @return TRUE if message is in the engine's queue
	 */
	bool isMessageProcessing(std::string const& serial, int uid_);
	/**
	 * @brief Remove all messages for the specified receiver serial. This function removes also the current message if necessary
	 * @param[in] serial Messages receiver serial
	 * @return none
	 */
	void removeMessagesForSerial(std::string const& serial);
	/**
	 * @brief Set autoResend messages option. If new option is TRUE and previous FALSE, the engine will be started
	 * @param[in] autoResendEnabled autoResendEnabled option
	 */
	void setAutoResendEnabled(bool autoResendEnabled);

	/**
	 * @brief Get autoResend messages option
	 * @return autoResendEnabled
	 */
	bool isAutoResendEnabled() const {
		return autoResendEnabled_;
	}
	/**
	 * @brief Resend a message. This function prioritize a user queue, marks message as unprocessed, and starts the engine if necessary.
	 * @param[in] serial Message receiver serial
	 * @param[in] msgId Message ID
	 * @return FALSE if message with given object was not found, TRUE otherwise
	 */
	bool resendMessage(std::string const& serial, int msgId);
	/**
	 * @brief Set SIP stack
	 * @param[in] sipStack SIP stack
	 * @return none
	 */
	void setSIPStack(MpISIPStack* sipStack) {
		sipStack_ = sipStack;
	}
};

typedef MpSingleton<MpAutoResendEngine> MpAutoResendSingl;

#endif /* __MP_AUTORESENDENGINE_H__ */
