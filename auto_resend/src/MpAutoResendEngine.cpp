

#include "MpAutoResendEngine.h"
#include "MpBaseService.h"
#include <iostream>
#include <climits>
#include <stdint.h>

MpAutoResendEngine::MpAutoResendEngine() :
		msgTransport_(0), sipStack_(0), presList_(0), dbConnLock_(
				"Database connector lock"), userPoolLock_("Msg pool RW lock"), started_(
				false), startedLock_("Started lock"), autoResendEnabled_(false) {
	MP_LOG1("Ctor");
}

MpAutoResendEngine::~MpAutoResendEngine() {
	MP_LOG1("Dtor");
}

void MpAutoResendEngine::addDBConnector(MpIDBConnector* dbConn) {
	MP_LOG1("Add a database connector");

	if (!dbConn)
		return;
	/*Add the connector to the internal list*/
	dbConnLock_.lock();
	dbConnectors_.push_back(dbConn);
	dbConnLock_.unlock();
}

void MpAutoResendEngine::addMessageInternal(MpMsgPayload const& message) {
	userPoolLock_.wLock();

	/*Search the pool entry corresponding to the message serial*/
	std::map<std::string, MpMsgPool>::iterator it;
	if ((it = userPool_.find(message.getUserSerial())) != userPool_.end()) {
		(*it).second.addMessage(message);
	} else {
		/*Entry was not found.Add it.*/
		userPool_.insert(
				std::pair<std::string, MpMsgPool>(message.getUserSerial(),
						message));
		priority_.push_back(message.getUserSerial());
		it = userPool_.find(message.getUserSerial());
	}
	/*Mark this user as clean for UX*/
	markUserPoolAsClean((*it).second);
	userPoolLock_.wUnlock();
}

void MpAutoResendEngine::addMessage(MpMsgPayload const& message) {
	MP_LOG1("Add a message to the message pool");
	addMessageInternal(message);

	/*Start engine if necessary*/
	startEngine();
}

void MpAutoResendEngine::syncWithDBConnectors() {
	MP_LOG1("Sync with DB connectors");
	dbConnLock_.lock();
	std::deque<MpIDBConnector*>::iterator it = dbConnectors_.begin();
	for (; it != dbConnectors_.end(); ++it) {
		/*Get messages from database([userSerial,message])*/
		const std::vector<MpMsgPayload>& messages = (*it)->getMessages();
		std::vector<MpMsgPayload>::const_iterator msgIt = messages.begin();
		for (; msgIt != messages.end(); ++msgIt)
			addMessageInternal(*msgIt);
		/*Move to next db connector*/
	}
	dbConnLock_.unlock();
}

bool MpAutoResendEngine::weightSortCmp(const std::string& p1,
		const std::string& p2) {
	std::map<std::string, MpMsgPool>::iterator pIt1 = userPool_.find(p1);
	std::map<std::string, MpMsgPool>::iterator pIt2 = userPool_.find(p2);

	if ((*pIt1).second.getWeight() > (*pIt2).second.getWeight())
		return true;

	return false;
}

void MpAutoResendEngine::sortMessages() {
	MP_LOG1("Sort messages by user weight");
	if (priority_.empty())
		return;
	bool swapped = true;
	while (swapped) {
		swapped = false;
		for (uint32_t i = 0; i < priority_.size() - 1; i++) {
			if (weightSortCmp(priority_[i], priority_[i + 1])) {
				std::string tmp = priority_[i];
				priority_[i] = priority_[i + 1];
				priority_[i + 1] = tmp;
				swapped = true;
			}
		}
	}
}

void MpAutoResendEngine::sendMessage() {
	MP_LOG1("Send message");
	userPoolLock_.wLock();
	/*Sort messages first (be fair and try to send the same number of messages for all users)*/
	sortMessages();

	/*Search the first online user from the pool and send its first message*/
	std::vector<std::string>::iterator it = priority_.begin();
	for (; it != priority_.end(); ++it) {
		std::map<std::string, MpMsgPool>::iterator pIt = userPool_.find(*it);
		/*If message not found in pool*/
		if (pIt == userPool_.end())
			continue;
		/*Test if pool is empty*/
		if ((*pIt).second.isPoolEmpty())
			continue;

		if (!(*pIt).second.isDirty()) {
			/*Send message now*/
			MP_LOG1("Send message to transport layer");
            
            const MpMsgPayload& message = (*pIt).second.getMessage(
                        autoResendEnabled_);
            if (message.getNumberOfRetries() <= 0)
                continue;
            msgTransport_->sendMessage(message);
            userPoolLock_.wUnlock();
			return;
		} else {
			markUserPoolProcessed((*pIt).second);
		}
	}
	userPoolLock_.wUnlock();
	/*No suitable pools. Stop for now and wait an external event.*/
	MP_LOG1("Stop engine");
	started_ = false;
}

void MpAutoResendEngine::markUserPoolProcessed(MpMsgPool& userPool) {
	std::deque<MpMsgPayload>& messages = userPool.getAllMessages();
	if (!messages.size())
		return;
	if (userPool.getWeight() == INT_MAX)
		return;
	std::deque<MpMsgPayload>::iterator it = messages.begin();
	for (; it != messages.end(); ++it) {
		/* Mark message as processed */
		(*it).markAsProcessed();

		/*Notify the db connectors*/
		dbConnLock_.lock();
		std::deque<MpIDBConnector*>::iterator itConn = dbConnectors_.begin();
		for (; itConn != dbConnectors_.end(); ++itConn) {
			if ((*itConn)->getMessageType() == (*it).getMessageType()) {
				(*itConn)->messageStatus((*it), MP_MESSAGE_NOT_SENT);
			}
		}
		dbConnLock_.unlock();
	}
	userPool.setWeight(INT_MAX);
}

void MpAutoResendEngine::messageStatus(const MpMsgPayload& message,
		mp_status_t status) {
	MP_LOG1("Message SIP xfer status callback");

	/*Notify the db connectors*/
	dbConnLock_.lock();
	std::deque<MpIDBConnector*>::iterator itConn = dbConnectors_.begin();
	for (; itConn != dbConnectors_.end(); ++itConn) {
		if ((*itConn)->getMessageType() == message.getMessageType()) {
			(*itConn)->messageStatus(message, status);
		}
	}
	dbConnLock_.unlock();

	/*If message was sent then delete it from the message pool*/
	userPoolLock_.wLock();
	std::map<std::string, MpMsgPool>::iterator it = userPool_.find(
			message.getUserSerial());
	/*If message found in pool*/
	if (it != userPool_.end()) {
		/*Mark message as processed*/
		(*it).second.markMsgAsProcessed(message.getUID());
		if (status == MP_MESSAGE_SENT) {
			/*Remove message from pool*/
			(*it).second.rmMessage(message.getUID());
			/*If pool entry has no more messages then remove it*/
			if (!(*it).second.getUnsentMsgNumber()) {
				/*Remove pool from priority vector*/
				for (std::vector<std::string>::iterator pIt = priority_.begin();
						pIt != priority_.end(); pIt++) {
					if ((*pIt) == (*it).first) {
						priority_.erase(pIt);
						break;
					}
				}
				userPool_.erase(it);
			} else {
				MP_LOG1("Increment weight");
				/*Increment weight for this pool*/
				(*it).second.setWeight((*it).second.getWeight() + 1);
			}
		} else {
			/*If peer is unreachable mark pool as dirty. And try when the peer is online again.*/
			(*it).second.markAsDirty();
			markUserPoolProcessed(((*it).second));
		}
	}
	userPoolLock_.wUnlock();

	/*Try to send another message*/
	startedLock_.lock();
	sendMessage();
	startedLock_.unlock();
}

void MpAutoResendEngine::buddy_state(pjsua_buddy_id buddy_id) {
	/*We don't care about this here*/
}

void MpAutoResendEngine::markUserPoolAsClean(MpMsgPool& userPool) {
	/*Probably this user has (or will have when will be online) a good connection*/
	userPool.setWeight(0);
	/*Mark pool as clean*/
	userPool.markAsClean();

    if (!isAutoResendEnabled()) {
        return;
	}
	
	std::deque<MpMsgPayload>& messages = userPool.getAllMessages();
	std::deque<MpMsgPayload>::iterator mIt = messages.begin();
    for (; mIt != messages.end(); mIt++) {
        (*mIt).markAsUnProcessed();
    }
}

void MpAutoResendEngine::buddy_state2(const MpBuddy& buddy) {
	MP_LOG1("Buddy state changed");
	userPoolLock_.wLock();
	std::map<std::string, MpMsgPool>::iterator it;
	if ((it = userPool_.find(buddy.getBuddySerial())) == userPool_.end()) {
		userPoolLock_.wUnlock();
		return;
	}
	if (buddy.getState() == MP_BUDDY_ONLINE) {
		MP_LOG1("Activating pool");
		markUserPoolAsClean((*it).second);
		userPoolLock_.wUnlock();
		startEngine();
		return;
	}
	userPoolLock_.wUnlock();
}

bool MpAutoResendEngine::isMessageProcessing(std::string const& serial,
		int uid_) {
	bool processing = false;

	userPoolLock_.rLock();
	std::map<std::string, MpMsgPool>::iterator it;
	if ((it = userPool_.find(serial)) != userPool_.end())
		processing = !(*it).second.getProcessedStatusAt(uid_);
	userPoolLock_.rUnlock();

	return processing;
}

void MpAutoResendEngine::removeMessagesForSerial(std::string const& serial) {
	assert(msgTransport_);
	if (msgTransport_)
		msgTransport_->removeMessageForSerial(serial);

	userPoolLock_.wLock();
	std::map<std::string, MpMsgPool>::iterator it;
	if ((it = userPool_.find(serial)) != userPool_.end())
		userPool_.erase(it);
	userPoolLock_.wUnlock();
}

void MpAutoResendEngine::startEngine() {
	/* Check if sip stack started */
	assert(sipStack_);
	if (!sipStack_->isSipStackStarted())
		return;
	startedLock_.lock();
	if (!started_) {
		MP_LOG1("Start engine");
		started_ = true;
		sendMessage();
	}
	startedLock_.unlock();
}

void MpAutoResendEngine::setAutoResendEnabled(bool autoResendEnabled) {
	bool startEng = (autoResendEnabled_ == false)
			&& (autoResendEnabled == true);

	startedLock_.lock();
	autoResendEnabled_ = autoResendEnabled;
	startedLock_.unlock();

	if (startEng)
		startEngine();
}

bool MpAutoResendEngine::resendMessage(std::string const& serial, int msgId) {
	int index = -1;
	userPoolLock_.wLock();
	/*Search for message in user pool*/
	std::map<std::string, MpMsgPool>::iterator it;
	if ((it = userPool_.find(serial)) != userPool_.end())
		index = (*it).second.getIndexForUID(msgId);
	/*Message not found -> return*/
	if (-1 == index) {
		userPoolLock_.wUnlock();
		return false;
	}
	/*Mark message as unprocessed*/
	(*it).second.markMsgAsUnprocessed(msgId);
	(*it).second.markAsClean();
	/*Prioritize user pool - set weight 0*/
	it = userPool_.begin();
	for (; it != userPool_.end(); it++)
		if ((*it).first == serial)
			(*it).second.setWeight(0);
		else
			(*it).second.setWeight((*it).second.getWeight() + 1);
	userPoolLock_.wUnlock();

	startEngine();

	return true;
}
