

#include "MpMsgPool.h"
#include "MpBaseService.h"

/*Assign an initial weight greater than the recently online weight(0) -> give priority to the recent online users.*/
MpMsgPool::MpMsgPool(MpMsgPayload const& message) :
		weight_(1), mutableWeight_(true), dirty_(false) {
	MP_LOG1("Ctor");
	messages_.push_back(message);
}

MpMsgPool::~MpMsgPool() {
}

void MpMsgPool::addMessage(MpMsgPayload const& message) {
	MP_LOG1("Add message");
	messages_.push_back(message);
}

const MpMsgPayload MpMsgPool::getMessage(bool autoResendEnabled) {
	MP_LOG1("Get message");
	/*Peek the first message*/
	if (autoResendEnabled) {
		return messages_.front(); // modified reference - BAD_EXA_ACCESS - at send invitation after it already has invitation request ... at first message send after invited .. <<<<if it crashes when he accepts my invite, it will crash at first message>>>>
	} else {
		/*If the user message settings are set to manually then we deliver only invitations and unprocessed messages*/
		std::deque<MpMsgPayload>::iterator it = messages_.begin();
		for (; it != messages_.end(); ++it) {
			if ((*it).getMessageType() != MP_TYPE_MESSAGE) {
				return (*it);
			} else if (!(*it).isMessageProcessed()) {
				return (*it);
			}
		}
	}

	return MpMsgPayload("", MpBuffer(), 0, 0, 0, MP_TYPE_MESSAGE, false);
}
void MpMsgPool::rmMessage(int msgId) {
	MP_LOG1("Delete message");
	std::deque<MpMsgPayload>::iterator it = messages_.begin();
	for (; it != messages_.end(); ++it) {
		if ((*it).getUID() == msgId) {
			messages_.erase(it);
			break;
		}
	}
}

bool MpMsgPool::isMessageAdded(int msgId) {
	std::deque<MpMsgPayload>::iterator it = messages_.begin();
	for (; it != messages_.end(); ++it) {
		if ((*it).getUID() == msgId) {
			return true;
		}
	}

	return false;
}

int MpMsgPool::getIndexForUID(int msgUID) {
	int index = -1;
	std::deque<MpMsgPayload>::iterator it = messages_.begin();
	for (int i = 0; it != messages_.end(); it++, i++) {
		if ((*it).getUID() == msgUID) {
			index = i;
			break;
		}
	}

	return index;
}

bool MpMsgPool::getProcessedStatusAt(int msgUID) {
	bool processed = false;
	int index = getIndexForUID(msgUID);
	if (-1 == index)
		return false;

	processed = messages_.at(index).isMessageProcessed();

	return processed;
}

bool MpMsgPool::isPoolEmpty() {
	return messages_.empty();
}

void MpMsgPool::markMsgAsUnprocessed(int msgUID) {
	int index = getIndexForUID(msgUID);
	if (-1 == index)
		return;
	messages_.at(index).markAsUnProcessed();
}

void MpMsgPool::markMsgAsProcessed(int msgUID) {
	int index = getIndexForUID(msgUID);
	if (-1 == index)
		return;
	messages_.at(index).markAsProcessed();
}
