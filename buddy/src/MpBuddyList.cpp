#include "MpBuddyList.h"
#include "MpBaseService.h"
#include "pjsua.h"
#include <iostream>
#include <algorithm>

MpBuddyList::MpBuddyList() :
		lock_("MpBuddyList"), presenceCb_("MpBuddyList_PRESENCE_LOCK"), sipStack_(
				0) {
	MP_LOG1("Ctor");
}

MpBuddyList::~MpBuddyList() {
	MP_LOG1("Dtor");
}

mp_status_t MpBuddyList::addBuddy(MpBuddy &buddy) {
	MP_LOG3("Adding buddy", buddy.getBuddySerial().c_str(), "...");
	assert(sipStack_ != 0);
	lock_.lock();

	if (serialIsValid(buddy.getBuddySerial().c_str()) == false) {
		MP_LOG3("Invalid serial", buddy.getBuddySerial().c_str(), "!!!");
		lock_.unlock();
		return MP_GENERAL_ERR;
	}

	/*Do not allow duplicates*/
	if (buddyList_.find(buddy.getBuddySerial()) != buddyList_.end()) {
		MP_LOG3("Duplicate serial", buddy.getBuddySerial().c_str(), "!!!");
		lock_.unlock();
		return MP_GENERAL_ERR;
	}

	mp_status_t status = sipStack_->subscribe(buddy);

	if (status == MP_SUCCESS) {
		buddyList_.insert(
				std::pair<std::string, MpBuddy>(buddy.getBuddySerial(), buddy));
	} else {
		MP_LOG1("PJSUA error occured. Buddy was deleted from list. Call this function again.");
	}
	lock_.unlock();

	return status;
}

mp_status_t MpBuddyList::rmBuddy(std::string const& serial) {
	MP_LOG3("Removing buddy", serial.c_str(), "...");
	assert(sipStack_ != 0);
	mp_status_t status = MP_GENERAL_ERR;
	lock_.lock();
	std::map<std::string, MpBuddy>::iterator it = buddyList_.find(serial);
	/*If user not found*/
	if (it == buddyList_.end()) {
		lock_.unlock();
		return MP_SUCCESS;
	}
	status = sipStack_->unsubscribe((*it).second.getBuddyID());
	if (status == MP_SUCCESS)
		buddyList_.erase(it);
	MP_LOG1("Buddy not found...");
	lock_.unlock();

	return status;
}

void MpBuddyList::buddy_state(pjsua_buddy_id buddy_id) {
	lock_.lock();
	/*lock cb pool*/
	presenceCb_.usePool();
	MP_LOG1("Buddy presence state changed...");

	std::map<std::string, MpBuddy>::iterator ind = buddyList_.begin();
	for (; ind != buddyList_.end(); ind++)
		if ((*ind).second.getBuddyID() == buddy_id)
			break;

	if (ind == buddyList_.end()) {
		presenceCb_.endUsePool();
		lock_.unlock();
		return;
	}
	MpBuddy& buddy = (*ind).second;

	/*Get presence cb pool*/
	vector<MpIPresence*> presCb = presenceCb_.getPool();
	vector<MpIPresence*>::iterator it = presCb.begin();

	/*Set buddy status*/
	pjsua_buddy_info info;
	pjsua_buddy_get_info(buddy_id, &info);
	buddy.setState(
			info.status == PJSUA_BUDDY_STATUS_ONLINE ?
					MP_BUDDY_ONLINE : MP_BUDDY_OFFLINE);

	for (; it < presCb.end(); ++it) {
		MP_LOG1("Callback found. Calling now...");
		(*it)->buddy_state(buddy_id);
		(*it)->buddy_state2(buddy);
	}
	/*release cb pool (read unlock)*/
	presenceCb_.endUsePool();
	lock_.unlock();
}

mp_status_t MpBuddyList::addPresenceCb(MpIPresence* presCb) {
	MP_LOG1("Adding presence callback...");
	presenceCb_.addPoolData(presCb);
	return MP_SUCCESS;
}

mp_status_t MpBuddyList::rmPresenceCb(MpIPresence* presCb) {
	MP_LOG1("Removing presence callback...");
	presenceCb_.rmPoolData(presCb);
	return MP_SUCCESS;
}

MpBuddy MpBuddyList::getBuddy(std::string const& serial) {
	MpBuddy buddy("");

	lock_.lock();
	std::map<std::string, MpBuddy>::iterator it = buddyList_.find(serial);
	if (it != buddyList_.end())
		buddy = (*it).second;
	lock_.unlock();

	return buddy;
}

std::string MpBuddyList::getBuddyUri(std::string const& serial) {
	MP_LOG1("Get buddy uri...");
	std::string uri = "";
	lock_.lock();

	std::map<std::string, MpBuddy>::iterator it = buddyList_.find(serial);
	if (it != buddyList_.end())
		uri = (*it).second.getBuddyUri();

	lock_.unlock();

	return uri;
}

bool MpBuddyList::isUserOnline(std::string const& serial) {
	MP_LOG1("Ask if user is online");
	bool online = false;
	lock_.lock();
	std::map<std::string, MpBuddy>::iterator it = buddyList_.find(serial);
	if (it == buddyList_.end()) {
		MP_LOG1("User not found");
		lock_.unlock();
		return false;
	}

	online = (*it).second.getState() == MP_BUDDY_ONLINE ? true : false;
	lock_.unlock();

	return online;
}

std::list<std::string> MpBuddyList::getOnlineUris() {
	std::list<std::string> onlineUris;
	// TODO get uri from serial and add it to list
	return onlineUris;
}

bool MpBuddyList::serialIsValid(std::string const& serial) {
	for (uint32_t i = 0; i < serial.length(); i++)
		if (!isalnum(serial.at(i)) && serial.at(i) != '_')
			return false;

	return true;
}

void MpBuddyList::reset() {
	MP_LOG1("Reset buddy list...");
	lock_.lock();
	buddyList_.clear();
	lock_.unlock();
}
