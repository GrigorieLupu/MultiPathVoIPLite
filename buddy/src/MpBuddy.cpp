#include "MpBuddy.h"
#include "MpBaseService.h"

MpBuddy::MpBuddy(std::string const& serial) :
		serial_(serial), state_(MP_BUDDY_OFFLINE), pjsuaId_(-1) {
	MP_LOG2("Creating buddy", serial_.c_str());
}

MpBuddy::~MpBuddy() {
	MP_LOG2("Destroying buddy", serial_.c_str());
}

MpBuddy::MpBuddy(const MpBuddy& buddy) {
	this->serial_ = buddy.getBuddySerial();
	this->state_ = buddy.getState();
	this->pjsuaId_ = buddy.getBuddyID();
}

MpBuddy& MpBuddy::operator=(const MpBuddy& buddy) {
	if (this == &buddy)
		return *this;

	this->serial_ = buddy.getBuddySerial();
	this->state_ = buddy.getState();
	this->pjsuaId_ = buddy.getBuddyID();

	return *this;
}

std::string MpBuddy::getBuddyUri() const {
	return MpUtils::getUriFromSerial(getBuddySerial().c_str(),
			MpService::instance()->getUserAccount()->accSettings_.getServerAddress().c_str(),
			MpService::instance()->getUserAccount()->accSettings_.getPort());
}

