#include "MpPresence.h"
#include "MpBaseService.h"

MpPresence::MpPresence() {
	MP_LOG1("Ctor");
}

MpPresence::~MpPresence() {
	MP_LOG1("Dtor");
}

void MpPresence::buddy_state(pjsua_buddy_id buddy_id) {
	MP_LOG1("Buddy presence state changed...");
}

void MpPresence::buddy_state2(const MpBuddy& buddy) {
	MP_LOG1("Buddy presence state changed...");

	std::stringstream ss;
	ss << "Buddy name " << buddy.getBuddySerial().c_str()
			<< (buddy.getState() == MP_BUDDY_ONLINE ? " ONLINE" : " OFFLINE");
	MP_LOG1((ss.str()).c_str());
}
