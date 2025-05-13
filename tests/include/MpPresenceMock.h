#ifndef __MP_PRESENCE_MOCK_H__
#define __MP_PRESENCE_MOCK_H__

#include "MpIPresence.h"

class MpPresenceMock: public MpIPresence {
public:
	bool buddyStateCalled;
	bool buddyState2Called;
	void buddy_state(pjsua_buddy_id buddy_id) {
		buddyStateCalled = true;
	}
	void buddy_state2(const MpBuddy& buddy) {
		buddyState2Called = true;
	}
};

#endif /* __MP_PRESENCE_MOCK_H__ */
