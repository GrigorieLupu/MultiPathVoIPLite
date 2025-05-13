#ifndef __MP_SIP_STACK_MOCK_H__
#define __MP_SIP_STACK_MOCK_H__

#include "MpISIPStack.h"

class MpSIPStackMock: public MpISIPStack {
private:
	mp_status_t subscribeStatus;
	mp_status_t unsubscribeStatus;
public:
	void setSubscribeStatus(mp_status_t status) {
		subscribeStatus = status;
	}
	void setUnsubscribeStatus(mp_status_t status) {
		unsubscribeStatus = status;
	}
	mp_status_t subscribe(MpBuddy& buddy) {
		return subscribeStatus;
	}
	mp_status_t unsubscribe(pjsua_buddy_id buddy_id) {
		return unsubscribeStatus;
	}
	bool isSipStackStarted() {
		return true;
	}
};

#endif
