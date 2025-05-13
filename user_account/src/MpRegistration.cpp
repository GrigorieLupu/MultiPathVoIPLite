#include "MpRegistration.h"
#include "MpBaseService.h"

#define THIS_TAG "MpRegistration"

MpRegistration::MpRegistration() {
	MP_LOG1("Ctor");
}

MpRegistration::~MpRegistration() {
}

void MpRegistration::registration_state(mp_online_state_t status) {
	if (status == MP_ONLINE) {
		MP_LOG1("Registration status ONLINE");
	} else if (status == MP_OFFLINE) {
		MP_LOG1("Registration status OFFLINE");
	} else {
		MP_LOG1("Registration status ERR");
	}
}
