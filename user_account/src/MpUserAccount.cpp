#include "MpUserAccount.h"
#include "MpBaseService.h"

MpUserAccount::MpUserAccount() :
		lock_(MP_USER_ACCOUNT_LOCK), reqStatus_(MP_OFFLINE), accSettings_("",
				0, "", 0, MP_NETWORK_UNREACHABLE, true, "", ""), regCb_(
				"MpUserAccount_REG_LOCK") {
	MP_LOG1("Ctor");
}

MpUserAccount::~MpUserAccount() {
	MP_LOG1("Dtor");
}

void MpUserAccount::registration_state(mp_status_t status) {
	regCb_.usePool();
	MP_LOG1("Registration status received");

	mp_online_state_t userStatus =
			status == MP_SUCCESS ? reqStatus_ : MP_OFFLINE;
	vector<MpIRegistration*> rCList = regCb_.getPool();
	vector<MpIRegistration*>::iterator it = rCList.begin();
	for (; it < rCList.end(); ++it) {
		MP_LOG1("Calling callback registration_state");
		(*it)->registration_state(userStatus);
	}
	regCb_.endUsePool();
}

mp_status_t MpUserAccount::authenticate(const char* pin,
		mp_crypto_elem_type_t type) {
	return MP_SUCCESS;
}

mp_status_t MpUserAccount::deauthenticate() {
	return MP_SUCCESS;
}

mp_status_t MpUserAccount::login(MpAccSettings const& accSettings) {

	reqStatus_ = MP_ONLINE;

	/*Start SIP stack and login*/
	mp_status_t status = MpService::instance()->getSIPStack()->startSIPStack(
			accSettings);
	if (status != MP_SUCCESS) {
		MP_LOG1("Start SIP stack error");
	} else {
		accSettings_ = accSettings;
	}

	serial_ = accSettings.getUserName();

	return status;
}

mp_status_t MpUserAccount::logout() {
	reqStatus_ = MP_OFFLINE;
	/*Logout and then stop SIP stack*/
	mp_status_t status = MpService::instance()->getSIPStack()->stopSIPStack();

	registration_state(status);

	return status;
}

mp_status_t MpUserAccount::addRegCallback(MpIRegistration* reg) {
	MP_LOG1("Add registration callback");
	MP_CHECK_INPUT(reg != MP_NULL, MP_INPUT_ERR);
	regCb_.addPoolData(reg);

	return MP_SUCCESS;

}

mp_status_t MpUserAccount::rmRegCallback(MpIRegistration* reg) {
	lock_.lock();
	MP_LOG1("Remove registration callback");
	MP_CHECK_INPUT(reg != MP_NULL, MP_INPUT_ERR);
	regCb_.rmPoolData(reg);

	return MP_SUCCESS;
}

mp_status_t MpUserAccount::setOnline(bool online) {
    return MpService::instance()->getSIPStack()->setOnline(online);
}

std::string MpUserAccount::getSerial() const {
	return serial_;
}

mp_status_t MpUserAccount::forceReregistration() {
    MP_LOG1("Force re-registration");
    
    // Setează offline și apoi online pentru a forța re-înregistrarea
    mp_status_t status = MpService::instance()->getSIPStack()->setOnline(false);
    if (status != MP_SUCCESS) {
        return status;
    }
    
    // Așteaptă puțin pentru a permite dezactivarea
    pj_thread_sleep(100);
    
    // Setează online pentru a forța re-înregistrarea
    status = MpService::instance()->getSIPStack()->setOnline(true);
    if (status != MP_SUCCESS) {
        return status;
    }
    
    return MP_SUCCESS;
}
