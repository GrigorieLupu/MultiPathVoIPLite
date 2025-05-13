#ifndef __MP_USERACCOUNT_H__
#define __MP_USERACCOUNT_H__

#include "MpLock.h"
#include "MpSingleton.h"
#include "MpConfig.h"
#include "MpStatus.h"
#include "MpIRegistration.h"
#include "MpAccSettings.h"
#include "MpPool.h"
#include <vector>
#include <iterator>

using namespace std;

#define MP_USER_ACCOUNT_LOCK "MP_USER_ACCOUNT_LOCK"

typedef enum {
	MP_SW_CRYPTO_ELEM = 0, ///< PKCS#12
} mp_crypto_elem_type_t;

class MpUserAccount {
	friend class MpSingleton<MpUserAccount> ;
	friend class MpSIPStack;
	friend class MpBuddy;
	friend class MpMsgManager;
private:
	MpLock lock_; ///< User account lock
	mp_online_state_t reqStatus_; ///< Last server status request
	MpAccSettings accSettings_; ///< Account settings
	MpPool<MpIRegistration> regCb_; ///< Registration callback vector
	std::string serial_; ///< Own serial

	/**
	 * @brief Ctor
	 * @return NONE
	 */
	MpUserAccount();
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	~MpUserAccount();
	/**
	 * @brief Copy Ctor
	 * @return NONE
	 */
	MpUserAccount(MpUserAccount const&);
	/**
	 * @brief Operator =
	 * @return MpUserAccount reference
	 */
	MpUserAccount& operator=(MpUserAccount const&);
	/**
	 * @brief Registration state callback
	 * @param[in] status Can be MP_STATUS_ONLINE, MP_STATUS_OFFLINE or MP_STATUS_ERR
	 * @return NONE
	 */
	void registration_state(mp_status_t status);
public:
	/**
	 * @brief Authenticate to cryptografic element (SW/HW) (THREAD SAFE)
	 * @param[in] pin Pin
	 * @param[out] type Crypto type (SW/HW)
	 * @return STATUS
	 */
	mp_status_t authenticate(const char* pin, mp_crypto_elem_type_t type);
	/**
	 * @brief Deauthenticate from cryptografic element (SW/HW) (THREAD SAFE)
	 * @return STATUS
	 */
	mp_status_t deauthenticate();
	/**
	 * @brief Login to SIP server (THREAD SAFE)
	 * @param[in] accSettings Account settings
	 * @return STATUS
	 */
	mp_status_t login(MpAccSettings const& accSettings);
	/**
	 * @brief Logout from SIP server (THREAD SAFE)
	 * @return STATUS
	 */
	mp_status_t logout();

	/**
	 * @brief Add registration callback
	 * @param[in] reg Registration callback [MpUserAccount stores only a copy of reg,it will not destroy it] (THREAD SAFE)
	 * @return STATUS
	 */
	mp_status_t addRegCallback(MpIRegistration* reg);
	
    /**
	 * @brief Remove registration callback
	 * @param[in] reg Registration callback [MpUserAccount stores only a copy of reg,it will not destroy it] (THREAD SAFE)
	 * @return STATUS
	 */
	mp_status_t rmRegCallback(MpIRegistration* reg);
    
    /**
     * @brief Set user online/offline status (this method will send a SIP PUBLISH request)
     * @param[in] online TRUE if user will be online, FALSE otherwise
     * @return status
     */
    mp_status_t setOnline(bool online);

	/**
	 * @brief Get own serial
	 * @return Serial
	 */
	std::string getSerial() const;

	    /**
     * @brief Forțează re-înregistrarea contului SIP
     * @return STATUS
     */
	 mp_status_t forceReregistration();
};

typedef MpSingleton<MpUserAccount> MpUserAccountSingleton;
#endif /* __MP_USERACCOUNT_H__ */
