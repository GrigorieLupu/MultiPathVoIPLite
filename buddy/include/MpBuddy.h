#ifndef __MP_BUDDY_H__
#define __MP_BUDDY_H__

#include "MpBuffer.h"
#include "MpStatus.h"
#include "pjsua.h"

typedef enum mp_buddy_online_status {
	MP_BUDDY_ONLINE,
	MP_BUDDY_OFFLINE
} mp_buddy_online_status_t;

class MpBuddy {
	friend class MpSIPStack;
private:
	std::string serial_; ///< Buddy SIP serial
	mp_buddy_online_status_t state_; ///< Buddy online state
	pjsua_buddy_id pjsuaId_; ///< pjsua buddy id
public:
	/**
	 * @brief Ctor
	 * @param[in] serial Buddy serial
	 * @return NONE
	 */
	MpBuddy(std::string const& serial);
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	~MpBuddy();
	/**
	 * @brief Copy Ctor
	 * @param[in] buddy Buddy
	 * @return none
	 */
	MpBuddy(const MpBuddy& buddy);
	/**
	 * @brief Assign operator
	 * @param[in] buddy Buddy
	 * @return reference to buddy
	 */
	MpBuddy& operator= (const MpBuddy& buddy);
	/**
	 * @brief Get buddy serial
	 * @return Buddy serial
	 */
	std::string const& getBuddySerial() const {
		return serial_;
	}
	/**
	 * @brief Set buddy online state
	 * @param[in] state Online state
	 * @return NONE
	 */
	void setState(mp_buddy_online_status_t state) {
		this->state_ = state;
	}
	/**
	 * @brief Get buddy online state
	 * @return Buddy online state (MP_STATUS_ONLINE or MP_STATUS_OFFLINE)
	 */
	mp_buddy_online_status_t getState() const {
		return state_;
	}
	/**
	 * @brief Get pjsua buddy id
	 * @return Pjsua buddy id
	 */
	pjsua_buddy_id getBuddyID() const {
		return pjsuaId_;
	}
	/**
	 * @brief Set pjsua buddy_id_
	 * @return NONE
	 */
	void setBuddyID(pjsua_buddy_id buddyId) {
		this->pjsuaId_ = buddyId;
	}
	/**
	 * @brief Get buddy uri
	 * @return Buddy uri
	 */
	std::string getBuddyUri() const;
};

#endif /* __MP_BUDDY_H__ */
