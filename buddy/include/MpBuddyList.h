#ifndef __MP_BUDDYLIST_H__
#define __MP_BUDDYLIST_H__

#include "MpBuddy.h"
#include "MpSingleton.h"
#include "MpLock.h"
#include "MpIPresence.h"
#include "MpIPresenceList.h"
#include "MpPool.h"
#include "MpISIPStack.h"
#include <map>
#include <list>

class MpBuddyList: public MpIPresence, public MpIPresenceList {
	friend class MpSingleton<MpBuddyList> ;
private:
	MpLock lock_; /* Buddy list lock*/
	std::map<std::string, MpBuddy> buddyList_; /* Buddy list*/
	MpPool<MpIPresence> presenceCb_; /* Presence callback vector*/
	MpISIPStack *sipStack_; /*SIP stack*/
	/**
	 * @brief Ctor
	 * @return NONE
	 */
	MpBuddyList();
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	~MpBuddyList();
	/**
	 * @brief Copy ctor
	 * @param[in] buddyList Buddy list
	 * @return NONE
	 */
	MpBuddyList(MpBuddyList const& buddyList);
	/**
	 * @brief Operator =
	 * @param[in] buddyList Buddy list
	 * @return BuddyList
	 */
	MpBuddyList& operator=(MpBuddyList const& buddyList);

	/**
	 * @brief Checks if a buddy serials is valid (contains only alphanumeric chars)
	 * @param[in] serial Buddy serial
	 * @return true if the serial is valid, false otherwise
	 */
	bool serialIsValid(std::string const& serial);
public:
	/**
	 * @brief Set SIP stack
	 * @param[in] sipStack SIP stack interface
	 * @return NONE
	 */
	void setSIPStack(MpISIPStack* sipStack) {
		sipStack_ = sipStack;
	}
	/**
	 * @brief Add buddy (subscribe buddy to server) [THREAD SAFE]
	 * @param[in] buddy Buddy
	 * @return STATUS
	 */
	mp_status_t addBuddy(MpBuddy &buddy);
	/**
	 * @brief Remove buddy (unsubscribe buddy from server) [THREAD SAFE]
	 * @param[in] buddySerial Buddy serial
	 * @return STATUS
	 */
	mp_status_t rmBuddy(std::string const& serial);
	/**
	 * @brief Buddy presence changed callback
	 * @param[in] buddy_id Buddy id
	 * @return NONE
	 */
	void buddy_state(pjsua_buddy_id buddyId);
	/**
	 * @brief Buddy presence changed callback
	 * @param[in] buddy Buddy
	 * @return NONE
	 */
	void buddy_state2(const MpBuddy& buddy) {
	}
	/**
	 * @brief Add presence callback (this function does not destroy presCb!!) [THREAD SAFE]
	 * @param[in] presCb Presence callback
	 * @return STATUS
	 */
	mp_status_t addPresenceCb(MpIPresence* presCb);
	/**
	 * @brief Remove presence callback (this function does not destroy presCb!!) [THREAD SAFE]
	 * @param[in] presCb Presence callback
	 * @return STATUS
	 */
	mp_status_t rmPresenceCb(MpIPresence* presCb);
	/**
	 * @brief Get buddy uri (The returned value must be deleted by the application!!)
	 * @param[in] budySerial Buddy serial
	 * @return Buddy uri
	 */
	std::string getBuddyUri(std::string const& serial);

	/**
	 * @brief Get Buddy by pjsua buddy id
	 * @param[in] buddy_id Pjsua buddy id
	 * @return Buddy object
	 */
	MpBuddy& getBuddy(pjsua_buddy_id buddyId);

	/**
	 * @brief Get Buddy by serial (std::string)
	 * @param[in] name Buddy serial
	 * @return Buddy object
	 */
	MpBuddy getBuddy(std::string const& serial);
	/**
	 * @brief Specifies whether a given user is online or not
	 * @param[in] serial User serial
	 * @return TRUE if user is ONLINE, FALSE otherwise
	 */
	bool isUserOnline(std::string const& serial);
	/**
	 * @brief Get a list of online contacts
	 * @return List of online contacts URI
	 */
	std::list<std::string> getOnlineUris();
	/**
	 * @brief Reset buddy list and unsubscribe presence
	 * @return none	
	 */
	void reset();
};

typedef MpSingleton<MpBuddyList> MpBLSingleton;

#endif /* __MP_BUDDYLIST_H__ */
