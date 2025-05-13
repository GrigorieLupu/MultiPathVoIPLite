#ifndef __MP_IPRESENCELIST_H__
#define __MP_IPRESENCELIST_H__

#include "MpUtils.h"

class MpIPresenceList {
public:
	/**
	 * @brief Specifies whether a given user is online or not
	 * @param[in] serial User serial
	 * @return TRUE if user is ONLINE, FALSE otherwise
	 */
	virtual bool isUserOnline(std::string const& serial) = 0;
	/**
	 * @brief Dtor
	 * @return none
	 */
	virtual ~MpIPresenceList() {
	}
};

#endif /* __MP_IPRESENCELIST_H__ */
