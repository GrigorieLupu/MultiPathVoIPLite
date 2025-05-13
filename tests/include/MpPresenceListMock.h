#ifndef __MP_PRESENCELISTMOCK_H__
#define __MP_PRESENCELISTMOCK_H__

#include "MpIPresenceList.h"
#include "MpUtils.h"
#include <vector>

class MpPresenceListMock: public MpIPresenceList {
private:
	std::vector<std::string> _users;
public:
	void insertUser(const std::string& serial);
	bool isUserOnline(std::string const& serial);
};


#endif /* __MP_PRESENCELISTMOCK_H__ */
