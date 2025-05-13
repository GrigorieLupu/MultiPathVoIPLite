#include "MpPresenceListMock.h"

void MpPresenceListMock::insertUser(const std::string& serial) {
	_users.push_back(serial);
}

bool MpPresenceListMock::isUserOnline(std::string const& serial) {
	std::vector<std::string>::iterator it = _users.begin();
	for(;it != _users.end();it++) {
		if((*it) == serial) {
			return true;
		}
	}
	return false;
}
