#ifndef __MP_ILOCK_H__
#define __MP_ILOCK_H__

#include <string.h>

class MpILock {

protected:
	char* lockName_;

public:
	/**
	 * @brief Ctor
	 * @param[in] lockName Lock name
	 * @return NONE
	 */
	MpILock(const char* lockName) {
		lockName_ = new char[strlen(lockName) + 1];
		strcpy(lockName_, lockName);
	}
	/**
	 * @brief Take lock
	 * @return NONE
	 */
	virtual void lock() = 0;
	/**
	 * @brief Release lock
	 * @return NONE
	 */
	virtual void unlock() = 0;
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	virtual ~MpILock() {
		if (lockName_ != MP_NULL) {
			delete[] lockName_;
			lockName_ = MP_NULL;
		}
	}

};

#endif /* __MP_ILOCK_H__ */
