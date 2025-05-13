#ifndef __MP_IRWLOCK_H__
#define __MP_IRWLOCK_H__
#include "MpUtils.h"
#include <string.h>

class MpIRWLock {

protected:
	std::string lockName_;

public:
	/**
	 * @brief Ctor
	 * @param[in] lockName Lock name
	 * @return NONE
	 */
	MpIRWLock(std::string const& lockName) {
		lockName_ = lockName;
	}
	/**
	 * @brief Take  read lock
	 * @return NONE
	 */
	virtual void rLock() = 0;
	/**
	 * @brief Release read lock
	 * @return NONE
	 */
	virtual void rUnlock() = 0;
	/**
	 * @brief Take write lock
	 * @return NONE
	 */
	virtual void wLock() = 0;
	/**
	 * @brief Release write lock
	 * @return NONE
	 */
	virtual void wUnlock() = 0;
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	virtual ~MpIRWLock() {
	}
};

#endif /* __MP_IRWLOCK_H__ */
