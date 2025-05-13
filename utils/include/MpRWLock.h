#ifndef __MP_RWLOCK_H__
#define __MP_RWLOCK_H__

#include "MpIRWLock.h"
#include <pthread.h>

class MpRWLock: MpIRWLock {
private:
	pthread_rwlock_t rwlock_; ///< read write lock
	pthread_rwlockattr_t rwattr; ///< attribute
public:
	/**
	 * @brief Ctor
	 * @param[in] name Lock name
	 * @return NONE
	 */
	MpRWLock(std::string const& name);
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	~MpRWLock();
	/**
	 * @brief Take  read lock
	 * @return NONE
	 */
	void rLock();
	/**
	 * @brief Release read lock
	 * @return NONE
	 */
	void rUnlock();
	/**
	 * @brief Take write lock
	 * @return NONE
	 */
	void wLock();
	/**
	 * @brief Release write lock
	 * @return NONE
	 */
	void wUnlock();
};

#endif /* __MP_RWLOCK_H__ */
