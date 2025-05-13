#ifndef __MP_LOCK_H__
#define __MP_LOCK_H__

#include "MpSingleton.h"
#include "MpILock.h"
#include <pthread.h>

class MpLock: MpILock {
private:
	pthread_mutex_t mutex_;
	pthread_mutexattr_t attr_;
public:
	/**
	 * @brief Ctor
	 * @param[in] lockName Lock name
	 * @return NONE
	 */
	 MpLock(const char* lockName);
	 /**
	 * @brief Dtor
	 * @return NONE
	 */
	~MpLock();
	/**
	 * @brief
	 */
	/**
	 * @brief Take lock
	 * @return NONE
	 */
	void lock();
	/**
	 * @brief Release lock
	 * @return NONE
	 */
	void unlock();
};

#endif /* __MP_LOCK_H__ */
