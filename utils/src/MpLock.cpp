#include "MpLock.h"
#include "MpBaseService.h"
#include "MpConfig.h"

MpLock::MpLock(const char* lockName) :
		MpILock(lockName) {
	MP_LOG2("Ctor", lockName_);
	pthread_mutexattr_init(&attr_);
	pthread_mutexattr_settype(&attr_, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&mutex_, &attr_);
}

MpLock::~MpLock() {
	MP_LOG2("Dtor", lockName_);
	pthread_mutexattr_destroy(&attr_);
	pthread_mutex_destroy(&mutex_);
}

void MpLock::lock() {
	MP_LOG2("Lock", lockName_);
	pthread_mutex_lock(&mutex_);
}

void MpLock::unlock() {
	MP_LOG2("Unlock", lockName_);
	pthread_mutex_unlock(&mutex_);
}
