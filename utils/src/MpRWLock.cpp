#include "MpBaseService.h"
#include "MpRWLock.h"
#include <string>

#define THIS_TAG "MpRWLock"

MpRWLock::MpRWLock(std::string const& name) :
		MpIRWLock(name) {
	MP_LOG1("Ctor");
	pthread_rwlockattr_init(&rwattr);
	pthread_rwlock_init(&rwlock_, &rwattr);
}

MpRWLock::~MpRWLock() {
	MP_LOG1("Dtor");
	pthread_rwlockattr_destroy(&rwattr);
	pthread_rwlock_destroy(&rwlock_);
}

void MpRWLock::rLock() {
	MP_LOG2("Read Lock", lockName_.c_str());
	pthread_rwlock_rdlock(&rwlock_);
}

void MpRWLock::rUnlock() {
	MP_LOG2("Read Unlock", lockName_.c_str());
	pthread_rwlock_unlock(&rwlock_);
}

void MpRWLock::wLock() {
	MP_LOG2("Write lock", lockName_.c_str());
	pthread_rwlock_wrlock(&rwlock_);
}

void MpRWLock::wUnlock() {
	MP_LOG2("Write unlock", lockName_.c_str());
	pthread_rwlock_unlock(&rwlock_);
}
