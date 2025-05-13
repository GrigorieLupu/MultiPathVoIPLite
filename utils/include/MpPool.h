#ifndef __MP_CBPOOL_H__
#define __MP_CBPOOL_H__

#include "MpStatus.h"
#include "MpUtils.h"
#include "MpRWLock.h"
#include <vector>
using namespace std;

template<class T>
class MpPool {
private:
	vector<T*> pool_; ///< Data pool
	MpRWLock rw_lock_; ///< Read write lock for pool access

	/**
	 * @brief Mark pool modify process
	 * @return
	 */
	void modifyPool() {
		rw_lock_.wLock();
	}
	/**
	 * @brief End pool modify process
	 * @return NONE
	 */
	void endModifyPool() {
		rw_lock_.wUnlock();
	}
public:
	/**
	 * @brief Ctor
	 * @return NONE
	 */
	MpPool(const char* name) :
		rw_lock_(name) {
	}
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	~MpPool() {
	}
	/**
	 * @brief Use pool. Must be called before getCbPool.
	 * @return NONE
	 */
	void usePool() {
		rw_lock_.rLock();
	}
	/**
	 * @brief Release pool. Must be called after reading and calling the pool functions is done.
	 * @return NONE
	 */
	void endUsePool() {
		rw_lock_.rUnlock();
	}

	/**
	 * @brief Get pool
	 * @return Pool
	 */
	const vector<T*>& getPool() {
		return pool_;
	}

	/**
	 * @brief Add pool data
	 * @param[in] pd Pool data
	 * @return NONE
	 */
	void addPoolData(T* cb) {
		MP_CHECK_INPUT(cb != MP_NULL,);
		modifyPool();
		this->pool_.push_back(cb);
		endModifyPool();

	}
	/**
	 * @brief Remove pool data
	 * @param[in] pd Pool data
	 * @return NONE
	 */
	void rmPoolData(const T* pd) {
		MP_CHECK_INPUT(pd != MP_NULL,);
		modifyPool();
		typename vector<T*>::iterator it = this->pool_.begin();
		for (; it < this->pool_.end(); ++it) {
			if ((*it) == pd) {
				this->pool_.erase(it);
				endModifyPool();
				return;
			}
		}
		endModifyPool();
	}

};
#endif /* __MP_CBPOOL_H__ */
