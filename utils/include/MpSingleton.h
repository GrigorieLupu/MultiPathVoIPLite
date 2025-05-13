#ifndef __MP_SINGLETON_H__
#define __MP_SINGLETON_H__

#include <stdio.h>
#include "MpUtils.h"

template<class T>
class MpSingleton {
protected:
	/**
	 * @brief Ctor
	 * @return NONE
	 */
	MpSingleton() {
	}
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	~MpSingleton() {
	}
private:
	static T* object_; ///< singleton object
	/**
	 * @brief Copy Ctor
	 * @return NONE
	 */
	MpSingleton(MpSingleton const&);
	/**
	 * @brief Operator = overloading
	 * @return NONE
	 */
	MpSingleton& operator=(MpSingleton const&);
public:
	/**
	 * @brief Instance getter
	 * @return T instance
	 */
	static T* instance() {
		if (!object_) {
			object_ = new T();
		}

		return object_;
	}
	/**
	 * @brief Instance releaser
	 * @return NONE
	 */
	static void release() {
		delete object_;
		object_ = nullptr;
	}
};

template<class T>
T* MpSingleton<T>::object_ = nullptr;

#endif /* __MP_SINGLETON_H__ */
