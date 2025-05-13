#ifndef __MP_LOGGER_H__
#define __MP_LOGGER_H__

#include "MpUtils.h"
#include "MpSingleton.h"
#include "MpIOutputStream.h"

class MpLogger {
	friend class MpSingleton<MpLogger> ;
private:
	MpIOutputStream *os_; ///< Output stream interface

protected:
	/**
	 * @brief Ctor
	 * @return NONE
	 */
	MpLogger();
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	~MpLogger();

public:
	/**
	 * @brief Print data
	 * @param[in] tag MSG TAG
	 * @param[in] fnc Function
	 * @param[in] data MSG DATA
	 * @return NONE
	 */
	void print(const char* tag, const char* fnc, const char* data);

	/**
	 * @brief Set logger output stream
	 * @param[in] os Custom output stream
	 * @return none
	 */
	void setOutputStream(MpIOutputStream* os) {os_ = os;}
};

typedef MpSingleton<MpLogger> MpLoggerSingleton;

#endif /* __MP_LOGGER_H__ */
