/*
 * IOutputStream.h
 *
 *  Created on: Jul 7, 2014
 *      Author: root
 */

#ifndef __MP_IOUTPUTSTREAM_H__
#define __MP_IOUTPUTSTREAM_H__

class MpIOutputStream {

public:
	/**
	 * @brief Print data to console
	 * @param[in] tag MSG TAG
	 * @param[in] fnc Function
	 * @param[in] data MSG DATA
	 * @return NONE
	 */
	virtual void printToConsole(const char* tag, const char* fnc,
			const char* data) = 0;

	/**
	 * @brief Print data to file
	 * @param[in] tag MSG TAG
	 * @param[in] fnc Function
	 * @param[in] data MSG DATA
	 * @return NONE
	 */
	virtual void printToFile(const char* tag, const char* fnc,
			const char* data) = 0;

	/**
	 * @brief Create the log file
	 * @return status
	 */
	virtual int createLogFile() = 0;

	/**
	 * @brief Close the log file
	 * @return status
	 */
	virtual void closeLogFile() = 0;

	/**
	 * @brief Dtor
	 * @return NONE
	 */
	virtual ~MpIOutputStream() {
	}
};

#endif /* __MP_IOUTPUTSTREAM_H__ */
