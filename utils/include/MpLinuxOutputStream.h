#ifndef __MP_LINUXOUTPUTSTREAM_H__
#define __MP_LINUXOUTPUTSTREAM_H__

#include "MpConfig.h"

#if MP_OS_LINUX==1
#include "MpIOutputStream.h"

#include <iostream>
#include <fstream>

class MpLinuxOutputStream: public MpIOutputStream {

private:
	std::ofstream file_; ///< Log file

	/**
	 * @brief Validates parameters and returns a buffer containing the log format
	 * @param[in] tag MSG TAG
	 * @param[in] fnc Function
	 * @param[in] data MSG DATA
	 * @param[out] buffer buffer to fill
	 * @param[in] length of the buffer to fill.must
	 * @return NONE
	 */
	void getLogFormat(const char* tag, const char* fnc, const char* data,
			char *buffer, size_t len);

public:
	/**
	 * @brief Ctor
	 * @return NONE
	 */
	MpLinuxOutputStream();
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	~MpLinuxOutputStream();
	/**
	 * @brief Print data to console
	 * @param[in] tag MSG TAG
	 * @param[in] fnc Function
	 * @param[in] data MSG DATA
	 * @return NONE
	 */
	void printToConsole(const char* tag, const char* fnc, const char* data);

	/**
	 * @brief Print data to file
	 * @param[in] tag MSG TAG
	 * @param[in] fnc Function
	 * @param[in] data MSG DATA
	 * @return NONE
	 */
	void printToFile(const char* tag, const char* fnc, const char* data);

	/**
	 * @brief Create the log file
	 * @return NONE
	 */
	int createLogFile();

	/**
	 * @brief Close the log file
	 * @return NONE
	 */
	void closeLogFile();
};

#endif

#endif /* __MP_LINUXOUTPUTSTREAM_H__ */
