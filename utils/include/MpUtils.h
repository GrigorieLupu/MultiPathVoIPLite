#ifndef __MP_UTILS_H__
#define __MP_UTILS_H__

#include "MpCheck.h"
#include <stdio.h>
#include <string>
#include <sstream>

#define MP_SIP_SCHEMA "sip:"
#define MP_SIP_TRANSPORT ";transport=tls"

#define MP_BUFF_SIZE 128
#define MP_FILE_NAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define MP_ASSERT_EQ(x,y) assert(x == y)
#define MP_ASSERT_NEQ(x,y) assert(x != y)
#define MP_NULL NULL
#define MP_FREE_CHAR_ARRAY(x)	delete[] x; x = MP_NULL;
#define MP_FREE_POINTER(x)		delete x; x = MP_NULL;

class MpUtils {

public:
	/**
	 * @brief Get serial from sip uri
	 * @param[in] sip_uri Sip URI
	 * @return Serial
	 */
	static std::string getSerialFromUri(const char* uri);

	/**
	 * @brief Get sip uri from serial, address and port
	 * @param[in] serial Buddy seria
	 * @param[in] address Server address
	 * @param[in] port Server port
	 * @return Sip URI
	 */
	static std::string getUriFromSerial(const char* serial, const char* address,
			unsigned int port);

	/**
	 * @brief Get current time
	 * @return tm structure representing current time
	 */
	static const struct tm getCurrentTime();
};

#endif /* __MP_UTILS_H__ */
