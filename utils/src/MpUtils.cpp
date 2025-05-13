#include "MpUtils.h"
#include <string.h>

std::string MpUtils::getSerialFromUri(const char* uri) {

	MP_CHECK_INPUT(uri != MP_NULL, MP_NULL);
	MP_CHECK_INPUT(strlen(uri) > 0, MP_NULL);

	std::string serial(uri);

	size_t beg = serial.find(MP_SIP_SCHEMA);
	MP_CHECK_INPUT(beg != std::string::npos, MP_NULL);
	size_t end = serial.rfind("@");
	MP_CHECK_INPUT(end != std::string::npos, MP_NULL);

	return serial.substr(beg + strlen(MP_SIP_SCHEMA), end - beg - strlen(MP_SIP_SCHEMA));
}

std::string MpUtils::getUriFromSerial(const char* serial, const char* address,
		unsigned int port) {

	MP_CHECK_INPUT(serial != MP_NULL, MP_NULL);
	MP_CHECK_INPUT(strlen(serial) > 0, MP_NULL);

	std::stringstream ss;
//	ss << "sip:" << serial << "@" << address << ":" << port;
//	ss << "sip:" << serial << "@" << address << ":" << port<<";transport=tcp";
	ss << MP_SIP_SCHEMA << serial << "@" << address << ":" << port
			<< MP_SIP_TRANSPORT;
	return ss.str();
}

const struct tm MpUtils::getCurrentTime() {

	time_t now = time(0);
	return *localtime(&now);

}
