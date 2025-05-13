#include "MpConfig.h"

#if MP_OS_LINUX==1
#include "MpLinuxOutputStream.h"
#include "MpUtils.h"
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <iostream>
using namespace std;

MpLinuxOutputStream::MpLinuxOutputStream() {
}

MpLinuxOutputStream::~MpLinuxOutputStream() {
}

int MpLinuxOutputStream::createLogFile() {
	const struct tm timeNow = MpUtils::getCurrentTime();

	char buffer[256] = { 0 };
	strftime(buffer, sizeof(buffer), "/tmp/mp_%Y%m%d%H%M%S.log", &timeNow);

	file_.open(buffer, std::ios_base::app | std::ios_base::out);
	if (!file_) {
		return -1;
	}
	return 0;
}

void MpLinuxOutputStream::closeLogFile() {
	file_.close();
}

void MpLinuxOutputStream::getLogFormat(const char* tag, const char* fnc,
		const char* data, char *buffer, size_t len) {

	MP_CHECK_INPUT(tag != MP_NULL,);
	MP_CHECK_INPUT(strlen(tag) > 0,);
	MP_CHECK_INPUT(data != MP_NULL,);
	MP_CHECK_INPUT(strlen(data) > 0,);

	const struct tm timeNow = MpUtils::getCurrentTime();

	strftime(buffer, len, "%Y-%m-%d.%X", &timeNow);
}

void MpLinuxOutputStream::printToConsole(const char* tag, const char* fnc,
		const char* data) {

	char buffer[256] = { 0 };
	getLogFormat(tag, fnc, data, buffer, sizeof(buffer));

	std::cout << buffer << " " << " PID:" << getpid() << " " << " TID:"
			  << pthread_self() << " " << tag << " " << fnc << "->" << data
			  << endl;
}

void MpLinuxOutputStream::printToFile(const char* tag, const char* fnc,
		const char* data) {

	char buffer[256] = { 0 };
	getLogFormat(tag, fnc, data, buffer, sizeof(buffer));

	file_ << buffer << " " << " PID:" << getpid() << " " << " TID:"
			<< pthread_self() << " " << tag << " " << fnc << "->" << data
			<< endl;
}

#endif

