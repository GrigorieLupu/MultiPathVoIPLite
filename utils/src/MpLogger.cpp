#include "MpLogger.h"
#include "MpOutputStreamFactory.h"

#if ANDROID == 1
#include <android/log.h>
#endif /* ANDROID */

MpLogger::MpLogger(): os_(0) {
}

MpLogger::~MpLogger() {
	delete os_;
}

void MpLogger::print(const char* tag, const char* fnc, const char* data)
{
#if MP_DEBUG == 1

	#if	MP_LOG_TO_CONSOLE == 1
		if(os_)
			os_->printToConsole(tag, fnc, data);
	#endif /* MP_LOG_TO_CONSOLE */

	#if	MP_LOG_TO_FILE == 1
		if(os_)
			os_->printToFile(tag, fnc, data);
	#endif /* MP_LOG_TO_FILE */

	#if ANDROID == 1
 	__android_log_print(ANDROID_LOG_DEBUG, tag, "%s\n", data);
	#endif /* ANDROID */

#endif /* MP_DEBUG */

}
