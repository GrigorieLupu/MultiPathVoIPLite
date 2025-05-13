#define DEBUG 1
#define THIS_TAG "Smkex"

#ifndef __ANDROID__
#include "MpBaseService.h"
#include "MpLogger.h"
#define LOGMSG(x) MpService::instance()->getLogger()->print(THIS_TAG, __FUNCTION__, (x))
#else
#define LOGMSG(x)
#define MP_LOG1(x)
#define MP_LOG2(x, y) 
#define MP_LOG2_INT(x, y)
#define MP_LOG2_HEX(x, y ,z)
#endif