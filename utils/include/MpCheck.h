#ifndef __MP_CHECK_H__
#define __MP_CHECK_H__

#include "MpErrors.h"

#define MP_CHECK_INPUT(expr,retval) \
do{ \
			if(!(expr)) { \
				return retval; \
			}\
}while(0)

#endif /* __MP_CHECK_H__ */
