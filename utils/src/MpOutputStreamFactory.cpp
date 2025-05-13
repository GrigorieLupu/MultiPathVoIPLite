#include "MpOutputStreamFactory.h"
#include "MpUtils.h"

MpIOutputStream* OutputStreamFactory::getOutputStream(mp_output_stream_type_t oType) {
	MpIOutputStream* os = (MpIOutputStream*) MP_NULL;
	switch (oType) {
	case MP_OUTPUT_STREAM_LINUX:
		os = new MpLinuxOutputStream();
		break;
	};
	return os;
}

