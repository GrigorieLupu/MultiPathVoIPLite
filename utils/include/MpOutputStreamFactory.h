#ifndef __MP_OUTPUTSTREAMFACTORY_H__
#define __MP_OUTPUTSTREAMFACTORY_H__

#include "MpIOutputStream.h"
#include "MpLinuxOutputStream.h"

typedef enum {
	MP_OUTPUT_STREAM_LINUX = 0, ///< Linux output stream (console)
} mp_output_stream_type_t;


class OutputStreamFactory {

public:
	/**
	 * @brief Get Output stream instance
	 * @param[in] oType Output stream type
	 * @return IOutpuStream
	 */
	static MpIOutputStream* getOutputStream(mp_output_stream_type_t oType);
};

#endif /* __MP_OUTPUTSTREAMFACTORY_H__ */
