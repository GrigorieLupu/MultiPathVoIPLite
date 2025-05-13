#ifndef __MP_BUFFER_H__
#define __MP_BUFFER_H__

#include "MpUtils.h"
#include <cassert>
#include <string.h>
#include <stdint.h>

class MpBuffer {
private:
	uint8_t* payload_; ///< Payload
	uint32_t len_; ///< Payload length
public:
	/**
	 * @brief Ctor
	 * @return NONE
	 */
	MpBuffer();
	/**
	 * @brief Ctor
	 * @param[in] payload Payload
	 * @param[in] len Payload length
	 * @return NONE
	 */
	MpBuffer(const uint8_t* payload, uint32_t len);
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	~MpBuffer();
	/**
	 * @brief Copy Ctor
	 * @param[in] buffer Original Buffer
	 * @return NONE
	 */
	MpBuffer(MpBuffer const& buffer);
	/**
	 * @brief Operator =
	 * @param[in] buffer Original Buffer
	 * @return Buffer reference
	 */
	MpBuffer& operator=(MpBuffer const& buffer);
	/**
	 * @brief Get payload length
	 * @return payload length
	 */
	uint32_t getLen() const {
		return this->len_;
	}
	/**
	 * @brief Get payload
	 * @return Payload
	 */
	const uint8_t* getPayload() const {
		return this->payload_;
	}
	/**
	 * @brief Set payload
	 * @param[in] payload Payload bytes
	 * @param[in] payloadLen Payload length
	 * @return none
	 */
	void setPayload(uint8_t *payload, uint32_t payloadLen);
	/**
	 * @brief Operator==
	 * @param[in] buffer Buffer
	 * @return TRUE or FALSE
	 */
	bool operator==(MpBuffer const& buffer) const;
	/**
	 * @brief Operator!=
	 * @param[in] buffer Buffer
	 * @return TRUE or FALSE
	 */
	bool operator!=(MpBuffer const& buffer) const;
	void dump() const;
};

#endif /* __MP_BUFFER_H__ */
