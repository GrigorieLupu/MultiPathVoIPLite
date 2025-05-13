#include "MpBuffer.h"
#include "MpUtils.h"
#include "MpBaseService.h"
#include <assert.h>

MpBuffer::MpBuffer() {
	MP_LOG1("Ctor");
	this->payload_ = MP_NULL;
	this->len_ = 0;
}

MpBuffer::MpBuffer(const uint8_t* payload, uint32_t len) {
	MP_LOG1("Ctor");
	this->payload_ = new uint8_t[len];
	assert(this->payload_ != MP_NULL);
	memcpy(this->payload_, payload, len);
	this->len_ = len;
}

MpBuffer::~MpBuffer() {
	if (this->len_ > 0 && this->payload_ != MP_NULL) {
		MP_FREE_CHAR_ARRAY(this->payload_);
		this->len_ = 0;
	}
}

MpBuffer::MpBuffer(MpBuffer const& buffer) {
	MP_LOG1("Copy Ctor");
	this->payload_ = new uint8_t[buffer.getLen()];
	assert(this->payload_ != MP_NULL);
	memcpy(this->payload_, buffer.getPayload(), buffer.getLen());
	this->len_ = buffer.getLen();

}

MpBuffer& MpBuffer::operator=(MpBuffer const& buffer) {
	MP_LOG1("Operator =");
	if (this != &buffer) {
		if (this->len_ > 0 && this->payload_ != MP_NULL) {
			this->len_ = 0;
			delete[] this->payload_;
		}
		this->payload_ = new uint8_t[buffer.getLen()];
		assert(this->payload_ != MP_NULL);
		memcpy(this->payload_, buffer.getPayload(), buffer.getLen());
		this->len_ = buffer.getLen();
	}
	return *this;
}

bool MpBuffer::operator==(MpBuffer const& buffer) const {
	MP_LOG1("Operator ==");
	return memcmp(payload_, buffer.payload_, len_) == 0 ? true : false;
}

bool MpBuffer::operator!=(MpBuffer const& buffer) const {
	MP_LOG1("Operator !=");
	return !operator==(buffer);
}

void MpBuffer::setPayload(uint8_t *payload, uint32_t payloadLen) {
	MP_CHECK_INPUT(payload != MP_NULL,);
	MP_CHECK_INPUT(payloadLen > 0,);

	MP_FREE_CHAR_ARRAY(this->payload_);
	this->payload_ = new uint8_t[payloadLen];
	memcpy(this->payload_, payload, payloadLen);
	len_ = payloadLen;
}

void MpBuffer::dump() const {
	/*FIXME not implemented yet*/
}
