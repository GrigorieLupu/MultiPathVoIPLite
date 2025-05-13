#ifndef __MP_MSGPAYLOAD_H__
#define __MP_MSGPAYLOAD_H__

#include "MpUtils.h"
#include "MpBuffer.h"

typedef enum {
	MP_TYPE_MESSAGE = 0, ///< SMS Message
	MP_TYPE_INVITATION, ///< Invitation message
	MP_TYPE_INVITATION_DELETE, ///< Invitation Delete message
	MP_TYPE_INVITATION_RESPONSE, ///< Invitation response message
} mp_msg_type_t;

class MpMsgPayload {
private:
	std::string userSerial_; ///< Message receiver serial
	MpBuffer payload_; ///< Message payload (message type is prepended)
	int uid_; ///< Message UID
	int numberOfRetries_; ///< Number of retries per message when send fails
	int xferStatus_; ///< SIP xfer status (SIP status)
	long accID_; ///< PJSIP account ID
//	int creationDate_; ///< Message creation date??? //FIXME check this field significance
	mp_msg_type_t messageType_; ///< Message type
	bool processed_; ///< Message has been processed by auto resend engine
	/**
	 * @brief Copy Message payload struct
	 * @param[in] msgPayload Message payload
	 * @return NONE
	 */
	void copyMsgPayload(MpMsgPayload const& msgPayload);
	/**
	 * @brief Set message payload. Prepends the message type for the transport layer.
	 * @param[in] payload Message payload
	 * @return none
	 */
	void setPayload(MpBuffer const& payload);
public:
	/**
	 * @brief Ctor
	 * @param[in] payload Message payload
	 * @param[in] object Message object
	 * @param[in] numberOfRetries Number of XFER retries
	 * @param[in] accID PJSIP Account ID
	 * @param[in] creationDate Message creation date
	 * @param[in] messageType Message type
	 * @param[in] processed If message was processed before by auto resend engine
	 * @return NONE
	 */
	MpMsgPayload(std::string const& userSerial, MpBuffer const& payload,
			int uid, int numberOfRetries, long accID, /*int creationDate,*/
			mp_msg_type_t messageType, bool processed);

	/**
	 * @brief Copy Ctor
	 * @param[in] msgPayload Message payload
	 * @return NONE
	 */
	MpMsgPayload(MpMsgPayload const& msgPayload);

	/**
	 * @brief Override operator=
	 * @param[in] msgPayload Message payload
	 * @return NONE
	 */
	MpMsgPayload& operator=(MpMsgPayload const& msgPayload);
	/**
	 * @brief Get message payload
	 * @return Message payload
	 */
	MpBuffer getPayload() const {
		return payload_;
	}
	/**
	 * @brief Format message payload to be sent over the SIP channel. Append the message type in front of the payload.
	 * @return NONE
	 */
	MpBuffer getTransportPayload() const;
	/**
	 * @brief Set user serial
	 * @param[in] userSerial User serial
	 * @reutrn none
	 */
	inline void setUserSerial(std::string const& userSerial) {
		userSerial_ = userSerial;
	}
	/**
	 * @brief Get user serial
	 * @return User serial
	 */
	inline std::string getUserSerial() const {
		return userSerial_; // BUG SOMETIMES - invite si remove
	}
	/**
	 * @brief Get number of xfer retries
	 * @return Number of retries
	 */
	inline int getNumberOfRetries() const {
		return numberOfRetries_;
	}
	/**
	 * @brief Set number of retries
	 * @param[in] numberOfRetries Number of retries
	 * @return NONE
	 */
	inline void setNumberOfRetries(int numberOfRetries) {
		this->numberOfRetries_ = numberOfRetries;
	}
	/**
	 * @brief Get XFER status
	 * @return XFER status
	 */
	inline int getXferStatus() const {
		return xferStatus_;
	}
	/**
	 * @brief Set xfer status
	 * @param[in] xferStatus
	 * @return NONE
	 */
	inline void setXferStatus(int xferStatus) {
		this->xferStatus_ = xferStatus;
	}
	/**
	 * @brief Get account ID
	 * @return Account ID
	 */
	inline long getAccID() const {
		return accID_;
	}
	/**
	 * @brief Set PJSIP accound ID
	 * @param[in] accID PJSIP Account ID
	 * @return NONE
	 */
	inline void setAccID(long accID) {
		this->accID_ = accID;
	}
	/**
	 * @brief Get creation date
	 * @return Creation date
	 */
//	int getCreationDate() const {
//		return creationDate_;
//	}
	/**
	 * @brief Set creation date
	 * @param[in] creationDate Message creation date
	 * @return NONE
	 */
//	void setCreationDate(int creationDate) {
//		this->creationDate_ = creationDate;
//	}
	/**
	 * @brief Get message type
	 * @return Message type
	 */
	inline mp_msg_type_t getMessageType() const {
		return messageType_;
	}
	/**
	 * @brief Set message type
	 * @param[in] messageType Message type
	 * @return NONE
	 */
	inline void setMessageType(mp_msg_type_t messageType) {
		this->messageType_ = messageType;
	}
	/**
	 * @brief Get message UID
	 * @return UID
	 */
	inline int getUID() const {
		return uid_;
	}
	/**
	 * @brief Set message uid
	 * @param[in] uid Message uid
	 * @return NONE
	 */
	inline void setUID(int uid) {
		this->uid_ = uid;
	}
//    /**
//     * @brief Get message object
//     * @return UID
//     */
//    void* getObject() const {
//        return object_;
//    }
//    /**
//     * @brief Set message object
//     * @param[in] object Message object
//     * @return NONE
//     */
//    void setObject(void* object) {
//        this->object_ = object;
//    }

	/**
	 * @return Return pointer to this object
	 */
	const MpMsgPayload* getPtr() const {
		return this;
	}

	/**
	 * @brief Test if message has been processed by auto resend engine
	 * @return TRUE if message has been processed
	 */
	bool isMessageProcessed() const {
		return processed_;
	}
	/**
	 * @brief Mark message as processed by auto resend engine
	 * @return none
	 */
	inline void markAsProcessed() {
		processed_ = true;
	}

	/**
	 * @brief Mark message as unprocessed by auto resend engine
	 * @return none
	 */
	inline void markAsUnProcessed() {
		processed_ = false;
	}

	void dump() const;
};

#endif /* __MP_MSGPAYLOAD_H__ */
