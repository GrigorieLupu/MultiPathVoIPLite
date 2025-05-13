#ifndef __MP_IINVITATION_H__
#define __MP_IINVITATION_H__

#include "MpStatus.h"
#include <stdint.h>

class MpIInvitationCallback {

public:
	/**
	 * @brief Callback called after invitation was received
	 * @param[in] invUID Invitation UID
	 * @param[in] invUIDLen Invitation UID length
	 * @param[in] senderURI Sender URI
	 * @param[in] senderURILen Sender URI length
	 * @param[in] senderCert Sender certificate
	 * @param[in] senderCertLen Sender certificate length
	 * @param[in] senderCn Sender CN
	 * @param[in] senderCnLen Sender CN length
	 * @return NONE
	 */
	virtual void invReceived(uint8_t* invUID, uint32_t invUIDLen,
			uint8_t* senderURI, uint32_t senderURILen, uint8_t* senderCert,
			uint32_t senderCertLen, char* senderCn) = 0;
	/**
	 * @brief Callback called after invitation response was received
	 * @param[in] invUID Invitation UID
	 * @param[in] invUIDLen Invitation UID length
	 * @param[in] senderCert Sender certificate
	 * @param[in] senderCertLen Sender certificate length
	 * @param[in] resp Invitation response
	 * @return NONE
	 */
	virtual void invRespReceived(uint8_t* invUID, uint32_t invUIDLen,
			uint8_t* senderCert, uint32_t senderCertLen, bool accepted) = 0;
	/**
	 * @brief Invitation received delete callback
	 * @param[in] senderUri Sender SIP URI
	 * @return none
	 */
	virtual void invDeleteReceived(const char* senderUri) = 0;

	/**
	 * @brief Dtor
	 * @return NONE
	 */
	virtual ~MpIInvitationCallback() {
	}
};

#endif /* __MP_IINVITATION_H__ */
