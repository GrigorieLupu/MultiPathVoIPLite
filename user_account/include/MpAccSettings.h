#ifndef MP_ACCSETTINGS_H_
#define MP_ACCSETTINGS_H_

#include "MpBuffer.h"
#include "MpConfig.h"
#include "MpUtils.h"
#include "MpStatus.h"
#include "MpNetworkState.h"
#include <stdint.h>

class MpAccSettings {
private:
	std::string serverAddress_; ///< SIP Server address
	uint32_t port_; ///< SIP Server port
	std::string userName_; ///< SIP user name
	uint32_t pjsipLogLevel_; ///< PJSIP log level
	mp_network_state_t networkState_; ///<network state
    bool verifyServer_;
	std::string certPath_; ///< SIP client certificate path
	std::string privKeyPath_; ///< SIP client private key path
public:
	/**
	 * @brief Ctor
	 * @param[in] serverAddress SIP Server address
	 * @param[in] port SIP Server port
	 * @param[in] userName SIP username
	 * @param[in] pjsipLogLevel SIP log level
	 * @param[in] networkState Network state
	 * @param[in] verifyServer Indicates if the server certificate should be validated
	 * @param[in] certPath SIP client certificate path
	 * @param[in] privKeyPath SIP client private key path
	 * @return NONE
	 */
	MpAccSettings(std::string const& serverAddress,
				uint32_t port,
				std::string const& userName,
				uint32_t pjsipLogLevel,
				mp_network_state_t networkState,
				bool verifyServer,
				std::string const& certPath,
				std::string const& privKeyPath);
	/**
	 * @brief Dtor
	 * @return NONE
	 */
	~MpAccSettings();

	/**
	 * @brief Get SIP server address
	 * @return SIP Server address
	 */
	std::string const& getServerAddress() const {
		return serverAddress_;
	}
	/**
	 * @brief Get SIp Server port
	 * @return SIP Server port
	 */
	uint32_t getPort() const {
		return port_;
	}

	std::string const& getUserName() const {
		return userName_;
	}
	/**
	 * @brief Get PJSIP log level
	 * @return PJSIP log level
	 */
	uint32_t getPjsipLogLevel() const {
		return pjsipLogLevel_;
	}
	
	/**
	 * @brief Get Network state
	 * @return network state
	 */
	mp_network_state_t getNetworkState() const {
		return networkState_;
	}

	/**
	 * @brief Get verify server status
	 * @return verify server status
	 */
    bool getVerifyServer() const {
        return verifyServer_;
    }
	
	/**
	 * @brief Get SIP client certificate path
	 * @return SIP client certificate path
	 */
	std::string getCertPath() const {
		return certPath_;
	}

	/**
	 * @brief Get SIP client private key path
	 * @return SIP client private key path
	 */
	std::string getPrivKeyPath() const {
		return privKeyPath_;
	}

	/**
	 * @brief Operator=
	 * @param[in] accSettings Account settings
	 * @return Account settings
	 */
	MpAccSettings& operator=(MpAccSettings const& accSettings);
};

#endif /* MP_ACCSETTINGS_H_ */
