#include "MpAccSettings.h"
#include "MpBaseService.h"

MpAccSettings::MpAccSettings(std::string const& serverAddress,
							 uint32_t port,
							 std::string const& userName,
							 uint32_t pjsipLogLevel,
							 mp_network_state_t networkState,
							 bool verifyServer,
							 std::string const& certPath,
							 std::string const& privKeyPath) : serverAddress_(serverAddress),
							   					  			port_(port),
												  			userName_(userName),
												  			pjsipLogLevel_(pjsipLogLevel),
												  			networkState_(networkState),
												  			verifyServer_(verifyServer),
															certPath_(certPath),
															privKeyPath_(privKeyPath) {
	MP_LOG1("Ctor");
}

MpAccSettings::~MpAccSettings() {
}

MpAccSettings& MpAccSettings::operator=(MpAccSettings const& accSettings) {
	if (this != &accSettings) {
		this->serverAddress_ = accSettings.serverAddress_;
		this->port_ = accSettings.port_;
		this->userName_ = accSettings.userName_;
	}
	MP_LOG1("Operator=");
	return *this;
}
