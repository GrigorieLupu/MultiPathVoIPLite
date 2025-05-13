#include "ISmkexTransport.h"

void ISmkexTransport::init(const std::string serverIP[], int serverPort[],
                           const std::string clientID[], int numberOfChannels)
{
    _numberOfChannels = numberOfChannels;
    for(int i = 0; i < numberOfChannels; i++) {
        _serverIP[i] = serverIP[i];
        _serverPort[i] = serverPort[i];
        _clientID[i] = clientID[i];
    }
}

void ISmkexTransport::addMsgCb(ISmkexTransportCallback* mcb) {
    msgCb_ = mcb;
}

void ISmkexTransport::rmMsgCb() {
    msgCb_ = NULL;
}