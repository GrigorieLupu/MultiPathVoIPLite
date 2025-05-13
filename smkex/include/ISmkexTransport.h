#ifndef __ISMKEX_TRANSPORT_H__
#define __ISMKEX_TRANSPORT_H__

#include <string>
#include "ISmkexTransportCallback.h"

#define NR_CONNECTIONS 2
#define SMKEX_TX_PATH "/public/send-message/"
#define SMKEX_RX_PATH "/public/smkex-websocket/"

class ISmkexTransport
{
public:
    /**
     * @brief Init transport module
     * @param serverIP List of server IP addresses
     * @param serverPort List of server ports
     * @param clientID List of client IDs
     * @param numberOfChannels Number of channels
     */
    void init(const std::string serverIP[], int serverPort[],
              const std::string clientID[], int numberOfChannels);

    /**
     * Destructor
     */
    virtual ~ISmkexTransport() {}

    /**
     * @brief Add RX callback
     * @param mcb RX callback
     */
    void addMsgCb(ISmkexTransportCallback* mcb);

    /**
     * @brief Remove RX callback
     * @param mcb RX callback
     */
    void rmMsgCb();

    /**
     * @brief Update messages from server: should be called if the transport uses a polling logic
     */
    virtual int updateMessagesFromServer() = 0;

    /**
     * @brief Send message to buddy
     * @param[in] buddy Buddy serial
     * @param[in] data Message data
     * @param[in] dataLen Message data length
     * @param[in] channel TX channel
     */
    virtual int sendMessageToBuddy(const std::string &buddy, const uint8_t *data,
                                   uint32_t dataLen, int channel) = 0;

protected:
    /* List of message callbacks */
    ISmkexTransportCallback *msgCb_;
    /* Holds the number of channels */
    int _numberOfChannels;
    /* Holds the list of servers */
    std::string _serverIP[NR_CONNECTIONS];
    /* Holds the server ports */
    int _serverPort[NR_CONNECTIONS];
    /* Holds the client IDs */
    std::string _clientID[NR_CONNECTIONS];
};

#endif /* __ISMKEX_TRANSPORT_H__ */