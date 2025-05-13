#ifndef __WEB_SOCKETS_H__
#define __WEB_SOCKETS_H__

#include <stdint.h>
#include <iostream>
#include <cstring>
#include <stdint.h> 
#include <string>
#include <time.h>
#include <libwebsockets.h>
#include "MpIMsg.h"
#include "MpPool.h"
#include "MpRWLock.h"
#include "MpStatus.h"
#include "MpUtils.h"
#include "ISmkexTransportCallback.h"
#include "ISmkexTransport.h"

#define BUFFER_SIZE 4096

class WebSockets: public ISmkexTransport {    

private:

    const struct lws_protocols protocols[2] = {
      {
        "http",
        callback_ws,
        0,
        0,
      },
      { NULL, NULL, 0, 0 }
    };
    const struct lws_protocols protocols_rx[2] = {
      {
        "ws",
        callback_ws_rx,
        0,
        0,
      },
      { NULL, NULL, 0, 0 }
    };

    // Stateful connection info for server, so we can poll as needed
    // (use updateMessagesFromServer())
	  int n_rx = 0;
    struct lws_client_connect_info i_rx[NR_CONNECTIONS];
    struct lws_context * context_rx;

    // static variables (needed for the static callbacks)
    static int bad[NR_CONNECTIONS], status[NR_CONNECTIONS], buf_len[NR_CONNECTIONS];
    static char buf[NR_CONNECTIONS][LWS_PRE + BUFFER_SIZE];
    static struct lws * client_wsi_rx[NR_CONNECTIONS];

    /**
     * @brief callback functions used by WebSockets
     */
    static int callback_ws(struct lws * wsi, enum lws_callback_reasons reason,
	                     void * user, void * in , size_t len);
    static int callback_ws_rx(struct lws * wsi, enum lws_callback_reasons reason,
	                     void * user, void * in , size_t len);

    // Internal methods
    
    /*
     * Initialise an RX connection to server
     */
    int init_rx(int channel, const char *serverIP, int serverPort, const std::string &clientID);

    /* Constructors */
    WebSockets() {}

    /* Destructor */
    ~WebSockets();

  public:
    static WebSockets &getInstance();

     /**
     * @brief Initialize a WebSockets object from the given data
     * @param server_ip: list of IPs for the WebSockets servers
     * @param server_port:  ports of the WebSockets servers
     * @param clientIDs: the list of client ID strings used with each WS server
     * @param nr_channels: the number of channels to use
    */
    void init(const std::string serverIP[], int serverPort[], const std::string clientID[], int nrChannels);

    /**
     * @brief Process incoming message
     * @param serial Sender serial
     * @param data Message data
     * @param dataLen Message data length
     * @param channel RX channel
     */
    void processMessage(const std::string &serial, const uint8_t *data, uint32_t dataLen, int channel);

    /**
     * @brief Retrieves available messages from server in local list
     *
     * Note: this method will block forever currently.
     * Use within a thread if needed.
     *
     * @return: zero if all goes well, non-zero otherwise
     */
    int updateMessagesFromServer();

    /**
     * @brief Sends a SmkexT4mRecord to the given buddy via the WebSocket server.
     *
     * Note: this function will block until the message is sent.
     *
     * @param buddy: the buddy to which we want to send a message.
     * @param rec: the record to be sent.
     * @param channel: the channel (server) to be used for communication (1 or 2)
     *
     * @returns zero if all goes well, non-zero otherwise.
     */
    int sendMessageToBuddy(const std::string &buddy, const uint8_t *data, uint32_t dataLen, int channel);
};

#endif