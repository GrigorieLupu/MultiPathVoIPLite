#include <iostream>
#include <string.h>
#include <cstring>
#include <vector>
#include <map>
#include <algorithm>
#include "base64.h"
#include "SmkexRecord.h"  
#include "Smkex.h"
#include "WebSockets.h"
#include "MpBaseService.h"
#define LOGMSG(x) MpService::instance()->getLogger()->print(THIS_TAG, __FUNCTION__, (x))
#define THIS_TAG "WebSockets"

// #ifndef __ANDROID__
// #include "MpBaseService.h"
// #include "MpLogger.h"
// #define LOGMSG(x) MpService::instance()->getLogger()->print(THIS_TAG, __FUNCTION__, (x))
// #else
// #define LOGMSG(x)
// #endif

#define DEBUG 1

// Define here all the static vars needed
int WebSockets::bad[NR_CONNECTIONS];
int WebSockets::status[NR_CONNECTIONS];
int WebSockets::buf_len[NR_CONNECTIONS];
char WebSockets::buf[NR_CONNECTIONS][LWS_PRE + BUFFER_SIZE];
struct lws * WebSockets::client_wsi_rx[NR_CONNECTIONS];

int WebSockets::init_rx(int channel, const char *serverIP, int serverPort, const std::string &clientID)
{
  char wspath[256];

  if (channel < 0 || channel >= NR_CONNECTIONS)
  {
    LOGMSG("Incorrect channel value\n");
    return -1;
  }

	memset(&i_rx[channel], 0, sizeof i_rx[channel]);
	i_rx[channel].context = context_rx;
  sprintf(wspath, SMKEX_RX_PATH "%s", clientID.c_str());
	i_rx[channel].path = wspath;
#if DEBUG
  printf("Path for receiving message through ws in channel %d: %s\n",
      channel, i_rx[channel].path);
#endif
	i_rx[channel].address = serverIP;
	i_rx[channel].port = serverPort;
	i_rx[channel].host = i_rx[channel].address;
	i_rx[channel].origin = i_rx[channel].address;
	i_rx[channel].protocol = protocols_rx[0].name;
	i_rx[channel].pwsi = & client_wsi_rx[channel];
	i_rx[channel].opaque_user_data = (void *)(intptr_t)channel;

	if (!lws_client_connect_via_info(&i_rx[channel]))
		LOGMSG("Error connecting to SMKEX server\n");

  return 0;
}

void WebSockets::init(const std::string serverIP[], int serverPort[], const std::string clientID[],
                      int nrChannels)
{
  struct lws_context_creation_info info_rx;

  LOGMSG("Initialising WebSockets class\n");

  ISmkexTransport::init(serverIP, serverPort, clientID, nrChannels);

  // Initialise WS RX Context
	memset(&info_rx, 0, sizeof info_rx);
	info_rx.port = CONTEXT_PORT_NO_LISTEN;
	info_rx.protocols = protocols_rx;
	info_rx.timeout_secs = 60;
	info_rx.connect_timeout_secs = 60;
	/*
	 * since we know this lws context is only ever going to be used with
	 * NR_CONNECTIONS client wsis / fds / sockets at a time, let lws know it doesn't
	 * have to use the default allocations for fd tables up to ulimit -n.
	 * It will just allocate for 1 internal and NR_CONNECTIONS + 1 (allowing for h2
	 * network wsi) that we will use.
	 */
	info_rx.fd_limit_per_thread = 1 + NR_CONNECTIONS + 1;
	n_rx = 0;
	context_rx = lws_create_context(&info_rx);
	if (!context_rx)
		LOGMSG("Error creating lws context for receive stream\n");

  // Initialise WS RX connection for each WS server
  for(int k = 0; k < _numberOfChannels; k++)
  {
#if DEBUG
    printf("About to initialise WS RX connection %d\n", k);
#endif
    if(init_rx(k, _serverIP[k].c_str(), _serverPort[k], _clientID[k]))
      LOGMSG("Error initiating WS RX connection\n");
  }

#if DEBUG
  printf("WebSocket constructor done\n");
#endif
}

WebSockets::~WebSockets()
{
	lws_context_destroy(context_rx);
}

int WebSockets::callback_ws(struct lws * wsi, enum lws_callback_reasons reason,
                               void * user, void * in , size_t len)
{
  LOGMSG("In callback_ws\n");
	int channel = (int)(intptr_t)lws_get_opaque_user_data(wsi);

#if DEBUG
  printf("In callback_ws for channel %d\n", channel);
#endif

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
    {
      LOGMSG("Connection Error\n");
      bad[channel] = 1;
      lws_cancel_service(lws_get_context(wsi));
      break;
    }

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
    {
      printf("Connection Closed\n");
      bad[channel] |= status[channel] != 200;
      lws_cancel_service(lws_get_context(wsi));
      break;
    }

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
    {
      printf("Connection Established\n");
      status[channel] = (int)lws_http_client_http_response(wsi);
      break;
    }

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
    {
      printf("Connection Completed\n");
      bad[channel] |= status[channel] != 200;
      lws_cancel_service(lws_get_context(wsi));
      break;
    }

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		if (!lws_http_is_redirected_to_get(wsi)) {
			uint8_t** up = (uint8_t**) in;
			uint8_t* uend = *up + len - 1;
        
      // TODO: check what to do with this returned value
			lws_add_http_header_content_length(wsi, buf_len[channel], up, uend);
			
			lws_client_http_body_pending(wsi, 1);
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
    {
      printf("Send data via POST request\n");
      if (lws_http_is_redirected_to_get(wsi))
        break;
      
      lws_client_http_body_pending(wsi, 0);
      
      unsigned char *start = (unsigned char*)&buf[channel][LWS_PRE];
      lws_write(wsi, start, buf_len[channel], LWS_WRITE_HTTP_FINAL);

      return 0;
    }

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

int WebSockets::callback_ws_rx(struct lws * wsi, enum lws_callback_reasons reason,
                               void * user, void * in , size_t len)
{
  LOGMSG("In callback_ws_rx\n");
	int channel = (int)(intptr_t)lws_get_opaque_user_data(wsi);

#if DEBUG
  printf("In callback_ws_rx for channel %d\n", channel);
#endif

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
    {
      LOGMSG("Connection Error in WS\n");
      client_wsi_rx[channel] = NULL;
      break;
    }

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
    {
      LOGMSG("Connection established in WS\n");
      break;
    }

	case LWS_CALLBACK_CLIENT_RECEIVE:
    {
      LOGMSG("Received data in WS callback\n");
#if DEBUG
      printf("In LWS_CALLBACK_CLIENT_RECEIVE for channel %d\n", channel);
#endif
    
      string rstr((const char * ) in);
      cout << "Received encoded data with len " << rstr.length() << ": " << rstr  << endl;

      // Decode data from base64 (expected)
      string sdata = base64_decode(rstr);

      // Create record (if possible) from received data
      SmkexT4mRecord rec(sdata.c_str(), sdata.length());
      cout << "After creating record" << endl;
      if (rec.getType() != SMKEX_T4M_Type::empty)
      {
        // Notify registered callbacks
        WebSockets::getInstance().processMessage(rec.getSrc(), (const uint8_t*)sdata.c_str(),
                                                  sdata.length(), channel);
      }
      else
        LOGMSG("Empty record in LWS_CALLBACK_CLIENT_RECEIVE");

      break;
    }

	case LWS_CALLBACK_CLIENT_CLOSED:
    {
      client_wsi_rx[channel] = NULL;
      break;
    }

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

// Note: we use multiple RX contexts through the user pointer
// Check here for the current implementation idea:
// https://libwebsockets.org/git/libwebsockets/tree/minimal-examples/http-client/minimal-http-client-multi/minimal-http-client-multi.c
// Or here for another possibility (virtual hosts):
// https://libwebsockets.org/pipermail/libwebsockets/2016-April/006122.html
// https://github.com/warmcat/libwebsockets/blob/main/plugins/protocol_lws_mirror.c
int WebSockets::updateMessagesFromServer()
{
  LOGMSG("In updateMessagesFromServer\n");

  // Check WS connection
	if (n_rx >= 0)
  {
		n_rx = lws_service(context_rx, 0);
#if DEBUG
    printf("For RX connection received n=%d\n", n_rx);
#endif
  }

  LOGMSG("Returning from updateMessagesFromServer\n");

	return 0;
}

// TODO: add some mechanism to avoid sending a new message before the previous one
// has been successfully sent
int WebSockets::sendMessageToBuddy(const std::string &buddy, const uint8_t *data, uint32_t dataLen, int channel)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	struct lws_context *context;
	int n = 0;

  if (channel < 0 || channel >= NR_CONNECTIONS)
  {
    LOGMSG("Incorrect channel index. Returning\n");
    return -1;
  }

  LOGMSG("About to send message to buddy through Web Socket\n");

#if DEBUG
  printf("Length of data (before B64 encoding) to be sent: %d\n", dataLen);
#endif

  // convert to Base64 so we can transmit over HTTP
  if (data == nullptr) {
    MP_LOG1("Atentie - data este null cand am incercat sa trimit! de len: ");
    MP_LOG1_INT(dataLen);
    MP_LOG1("\n");
  } 
  string datab64 = base64_encode(data, dataLen);
  memcpy(buf[channel] + LWS_PRE, datab64.c_str(), datab64.length() + 1);
  delete[] data;
  buf_len[channel] = datab64.length()+1;

  // Setup WS connection params
	memset(&info, 0, sizeof info);
	info.port = CONTEXT_PORT_NO_LISTEN;
	/*
	 * since we know this lws context is only ever going to be used with
	 * NR_CONNECTIONS client wsis / fds / sockets at a time, let lws know it doesn't
	 * have to use the default allocations for fd tables up to ulimit -n.
	 * It will just allocate for 1 internal and NR_CONNECTIONS + 1 (allowing for h2
	 * network wsi) that we will use.
	 */
	info.fd_limit_per_thread = 1 + NR_CONNECTIONS + 1;
  info.protocols = protocols;
  bad[channel] = 0;
  status[channel] = 0;
	context = lws_create_context(&info);
	if (!context) {
    LOGMSG("Error creating lws context\n");
		return -1;
	}

	memset(&i, 0, sizeof i);
	i.context = context;
  string path = SMKEX_TX_PATH;
  path += _clientID[channel];
  path += "/";
  path += buddy;
	i.path = path.c_str();
#if DEBUG
  printf("Sending message on channel %d through ws path %s\n", channel, i.path);
  printf("Length of base64 data to be sent: %d\n", buf_len[channel]);
#endif
  i.address = _serverIP[channel].c_str();
  i.port = _serverPort[channel];
	i.host = i.address;
	i.origin = i.address;
  i.protocol = protocols[0].name;
	i.opaque_user_data = (void *)(intptr_t)channel;
	i.method = "POST";
#if DEBUG
  printf("Sending data to server IP %s and port %d using protocol %s\n",
         i.address, i.port, i.protocol);
#endif
	
	if (!lws_client_connect_via_info(&i))
  {
    LOGMSG("Cannot connect to server/ip\n");
		return -11;
  }

  while (!bad[channel] && !status[channel] && n >= 0)
    n = lws_service(context, 0);

#if DEBUG
  printf("Sending message ended with status=%d and bad=%d\n",
      status[channel], bad[channel]);
#endif

	lws_context_destroy(context);

	return bad[channel];
}

WebSockets &WebSockets::getInstance()
{
  static WebSockets instance;

  return instance;
}

void WebSockets::processMessage(const std::string &serial, const uint8_t *data,
                                uint32_t dataLen, int channel)
{
  if (msgCb_)
    msgCb_->onMsgReceived(serial, data, dataLen, channel);    
}

