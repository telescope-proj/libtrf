#ifndef _TRF_NCP_CLIENT_H_
#define _TRF_NCP_CLIENT_H_

#include "internal/trfi_ncp_client.h"

/**
  * @brief Initiate client resources and negotiate with the server.
  * @param ctx      Context to use
  * @param host     Server host
  * @param port     Server port
  * @return 0 on success, negative erro code on error.
*/
int trfNCClientInit(PTRFContext ctx, char * host, char * port);

/**
  * @brief Close the negotiation channel from the client.
  * @param ctx  Context to use.
  * @return 0 on success, negative error code on failure.
*/
int trfNCClientClose(PTRFContext ctx);

#endif // _TRF_NCP_CLIENT_H_