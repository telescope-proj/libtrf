#ifndef _TRF_NCP_SERVER_H_
#define _TRF_NCP_SERVER_H_

#include "internal/trfi_ncp_server.h"

/**
  * @brief Initialize the out-of-band negotiation channel client. Sets the
  * client FD inside of the context to an established connection.
  * 
  * @param ctx      Context to use.
  * @param host     Hostname to connect to
  * @param port     Port to connect to.
  * @return 0 on success, negative error code on failure
*/
int trfNCServerInit(PTRFContext ctx, char * host, char * port);

/**
  * @brief Accepts an incoming connection.
  * @param ctx      Context to use.
  * @param ctx_out  Client context.
  * @return 0 on sucess, negative erro code on failure.
*/
int trfNCAccept(PTRFContext ctx, PTRFContext * ctx_out);

/**
  * @brief Close the negotiation channel server, disconneting the client.
  * @param ctx      Context to use
  * @return 0 on success, negative error code on failure
*/
int trfNCServerClose(PTRFContext ctx);

/**
  * @brief Allocate memory for a new session.
  * @param ctx  Context to store connection
  * @param out  Pointer to the created session, also accessible via the client
  * list in ctx
  * @return 0 on success, negative error code on failure.
*/
int trfNCNewSession(PTRFContext ctx, PTRFContext * out);


int trfNCServerDisconnectClient(PTRFContext client_ctx);

#endif // _TRF_NCP_SERVER_H_