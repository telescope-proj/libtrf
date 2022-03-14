#ifndef _TRF_INTERNAL_NCP_SERVER_H_
#define _TRF_INTERNAL_NCP_SERVER_H_

#include "internal/trfi_ncp.h"

int trf__NCServerCreateSocket(const char * host, const char * port,
                              TRFSock * sock);

int trf__NCServerExchangeVersions(PTRFContext ctx, TRFSock client_sock,
                                  uint8_t * buffer, size_t size,
                                  uint64_t * session_id);

int trf__NCServerExchangeViableLinks(PTRFContext ctx, TRFSock client_sock,
                                     uint8_t * buffer, size_t size,
                                     PTRFAddrV * av);

int trf__NCServerGetClientFabrics(PTRFContext ctx, TRFSock client_sock,
                                  uint64_t session_id, 
                                  uint8_t * buffer, size_t size,
                                  PTRFContext * new_ctx);

#endif // _TRF_INTERNAL_NCP_SERVER_H_