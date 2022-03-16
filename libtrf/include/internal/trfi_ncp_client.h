/*
    SPDX-License-Identifier: LGPL-2.1-only

    Telescope Project
    Remote Framebuffer Library
    Negotiation Channel Protocol

    Copyright (c) 2022 Tim Dettmar

    This library is free software; you can redistribute it and/or modify it
    under the terms of the GNU Lesser General Public License as published by the
    Free Software Foundation; version 2.1. 

    This library is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
    for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this library; if not, write to the Free Software Foundation,
    Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
*/

#ifndef _TRF_INTERNAL_NCP_CLIENT_H_
#define _TRF_INTERNAL_NCP_CLIENT_H_

#include "internal/trfi_ncp.h"

int trf__NCCreateClientSocket(const char * host, const char * port,
                              TRFSock * sock);

int trf__NCSendClientHello(PTRFContext ctx, uint8_t * buffer, size_t size);


int trf__NCRecvServerHello(PTRFContext ctx, uint8_t * buffer, size_t size,
                           TrfMsg__MessageWrapper ** out);

int trf__NCSendInterfaceList(PTRFContext ctx, uint8_t * buffer, size_t size,
                             uint64_t flags);

int trf__NCRecvServerAddrs(PTRFContext ctx, uint8_t * buffer, size_t size,
                           PTRFInterface * out);

int trf__NCSendClientTransports(PTRFContext ctx, PTRFInterface dests, 
                                uint8_t * buffer, size_t size);

int trf__NCRecvAndTestCandidate(PTRFContext ctx, uint8_t * buffer, size_t size);

#endif // _TRF_INTERNAL_NCP_CLIENT_H_