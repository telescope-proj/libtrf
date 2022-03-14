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

#ifndef _TRF_INTERNAL_NCP_H_
#define _TRF_INTERNAL_NCP_H_

#include "trf_ncp.h"

#define trf__Min(a, b) ((a) < (b) ? (a) : (b))
#define trf__Max(a, b) ((a) > (b) ? (a) : (b))
#define trf__ClientFD(ctx) ((ctx)->cli.client_fd)
#define trf__ProtoFree(msg) \
    trf_msg__message_wrapper__free_unpacked(msg, NULL); msg = NULL;

int trf__NCSendTransportNack(PTRFContext ctx, TRFSock sock, uint32_t reason,
                             uint8_t * buffer, size_t size);

int trf__SetSockNonBlocking(TRFSock sock);

int trf__SetSockBlocking(TRFSock sock);

int trf__AddrMsgToInterface(TrfMsg__MessageWrapper * msg, PTRFInterface * out);



#endif // _TRF_INTERNAL_NCP_H_