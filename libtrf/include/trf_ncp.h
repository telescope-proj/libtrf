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

/**
 * @file    trf_ncp.h
 * @brief   Negotiation Channel Protocol Messaging Functions
 */

#ifndef _TRF_NCP_H_
#define _TRF_NCP_H_

#include "trf.h"
#include "trf_msg.h"
#include "trf_inet.h"
#include "trf_interface.h"
#include "trf_protobuf.h"

#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>

#if defined(__linux__)
#include <linux/sockios.h>
#include <linux/if.h>
#include <linux/ethtool.h>
#endif

#include <endian.h>

#define TRF_API_MAJOR    0
#define TRF_API_MINOR    1
#define TRF_API_PATCH    0

/**
  * @brief Initializes the out of band negatiation channel for the server. Sets the listening FD inside the context.
  * @param ctx      Context to use
  * @param host     Hostname to bind to
  * @param port     Port to bind to
  * @return 0 on success, negative error code on failure
*/
int trfNCServerInit(PTRFContext ctx, char * host, char * port);


/**
  * @brief Initialize the out-of-band negotiation channel client. Sets the client FD inside of the context to an established connection.
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
  * @brief Clos the negotiation channel server, disconneting the client.
  * @param ctx      Context to use
  * @return 0 on success, negative error code on failure
*/
int trfNCServerClose(PTRFContext ctx);

/**
  * @brief Initiate the client server communitation, sending API version
  * @param ctx      Context to use
  * @param host     Server host
  * @param port     Server port
  * @return 0 on success, negative erro code on error.
*/
int trfNCClientInit(PTRFContext ctx, char * host, char * port);

/**
  * @brief Close the negotiation channel from client.
  * @param ctx  Context to use.
  * @return 0 on success, negative error code on failure.
*/
int trfNCClientClose(PTRFContext ctx);

/**
  * @brief Allocate memory for a new session.
  * @param ctx  Context to store connection
  * @param out  Pointer to the created session, also accessible via the client list in ctx
  * @return 0 on success, negative error code on failure.
*/
int trfNCNewSession(PTRFContext ctx, PTRFContext * out);

/**
  * @brief Add Protobuf message to PTRFInterface
  * @param msg      Protobuf message wrapper
  * @param out      PTRFInterface to message to be decoded into
  * @return 0 on success, negative error code on failure
*/
int trf__AddrMsgToInterface(TrfMsg__MessageWrapper * msg, PTRFInterface * out);

/**
 * @brief Receive a message on the main channel, into the message buffer.
 * @note  This function is not thread safe.
 *
 * @param ctx           Context. Clients should specify their contexts created
 *                      by trfNCClientInit(), while servers should specify the
 *                      client connection identifier created by trfNCAccept().
 *
 * @param timeout_ms    Receive timeout in milliseconds. If the timeout is
 *                      reached, the function returns with a negative error
 *                      -ETIMEDOUT. To block forever, use a timeout of -1.
 *
 * @param rate_limit    Polling rate limit. The polling routines wait the given
 *                      number of milliseconds before checking for new data.
 *                      There are two special values: 0 means no rate limit, and
 *                      -1 attempts to use synchronous polling routines.
 *
 * @param out           Pointer to the allocated message buffer. The data stored
 *                      within this buffer should be freed by the caller.
 *
 *                      @warning The data format returned by this function is
 *                      not guaranteed to be stable. You must free the message
 *                      using the trfFreeMessage() function, instead of calling
 *                      free().
 *
 * @param msg_type      Pointer to the message type. This is an output parameter
 *                      set to the message type flag of the received message,
 *                      corresponding to a value in enum TRFM_Type.
 *
 * @return              0 on success, negative error code on failure. 
 *
 *                      -ETIMEDOUT is returned if the timeout is reached. 
 *
 *                      -EBADMSG is returned if the received message is either
 *                      malformed or inapproriate for the current context.
*/
// int trfGetMessage(PTRFContext ctx, int timeout_ms, int rate_limit, void ** out,
//     int * msg_type);

// static void trfFreeMessage(void * msg)
// {
//     if (msg)
//         trf_msg__message_wrapper__free_unpacked(msg, NULL);
// }

#endif