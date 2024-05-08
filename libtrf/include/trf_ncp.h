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
#include "trf_def.h"
#include "trf_msg.h"
#include "trf_inet.h"
#include "trf_interface.h"
#include "trf_protobuf.h"
#include "trf_platform.h"

#include <string.h>
#include <stdlib.h>

#if defined(__linux__)
#include <linux/sockios.h>
#include <linux/if.h>
#include <linux/ethtool.h>
#endif

#if defined(_TRF_UNIX_)
    #include <ifaddrs.h>
    #include <sys/ioctl.h>
    #include <netinet/in.h>
    #if defined(_TRF_OSX_)
        #include "osx/endian.h"
    #else
        #include <endian.h>
    #endif
    #include <fcntl.h>
#endif

#define TRF_API_MAJOR    0
#define TRF_API_MINOR    3
#define TRF_API_PATCH    9

// Preserved for compatibility
#define trfNCSendDelimited trfNCSendMsg
#define trfNCRecvDelimited trfNCRecvMsg
#define trfNCFullRecv trfNCRecv
#define trfNCFullSend trfNCSend

/**
 * @brief           Poll for incoming messages on the socket.
 * 
 * @param sock      Socket descriptor.
 * 
 * @return          Whether there is an incoming message.
 *                  Negative error code on failure.
 */
int trfNCPollMsg(TRFSock sock);

/**
  * @brief          Receive a delimited message in TRF Protocol Buffers format.
  * 
  * @param sock     Socket descriptor to receive from.
  * 
  * @param buf      Buffer to receive data into
  * 
  * @param size     Buffer max size
  * 
  * @param timeout  Receive timeout
  * 
  * @param handle   Handle to received message (raw data stored inside buf)
  * 
  * @return 0 on success, negative error code on failure
*/
int trfNCRecvMsg(TRFSock sock, uint8_t * buf, uint32_t size, int timeout, 
    TrfMsg__MessageWrapper ** handle);

/**
  * @brief          Sends a delimited message in TRF Protocol Buffers format.
  * 
  * @param fd       File descriptor to send to.
  * 
  * @param buf      Scratch buffer for writing data to be sent
  * 
  * @param size     Buffer max size
  * 
  * @param timeout  Send timeout in milliseconds
  * 
  * @param handle   Message data handle, to be packed into buf and sent
  * 
  * @return         0 on success, negative error code on failure.
*/
int trfNCSendMsg(TRFSock sock, uint8_t * buf, uint32_t size, int timeout, 
    TrfMsg__MessageWrapper * handle);

/**
  * @brief          Reliably recieves messages on the socket.
  *
  *                 Blocks until a message has been received in its entirety, or
  *                 a timeout or error occurs.
  *
  * @param sock     Socket to read from.
  *
  * @param size     TNumber of bytes to receive.
  *
  * @param buf      Pointer to buffer where message will be stored
  *
  * @param timeout  Timeout in milliseconds
  *
  * @return         0 on success, negative error code on failure
*/
int trfNCRecv(TRFSock sock, ssize_t length, uint8_t * buf, int timeout);

/**
  * @brief          Reliably sends messages on the socket.
  *
  *                 Blocks until a message has been sent in its entirety, or a 
  *                 timeout or error occurs.
  * 
  * @param sock     Socket to send to.
  * 
  * @param size     Number of bytes to send.
  * 
  * @param buf      Buffer containing the message to be sent
  * 
  * @param timeout  Timeout in milliseconds
  * 
  * @return         0 on success, negative error code on failure
*/
int trfNCSend(TRFSock sock, ssize_t length, uint8_t * buf, int timeout);

/**
  * @brief Add Protobuf message to PTRFInterface
  * @param msg      Protobuf message wrapper
  * @param out      PTRFInterface to message to be decoded into
  * @return 0 on success, negative error code on failure
*/
int trf__AddrMsgToInterface(TrfMsg__MessageWrapper * msg, PTRFInterface * out);

#endif