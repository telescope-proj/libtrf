/*
    SPDX-License-Identifier: LGPL-2.1-only

    Telescope Project
    Remote Framebuffer Library
    NCP Internal Messaging Functions

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
 * @file trf_msg.h
 * @brief Main channel raw data send/receive functions
 * 
 * This file contains functions to send and receive delimited messages reliably
 * over a TCP socket. You should not need to use this in your programs, as high
 * level abstractions for TRF messages are provided.
 */

#ifndef _TRF_MSG_H_
#define _TRF_MSG_H_

#include <sys/socket.h>
#include <arpa/inet.h>
#include "trf_def.h"
#include "trf_msg.pb-c.h"

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
int trfNCRecvDelimited(TRFSock sock, uint8_t * buf, uint32_t size, int timeout, 
    TrfMsg__MessageWrapper ** handle );

/**
  * @brief Sends a delimited message in TRF Protocol Buffers format.
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
int trfNCSendDelimited(TRFSock sock, uint8_t * buf, uint32_t size, int timeout, 
    TrfMsg__MessageWrapper * handle);

/**
  * @brief        Reliably recieves messages on the socket.
  * 
  * Blocks until a message has been received in its entirety, or a timeout or
  * error occurs.
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
int trfNCFullRecv(TRFSock sock, ssize_t length, uint8_t * buf, int timeout);

/**
  * @brief          Reliably sends messages on the socket.
  *
  * Blocks until a message has been sent in its entirety, or a timeout or error
  * occurs.
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
int trfNCFullSend(TRFSock sock, ssize_t length, uint8_t * buf, int timeout);

/**
 * @brief           Pack message into a buffer to be sent
 * 
 * @param handle    Handle to message wrapper containing message to be sent
 * 
 * @param size      Size of provided buffer
 * 
 * @param buf       Buffer to store packed message
 * 
 * @param size_out  Output size of packed data in bytes
 * 
 * @return          0 on success, negative error code on failure
 */
int trfMsgPack(TrfMsg__MessageWrapper * handle, uint32_t size, uint8_t * buf, 
    uint32_t * size_out);

/**
 * @brief         Unpack delimited message from buffer
 * 
 * @param handle  Handle to be set to unpacked message data
 * 
 * @param size    Length of the serialized message to be decoded
 * 
 * @param buf     Buffer containing message
 * 
 * @return        0 on success, negative error code on failure
 */
int trfMsgUnpack(TrfMsg__MessageWrapper ** handle, uint32_t size, uint8_t * buf);

static inline int32_t trfMsgGetPackedLength(uint8_t * buf)
{
   return ntohl(* (int32_t *) buf);
}

static inline uint8_t * trfMsgGetPayload(uint8_t * buf)
{
    return buf + sizeof(int32_t);
}

#endif