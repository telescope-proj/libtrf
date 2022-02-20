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
  * @brief Receive a delimited message in TRF Protocol Buffers format.
  * @param File descriptor to receive from.
  * @param buf      Buffer to receive data into
  * @param size     Buffer max size
  * @param timeout  Receive timeout
  * @param handle   Handle to received message (raw data stored inside buf)
  * @return 0 on success, negative error code on failure
*/
int trfNCRecvDelimited(int fd, uint8_t * buf, uint32_t size, int timeout, 
    TrfMsg__MessageWrapper ** handle );

/**
  * @brief Sends a delimited message in TRF Protocol Buffers format.
  * @param fd       File descriptor to send to.
  * @param buf      Scratch buffer for writing data to be sent
  * @param size     Buffer max size
  * @param timeout  Send timeout
  * @param handle Message data handle, to be packed into buf and sent
  * @return 0 on success, negative error code on failure.
*/
int trfNCSendDelimited(int fd, uint8_t * buf, uint32_t size, int timeout, 
    TrfMsg__MessageWrapper * handle );

/**
  * @brief Receives a message. Blocks until all bytes are received.
  * @param client_socket        Socket to read data from
  * @param message_length       Length of message to be received
  * @param client message       buffer to store the message
  * @return number of bytes transferred, -1 on error
*/
int trfNCFullRecv(int client_socket, ssize_t message_length, 
  unsigned char * client_message);

/**
  * @brief Sends a message. Blocks until all bytes are received.
  * @param server_socket    File descriptor to send data into
  * @param message_length   Length of messsage to send
  * @param message          Buffer of message to send  
  * @return The number of bytes transferred, -1 on error   
*/
int trfNCFullSend(int server_socket, ssize_t message_length, 
  unsigned char * message);

/**
 * @brief Pack Message into memory buffer for sending over libfabric
 * 
 * @param handle      MessageWrapper containing data
 * @param size        Size of buffer
 * @param buf         Buffer to serialize message into
 * @param size_out    Output size of data packed
 * @return 0 on success, Negative error code on error
 */
int trfFabricPack(TrfMsg__MessageWrapper * handle, uint32_t size, void * buf, 
    uint32_t * size_out);

/**
 * @brief Unpack Message received from libfabric
 * @param ctx   Context to use
 * @param msg   Message wrapper to decode into
 * @param size  Size of message to be decoded
 * @return 0 on success, Negative error code on error
 */
int trfMsgUnpack(PTRFContext ctx, TrfMsg__MessageWrapper **msg, uint64_t size);

#endif