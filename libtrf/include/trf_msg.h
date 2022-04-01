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
 * @return          Number of bytes written, negative error code on failure.
 */
ssize_t trfMsgPack(TrfMsg__MessageWrapper * handle, uint32_t size, uint8_t * buf);

/**
 * @brief           Pack message into a buffer to be sent. Generic version.
 * 
 * @param handle    Handle to message wrapper containing message to be sent
 * 
 * @param size      Size of provided buffer
 * 
 * @param buf       Buffer to store packed message
 * 
 * @param size_out  Output size of packed data in bytes
 * 
 * @return          Number of bytes written, negative error code on failure.
 */
ssize_t trfMsgPackProtobuf(ProtobufCMessage * message, uint32_t size,
                           uint8_t * buf);

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
ssize_t trfMsgUnpack(TrfMsg__MessageWrapper ** handle, uint32_t size,
                     uint8_t * buf);

/**
 * @brief         Unpack delimited message from buffer. Generic version.
 * 
 * @param handle  Handle to be set to unpacked message data
 * 
 * @param size    Length of the serialized message to be decoded
 * 
 * @param buf     Buffer containing message
 * 
 * @return        0 on success, negative error code on failure
 */
ssize_t trfMsgUnpackProtobuf(ProtobufCMessage ** out,
                             const ProtobufCMessageDescriptor * desc,
                             size_t size, uint8_t * buf);


static inline int32_t trfMsgGetPackedLength(uint8_t * buf)
{
   return ntohl(* (int32_t *) buf);
}

static inline uint8_t * trfMsgGetPayload(uint8_t * buf)
{
    return buf + sizeof(int32_t);
}

#endif