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

#include "trf_msg.h"
#include "trf_log.h"

int trfMsgPack(TrfMsg__MessageWrapper * handle, uint32_t size, uint8_t * buf, 
    uint32_t * size_out)
{
    if (!handle)
        return -EINVAL;

    size_t to_write = trf_msg__message_wrapper__get_packed_size(handle);
    if (!to_write)
    {
        trf__log_trace("Unable to get message size");
        return -EINVAL;
    } 
    // Protobuf messages must not exceed 2GB in size
    else if (to_write > size - sizeof(uint32_t) 
             || to_write + sizeof(uint32_t) >= (1 << 31))
    {
        trf__log_trace("Buffer too small to store message");
        return -ENOMEM;
    }
    trf__log_trace("To send: %lu, type: %d", to_write, handle->wdata_case);
    * (uint32_t *) buf = htonl(to_write);
    size_t pack_sz = trf_msg__message_wrapper__pack(
        handle, buf + sizeof(uint32_t)
    );
    if (pack_sz != to_write)
    {
        trf__log_trace("Mismatched packed size %lu/%lu", to_write, pack_sz);
        return -EIO;
    }
    *size_out = to_write + sizeof(uint32_t);
    return 0;
}

int trfMsgUnpack(TrfMsg__MessageWrapper ** handle, uint32_t size, uint8_t * buf)
{
    trf__log_trace("Attempting to unpack message %p with size %d", buf, size);
    if (!buf || size == 0 || size >= (1 << 31))
    {
        trf__log_trace("Invalid buffer or size");
        return -EINVAL;
    }
    *handle = trf_msg__message_wrapper__unpack(NULL, size, buf);
    if (!*handle)
    {
        return -EIO;
    }
    trf__log_debug("Unpacked message size: %d, type: %d",
        trf_msg__message_wrapper__get_packed_size(*handle),
        (*handle)->wdata_case);
    return 0;
}