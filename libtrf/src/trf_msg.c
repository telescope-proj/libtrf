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

ssize_t trfMsgPackProtobuf(ProtobufCMessage * msg, uint32_t size, uint8_t * buf)
{
    if (!msg || !protobuf_c_message_check(msg))
        return -EINVAL;

    size_t to_write = protobuf_c_message_get_packed_size(msg);
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
        return -ENOBUFS;
    }
    trf__log_trace("To send: %lu", to_write);
    * (uint32_t *) buf = htonl(to_write);
    size_t pack_sz = protobuf_c_message_pack(msg, buf + sizeof(uint32_t));
    if (pack_sz != to_write)
    {
        trf__log_trace("Mismatched packed size %lu/%lu", to_write, pack_sz);
        return -EIO;
    }
    return to_write + sizeof(uint32_t);
}

ssize_t trfMsgPack(TrfMsg__MessageWrapper * handle, uint32_t size,
                   uint8_t * buf)
{
    return trfMsgPackProtobuf((ProtobufCMessage *) handle, size, buf);
}

ssize_t trfMsgUnpackProtobuf(ProtobufCMessage ** out,
                             const ProtobufCMessageDescriptor * desc,
                             size_t size, uint8_t * buf)
{
    if (!out || !desc || !size || !buf)
        return -EINVAL;

    *out = protobuf_c_message_unpack(desc, NULL, size, buf);
    if (!*out)
        return -EIO;

    return 0;
}

ssize_t trfMsgUnpack(TrfMsg__MessageWrapper ** handle, uint32_t size,
                     uint8_t * buf)
{
    return trfMsgUnpackProtobuf((ProtobufCMessage **) handle, 
                                (const ProtobufCMessageDescriptor *) 
                                &trf_msg__message_wrapper__descriptor,
                                size, buf);
}