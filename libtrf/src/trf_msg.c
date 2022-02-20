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

int trfNCRecvDelimited(int fd, uint8_t * buf, uint32_t size, int timeout, 
    TrfMsg__MessageWrapper ** handle )
{
    if (fd < 0 || !buf || !size || !handle)
        return -EINVAL;

    // Receive 4-byte delimiter and convert to host byte order
    int ret;
    uint32_t len;
    if ((ret = trfNCFullRecv(fd, 4, (uint8_t *) &len)) != 4)
    {
        trf__log_trace("Receive failed");
        return ret;
    }
    len = ntohl(len);
    if (len > size)
    {
        trf__log_trace(
            "Message length %d invalid or exceeds buffer size %d",
            len, size
        );
        return -EIO;
    }

    // Receive message payload
    trf__log_debug("Message length %d", len);
    if (trfNCFullRecv(fd, len, buf) != len)
    {
        trf__log_trace("Message receive failed");
        return -EIO;
    }
    trf__log_trace("Received message");
    
    *handle = trf_msg__message_wrapper__unpack(NULL, len, buf);
    if (!*handle)
    {
        trf__log_trace("Unknown decoding error");
        return -EIO;
    }

    return 0;
}

int trfNCSendDelimited(int fd, uint8_t * buf, uint32_t size, int timeout, 
    TrfMsg__MessageWrapper * handle )
{
    if (fd < 0 || !buf || !size || !handle)
        return -EINVAL;

    size_t to_write = trf_msg__message_wrapper__get_packed_size(handle);
    if (!to_write)
    {
        trf__log_trace("Unable to get message size");
        return -EINVAL;
    } else if (to_write > (size - sizeof(uint32_t)))
    {
        trf__log_trace("Buffer too small to store message");
        return -ENOMEM;
    }
    trf__log_trace("To send: %lu", to_write);
    * (uint32_t *) buf = htonl(to_write);
    size_t pack_sz = trf_msg__message_wrapper__pack(
        handle, buf + sizeof(uint32_t)
    );
    if (pack_sz != to_write)
    {
        trf__log_trace("Mismatched packed size %lu/%lu", to_write, pack_sz);
        return -EIO;
    }
    if (trfNCFullSend(fd, to_write + 4, buf) != to_write + 4)
    {
        trf__log_trace("Write failed");
        return -EIO;
    }

    return 0;
}

int trfNCFullRecv(int client_socket, ssize_t len, uint8_t * client_message)
{
    ssize_t cur_recv = 0;
    ssize_t loop_recv = 0;
    trf__log_trace("<< %d bytes", len);
    while (len != cur_recv)
    {
        loop_recv = recv(
            client_socket, client_message + cur_recv, len - cur_recv, 
            MSG_NOSIGNAL
        );
        switch (loop_recv)
        {
            case 0:
                trf__log_trace("Connection closed");
                return -ENOTCONN;
            case -1:
                trf__log_trace("Recv failed: %s", strerror(errno));
                return -errno;
            default:
                cur_recv += loop_recv;
        }
    }
    trf__log_trace("Receive Completed");
    return cur_recv;
}

int trfNCFullSend(int client_socket, ssize_t len, uint8_t * client_message)
{
    ssize_t cur_send = 0;
    ssize_t loop_send = 0;
    trf__log_trace(">> %d bytes", len);
    while (len != cur_send)
    {
        loop_send = send(
            client_socket, client_message + cur_send, len - cur_send, 
            MSG_NOSIGNAL
        );
        switch (loop_send)
        {
            case 0:
                trf__log_trace("Connection closed");
                return -ENOTCONN;
            case -1:
                trf__log_trace("Send failed: %s", strerror(errno));
                return -errno;
            default:
                cur_send += loop_send;
        }
    }
    trf__log_trace("Send Completed");
    return cur_send;
}

int trfFabricPack(TrfMsg__MessageWrapper * handle, uint32_t size, void * buf, 
    uint32_t * size_out)
{
    if (!handle)
        return -EINVAL;

    size_t to_write = trf_msg__message_wrapper__get_packed_size(handle);
    if (!to_write)
    {
        trf__log_trace("Unable to get message size");
        return -EINVAL;
    } else if (to_write > (size - sizeof(uint32_t)))
    {
        trf__log_trace("Buffer too small to store message");
        return -ENOMEM;
    }
    trf__log_trace("To send: %lu", to_write);
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

int trfMsgUnpack(PTRFContext ctx, TrfMsg__MessageWrapper **msg, uint64_t size){
    * msg = trf_msg__message_wrapper__unpack(NULL, size, 
        ctx->xfer.fabric->msg_ptr + sizeof(uint32_t));
    if(!*msg){
        return -1;
    }
    return 0;
}