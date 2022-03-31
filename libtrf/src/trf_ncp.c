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

#include "trf_ncp.h"

int trfNCPollMsg(TRFSock sock)
{
    if (!trfSockValid(sock))
        return -ENOTSOCK;

    int ret;
    uint32_t delim;
    ret = recv(sock, &delim, 4, MSG_PEEK | MSG_NOSIGNAL);
    if (ret < 0)
        return -errno;

    //trf__log_trace("Peeked message header: %d", ntohl(delim));
    
    return ret;
}

int trfNCRecvMsg(TRFSock sock, uint8_t * buf, uint32_t size, int timeout, 
    TrfMsg__MessageWrapper ** handle )
{
    if (!trfSockValid(sock) || !buf || !size || !handle)
        return -EINVAL;

    int ret;
    uint32_t len;

    // Receive 4-byte delimiter and convert to host byte order
    ret = trfNCFullRecv(sock, 4, buf, timeout);
    if (ret != 4)
    {
        trf__log_trace("Message header receive failed");
        return ret < 0 ? ret : -EIO;
    }

    // Protobuf messages must not exceed 2GB in size
    len = ntohl(* (uint32_t *) buf);
    if (len > size || len > (1 << 31))
    {
        trf__log_trace(
            "Message length %d invalid or exceeds buffer size %d",
            len, size
        );
        return -EIO;
    }

    // Receive message payload
    ret = trfNCFullRecv(sock, len, buf, timeout);
    if (ret != len)
    {
        trf__log_trace("Message receive failed");
        return ret < 0 ? ret : -EIO;
    }

    // Attempt to unpack the message
    return trfMsgUnpack(handle, len, buf);
}

int trfNCSendMsg(TRFSock sock, uint8_t * buf, uint32_t size, int timeout, 
    TrfMsg__MessageWrapper * handle)
{
    trf__log_trace("trfNCSendDelimited(sock: %d, buf: %p, size: %d, "
                   "timeout: %d, handle: %p)",
                   sock, buf, size, timeout, handle);
    if (!trfSockValid(sock) || !buf || !size || !handle)
    {
        return -EINVAL;
    }

    int ret;
    
    // Pack message to be sent.
    uint32_t to_write;
    ret = trfMsgPack(handle, size, buf, &to_write);
    if (ret < 0)
    {
        return ret;
    }

    // Send complete message
    ret = trfNCFullSend(sock, to_write, buf, timeout);
    if (ret != to_write)
    {
        return ret < 0 ? ret : -EIO;
    }

    return 0;
}

int trfNCRecv(TRFSock sock, ssize_t len, uint8_t * buf, 
    int timeout)
{
    struct timespec deadline;
    trfGetDeadline(&deadline, timeout);
    ssize_t cur_recv = 0;
    ssize_t loop_recv = 0;
    trf__log_trace("<< %d bytes", len);
    while (len != cur_recv)
    {
        loop_recv = recv(sock, buf + cur_recv, len - cur_recv, MSG_NOSIGNAL);
        switch (loop_recv)
        {
            case 0:
                trf__log_trace("Connection closed");
                return -ENOTCONN;
            case -1:
                if (errno == EAGAIN)
                    break;

                trf__log_trace("Recv failed: %s", strerror(errno));
                return -errno;
            default:
                cur_recv += loop_recv;
        }
        if (trf__HasPassed(CLOCK_MONOTONIC, &deadline))
        {
            break;
        }
        trfSleep(1);
    }
    trf__log_trace("Receive Completed");
    return cur_recv;
}

int trfNCSend(TRFSock sock, ssize_t len, uint8_t * buf,
    int timeout)
{
    struct timespec deadline;
    trfGetDeadline(&deadline, timeout);
    ssize_t cur_send = 0;
    ssize_t loop_send = 0;
    trf__log_trace(">> %d bytes", len);
    while (len != cur_send)
    {
        loop_send = send(sock, buf + cur_send, len - cur_send, MSG_NOSIGNAL);
        switch (loop_send)
        {
            case 0:
                trf__log_trace("Connection closed");
                return -ENOTCONN;
            case -1:
                if (errno == EAGAIN)
                    break;

                trf__log_trace("Send failed: %s", strerror(errno));
                return -errno;
            default:
                cur_send += loop_send;
        }
        if (trf__HasPassed(CLOCK_MONOTONIC, &deadline))
        {
            break;
        }
        trfSleep(1);
    }
    trf__log_trace("Send Completed");
    return cur_send;
}