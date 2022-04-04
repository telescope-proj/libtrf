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

#include "internal/trfi_ncp_client.h"

int trfNCClientInit(PTRFContext ctx, char * host, char * port)
{
    if (!ctx)
    {
        trf__log_error("Client init: Invalid connection context");
        return -EINVAL;
    }

    // Read OS specific configurations
    #if (defined (_TRF_OSX_))
    if(trfParseConfig("conf/osx/networks.conf") < 0)
    #else
    if(trfParseConfig("conf/linux/networks.conf") < 0)
    #endif
    {
        trf__log_error("Unable to open up config file");
        return -EINVAL;
    }

    if (!ctx->opts)
    {
        PTRFContextOpts opts = calloc(1, sizeof(struct TRFContextOpts));
        trfSetDefaultOpts(opts);
        ctx->opts = opts;
    }

    if (ctx->xfer.fabric)
    {
        trf__log_error("Client already initialized");
        return -EALREADY;
    }

    trf__log_info("libtrf client %d.%d.%d initializing", 
        TRF_API_MAJOR, TRF_API_MINOR, TRF_API_PATCH
    );

    int ret;

    ret = trf__NCCreateClientSocket(host, port, &ctx->cli.client_fd);
    if (ret < 0)
    {
        trf__log_error("Failed to create client socket");
        return ret;
    }

    trf__log_debug("Connected");

    // Set up buffers

    size_t buff_size = ctx->opts->nc_snd_bufsize > ctx->opts->nc_rcv_bufsize ?
        ctx->opts->nc_snd_bufsize : ctx->opts->nc_rcv_bufsize;
    uint8_t * buff = trfAllocAligned(buff_size, trf__GetPageSize());
    if (!buff)
    {
        trf__log_error("Unable to allocate buffer!");
        goto close_sock;
    }

    // Send hello message

    ret = trf__NCSendClientHello(ctx, buff, buff_size);
    if (ret < 0)
    {
        trf__log_error("Failed to send client hello message");
        goto free_buff;
    }

    // Get session ID from server

    TrfMsg__MessageWrapper * msg = NULL;
    ret = trf__NCRecvServerHello(ctx, buff, buff_size, &msg);
    if (ret < 0 || !msg)
    {
        trf__log_error("Failed to receive server hello message");
        goto free_buff;
    }

    switch (msg->wdata_case)
    {
        case TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_HELLO:
            ctx->cli.session_id = msg->server_hello->new_session_id;
            break;
        case TRF_MSG__MESSAGE_WRAPPER__WDATA_SERVER_REJECT:
        {
            TrfMsg__APIVersion * ver = msg->server_reject->version;
            trf__log_error(
                "API ver. mismatch! "
                "Client Version: %d.%d.%d; Server: %d.%d.%d",
                TRF_API_MAJOR, TRF_API_MINOR, TRF_API_PATCH,
                ver->api_major, ver->api_minor, ver->api_patch
            );
            goto free_buff;
        }
        default:
            trf__log_error("Unexpected message type in buffer!");
            goto free_buff;
    }

    trf__ProtoFree(msg);
    trf__log_info("API version valid. Session: %lu", 
                  ctx->cli.session_id);

    // Send list of client interfaces

    ret = trf__NCSendInterfaceList(ctx, buff, buff_size, 0);
    if (ret < 0)
    {
        trf__log_error("Failed to send interface list");
        goto free_buff;
    }

    // Receive possibly viable address from server
    
    PTRFInterface svr_ifs = NULL;
    ret = trf__NCRecvServerAddrs(ctx, buff, buff_size, &svr_ifs);
    if (ret < 0 || !svr_ifs)
    {
        trf__log_error("Failed to receive server address message: %s",
                       strerror(-ret));
        goto free_buff;
    }

    // Determine client transports which are viable

    ret = trf__NCSendClientTransports(ctx, svr_ifs, buff, buff_size);
    if (ret < 0)
    {
        trf__log_error("Failed to send client transport message");
        goto free_svr_if_list;
    }

    // Get a viable transport that we can try to connect to. We will try
    // connections one by one until we either find a working connection, or the
    // server gives up and has no more entries to send.

    int index = 0;
    int ret2 = 0;
    do {
        ret = trf__NCRecvAndTestCandidate(ctx, buff, buff_size);
        if (ret == 0)
        {
            trf__log_debug("Fabric connection established");
            break;
        }
        else if (ret == -ETIMEDOUT)
        {
            ret2 = trf__NCSendTransportNack(ctx, trf__ClientFD(ctx), index, 
                                            -ret, buff, buff_size);
            if (ret2 < 0)
            {
                break;
            }
        }
        index++;
    } while (ret == -ETIMEDOUT);

    if (ret2 != 0)
    {
        trf__log_error("Failed to send transport NACK: %s. Fabric status: %s", 
                       strerror(-ret2), fi_strerror(-ret));
        goto free_svr_if_list;
    }

    if (ret != 0)
    {
        trf__log_error("Fabric connection failed: %s", strerror(-ret));
        goto free_svr_if_list;
    }

    ctx->type = TRF_EP_SINK;

    // Connected - clean up, but keep the control channel open

    trfFreeInterfaceList(svr_ifs);
    free(buff);

    return 0;
    
free_svr_if_list:
    trfFreeInterfaceList(svr_ifs);
free_buff:
    free(buff);
close_sock:
    if (trfSockValid(ctx->cli.client_fd)) {
        close(ctx->cli.client_fd);
        ctx->cli.client_fd = -1;
    }
    return ret;
}

int trfNCClientClose(PTRFContext ctx)
{
    if (!ctx)
    {
        trf__log_error("Client close: Invalid connection context");
        return -EINVAL;
    }

    if (ctx->cli.client_fd <= 0)
    {
        trf__log_error("Client close: No connection");
        return -ENOTCONN;
    }

    TrfMsg__MessageWrapper msg = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__Disconnect disc = TRF_MSG__DISCONNECT__INIT;
    msg.wdata_case = TRF_MSG__MESSAGE_WRAPPER__WDATA_DISCONNECT;
    msg.disconnect = &disc;
    disc.info = 0;

    size_t bufsz = trf_msg__message_wrapper__get_packed_size(&msg);
    uint8_t * buff = calloc(1, bufsz);

    trfNCSendDelimited(ctx->cli.client_fd, buff, bufsz, 0, &msg);

    close(ctx->cli.client_fd);
    ctx->cli.client_fd = -1;
    return 0;
}