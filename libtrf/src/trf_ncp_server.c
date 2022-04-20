/*
    SPDX-License-Identifier: LGPL-2.1-only

    Telescope Project
    Remote Framebuffer Library
    NCP Server Functions

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

#include "internal/trfi_ncp_server.h"

// Client-server OOB connection setup

int trfNCServerInit(PTRFContext ctx, char * host, char * port)
{
    srand(time(NULL));
    if (!ctx)
    {
        trf__log_error("Server init: Invalid connection context");
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

    if (ctx->svr.listen_fd > 0)
    {
        trf__log_error("Server init: Socket exists");
        return -EALREADY;
    }

    trf__log_info("libtrf server %d.%d.%d initializing",
        TRF_API_MAJOR, TRF_API_MINOR, TRF_API_PATCH
    );

    // Create the socket

    int ret;
    ret = trf__NCServerCreateSocket(host, port, &ctx->svr.listen_fd);
    if (ret < 0)
    {
        trf__log_error("Server init: Failed to create socket");
        return ret;
    }

    return 0;

}

int trfNCAccept(PTRFContext ctx, PTRFContext * ctx_out)
{
    // Check the socket has been created
    if (!ctx->svr.listen_fd)
    {
        return -EINVAL;
    }

    // Allocate a message buffer
    int ret = 0;
    socklen_t client_size;
    size_t mbuf_size = ctx->opts->nc_snd_bufsize > ctx->opts->nc_rcv_bufsize ?
        ctx->opts->nc_snd_bufsize : ctx->opts->nc_rcv_bufsize;
    uint8_t * mbuf = calloc(1, mbuf_size);
    if (!mbuf)
    {
        return -ENOMEM;
    }
    
    // Accept an incoming connection on the side channel
    struct sockaddr_in6 client_addr;
    TRFSock client_sock = TRFInvalidSock;
    client_size = sizeof(client_addr);
    client_sock = accept(
        ctx->svr.listen_fd, (struct sockaddr *) &client_addr, &client_size
    );
    if (!trfSockValid(client_sock))
    {
        if (errno != EINTR)
        {
            trf__log_error("Unable to accept client connection: %s",
                           strerror(errno));
        }
        ret = -errno;
        goto free_buf;
    }

    trf__SetSockNonBlocking(client_sock);

    // Receive client hello message and verify API version
    
    uint64_t session_id = 0;
    ret = trf__NCServerExchangeVersions(ctx, client_sock, mbuf, mbuf_size,
                                        &session_id);
    if (ret < 0)
    {
        trf__log_error("Version exchange failed: %s", strerror(-ret));
        goto close_sock;
    }

    // Once we have a connection, we will receive a list of client addresses and
    // send back the viable ones

    ret = trf__NCServerExchangeViableLinks(ctx, client_sock, mbuf, mbuf_size,
                                           NULL);
    if (ret < 0)
    {
        trf__log_error("Unable to get viable links: %s", strerror(-ret));
        goto close_sock;
    }

    // The client will send back fabric interfaces that are viable. Keep trying
    // until a valid interface is found.

    PTRFContext cli_ctx = NULL;
    ret = trf__NCServerGetClientFabrics(ctx, client_sock, session_id, mbuf,
                                        mbuf_size, &cli_ctx);
    if (ret < 0)
    {
        trf__log_error("Unable to find common fabric interface: %s", 
                       fi_strerror(-ret));
        goto close_sock;
    }

    // Return the created context

    cli_ctx->cli.client_fd = client_sock;
    *ctx_out = cli_ctx;
    free(mbuf);
    return 0;

close_sock:
    if (client_sock) {
        close(client_sock);
    }
free_buf:
    free(mbuf);
    return ret;
}

int trfNCNewSession(PTRFContext ctx, PTRFContext * out)
{
    int ret;    
    if (ctx->type != TRF_EP_SOURCE)
        return -EINVAL;
    
    uint64_t session_id = trf__Rand64();
    if (session_id == 0)
    {
        trf__log_error("trf__Rand64() returned invalid session ID");
        return -EAGAIN;
    }
    if (trf__CheckSessionID(ctx, session_id) < 0)
    {
        ret = trf__AllocSessionForClient(ctx, session_id, out);
        if (ret)
        {
            trf__log_error("Could not allocate session");
            return ret;
        }
    }
    return 0;
}

int trfNCServerClose(PTRFContext ctx)
{
    if (!ctx)
    {
        trf__log_error("Server close: Invalid connection context");
        return -EINVAL;
    }

    if (!ctx->svr.clients)
    {
        trf__log_error("No clients");
        return -ENOTCONN;
    }

    if (ctx->svr.listen_fd <= 0)
    {
        trf__log_error("Server close: No connection");
        return -ENOTCONN;
    }

    TrfMsg__MessageWrapper msg = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__Disconnect disc = TRF_MSG__DISCONNECT__INIT;
    msg.wdata_case = TRF_MSG__MESSAGE_WRAPPER__WDATA_DISCONNECT;
    msg.disconnect = &disc;
    disc.info = 0;

    size_t bufsz = trf_msg__message_wrapper__get_packed_size(&msg);
    uint8_t * buff = calloc(1, bufsz);
    
    for (int i = 0; i < ctx->svr.max_clients; i++)
    {
        if (ctx->svr.clients[i])
        {
            if (trfNCSendDelimited(ctx->svr.clients[i]->cli.client_fd, 
                                   buff, bufsz, 0, &msg) < 0)
            {
                trf__log_error("unable to disconnect client");
            }
        }
    }

    close(ctx->svr.listen_fd);
    ctx->svr.listen_fd = -1;
    return 0;
}

int trfNCServerDisconnectClient(PTRFContext client_ctx)
{
    if (!client_ctx)
    {
        trf__log_debug("Client context invalid!");
        return -EINVAL;
    }

    if (client_ctx->type != TRF_EP_CONN_ID)
    {
        trf__log_debug("Endpoint type invalid!");
        return -EINVAL;
    }
    
    TrfMsg__MessageWrapper msg = TRF_MSG__MESSAGE_WRAPPER__INIT;
    TrfMsg__Disconnect disc = TRF_MSG__DISCONNECT__INIT;
    msg.wdata_case = TRF_MSG__MESSAGE_WRAPPER__WDATA_DISCONNECT;
    msg.disconnect = &disc;
    disc.info = 0;

    size_t bufsz = trf_msg__message_wrapper__get_packed_size(&msg);
    uint8_t * buff = calloc(1, bufsz);

    trfNCSendDelimited(client_ctx->cli.client_fd, buff, bufsz, 0, &msg);
    close(client_ctx->cli.client_fd);
    return 0;
}