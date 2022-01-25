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

#include "trf-ncp.h"

int trfNCServerInit(PTRFContext ctx, char * host, char * port)
{
    if (!ctx)
    {
        trf_error("Server init: Invalid connection context\n");
        return -EINVAL;
    }

    if (!ctx->oob)
    {
        ctx->oob = calloc(1, sizeof(*ctx->oob));
        if (!ctx->oob)
        {
            trf_error("Server init: Out of memory\n");
            return -ENOMEM;
        }
    }

    if (ctx->oob->listen_fd > 0)
    {
        trf_error("Server init: Socket exists\n");
        return -EALREADY;
    }
    
    struct addrinfo hints;
    struct addrinfo * res;
    int sfd = -1;
    int ret;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family     = AF_UNSPEC;
    hints.ai_socktype   = SOCK_STREAM;
    hints.ai_flags      = AI_PASSIVE;

    ret = getaddrinfo(host, port, &hints, &res);
    if (ret != 0)
    {
        trf_error("getaddrinfo() failed: %s\n", gai_strerror(ret));
        return -ret;
    }

    struct addrinfo * res_p;

    for (res_p = res; res_p != NULL; res_p = res_p->ai_next)
    {
        sfd = socket(res_p->ai_family, res_p->ai_socktype, res_p->ai_protocol);
        if (sfd == -1)
        {
            continue;
        }

        ret = bind(sfd, res_p->ai_addr, res_p->ai_addrlen);
        if (ret == 0)
        {
            break;
        }
    }

    freeaddrinfo(res);

    if (sfd == -1)
    {
        trf_error("Failed to bind to %s:%s\n", host, port);
        return -1;
    }
    
    
    ret = listen(sfd, 1);
    if (ret == -1)
    {
        trf_error("Could not listen\n");
        return -1;
    }

    return sfd;
}


int trfNCClientInit(PTRFContext ctx, char * host, char * port)
{
    if (!ctx)
    {
        trf_error("Client init: Invalid connection context\n");
        return -EINVAL;
    }

    if (!ctx->oob)
    {
        ctx->oob = calloc(1, sizeof(*ctx->oob));
        if (!ctx->oob)
        {
            trf_error("Client init: Out of memory\n");
            return -ENOMEM;
        }
    }

    if (ctx->oob->client_fd > 0)
    {
        trf_error("Client init: Socket exists\n");
        return -EALREADY;
    }
    
    struct addrinfo hints;
    struct addrinfo * res;
    int sfd = -1;
    int ret;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family     = AF_UNSPEC;
    hints.ai_socktype   = SOCK_STREAM;
    hints.ai_flags      = AI_PASSIVE;

    ret = getaddrinfo(host, port, &hints, &res);
    if (ret != 0)
    {
        trf_error("Client init: getaddrinfo() failed: %s\n", gai_strerror(ret));
        return -ret;
    }

    struct addrinfo * res_p;

    for (res_p = res; res_p != NULL; res_p = res_p->ai_next)
    {
        sfd = socket(res_p->ai_family, res_p->ai_socktype, res_p->ai_protocol);
        if (sfd == -1)
        {
            continue;
        }

        ret = connect(sfd, res_p->ai_addr, res_p->ai_addrlen);
        if (ret == 0)
        {
            break;
        }
    }

    if (sfd == -1)
    {
        trf_error("Failed to connect to %s:%s\n", host, port);
        return -1;
    }

    freeaddrinfo(res);
    ctx->oob->fd = sfd;
    return 0;

}


int trfNCServerAccept(PTRFContext ctx)
{
    int cfd = -1;
    int ret;

    cfd = accept(ctx->oob->listen_fd, NULL, NULL);
    if (cfd == -1)
    {
        trf_error("Could not accept connection\n");
        return -errno;
    }

    ctx->oob->client_fd = cfd;
    return 0;
}


int trfNCServerClose(PTRFContext ctx)
{
    if (!ctx)
    {
        trf_error("Server close: Invalid connection context\n");
        return -EINVAL;
    }

    if (!ctx->oob)
    {
        trf_error("Server close: No connection\n");
        return -ENOTCONN;
    }

    if (ctx->oob->listen_fd == -1)
    {
        trf_error("Server close: No connection\n");
        return -ENOTCONN;
    }

    if (ctx->oob->client_fd > 0)
    {
        close(ctx->oob->client_fd);
        ctx->oob->client_fd = -1;
    }

    close(ctx->oob->listen_fd);
    ctx->oob->listen_fd = -1;
    return 0;
}


int trfNCClientClose(PTRFContext ctx)
{
    if (!ctx)
    {
        trf_error("Client close: Invalid connection context\n");
        return -EINVAL;
    }

    if (!ctx->oob)
    {
        trf_error("Client close: No connection\n");
        return -ENOTCONN;
    }

    if (ctx->oob->client_fd == -1)
    {
        trf_error("Client close: No connection\n");
        return -ENOTCONN;
    }

    close(ctx->oob->client_fd);
    ctx->oob->client_fd = -1;
    return 0;
}

