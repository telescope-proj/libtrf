/*
    SPDX-License-Identifier: LGPL-2.1-only

    Telescope Project
    Remote Framebuffer Library
    Internal Functions

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

#include "internal/trfi.h"

int trf__AllocSessionForClient(PTRFContext ctx, uint64_t session_id, 
    PTRFContext * ctx_out)
{
    if (!ctx || !ctx_out)
    {
        return -EINVAL;
    }

    *ctx_out = NULL;

    // If this is the first client, allocate memory in the client list
    struct TRFContext ** client_list = ctx->svr.clients;
    if (!client_list)
    {
        client_list = calloc(ctx->opts->max_clients, sizeof(void *));
        if (!client_list)
            return -ENOMEM;

        ctx->svr.max_clients = ctx->opts->max_clients;
    }

    // Find a free node in the client list

    for (int i = 0; i < ctx->svr.max_clients; i++)
    {
        if (!client_list[i])
        {
            // Allocate memory for the client context
            struct TRFContext * client = calloc(1, sizeof(struct TRFContext));
            if (!client)
                return -ENOMEM;

            // Initialize the client context
            client->type            = TRF_EP_CONN_ID;
            client->cli.session_id  = session_id;

            // Set the client context
            *ctx_out = client;
            client_list[i] = client;
            return 0;
        }
    }

    // No free node was found

    return -ENOSPC;

}