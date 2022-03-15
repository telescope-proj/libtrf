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
    int allocd_mem = 0;
    if (!ctx || !ctx_out)
    {
        return -EINVAL;
    }
    *ctx_out = NULL;
    // If this is the first client allocate memory in the client list
    if (!ctx->svr.clients)
    {
        ctx->svr.clients = calloc(1, sizeof(struct TRFContext));
        if (!ctx->svr.clients)
        {
            free(ctx->svr.clients);
        }
        allocd_mem = 1;
    }

    PTRFContext cli_node = ctx->svr.clients;

    while (1)
    {
        if (cli_node->type == TRF_EP_FREE)
        {
            cli_node->type = TRF_EP_CONN_ID;
            cli_node->cli.session_id = session_id;
        }
        if (cli_node->next == NULL)
        {
            cli_node->next = calloc(1, sizeof(struct TRFContext));
            if (!cli_node->next)
            {
                trf__log_error("Failed to allocate client context memory");
                if (allocd_mem) {
                    free(ctx->svr.clients);
                }
                return -ENOMEM;
            }
            cli_node->next->type = TRF_EP_CONN_ID;
            cli_node->next->cli.session_id = session_id;
            *ctx_out = cli_node->next;
            return 0;
        }
        cli_node = cli_node->next;
    }
}