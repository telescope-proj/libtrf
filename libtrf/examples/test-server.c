/*
    SPDX-License-Identifier: LGPL-2.1-only

    Telescope Project
    Example Server

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

#include "trf.h"

int main(int argc, char ** argv)
{
    int ret;
    
    /*  Allocate context to store connection information 
    */

    PTRFContext ctx = trfAllocContext();
    if (!ctx) {
        printf("Context creation failed...\n");
        return 1;
    }
    
    /*  Enable the framebuffer source (server), specifying the host, port, and
        context we just created. 
    */
    
    ret = trfSourceInit("127.0.0.1", "1234", ctx);
    if (ret < 0) {
        printf("Source init failed...\n");
        return 1;
    }

    /*  Wait for a client to connect. */

    while (1) 
    {
        ret = trfSourceCheckReq(ctx, 0);
        if (ret > 0)
        {
            printf("Got request\n");
            break;
        }
        else if (ret < 0)
        {
            printf("Error\n");
            break;
        }
        trfSleep(1);
    }

    PTRFContext client = trfAllocContext();
    ret = trfAccept(ctx, client);
    if (ret < 0) {
        printf("Accept failed...\n");
        return 1;
    }

    trf_debug("Waiting for message...\n");

    ret = trfGetCQEvent(ctx);
    if (ret) {
        printf("Failed to get CQ event!\n");
        return 1;
    }

    printf("Message: %s\n", (char *) ctx->msg_mr->fid.context);
    trfSleep(1000);

}