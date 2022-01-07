/*
    SPDX-License-Identifier: LGPL-2.1-only

    Telescope Project
    Example Client

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
    ssize_t n;
    PTRFContext ctx = trfAllocContext();
    
    trf_debug("Connecting to server...\n");
    
    ret = trfSinkInit("127.0.0.1", "1234", ctx);
    if (ret) {
        printf("Sink init failed...\n");
        return 1;
    }

    trf_debug("Connected to server\n");
    
    ret = trfAllocLocalBuffer(ctx, 4096, &ctx->fb_mr);
    if (ret) {
        printf("Failed to allocate local buffer!\n");
        return 1;
    }

    trf_debug("Allocated local buffer\n");

    char * test_str = "Hello from the client!";
    size_t test_str_len = strlen(test_str) + 1;
    
    memcpy(ctx->fb_mr->fid.context, test_str, test_str_len);

    trf_debug("Sending message...\n");

    n = fi_send(ctx->ep, ctx->fb_mr->fid.context, test_str_len,
        ctx->fb_mr, 0, NULL);
    if (n < 0) {
        trf_fi_error("Send message", (int) n);
    }
    
    ret = trfGetCQEvent(ctx);
    if (ret) {
        printf("Failed to get CQ event!\n");
        return 1;
    }

    printf("Message sent!\n");

    trfSleep(1);

}