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
#include "trf_ncp.h"
#include <signal.h>

int main(int argc, char ** argv)
{
    char* host = "0.0.0.0";
    char* port = "35096";
    int ret;

    PTRFContext ctx = trfAllocContext();

    PTRFDisplay displays = calloc(1, sizeof(struct TRFDisplay));

    displays->id = 0;
    displays->name = "test";
    displays->width = 1920;
    displays->height = 1080;
    displays->rate = 60;
    displays->format = TRF_TEX_BGRA_8888;
    displays->dgid = 0;
    displays->x_offset = 0;
    displays->y_offset = 0;

    ctx->displays = displays;

    if (trfNCServerInit(ctx,host,port) < 0)
    {
        printf("unable to initiate server\n");
        return -1;
    }

    PTRFContext client_ctx;
    if (trfNCAccept(ctx, &client_ctx) < 0)
    {
        printf("unable to accept client\n");
        return -1;
    }

    ret = trfBindDisplayList(client_ctx, displays);
    if (ret < 0)
    {
        printf("unable to bind displays\n");
        return -1;
    }

    // if (trfNCSendDisplayList(client_ctx) < 0){
    //     printf("Unable to send displays to client\n");
    //     return -1;
    // }

    printf("Connection established\n");
    // if((ret = trfGetMessage(client_ctx)) < 0)
    // {
    //     printf("unable to get poll messages\n");
    //     return -1;
    // }

    uint64_t *processed = malloc(sizeof(*processed));
    if(!processed){
        printf("unable to allocate processed\n");
        return -1;
    }
    int timeout = 1000;
    int rate = 5;
    void * msg;
    
    if((ret = trfGetMessageAuto(client_ctx, TRFM_SET_CAP, processed, timeout, rate, &msg)) < 0){
        printf("unable to get poll messages: %d\n", ret);
        return -1;
    }

    TrfMsg__MessageWrapper * mw = msg;
    if(mw->wdata_case != TRF_MSG__MESSAGE_WRAPPER__WDATA_CLIENT_DISP_REQ){
        printf("Wrong Message Type\n");
        return -1;
    }
    trfDestroyContext(client_ctx);
    trfDestroyContext(ctx);

}