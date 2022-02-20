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
#include "trf_ncp.h"
#include <signal.h>

int main(int argc, char ** argv)
{
    char* host = "127.0.0.1";
    char* port = "35101";
    PTRFContext ctx = trfAllocContext();
    if(trfNCClientInit(ctx,host,port)<0){
        printf("unable to initiate client\n");
        fflush(stdout);
        return -1;
    }
    printf("Hello!\n");


    PTRFDisplay displays;
    printf("Retrieving displays\n");
    ssize_t ret;
    ret = trfGetServerDisplays(ctx, &displays);
    if (ret < 0)
    {
        printf("Unable to get server display list: error %s\n", strerror(ret));
        return -1;
    }

    printf("Server Display List\n");
    printf("---------------------------------------------\n");

    for (PTRFDisplay tmp_disp = displays; tmp_disp != NULL; 
        tmp_disp = tmp_disp->next)
    {
        printf("Display ID:    %d\n", tmp_disp->id);
        printf("Display Name:  %s\n", tmp_disp->name);
        printf("Resolution:    %d x %d\n", tmp_disp->width, tmp_disp->height);
        printf("Refresh Rate:  %d\n", tmp_disp->rate);
        printf("Pixel Format:  %d\n", tmp_disp->format);
        printf("Display Group: %d\n", tmp_disp->dgid);
        printf("Group Offset:  %d, %d\n", tmp_disp->x_offset, tmp_disp->y_offset);
        printf("---------------------------------------------\n");
    }

    // Register buffer to store the first display's framebuffer

    displays->fb_addr = calloc(1, trfGetDisplayBytes(displays));
    ret = trfRegDisplaySink(ctx, displays);
    if (ret < 0)
    {
        printf("Unable to register display sink: error %s\n", strerror(ret));
        return -1;
    }

    // Indicate to the server that the client is ready to receive frames

    if((ret = trfSendClientReq(ctx,displays)) < 0){
        printf("Unable to send Display Request");
        return -1;
    }

    #define timespecdiff(_start, _end) \
        (((_end).tv_sec - (_start).tv_sec) * 1000000000 + \
        ((_end).tv_nsec - (_start).tv_nsec))

    // Request 100 frames from the first display in the list
    printf("Requesting 100 frames\n");
    struct timespec tstart, tend;
    for (int f = 0; f < 100; f++)
    {
        clock_gettime(CLOCK_MONOTONIC, &tstart);
        ret = trfRecvFrame(ctx, displays);
        if (ret < 0)
        {
            printf("Unable to receive frame: error %s\n", strerror(-ret));
            return -1;
        }
        clock_gettime(CLOCK_MONOTONIC, &tend);
        double tsd1 = timespecdiff(tstart, tend) / 1000000.0;
        struct fi_cq_data_entry de;
        ret = trfGetRecvProgress(ctx, &de, 999999);
        if (ret < 0)
        {
            printf("Unable to get receive progress: error %s\n", strerror(-ret));
            return -1;
        }
        clock_gettime(CLOCK_MONOTONIC, &tend);
        double tsd2 = timespecdiff(tstart, tend) / 1000000.0;
        printf( "[Frame %d] Size: %ld bytes, Request: %f ms, Received: %f ms, "
                "Rate: %f Gbit/s, Pk FPS: %f\n",
                f, trfGetDisplayBytes(displays), tsd1, tsd2, 
                ((double) trfGetDisplayBytes(displays)) / tsd2 / 1e5,
                1000.0 / tsd2
        );
        displays->frame_cntr++;
    }
    
    trfDestroyContext(ctx);
    // info = trfGetFabricProviders(host, port, TRF_EP_SINK, &info);
    // if (!info) {
    //     trf_error("unable to get fabric providers\n");
    //     return -1;
    // }
   
}