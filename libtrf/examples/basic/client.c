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
#include "trf_ncp_client.h"
#include <signal.h>

#if defined(__linux__)
    #include <sys/mman.h>
#endif

int main(int argc, char ** argv)
{
    char* host = "127.0.0.1";
    char* port = "35101";

    PTRFContext ctx = trfAllocContext();
    if (trfNCClientInit(ctx, host, port) < 0)
    {
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

    displays->mem.ptr = trfAllocAligned(trfGetDisplayBytes(displays), 2097152);
    ret = trfRegDisplaySink(ctx, displays);
    if (ret < 0)
    {
        printf("Unable to register display sink: error %s\n", strerror(ret));
        return -1;
    }
    
    #if defined(__linux__)
        madvise(displays->mem.ptr, trfGetDisplayBytes(displays), MADV_HUGEPAGE);
    #endif

    // Indicate to the server that the client is ready to receive frames

    if ((ret = trfSendClientReq(ctx,displays)) < 0)
    {
        printf("Unable to send display request");
        return -1;
    }

    // Wait until the server is ready

    TrfMsg__MessageWrapper * msg = NULL;
    PTRFXFabric f = ctx->xfer.fabric;
    ret = trfFabricRecvMsg(ctx, &f->msg_mem, trfMemPtr(&f->msg_mem),
                           trfMemSize(&f->msg_mem), f->peer_addr, ctx->opts,
                           &msg);
    if (trfPBToInternal(msg->wdata_case) != TRFM_SERVER_ACK)
    {
        printf("Invalid message type %d received", msg->wdata_case);
        return -1;
    }

    #define timespecdiff(_start, _end) \
        (((_end).tv_sec - (_start).tv_sec) * 1000000000 + \
        ((_end).tv_nsec - (_start).tv_nsec))

    // Request 100 frames from the first display in the list
    printf( "\"Frame\",\"Size\",\"Request (ms)\",\"Frame Time (ms)\""
            ",\"Speed (Gbit/s)\",\"Framerate (Hz)\"\n");
    struct timespec tstart, tend;
    for (int f = 0; f < 100; f++)
    {
        // Post a frame receive request. This will inform the server that the
        // client is ready to receive a frame, but the frame will not be ready
        // until the server sends an acknowledgement.
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
        struct fi_cq_err_entry err;
        ret = trfGetRecvProgress(ctx, &de, &err, 1, NULL);
        if (ret < 0)
        {
            printf("Unable to get receive progress: error %s\n", 
                   strerror(-ret));
            return -1;
        }

        ret = trfMsgUnpack(&msg, 
                           trfMsgGetPackedLength(ctx->xfer.fabric->msg_mem.ptr),
                           trfMsgGetPayload(ctx->xfer.fabric->msg_mem.ptr));
        if (ret < 0)
            return -1;

        switch (trfPBToInternal(msg->wdata_case))
        {
            case TRFM_SERVER_ACK_F_REQ:
                clock_gettime(CLOCK_MONOTONIC, &tend);
                double tsd2 = timespecdiff(tstart, tend) / 1000000.0;
                printf("%d,%ld,%f,%f,%f,%f\n",
                    f, trfGetDisplayBytes(displays), tsd1, tsd2, 
                    ((double) trfGetDisplayBytes(displays)) / tsd2 / 1e5,
                    1000.0 / tsd2);
            default:
                printf("Message type %d received!", msg->wdata_case);
        }

        displays->frame_cntr++;
    }
    
    // Once done, destroy the context releasing all resources and closing the
    // connection.
    trfDestroyContext(ctx);
}