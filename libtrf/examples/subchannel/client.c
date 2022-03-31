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
#include "common.h"

#include <signal.h>

#if defined(__linux__)
    #include <sys/mman.h>
#endif

pthread_mutex_t mut;

void * demo_thread(void * arg)
{
    trf__log_set_level(2);
    ts_printf("Demo thread started\n");
    PTRFContext ctx = (PTRFContext) arg;
    size_t s = trf__GetPageSize();
    void * mem = trfAllocAligned(s, s);
    if (!mem)
        return (void *) ENOMEM;

    uint32_t * counter = (uint32_t *) mem;
    
    intptr_t ret = trfRegInternalMsgBuf(ctx, mem, s);
    if (ret < 0)
        return (void *) -ret;

    struct TRFMem * mr = &ctx->xfer.fabric->msg_mem;

    while (*counter < 100)
    {
        ret = trfFabricRecv(ctx, mr, trfMemPtr(mr), 4, 
                            ctx->xfer.fabric->peer_addr, ctx->opts);
        if (ret < 0)
        {
            ts_printf("Fabric recv failed: %s\n", fi_strerror(-ret));
            return (void *) -ret;
        }

        *counter += 1;
        ts_printf("Counter: %d\n", *counter);
        trfSleep(1);

        ret = trfFabricSend(ctx, mr, trfMemPtr(mr), 4,
                            ctx->xfer.fabric->peer_addr, ctx->opts);
        if (ret < 0)
        {
            ts_printf("Fabric send failed: %s\n", fi_strerror(-ret));
            return (void *) -ret;
        }

    }

    return NULL;
}

int main(int argc, char ** argv)
{
    char* host = "127.0.0.1";
    char* port = "35101";
    pthread_t t;

    PTRFContext ctx = trfAllocContext();
    if (trfNCClientInit(ctx, host, port) < 0)
    {
        ts_printf("unable to initiate client\n");
        fflush(stdout);
        return -1;
    }
    ts_printf("Hello!\n");
    ts_printf("Socket FD: %d", ctx->cli.client_fd);

    PTRFDisplay displays;
    ts_printf("Retrieving displays\n");
    ssize_t ret;
    ret = trfGetServerDisplays(ctx, &displays);
    if (ret < 0)
    {
        ts_printf("Unable to get server display list: error %s\n", strerror(ret));
        return -1;
    }

    ts_printf("Server Display List\n");
    ts_printf("---------------------------------------------\n");

    for (PTRFDisplay tmp_disp = displays; tmp_disp != NULL; 
        tmp_disp = tmp_disp->next)
    {
        ts_printf("Display ID:    %d\n", tmp_disp->id);
        ts_printf("Display Name:  %s\n", tmp_disp->name);
        ts_printf("Resolution:    %d x %d\n", tmp_disp->width, tmp_disp->height);
        ts_printf("Refresh Rate:  %d\n", tmp_disp->rate);
        ts_printf("Pixel Format:  %d\n", tmp_disp->format);
        ts_printf("Display Group: %d\n", tmp_disp->dgid);
        ts_printf("Group Offset:  %d, %d\n", tmp_disp->x_offset, tmp_disp->y_offset);
        ts_printf("---------------------------------------------\n");
    }

    // Register buffer to store the first display's framebuffer

    displays->mem.ptr = trfAllocAligned(trfGetDisplayBytes(displays), 2097152);
    ret = trfRegDisplaySink(ctx, displays);
    if (ret < 0)
    {
        ts_printf("Unable to register display sink: error %s\n", strerror(ret));
        return -1;
    }
    
    #if defined(__linux__)
        madvise(displays->mem.ptr, trfGetDisplayBytes(displays), MADV_HUGEPAGE);
    #endif

    // Indicate to the server that the client is ready to receive frames

    if ((ret = trfSendClientReq(ctx,displays)) < 0)
    {
        ts_printf("Unable to send display request");
        return -1;
    }

    // Wait until the server is ready

    TrfMsg__MessageWrapper * msg = NULL;
    PTRFXFabric f = ctx->xfer.fabric;
    ret = trfFabricRecvMsg(ctx, &f->msg_mem, trfMemPtr(&f->msg_mem),
                           trfMemSize(&f->msg_mem), f->peer_addr, ctx->opts,
                           &msg);
    if (ret < 0)
    {
        ts_printf("Unable to receive message: %s\n", fi_strerror(-ret));
        return -1;
    }
    
    if (trfPBToInternal(msg->wdata_case) != TRFM_SERVER_ACK)
    {
        ts_printf("Invalid message type %d received", msg->wdata_case);
        return -1;
    }

    // Create a subchannel

    ts_printf("Creating subchannel with ID 10...\n");
    PTRFContext sub = NULL;
    ret = trfCreateSubchannel(ctx, &sub, 10);
    if (ret < 0)
    {
        ts_printf("Could not create subchannel: %s\n", fi_strerror(-ret));
        return -1;
    }

    // Create a new thread to use the subchannel
    ret = pthread_create(&t, NULL, demo_thread, sub);
    if (ret)
        ts_printf("Error creating thread: %s\n", strerror(errno));

    
    #define timespecdiff(_start, _end) \
        (((_end).tv_sec - (_start).tv_sec) * 1000000000 + \
        ((_end).tv_nsec - (_start).tv_nsec))

    
    // Request 100 frames from the first display in the list
    
    ts_printf( "\"Frame\",\"Size\",\"Request (ms)\",\"Frame Time (ms)\""
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
            ts_printf("Unable to receive frame: error %s\n", strerror(-ret));
            return -1;
        }
        clock_gettime(CLOCK_MONOTONIC, &tend);
        double tsd1 = timespecdiff(tstart, tend) / 1000000.0;
        struct fi_cq_data_entry de;
        struct fi_cq_err_entry err;
        ret = trfGetRecvProgress(ctx, &de, &err, 1, NULL);
        if (ret < 0)
        {
            ts_printf("Unable to get receive progress: error %s\n", 
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
                ts_printf("%d,%ld,%f,%f,%f,%f\n",
                    f, trfGetDisplayBytes(displays), tsd1, tsd2, 
                    ((double) trfGetDisplayBytes(displays)) / tsd2 / 1e5,
                    1000.0 / tsd2);
                break;
            default:
                ts_printf("Message type %d received!", msg->wdata_case);
        }

        displays->frame_cntr++;
    }
    
    // Wait for the other thread to finish
    uint64_t * retval;
    pthread_join(t, (void *) &retval);
    if (retval)
        ts_printf("Thread failed with: %s", strerror(errno));

    // Once done, destroy the context releasing all resources and closing the
    // connection.
    trfDestroyContext(ctx);
}