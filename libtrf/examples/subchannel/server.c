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
#include "trf_ncp_server.h"
#include "common.h"

#include <signal.h>
#include <pthread.h>

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
    *counter = 0;

    intptr_t ret = trfRegInternalMsgBuf(ctx, mem, s);
    if (ret < 0)
        return (void *) -ret;

    struct TRFMem * mr = &ctx->xfer.fabric->msg_mem;

    while (*counter < 100)
    {
        uint32_t prev = *counter;
        ts_printf("Counter: %d\n", *counter);
        ret = trfFabricSend(ctx, mr, trfMemPtr(mr), 4,
                            ctx->xfer.fabric->peer_addr, ctx->opts);
        if (ret < 0)
        {
            ts_printf("Fabric send failed: %s\n", fi_strerror(-ret));
            return (void *) -ret;
        }

        ret = trfFabricRecv(ctx, mr, trfMemPtr(mr), 4, 
                            ctx->xfer.fabric->peer_addr, ctx->opts);
        if (ret < 0)
        {
            ts_printf("Fabric recv failed: %s\n", fi_strerror(-ret));
            return (void *) -ret;
        }
        
        if (*counter == prev)
        {
            ts_printf("Client did not increment counter!\n");
            return (void *) EBADE;
        }

    }

    ts_printf("Counter check passed!");

    // In this test the client is expected to send a disconnect

    ctx->disconnected = 1;
    trfDestroyContext(ctx);

    return NULL;
}

int main(int argc, char ** argv)
{
    char* host = "0.0.0.0";
    char* port = "35101";
    bool  ci   = 0;

    printf("argc: %d\n", argc);

    if (argc >= 2)
        host = argv[1];

    if (argc >= 3)
        port = argv[2];

    if (argc >= 4)
        if (strncmp(argv[3], "ci", 2) == 0)
            ci = 1;

    int ret;
    int opaque = 0;

    pthread_t t;
    PTRFContext ctx = trfAllocContext();
    PTRFDisplay displays = calloc(1, sizeof(struct TRFDisplay));

    // Example display, named "test", with a resolution of 1920x1080.
    
    displays->id = 0;
    displays->name = "test";
    displays->width = 1920;
    displays->height = 1080;
    displays->rate = 60;
    displays->format = TRF_TEX_BGRA_8888;
    displays->dgid = 0;
    displays->x_offset = 0;
    displays->y_offset = 0;

    // Initialize the server's resources and start listening on the specified
    // host and port for incoming negotiation channel connections.

    if (trfNCServerInit(ctx, host, port) < 0)
    {
        printf("unable to initiate server\n");
        return 1;
    }

    // Block until a client connects. This will establish a link with the client
    // on the best available fabric. Once this call returns succesfully, future
    // messages must be sent over the fabric, as the socket connection will be
    // closed after the negotiation phase.

    PTRFContext client_ctx;
    if (trfNCAccept(ctx, &client_ctx) < 0)
    {
        printf("unable to accept client\n");
        return 1;
    }

    // Bind a display list to the client context. This will be used to respond
    // to metadata requests, as well as limit the set of displays that this
    // specific client may use. As such, while the display IDs should be unique
    // between all contexts, the actual number of displays may be different.

    ret = trfBindDisplayList(client_ctx, displays);
    if (ret < 0)
    {
        printf("unable to bind displays\n");
        return 1;
    }

    printf("Connection established\n");

    uint64_t processed;
    TrfMsg__MessageWrapper * msg = NULL;
    
    // This function automatically processes messages, according to the input
    // values. Specify which messages should be processed internally, and the
    // system will attempt to auto-respond to them. Certain requests, such as
    // data requests and errors, may not be processed internally and must be
    // handled manually, even if the flags for them are set.

    ret = trfGetMessageAuto(client_ctx, TRFM_SET_DISP, &processed, 
                            (void **) &msg, &opaque);
    if (ret < 0)
    {
        printf("unable to get poll messages: %d\n", ret);
        return 1;
    }

    if (msg && trfPBToInternal(msg->wdata_case) != TRFM_CLIENT_DISP_REQ)
    {
        printf("Wrong Message Type 1: %" PRIu64 "\n", trfPBToInternal(msg->wdata_case));
        return 1;
    }

    printf("Requesting second message...\n");
    trf__ProtoFree(msg);
    
    // The client will indicate that it requires a specific display, and the
    // server should allocate the required memory.
    
    ret = trfGetMessageAuto(client_ctx, TRFM_CLIENT_REQ, &processed, 
                            (void **) &msg, &opaque);
    if (ret < 0)
    {
        printf("unable to get poll messages: %d\n", ret);
        return 1;
    }

    if (msg && trfPBToInternal(msg->wdata_case) != TRFM_CLIENT_REQ)
    {
        printf("Wrong Message Type 2: %" PRIu64 "\n", 
               trfPBToInternal(msg->wdata_case));
        return 1;
    }

    // Get the display requested

    PTRFDisplay req_disp = trfGetDisplayByID(displays, 
        msg->client_req->display[0]->id);
    if (!req_disp)
    {
        printf("unable to get display: %s\n", strerror(errno));
        return 1;
    }

    trf__ProtoFree(msg);

    // Allocate a dummy framebuffer - normally in your application this should
    // be the pointer to the capture source's buffer.

    req_disp->mem.ptr = trfAllocAligned(trfGetDisplayBytes(displays), 2097152);
    if (!req_disp->mem.ptr)
    {
        printf("unable to allocate framebuffer\n");
        return 1;
    }

    #if defined(__linux__)
        madvise(trfMemPtr(&req_disp->mem), trfGetDisplayBytes(displays),
                MADV_HUGEPAGE);
    #endif

    // Register the buffer.

    ret = trfRegDisplaySource(client_ctx, req_disp);
    if (ret < 0)
    {
        printf("unable to register display source: %d\n", ret);
        return 1;
    }

    memset(req_disp->mem.ptr, 0, trfGetDisplayBytes(req_disp));

    // Acknowledge the request

    uint32_t disp_id = req_disp->id;
    ret = trfAckClientReq(client_ctx, &disp_id, 1);
    if (ret < 0)
    {
        printf("unable to acknowledge request: %d\n", ret);
        return 1;
    }

    // Frame integrity check
    uint32_t fcheck = 0;

    // Handle incoming frame requests

    PTRFContext sub = NULL;
    while (1)
    {
        ret = trfGetMessageAuto(client_ctx, ~TRFM_CLIENT_F_REQ, &processed, 
            (void **) &msg, &opaque);
        if (ret < 0)
        {
            printf("unable to get poll messages: %d\n", ret);
            return 1;
        }
        else if (processed == TRFM_CH_OPEN)
        {
            // Client wants to open a subchannel
            if (sub)
            {
                printf("Warning: Client already opened a subchannel!");
                continue;
            }
            ret = trfProcessSubchannelReq(client_ctx, &sub, msg);
            if (ret < 0)
            {
                printf("Subchannel creation failed\n");
                continue;
            }
            printf("Opened subchannel %d\n", sub->channel_id);

            // Create a new thread to use the subchannel
            ret = pthread_create(&t, NULL, demo_thread, sub);
            if (ret)
                printf("Error creating thread: %s\n", strerror(errno));
        }
        if (processed == TRFM_CLIENT_F_REQ)
        {
            if (ci)
            {
                // Data integrity check
                fcheck += 0x01010101;
                for (int i = 0; i <= trfGetDisplayBytes(req_disp) / 4; i++)
                {
                    * (((uint32_t *) trfGetFBPtr(displays)) + i) = fcheck;
                }
            }

            // Handle the frame request
            ret = trfSendFrame(client_ctx, req_disp, msg->client_f_req->addr, 
                msg->client_f_req->rkey);
            if (ret < 0)
            {
                printf("unable to send frame: %d\n", ret);
                return 1;
            }

            struct fi_cq_data_entry de;
            struct fi_cq_err_entry err;

            ret = trfGetSendProgress(client_ctx, &de, &err, 1, NULL);
            if (ret <= 0)
            {
                if (ret == -FI_EAVAIL)
                {
                    printf("Error: %s\n", fi_strerror(err.err));
                }
                else
                {
                    printf("Error: %s\n", fi_strerror(-ret));
                }
                break;
            }

            req_disp->frame_cntr++;
            if((ret = trfAckFrameReq(client_ctx, req_disp)) < 0)
            {
                printf("Unable to send Ack: %s\n", fi_strerror(ret));
            }
            printf("Sent frame: %d\n", req_disp->frame_cntr);
        }
        else if (processed == TRFM_DISCONNECT)
        {
            // If the peer initiates a disconnect, setting this flag will ensure
            // that a disconnect message is not sent back to an already
            // disconnected peer (which results in a wait until the timeout).
            ctx->disconnected = 1;
            printf("Client requested a disconnect\n");
            break;
        }
        else
        {
            printf("Wrong message type...\n");
        }
    }

    uint64_t * retval;
    pthread_join(t, (void *) &retval);
    if (retval)
    {
        printf("Thread failed with: %s", strerror(errno));
        return 1;
    }
    
    // Deregister the frame buffer before freeing memory
    void * fb = req_disp->mem.ptr;
    trfUpdateDisplayAddr(client_ctx, req_disp, NULL);
    free(fb);

    // Destroy context objects
    trfDestroyContext(client_ctx);
    trfDestroyContext(ctx);
}