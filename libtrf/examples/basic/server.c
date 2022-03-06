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
#include <sys/mman.h>

int main(int argc, char ** argv)
{
    char* host = "0.0.0.0";
    char* port = "35101";
    int ret;

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
        return -1;
    }

    // Block until a client connects. This will establish a link with the client
    // on the best available fabric. Once this call returns succesfully, future
    // messages must be sent over the fabric, as the socket connection will be
    // closed after the negotiation phase.

    PTRFContext client_ctx;
    if (trfNCAccept(ctx, &client_ctx) < 0)
    {
        printf("unable to accept client\n");
        return -1;
    }

    // Bind a display list to the client context. This will be used to respond
    // to metadata requests, as well as limit the set of displays that this
    // specific client may use. As such, while the display IDs should be unique
    // between all contexts, the actual number of displays may be different.

    ret = trfBindDisplayList(client_ctx, displays);
    if (ret < 0)
    {
        printf("unable to bind displays\n");
        return -1;
    }

    printf("Connection established\n");

    uint64_t processed;
    TrfMsg__MessageWrapper * msg = NULL;
    
    // This function automatically processes messages, according to the input
    // values. Specify which messages should be processed internally, and the
    // system will attempt to auto-respond to them. Certain requests, such as
    // data requests and errors, may not be processed internally and must be
    // handled manually, even if the flags for them are set.

    ret = trfGetMessageAuto(client_ctx, TRFM_SET_DISP, &processed, (void **) &msg);
    if (ret < 0)
    {
        printf("unable to get poll messages: %d\n", ret);
        return -1;
    }

    if (msg && trfPBToInternal(msg->wdata_case) != TRFM_CLIENT_DISP_REQ)
    {
        printf("Wrong Message Type 1: %lu\n", trfPBToInternal(msg->wdata_case));
        return -1;
    }
    printf("Requesting second message...\n");
    
    // The client will indicate that it requires a specific display, and the
    // server should allocate the required memory.
    
    ret = trfGetMessageAuto(client_ctx, 0, &processed, (void **) &msg);
    if (ret < 0)
    {
        printf("unable to get poll messages: %d\n", ret);
        return -1;
    }

    if (msg && trfPBToInternal(msg->wdata_case) != TRFM_CLIENT_REQ)
    {
        printf("Wrong Message Type 2: %lu\n", trfPBToInternal(msg->wdata_case));
        return -1;
    }

    // Get the display requested

    PTRFDisplay req_disp = trfGetDisplayByID(displays, 
        msg->client_req->display[0]->id);
    if (!req_disp)
    {
        printf("unable to get display: %s\n", strerror(errno));
        return -1;
    }

    // Allocate a dummy framebuffer - normally in your application this should
    // be the pointer to the capture source's buffer.

    req_disp->fb_addr = trfAllocAligned(trfGetDisplayBytes(displays), 2097152);
    if (!req_disp->fb_addr)
    {
        printf("unable to allocate framebuffer\n");
        return -1;
    }
    madvise(req_disp->fb_addr, trfGetDisplayBytes(displays), MADV_HUGEPAGE);

    // Register the buffer.

    ret = trfRegDisplaySource(client_ctx, req_disp);
    if (ret < 0)
    {
        printf("unable to register display source: %d\n", ret);
        return -1;
    }

    // Acknowledge the request

    uint32_t disp_id = req_disp->id;
    ret = trfAckClientReq(client_ctx, &disp_id, 1);
    if (ret < 0)
    {
        printf("unable to acknowledge request: %d\n", ret);
        return -1;
    }

    // Handle incoming frame requests

    while (1)
    {
        ret = trfGetMessageAuto(client_ctx, ~TRFM_CLIENT_F_REQ, &processed, 
            (void **) &msg);
        if (ret < 0)
        {
            printf("unable to get poll messages: %d\n", ret);
            return -1;
        }
        if (processed == TRFM_CLIENT_F_REQ)
        {
            // Handle the frame request
            ret = trfSendFrame(client_ctx, req_disp, msg->client_f_req->addr, 
                msg->client_f_req->rkey);
            if (ret < 0)
            {
                printf("unable to send frame: %d\n", ret);
                return -1;
            }

            struct fi_cq_data_entry de;
            struct fi_cq_err_entry err;

            ret = trfGetSendProgress(client_ctx, &de, &err, 1);
            if (ret <= 0)
            {
                printf("Error: %s\n", fi_strerror(-ret));
                break;
            }
            req_disp->frame_cntr++;
            if((ret = trfAckFrameReq(client_ctx, req_disp)) < 0){
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

    trfDestroyContext(client_ctx);
    trfDestroyContext(ctx);
}