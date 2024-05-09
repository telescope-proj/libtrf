/*
    SPDX-License-Identifier: LGPL-2.1-only

    Telescope Project
    Remote Framebuffer Library
    Libfabric-based data fabric interface

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

#include "trf_fabric.h"

/* ---- Send operations ---- */

ssize_t trfFabricSend(PTRFContext ctx, PTRFMem mem, void * addr, size_t len,
                      fi_addr_t peer, PTRFContextOpts opts)
{
    if (!ctx || !mem)
        return -EINVAL;

    PTRFContextOpts o   = opts ? opts : ctx->opts;
    PTRFXFabric f       = ctx->xfer.fabric;
    fi_addr_t dest      = peer != FI_ADDR_UNSPEC ? peer : f->peer_addr;
    ssize_t ret;

    struct timespec deadline;
    ret = trfGetDeadline(&deadline, o->fab_snd_timeo);
    if (ret < 0)
        return ret;

    do
    {
        ret = trfFabricSendUnchecked(ctx, mem, addr, len, dest);
        if (ret < 0 && ret != -FI_EAGAIN)
        {
            trf__log_trace("Unchecked send failed: %s", fi_strerror(-ret));
            return ret;
        }
        if (ret == 0)
        {
            break;
        }
        trfNanoSleep(ctx->opts->fab_poll_rate);
    } while (ret == -FI_EAGAIN && !trf__HasPassed(CLOCK_MONOTONIC, &deadline));
    
    struct fi_cq_data_entry cqe;
    struct fi_cq_err_entry err;
    ret = trfFabricPollSend(ctx, &cqe, &err, ctx->opts->fab_cq_sync, 
                            ctx->opts->fab_poll_rate, &deadline, 1);
    if (ret == 1)
    {
        return ret;
    }
    else if (ret == 0)
    {
        trf__log_debug("Operation submitted - verification timeout");
        return -EINPROGRESS;
    }
    else
    {
        trf__log_debug("CQ read failed (%d): %s", 
            ret,
            trf__FabricGetCQErrString(ctx->xfer.fabric->tx_cq->cq, &err));
        return ret;
    }
}

ssize_t trfFabricSendMsg(PTRFContext ctx, PTRFMem mem, void * addr, size_t len,
                         fi_addr_t peer, PTRFContextOpts opts, 
                         TrfMsg__MessageWrapper * msg)
{
    if (!ctx || !mem || !msg)
        return -EINVAL;

    if (!addr)
        addr = trfMemPtr(mem);

    if (!len)
        len = trfMemSize(mem);

    ssize_t ret;
    ret = trfMsgPack(msg, len, addr);
    if (ret < 0)
        return ret;
    
    return trfFabricSend(ctx, mem, addr, ret, peer, opts);
}

/* ---- Receive operations ---- */


ssize_t trfFabricRecv(PTRFContext ctx, PTRFMem mem, void * addr, size_t len,
                      fi_addr_t peer, PTRFContextOpts opts)
{
    if (!ctx || !mem)
        return -EINVAL;

    PTRFContextOpts o   = opts ? opts : ctx->opts;
    PTRFXFabric f       = ctx->xfer.fabric;
    fi_addr_t dest      = peer != FI_ADDR_UNSPEC ? peer : f->peer_addr;
    ssize_t ret;

    struct timespec deadline;
    ret = trfGetDeadline(&deadline, o->fab_rcv_timeo);
    if (ret < 0)
        return ret;

    do
    {
        ret = trfFabricRecvUnchecked(ctx, mem, addr, len, dest);
        if (ret < 0 && ret != -FI_EAGAIN)
        {
            trf__log_trace("Unchecked recv failed: %s", fi_strerror(-ret));
            return ret;
        }
        if (ret == 0)
        {
            break;
        }
        trfNanoSleep(ctx->opts->fab_poll_rate);
    } while (ret == -FI_EAGAIN && !trf__HasPassed(CLOCK_MONOTONIC, &deadline));

    struct fi_cq_data_entry cqe;
    struct fi_cq_err_entry err;
    ret = trfFabricPollRecv(ctx, &cqe, &err, ctx->opts->fab_cq_sync,
                            ctx->opts->fab_poll_rate, &deadline, 1);
    if (ret == 1)
    {
        return ret;
    }
    else if (ret == 0)
    {
        trf__log_debug("Operation submitted - verification timeout");
        return -EINPROGRESS;
    }
    else
    {
        trf__log_debug("CQ read failed: %s/%s", fi_strerror(-ret),
            trf__FabricGetCQErrString(ctx->xfer.fabric->rx_cq->cq, &err));
        return ret;
    }
}

ssize_t trfFabricRecvMsg(PTRFContext ctx, PTRFMem mem, void * addr, size_t len,
                         fi_addr_t peer, PTRFContextOpts opts, 
                         TrfMsg__MessageWrapper ** msg)
{
    if (!ctx || !mem || !msg)
        return -EINVAL;

    if (!addr)
        addr = trfMemPtr(mem);

    if (!len)
        len = trfMemSize(mem);

    ssize_t ret;
    ret = trfFabricRecv(ctx, mem, addr, len, peer, opts);
    if (ret < 0)
        return ret;

    if (trfMsgGetPackedLength(addr) > len)
    {
        trf__log_debug("Message exceeds buffer length");
        return -ENOBUFS;
    }

    return trfMsgUnpack(msg, trfMsgGetPackedLength(addr),
                        trfMsgGetPayload(addr));
}